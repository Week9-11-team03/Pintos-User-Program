#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
// Project 2 : System Call
#include "kernel/stdio.h"
#include "threads/init.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "devices/input.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

static struct lock filesys_lock;

void
syscall_init (void) {
	lock_init(&filesys_lock);

	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

// 유저 포인터가 유효한지 검사
void check_user_ptr(const void *ptr) {
	if (ptr == NULL || !is_user_vaddr(ptr) || pml4_get_page(thread_current()->pml4, ptr) == NULL) {
		exit(-1);
	}
}

// 유효한 fd인지 확인 후, 해당 파일 포인터를 반환
static struct file *get_valid_file(int fd) {
	struct thread *curr = thread_current();

	if (fd >= 64 || curr->fdt[fd] == NULL) {
		exit(-1);
	}

	return curr->fdt[fd];
}

void halt() {
	power_off();
}

int write(int fd, const void *buffer, unsigned size) {
	struct thread *curr = thread_current();

	check_user_ptr(buffer);

	int bytes_written = 0;

	if (fd == 1) {
		putbuf(buffer, size);
		bytes_written = size;
	}
	else if (fd >= 2 && fd < 64 && curr->fdt[fd] != NULL) {
		struct file *file = curr->fdt[fd];
		lock_acquire(&filesys_lock);
		bytes_written = file_write(file, buffer, size);
		lock_release(&filesys_lock);
	} 
	else {
		return -1;
	}

	return bytes_written;
}

void exit(int status) {
	struct thread *curr = thread_current();
	curr->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

bool create(const char *file, unsigned initial_size) {
	check_user_ptr(file);
	return filesys_create(file, initial_size);
}

int open(const char *file) {
	check_user_ptr(file); 

	struct file *opened_file = filesys_open(file);
	
	if (opened_file == NULL) {
		return -1;
	}

	struct thread *curr = thread_current();

	int fd;
	for (fd = 2; fd < 64; fd++) {
		if (curr->fdt[fd] == NULL) {
			curr->fdt[fd] = opened_file;
			return fd;
		}
	}
	
	file_close(opened_file);  
	return -1;
}

/*	Close file descriptor fd
	Use void file_close(struct file *file)*/
void close(int fd) {
	struct thread *curr = thread_current();
	struct file *file = get_valid_file(fd);
	curr->fdt[fd] = NULL;

	lock_acquire(&filesys_lock);
	file_close(file);
	lock_release(&filesys_lock);
}

int filesize (int fd) {
	struct file *file = get_valid_file(fd);
	return file_length(file);
}

int read (int fd, void *buffer, unsigned size) {
	struct thread *curr = thread_current();
	check_user_ptr(buffer);

	if (fd == 0) {
		for (int i =0; i < size; i++) {
			((char *)buffer)[i] = input_getc();
		}
		return size;
	} 
	else if (fd >= 2 && fd < 64 && curr->fdt[fd] != NULL) {
		struct file *file = get_valid_file(fd);
	
		lock_acquire(&filesys_lock);
		int bytes_read = file_read(file, buffer, size);
		lock_release(&filesys_lock);
	
		return bytes_read;
	} 
	else {
		return -1;
	}
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	uint64_t syscall_number = f->R.rax;
	// printf("rax: %ld, rdi: %ld, rsi: %ld, rdx: %ld, r10: %ld, r8: %ld, r9: %ld\n", f->R.rax, f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8, f->R.r9);
	
	switch (syscall_number) {
		case SYS_HALT: {
			halt();			// PintOS 종료
			break;
		}
		case SYS_EXIT: {
			exit(f->R.rdi);	// Process 종료
			break;
		}
		case SYS_WRITE: {
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		}
		case SYS_WAIT: {
			tid_t tid = f->R.rdi;
			f->R.rax = process_wait(tid);
			break;
		}
		case SYS_OPEN: {
			f->R.rax = open((const char *)f->R.rdi);
			break;
		}
		case SYS_CREATE: {
			f->R.rax = create((const char *)f->R.rdi, f->R.rsi);
			break;
		}
		case SYS_CLOSE: {
			close(f->R.rdi);
			break;
		}
		case SYS_READ: {
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		}
		case SYS_FILESIZE: {
			f->R.rax = filesize(f->R.rdi);
			break;
		}
		default: {
			exit(-1);
		}
	}
}