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

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

static struct lock filesys_lock;

int get_user(uint8_t *dst, const uint8_t *uaddr);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&filesys_lock);
}


void syscall_handler(struct intr_frame *f) {
    // syscall 번호 및 인자 추출
    int syscall_n = f->R.rax;
    uint64_t arg1 = f->R.rdi;
    uint64_t arg2 = f->R.rsi;
    uint64_t arg3 = f->R.rdx;
    uint64_t arg4 = f->R.r10;
    uint64_t arg5 = f->R.r8;
    uint64_t arg6 = f->R.r9;  

    switch (syscall_n) {
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
            exit((int)arg1);
            break;
        case SYS_WRITE:
            f->R.rax = write((int)arg1, (const void *)arg2, (unsigned)arg3);
            break;
        case SYS_OPEN:
            f->R.rax = open((const char *)arg1);
            break;
        case SYS_CREATE:
            f->R.rax = create((const char *)arg1, (unsigned)arg2);
            break;
        case SYS_READ:
            f->R.rax = read((int)arg1, (void *)arg2, (unsigned)arg3);
            break;
        case SYS_FILESIZE:
            f->R.rax = filesize((int)arg1);
            break;
        case SYS_CLOSE:
            close((int)arg1);
            break;
		// case SYS_FORK:
		//     fork();
		// 	break;
		case SYS_EXEC:
		    f->R.rax = exec((const char *)arg1);
			break;
    }
}




int write(int fd, const void *buffer, unsigned size)
{
	
	int bytes_written;
	struct thread *t = thread_current(); // 현재 쓰레드 포인터 획득
	check_user_ptr(buffer);				 // 버퍼 유효성 검사.

	if (fd == 1) // 출력 처리
	{
		putbuf(buffer, size);
		bytes_written = size;
	}
	else if (fd >= 2 && fd < MAX_FD && t->fd_table[fd] != NULL)
	{
		struct file *file = t->fd_table[fd];
		lock_acquire(&filesys_lock);					// 전역 락 획득.
		bytes_written = file_write(file, buffer, size); // 쓰기 연산.
		lock_release(&filesys_lock);					// 전역 락 해제
	}
	else
	{
		return -1;
	}
	return bytes_written;
}

void halt()
{
	power_off();
}

void exit(int status)
{
	thread_current()->status_code = status;
	thread_exit(); // this leads to process exit.
}

int open(const char *file_name)
{

	struct thread *t = thread_current(); // 현재 쓰레드 포인터를 획득
	check_user_ptr(file_name);			 // 포인터 유효성 검사

	lock_acquire(&filesys_lock);				 // 전역 락 획득
	struct file *file = filesys_open(file_name); // 파일 오픈 작업 수행
	lock_release(&filesys_lock);				 // 전역 락 해제

	if (file == NULL) // 실패 시 -1 리턴.
	{
		return -1;
	}

	// File load success.
	int fd = t->next_fd;	// fd 값 획득
	t->fd_table[fd] = file; // 파일 테이블에 할당.
	t->next_fd++;

	return fd;
}

int create(const char *file_name, unsigned initial_size)
{
	check_user_ptr(file_name);
	return filesys_create(file_name, initial_size);
}

// returns number of bytes actually read
int read(int fd, void *buffer, unsigned size)
{
	int bytes_read;
	struct thread *t = thread_current();

	check_user_ptr(buffer);

	if (fd == 0)
	{
		input_init();
		uint8_t key = input_getc();
		return 1;
	}
	else if (fd >= 2 && fd < MAX_FD && t->fd_table[fd] != NULL)
	{
		struct file *file = t->fd_table[fd];

		lock_acquire(&filesys_lock);
		bytes_read = file_read(file, buffer, size);
		lock_release(&filesys_lock);
		return bytes_read;
	}
	else
	{
		return -1;
	}
}



int filesize(int fd)
{
	struct thread *t = thread_current();
	if (fd >= 2 && fd < MAX_FD && t->fd_table[fd] != NULL)
	{
		struct file *file = t->fd_table[fd];
		lock_acquire(&filesys_lock);
		int file_size = file_length(file);
		lock_release(&filesys_lock);
		return file_size;
	}
	return -1;
}

void close(int fd)
{

	struct thread *t = thread_current();

	if (fd >= 2 && fd < MAX_FD && t->fd_table[fd] != NULL)
	{
		struct file *file = t->fd_table[fd];

		lock_acquire(&filesys_lock);
		file_close(file);
		lock_release(&filesys_lock);
		t->fd_table[fd] = NULL;
	}
}


void check_user_ptr(const char *buffer)
{
	struct thread *cur = thread_current();
	if (buffer == NULL || !is_user_vaddr(buffer) || pml4_get_page(thread_current()->pml4, buffer) == NULL)
	{
		exit(-1);
	}
}

void check_string_ptr(const char *str) {
	while (true) {
		if (str == NULL || !is_user_vaddr(str) || pml4_get_page(thread_current()->pml4, str) == NULL)
			exit(-1);
		if (*str == '\0') break;
		str++;
	}
}


// /*
// 현재 프로세스가 새로운 실행 파일로 완전히 바뀌도록 하는 함수
// 즉, 현재의 코드, 메모리, 스택, 명령어 포인터 등을 모두 덮어씌워서 다른 프로그램이 되게 만드는 함수
// */
int exec(const char *file_name){
	struct thread *t = thread_current(); // 현재 쓰레드 포인터를 획득
	check_string_ptr(file_name);			 // 포인터 유효성 검사

	char *fn_copy = palloc_get_page(0);
	if (fn_copy == NULL) return -1;
	strlcpy(fn_copy, file_name, PGSIZE);

	int result = process_exec((void *)fn_copy);  // 전체 인자 넘겨야 함

	// 여기서 free하지 마! process_exec → load에서 처리함
	return result;
}

// int get_user(uint8_t *dst, const uint8_t *uaddr) {
// 	if (!is_user_vaddr(uaddr) || pml4_get_page(thread_current()->pml4, uaddr) == NULL)
// 		return -1;

// 	*dst = *uaddr;
// 	return 0;
// }


// char *copy_in_string(const char *usr_str) {
// 	char *kernel_buf = palloc_get_page(0);
// 	if (kernel_buf == NULL)
// 		thread_exit();

// 	size_t i = 0;
// 	uint8_t byte;
// 	while (i < PGSIZE) {
// 		if (get_user(&byte, usr_str + i) == -1) {
// 			palloc_free_page(kernel_buf);
// 			thread_exit();
// 		}
// 		kernel_buf[i] = byte;
// 		if (byte == '\0')
// 			return kernel_buf;
// 		i++;
// 	}

// 	kernel_buf[PGSIZE - 1] = '\0';
// 	return kernel_buf;
// }


// int exec(const char *file_name){
// 	char *fn_copy = copy_in_string(file_name);
// 	if (fn_copy == NULL)
// 		return -1;

// 	int result = process_exec(fn_copy);
// 	// process_exec 안에서 fn_copy는 해제됨
// 	return result;
// }
