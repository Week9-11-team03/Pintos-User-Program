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

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

void halt() {
	power_off();
}

int write(int fd, const void *buffer, unsigned size) {
	if (fd == 1) {
		putbuf(buffer, size);
	}
}

void exit(int status) {
	struct thread *curr = thread_current();
	curr->exit_status = status;
	thread_exit();
}

bool create(const char *file, unsigned initial_size) {
	
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	uint64_t syscall_number = f->R.rax;
	//printf("rax: %ld, rdi: %ld, rsi: %ld, rdx: %ld, r10: %ld, r8: %ld, r9: %ld\n", f->R.rax, f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8, f->R.r9);
	
	switch (syscall_number) {
	case SYS_HALT: {
		halt();
		break;
	}
	case SYS_WRITE: {
		write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	}
	case SYS_WAIT: {
		tid_t tid = f->R.rdi;
		f->R.rax = process_wait(tid);
		break;
	}
	case SYS_EXIT: {
		int status = f->R.rdi;
		exit(status);
		break;
	}
	case SYS_CREATE: {

		break;
	}
	case SYS_REMOVE: {

		break;
	}
	case SYS_OPEN: {

		break;
	}
	case SYS_FILESIZE: {
		
		break;
	}
	case SYS_READ: {

		break;
	}
	case SYS_SEEK: {

		break;
	}
	case SYS_TELL: {

		break;
	}
	case SYS_CLOSE: {

		break;
	}
	default: {
		printf ("system call!\n");
		break;
	}
	}

	do_iret(f);
	//thread_exit ();
}