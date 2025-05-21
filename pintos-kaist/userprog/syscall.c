#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

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

/* The main system call interface */
void syscall_handler (struct intr_frame *f) {
	// printf("rax: %ld, rdi: %ld, rsi: %ld, rdx: %ld, r10: %ld, r8: %ld, r9: %ld\n",
	//        f->R.rax, f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8, f->R.r9);

	int syscall_n = f->R.rax;
	uint64_t arg1 = f->R.rdi;
	uint64_t arg2 = f->R.rsi;
	uint64_t arg3 = f->R.rdx;
	uint64_t arg4 = f->R.r10;
	uint64_t arg5 = f->R.r8;
	uint64_t arg6 = f->R.r9;

	switch(syscall_n){
		case SYS_HALT:
			sys_halt();
			break;
		case SYS_EXIT:
			sys_exit(arg1);
			break;
		case SYS_WAIT:
		    f->R.rax = sys_wait(arg1);
			break; 
		case SYS_WRITE:
            f->R.rax = sys_write(arg1, (const void *)arg2, arg3);
            break;
		case SYS_FORK:
			break;
		case SYS_OPEN:
			break;
		default:
			//printf("syscall!\n");
			//do_iret(f);
			thread_exit(); // 예외 처리
	}
}




//인자로 파일 디스크립터 fd, 버퍼 주소 buffer, 출력할 바이트 수 size를 받는다.
int sys_write(int fd, const void *buffer, unsigned size){
	//fd == 1은 표준출력
	//즉, 콘솔 창에 출력하는 경우 처리
	if (fd == 1){
		putbuf(buffer, size); // 주어진 버퍼의 내용을 size만큼 커널 콘솔에 출력
	}

}

void 
sys_halt(void){
	power_off();
}

void sys_exit(int status) {
    printf("%s: exit(%d)\n", thread_name(), status);
    thread_current()->exit_status = status;
    thread_exit();  // 이걸 호출해야 현재 유저 스레드 종료됨
}


int sys_wait(tid_t pid){
	int status = process_wait(pid);
	return status;
}