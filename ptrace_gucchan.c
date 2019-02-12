
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>

// PTRACE_ATTACH -> PTRACE_SYSCALL -> PTRACE_DETACH/PTRACE_KILL
// a process to be examined halts every time any signals but SIGKILL are received
char *syscall_lookup_table[16] = {
    NULL, "exit", "fork", "read", "write", "open", "close", "waitpid",
    "creat", "link", "unlink", "execve", "chdir", "time", "mknod", "chmod", "lchown"
};
int main(int argc, char *argv[]) {
    struct user_reg_struct reg_state;
    pid_t attach_pid = atoi(argv[1]);

    if(ptrace(PTRACE_ATTACH, attach_pid, NULL, NULL) == -1) {
        printf("Syscall Tracer: failed to initialize ptrace() system call\n");
        exit(EXIT_FAILURE);
    }
    int st;
    waitpid(attach_pid, &st, WCONTINUED);

    while(ptrace(PTRACE_SYSCALL, attach_pid, NULL, NULL) == 0) {
        wait(NULL);
        ptrace(PTRACE_GETREGS, attach_pid, 0, &reg_state);
        unsigned int syscall_nr = reg_state.orig_rax; // asm/unistd.h
        if(syscall_nr > 0 && syscall_nr <= 16) {
            printf("Syscall: Syscall(%d) = %s called\n", syscall_nr, syscall_lookup_table[syscall_nr]);
        }
    }
    return 0;
}
