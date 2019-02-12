
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <asm/unistd.h>

#include <sys/syscall.h>

char *syscall_lookup_table[333] = {
    "read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "mmap", "mprotect", "mummap",
    "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread", "pwrite", "readv", "writev",
    "access", "pipe", "select", "sched_yiled", "mremap", "msync", "mincore", "madvise", "shmget", "shmat",
    "shmctl", "dup", "dup", "pause", "nanosleep", "getitimer", "alarm", "setitimer", "getpid", "sendfile",
    "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind", "listen",
    "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve",
    "exit", "wait4", "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl",
    "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename",
    "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown",
    "umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid",
    "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp", "setsid", "setreuid", "setregid",
    "getgroups", "setgroups", "setresuid", "getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid",
    "getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack",
    "utime", "mknod", "uselib", "personality", "ustat", "statfs", "fstatfs", "sysfs", "getpriority", "setpriority",
    "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max",
    "sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock", "mlockall", "munlockall", "vhangup",
    "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit", "chroot", "sync", "acct",
    "settimeofday", "mount", "umount", "swapon", "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm",
    "create_module", "init_module", "delete_module", "get_kernel_syms", "query_module", "quotactl", "nfsservctl",
    "getpmsg", "putpmsg", "afs_syscall", "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr",
    "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr",
    "lremovexattr", "fremovexattr", "tkill", "time", "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area",
    "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create",
    "epoll_ctl_old", "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall", "semtimedop",
    "fadvise64", "timer_create", "timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime",
    "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver",
    "mbind", "set_mempolicy", "get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify",
    "mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key", "keyctl", "ioprio_set", "ioprio_get", "inotify_init",
    "inotify_add_watch", "inotify_rm_watch", "migrate_pages", "openat", "mkdirat", "mknodat", "fchownat", "futimesat",
    "newfstatat", "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll",
    "unshare", "set_robust_list", "get_robust_list", "splice", "tee", "sync_file_range", "vmsplice", "move_pages", "utimensat",
    "epoll_pwait", "signalfd", "timerfd", "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime", "accept4", "signalfd4",
    "eventfd", "epoll_create", "dup3", "pipe", "inotify_init", "preadv", "pwritev", "rt_tgsigqueueinfo", "perf_event_open",
    "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64", "name_to_handle_at", "open_by_handle_at", "clock_adjtime",
    "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv", "process_vm_writev", "kcmp", "finit_module", "sched_setattr",
    "sched_getattr", "renameat", "seccomp", "getrandom", "memfd_create", "kexec_file_load", "bpf", "execveat", "userfaultfd",
    "membarrier", "mlock", "copy_file_range", "preadv", "pwritev", "pkey_mprotect", "pkey_alloc", "pkey_free", "statx"};

// プロセスにアタッチしてシステムコールが実行されようとしている直前でレジスタの状態を補足してそれを表示することが目的
int main(int argc, char **argv[])
{
    assert(argc == 2);

    struct user_regs_struct reg_state;
    pid_t pid = atoi(argv[1]);

    int st;

    // long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
    assert(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == 0);
    printf("attached to pid: %d\n", pid);

    unsigned int syscall_nr;
    while (1)
    {
        waitpid(pid, &st, 0);

        // 子プロセスが正常に終了した場合に真を返す。
        if (WIFEXITED(st))
        {
            break;
        }
        else if (WIFSTOPPED(st))
        { // WIFSTOPPED - 子プロセスがシグナルの配送により停止した場合に真を返す。
            ptrace(PTRACE_GETREGS, pid, NULL, &reg_state);
            syscall_nr = reg_state.orig_rax;

            // syscall_lookup_tableに入っているものに収まっている、かつ、NULLではないもの
            if (syscall_nr >= 0 && syscall_nr <= 333)
            {
                if (syscall_nr != 231)
                    printf("[orig_rax]Syscall: Syscall(%d) = %s called\n", syscall_nr, syscall_lookup_table[syscall_nr]);
                else
                    break;
            }
        }
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    }

    assert(ptrace(PTRACE_DETACH, pid, NULL, 0) == 0);
    printf("detached from pid: %d\n", pid);

    return 0;
}
