#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
    int ret;
    int notifyfd, fd;

    if (argc != 2) {
        printf("usage: %s <file path>\n", argv[0]);
        exit(-1);
    }

    // 相关规则可看 BPF_FILTER目录下的bpf_macro.c
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, nr))),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_open, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_USER_NOTIF),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_openat, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_USER_NOTIF),

        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };

    // 加载BPF过滤器，需要通过prctl将no_new_priv置位， 或者调用线程有CAP_SYS_ADMIN权限
    ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    // 参考文档： https://man7.org/linux/man-pages/man2/seccomp.2.html
    // flag
    // SECCOMP_FILTER_FLAG_NEW_LISTENER (since Linux 5.0)
    //                  After successfully installing the filter program,
    //                  return a new user-space notification file
    //                  descriptor.  (The close-on-exec flag is set for the
    //                  file descriptor.)  When the filter returns
    //                  SECCOMP_RET_USER_NOTIF a notification will be sent
    //                  to this file descriptor.
    //                  At most one seccomp filter using the
    //                  SECCOMP_FILTER_FLAG_NEW_LISTENER flag can be
    //                  installed for a thread.
    //                  See seccomp_unotify(2) for further details. seccomp_unotify(2): https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html
    // 获得一个seccomp-unotify的fd
    notifyfd = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (notifyfd < 0) {
        printf("seccomp failed: %s\n", strerror(errno));
        exit(-1);
    }

    printf("tid: %ld, notify fd: %d\n", syscall(SYS_gettid), notifyfd);

    // 使用target程序的第一个参数作为 open系统调用创建文件的路径
    fd = open(argv[1], O_CREAT|O_RDWR);
    // ...... 在此停顿，等待supervisor程序判断
    if (fd < 0) {
        printf("open failed: %s\n", strerror(errno));
        exit(-1);
    } else {
        printf("open succeeded\n");
    }

    close(fd);
    close(notifyfd);

    return 0;
}