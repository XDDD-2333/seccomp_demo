#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/seccomp.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

static void process_notifications(int notifyfd)
{
    __u64  id;
    struct seccomp_notif_sizes sizes;
    struct seccomp_notif *req;
    struct seccomp_notif_resp *resp;
    // struct seccomp_notif包含五个成员：
        // 结构体的 输入长度
        // 每个过滤器唯一的 id 
        // 触发请求进程的 pid （如果进程的pid命名空 间对于监听者的pid命名空间不可见的话，可能为0）
        // 通知还包含传递给seccomp的 data 
        // 和一个过滤器标志。

    char path[PATH_MAX];
    int memfd;
    ssize_t s;

    // https://www.kernel.org/doc/html/latest/translations/zh_CN/userspace-api/seccomp_filter.html
    // https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
    // 获取 seccomp 用户空间通知的大小
    // struct seccomp_notif_sizes 结构体可以用于确定seccomp通知中各种结构体的大小。 struct seccomp_data 的大小可能未来会改变
    // 所以需要SECCOMP_GET_NOTIF_SIZES来决定需要分配的多种结构体的大小。可以查看 samples/seccomp/user-trap.c 中的例子
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == -1) {
        printf("seccomp failed: %s", strerror(errno));
        exit(-1);
    }

    assert((req = malloc(sizes.seccomp_notif)));
    assert((resp = malloc(sizes.seccomp_notif_resp)));

    memset(req, 0, sizes.seccomp_notif);
    memset(resp, 0, sizes.seccomp_notif_resp);

    // 读取seccomp 通知文件描述符来接收一个 struct seccomp_notif存到 req中
    if (ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_RECV, req) == -1) {
        printf("ioctl failed: %s\n", strerror(errno));
        exit(-1);
    }

    printf("Got notification for PID: %d, id is %llx\n",
            req->pid, req->id);

    id = req->id;
    // 判断之前ioctl SECCOMP_IOCTL_NOTIF_REC参数返回得到的notification ID 是否还有效
    if (ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == -1) {
        printf("Notification ID check: target has died: %s\n",
                strerror(errno));
        exit(-1);
    }

    snprintf(path, sizeof(path), "/proc/%d/mem", req->pid);
    memfd = open(path, O_RDONLY);
    if (memfd < 0) {
        printf("open mem file failed: %s\n", path);
        exit(-1);
    }
    printf("SYSCALL: %d\n", req->data.nr);

// 通过/proc/[pid]/mem文件获取到open调用传入的指针所指向的文件名
    if (req->data.nr == SYS_open) {
        assert(lseek(memfd, req->data.args[0], SEEK_SET) >= 0);
    } else if (req->data.nr == SYS_openat) {

        printf("memory address: 0x%016llX\n", req->data.args[1]);
        assert(lseek(memfd, req->data.args[1], SEEK_SET) >= 0);
    }

    assert((s = read(memfd, path, sizeof(path))) > 0);

    printf("open path: %s\n", path);
    // printf("open path's lenth: %ld\n", strlen(path));

    close(memfd);

    // 根据路径对resp进行赋值
    // 不允许在当前目录下创建noopen.txt文件，以./noopen.txt为路径参数创建文件
    // printf("path len : %ld\n", strlen("./noopen.txt"));
    // printf("strncmp return : %d\n", strncmp(path, "./noopen.txt", strlen("./noopen.txt")));
    if (strlen(path) == strlen("./noopen.txt") &&
        strncmp(path, "./noopen.txt", strlen("./noopen.txt")) == 0)
    {
        printf("Denied\n");
        resp->error = -EPERM;
        resp->flags = 0;
    } else {
        printf("Allowed\n");
        resp->error = 0;
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    }

    resp->id = req->id;

    //  supervisor可以根据这些信息决定做什么，并通过 ioctl(SECCOMP_IOCTL_NOTIF_SEND) 发送一个响应，表示应该给用户空间返回什么。
    //  struct seccomp_notif_resp 的 id 成员应该和 struct seccomp_notif 的 id 一致。
    if (ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_SEND, resp) == -1) {
        if (errno == ENOENT) {
            printf("Response failed with ENOENT; perhaps target "
                   "process's syscall was interrupted by signal?\n");
        } else {
            printf("ioctl failed: %s\n", strerror(errno));
            exit(-1);
        }
    }

    free(req);
    free(resp);
}

int main(int argc, char **argv)
{
    int pidfd;
    int notifyfd, targetfd;
    pid_t pid;

    if (argc != 3) {
        printf("usage: %s <pid> <target fd>\n", argv[0]);
        exit(-1);
    }

    pid = atoi(argv[1]);
    targetfd = atoi(argv[2]);
    printf("PID: %d, TARGET FD: %d\n", pid, targetfd);

    // SYS_pidfd_open函数生成一个PID进程id对应的文件描述符
    pidfd = syscall(SYS_pidfd_open, pid, 0);
    assert(pidfd >= 0);
    printf("PIDFD: %d\n", pidfd);

    // supervisor通过pidfd_getfd系统调用从target进程seccomp-unotify的fd, 从fd中获取到系统调用的调用通知。
    // 从pidfd中获取对应进程中对应targetfd的文件描述符
        // #define __NR_pidfd_getfd 438
        // __SYSCALL(__NR_pidfd_getfd, sys_pidfd_getfd)
// 由于本人 ubuntu20.04 系统中<sys/syscall.h> 无SYS_pidfd_getfd， 所以硬编码了SYS_pidfd_getfd为438
    // notifyfd = syscall(SYS_pidfd_getfd, pidfd, targetfd, 0); 
    notifyfd = syscall(438, pidfd, targetfd, 0); 
    
    // 简单check一下错误，发现supervisor需要root权限 
    printf("pidfd_getfd result: %s\n", strerror(errno));
    assert(notifyfd >= 0);
    printf("NOTIFY FD: %d\n", notifyfd);

    process_notifications(notifyfd);

    return 0;
}