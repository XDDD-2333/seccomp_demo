#include <unistd.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <fcntl.h>

// STRICT模式只允许使用read, write, _exit, sigreturn4个系统调用，调用其他系统调用时，内核会发送SIGKILL信号终止进程
// 代码里不使用printf而是使用write输出，是因为printf实现本身可能还会调用write之外其他的系统调用

int main(int argc, char **argv)
{
    // 未开启SECCOMP的open系统调用可以正常执行
    open("/dev/null", O_RDONLY);
#define MESSAGE1    "open called\n"
    write(STDOUT_FILENO, MESSAGE1, sizeof(MESSAGE1));
    // 开启SECCOMP的STRICT模式
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
    // 此代码的write系统调用被允许，输出正常
#define MESSAGE2    "seccomp open called \n"
    write(STDOUT_FILENO, MESSAGE2, sizeof(MESSAGE2));
    // 代码的open系统调用被禁止
    open("/dev/null", O_RDONLY);
#define MESSAGE3    "You can't see this message\n" 
    write(STDOUT_FILENO, MESSAGE3, sizeof(MESSAGE3));

    return 0;
}