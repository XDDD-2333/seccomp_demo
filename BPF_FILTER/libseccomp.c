#include <unistd.h>
// libseccomp库，编译程序时需要链接libseccomp，-lseccomp
// 详细使用方法见官方文档 https://github.com/seccomp/libseccomp/tree/main/doc
#include <seccomp.h>

int main(int agrc, char **argv)
{
    // scmp_filter_ctx是过滤逻辑所使用的上下文结构
    scmp_filter_ctx ctx;

    // seccomp_init函数对上下文结构体进行初始化
    //      若参数为SCMP_ACT_ALLOW, 则过滤为黑名单模式
    //      若为SCMP_ACT_KILL，则为白名单模式，即进程调用没有匹配到规则的系统调用都会杀死，默认不允许所有的系统调用
    ctx = seccomp_init(SCMP_ACT_KILL);

    // seccomp_rule_add函数用来添加规则
    // 与传统STRICT模式相同，允许read, write, sig_return, exit4个系统调用
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);

    // 对于dup2 系统调用，检查参数。根据传入的参数来进行判断。只有传入的两个参数为1和2时即 dup2(1, 2)时，被允许运行 
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 2,
            SCMP_A0(SCMP_CMP_EQ, 1),
            SCMP_A1(SCMP_CMP_EQ, 2));

    // seccomp_load函数加载过滤器
    seccomp_load(ctx);

#define MESSAGE1    "Filter loaded\n"
    write(STDOUT_FILENO, MESSAGE1, sizeof(MESSAGE1));
    // 允许运行
    dup2(1, 2);

#define MESSAGE2    "Dup2(1, 2) succeeded\n"
    write(STDOUT_FILENO, MESSAGE2, sizeof(MESSAGE2));
    // 不允许运行
    dup2(2, 42);

#define MESSAGE3    "You can't see this message\n"
    write(STDOUT_FILENO, MESSAGE3, sizeof(MESSAGE3));

    return 0;
}