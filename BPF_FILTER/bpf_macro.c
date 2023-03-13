#include <stdio.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <stddef.h>

int main(int argc, char **argv)
{
    int ret;

// 详细参考 https://man.openbsd.org/bpf
// BPF_* There are eight classes of instructions: BPF_LD, BPF_LDX, BPF_ST, BPF_STX, BPF_ALU, BPF_JMP, BPF_RET, and BPF_MISC. 
// The bpf interface provides the following macros to facilitate array initializers: 
// BPF_STMT (opcode, operand)
// BPF_JUMP (opcode, operand, true_offset, false_offset)
    struct sock_filter filter[] = {
        // 基于BPF指令和内核定义的宏<linux/filter.h>实现过滤程序
        // 过滤程序从seccomp_data结构中读取nr字段的值，装载到寄存器中
        // BPF_LD：加载指令， BPF_W：数据大小为一个字， BPF_ABS：数据有一个固定的偏移量
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, nr))),
        // 进行一系列的系统调用号的匹配和跳转操作。如果任何一个系统调用号都没有匹配到，则返回SECCOMP_RET_KILL, 内核将终止进程。
        // 实现传统STRICT模式的seccomp
        // BPF_JMP：跳转指令
        // BPF_JMP+BPF_JEQ+BPF_K 对应操作为 PC = (nr==__NR_read)? (PC+ 0): (PC+ 1);  
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_read, 0, 1),
        // BPF_RET：终止程序，不同的返回值，指示内核进行不同的处理逻辑
        /*
            SECCOMP_RET_KILL: 立即终止进程
            SECCOMP_RET_TRAP: 发送一个可捕获的SIGSYS
            SECCOMP_RET_ERROR: 指定errno的值并返回
            SECCOMP_RET_TRACE: 由被附加的ptrace tracer裁决
            SECCOMP_RET_ALLOW: 允许这个系统调用继续
        */
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),   
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_write, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_exit, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_exit_group, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_rt_sigreturn, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
        
        //是否匹配 dup2系统调用
    //    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_dup2, 0, 1),
    //    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
        // 过滤程序返回SECCOMP_RET_KILL
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };

    // 加载BPF过滤器，需要调用线程有CAP_SYS_ADMIN权限，或者 通过prctl将no_new_priv置位
    ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        printf("prctl failed\n");
        exit(1);
    }

#define MESSAGE1    "Filter loaded \n"
    write(STDOUT_FILENO, MESSAGE1, sizeof(MESSAGE1));

    ret = dup2(1, 2);

#define MESSAGE2    "dup2 called \n"
    write(STDOUT_FILENO, MESSAGE2, sizeof(MESSAGE2));

    _exit(0);

    return 0;
}