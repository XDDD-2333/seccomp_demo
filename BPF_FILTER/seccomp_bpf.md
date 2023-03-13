
在3.5版本的内核中引入一种新的seccomp模式。它基于BPF来过滤系统调用，这种模式叫做SECCOMP_MODE_FILTER。这种模式下，可以自定义被允许使用的系统调用，而自定义过滤规则是借由BPF语言来实现。因而这种模式也叫做Seccomp-BPF。

过滤规则仍旧使用BPF的struct socket_filter结构来表示，但匹配的内容却是系统调用号和参数内容，但是过滤程序不能解引用指针(dereference pointer)，去匹配指针指向的内容。

BPF程序可以不同的返回值，指示内核进行不同的处理逻辑，如:

    SECCOMP_RET_KILL: 立即终止进程
    SECCOMP_RET_TRAP: 发送一个可捕获的SIGSYS
    SECCOMP_RET_ERROR: 指定errno的值并返回
    SECCOMP_RET_TRACE: 由被附加的ptrace tracer裁决
    SECCOMP_RET_ALLOW: 允许这个系统调用继续

随着内核发展，返回值也在变化，5.17版本上已经有更多的返回值，可以参考内核文档 https://www.kernel.org/doc/html/v5.17/userspace-api/seccomp_filter.html。

对于同一个系统调用可以加载多个过滤器。这种场景下，系统调用的裁决结果以最高优先级的返回值为准，返回值优先级也可以参考不同版本内核的上述文档。

BPF语言本身提供了一套指令集来实现过滤功能。可以直接基于BPF指令和内核定义的宏来编写过滤程序。BPF的指令规范可以参考 https://man.openbsd.org/bpf

seccomp-BPF模式的使用流程是这样的:

    1、以struct socket_filter的数组承载过滤规则
    2、以struct sock_fprog结构来封装上述过滤规则
    3、使用prctl系统调用加载上述struct sock_fprog

而BPF程序的输入是struct seccomp_data结构:

    struct seccomp_data {
        int nr;
        __u32 arch;
        __u64 instruction_pointer;
        __u64 args[6];
    };

低效率的开发方式：直接基于BPF指令和内核定义的宏来编写过滤程序
    
    demo：/BPF_FILTER/bpf_macro.c  
    编译：gcc bpf_macro.c -o filter

使用更高阶的API库libseccomp开发，具体参考官方仓库文档 https://github.com/seccomp/libseccomp/tree/main/doc
    
    demo：/BPF_FILTER/libseccomp.c  
    Ubuntu下环境配置：sudo apt install libseccomp-dev
    编译：gcc libseccomp.c -lseccomp -o lib_filter
