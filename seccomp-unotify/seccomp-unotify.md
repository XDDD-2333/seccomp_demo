在5.0版本内核又加入了seccomp-unotify机制，5.9版本又做了特性增强。seccomp-BPF模式对系统调用的裁决是由过滤程序自己完成的，而seccomp-unotify机制能够将裁决权转移给另一个用户态进程。

详细特性介绍: https://brauner.io/2020/07/23/seccomp-notify.html

我们将加载过滤程序的进程叫做target, 接收通知的进程叫做supervisor。在这个模式中，supervisor不仅对是否允许系统调用能够做出裁决，它还可以代替target进程完成这个系统调用的行为。这大大扩大了seccomp机制的应用范围。此前的Seccomp-BPF模式只能检测系统调用的参数，不能解引用指针。而现在这个unotify模式还可以去查看指针所指向的内存

seccomp的中文文档： https://www.kernel.org/doc/html/latest/translations/zh_CN/userspace-api/seccomp_filter.html

supervisor程序需要在Root权限下运行，因为其需要拷贝其他进程打开的文件描述符

    # 编译target
    gcc target.c -o target
    # 编译supervisor
    gcc supervisor.c -o supervisor

具体使用参考也可以查看： https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html

    # 此创建文件的操作会被终止
    ./target ./noopen.txt
    # 将target得到的信息作为supervisor的参数，注意需要root权限运行
    sudo ./supervisor tid notify-fd

当文件名为/tmp/noopen.txt时，open被禁止，其他文件名则允许执行。

禁止创建noopen.txt文件，运行结果如下：

    # 先运行 target
    dhz@ubuntu:~/workspace/seccomp/seccomp-unotify$ sudo ./target ./noopen.txt
    tid: 42454, notify fd: 3
    
    # target卡住，再运行 supervisor
    dhz@ubuntu:~/workspace/seccomp/seccomp-unotify$ sudo ./supervisor 42454 3
    PID: 42454, TARGET FD: 3
    PIDFD: 3
    pidfd_getfd result: Success
    NOTIFY FD: 4
    Got notification for PID: 42454, id is 43131f51e28226d0
    SYSCALL: 257
    memory address: 0x00007FFECB0B457D
    open path: ./noopen.txt
    Denied

    # 最后 target 运行结果
    dhz@ubuntu:~/workspace/seccomp/seccomp-unotify$ sudo ./target ./noopen.txt
    tid: 42454, notify fd: 3
    open failed: Operation not permitted

允许创建open.txt文件，运行结果如下：

    # 先运行 target
    dhz@ubuntu:~/workspace/seccomp/seccomp-unotify$ sudo ./target ./open.txt
    tid: 43183, notify fd: 3

    # target卡住，再运行 supervisor
    dhz@ubuntu:~/workspace/seccomp/seccomp-unotify$ sudo ./supervisor 43183 3
    PID: 43183, TARGET FD: 3
    PIDFD: 3
    pidfd_getfd result: Success
    NOTIFY FD: 4
    Got notification for PID: 43183, id is 5c1443c84a6dadec
    SYSCALL: 257
    memory address: 0x00007FFD999498EC
    open path: ./open.txt
    Allowed

    # 最后 target 运行结果
    dhz@ubuntu:~/workspace/seccomp/seccomp-unotify$ sudo ./target ./open.txt
    tid: 43183, notify fd: 3
    open succeeded