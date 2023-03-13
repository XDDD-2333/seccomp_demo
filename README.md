## *Overview*
seccomp代表secure computing，是早在2.6.12版本就引入到内核的特性，用来限制进程可以使用的系统调用。它作用于进程里的线程(task)。

最初，seccomp只允许使用read, write, _exit, sigreturn4个系统调用，调用其他系统调用时，内核会发送SIGKILL信号终止进程。

沉寂了一些年之后，在3.5版本的内核中引入一种新的seccomp模式。它基于BPF来过滤系统调用，这种模式叫做SECCOMP_MODE_FILTER。这种模式下，可以自定义被允许使用的系统调用，而自定义过滤规则是借由BPF语言来实现。因而这种模式也叫做Seccomp-BPF。

之后，在5.0版本内核又加入了seccomp-unotify机制，5.9版本又做了特性增强。seccomp-BPF模式对系统调用的裁决是由过滤程序自己完成的，而seccomp-unotify机制能够将裁决权转移给另一个用户态进程。

## Documents

+ STRICT模式的seccomp [STRICT_doc](./STRICT/strict.md)
+ Seccomp-BPF [Seccomp-BPF_docs](./BPF_FILTER/seccomp_bpf.md)
+ Seccomp-Unotify [Seccomp-Unotify_docs](./seccomp-unotify/seccomp-unotify.md)


### 主要参考文档：
+ https://kernel-security.blog.csdn.net/article/details/127710240?spm=1001.2014.3001.5502
+ http://just4coding.com/2021/10/31/core-dump/