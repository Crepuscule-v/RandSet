#include <syscall.h>
long __read(int fd, char *buf, long len) {
    register long rax asm("rax") = SYS_read;
    register long rdi asm("rdi") = fd;
    register long rsi asm("rsi") = buf;
    register long rdx asm("rdx") = len;

    asm volatile("syscall"
                 : "+a"(rax)
                 : "r"(rdi), "r"(rsi), "r"(rdx), "r"(rax)
                 : "rcx", "r11", "memory");

    return rax;
}
