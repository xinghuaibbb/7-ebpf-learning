#!/usr/bin/python3
from bcc import BPF
from time import sleep
program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/string.h>

struct key_t 
{
    char name[16];  // 1
};


BPF_HASH(counter_table, struct key_t , u64);  // 1

int write_c(void *ctx) {
    struct key_t key = {};
    __builtin_memcpy(key.name, "write", sizeof(key.name));  // 2
    u64 counter = 0;
    u64 *p;

    p = counter_table.lookup(&key);  // 3
    if (p != 0) {  // 4
        counter = *p;
    }
    counter++;  // 5
    counter_table.update(&key, &counter);  // 6
    return 0;
}

int openat_c(void *ctx) {
     struct key_t key = {};
    __builtin_memcpy(key.name, "openat", sizeof(key.name));  // 2
    u64 counter = 0;
    u64 *p;

    p = counter_table.lookup(&key);  // 3
    if (p != 0) {  // 4
        counter = *p;
    }
    counter++;  // 5
    counter_table.update(&key, &counter);  // 6
    return 0;
}

"""

b = BPF(text=program)
# syscall = b.get_syscall_fnname("execve") # hzh
syscall = b.get_syscall_fnname("write")  # hzh
syscall2 = b.get_syscall_fnname("openat")  # hzh
b.attach_kprobe(event=syscall, fn_name="write_c")
b.attach_kprobe(event=syscall2, fn_name="openat_c")  # hzh

while True:
    sleep(2)
    s = ""
    for k,v in b["counter_table"].items():
        key = k.name.decode()
        s += f"{key}: {v.value}\t"
    print(s)



