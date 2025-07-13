#!/usr/bin/python3
from bcc import BPF
from time import sleep

program = r"""
int hello(void *ctx)
{
    bpf_trace_printk("Hello World!");
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")
print("Attaching to syscall:", syscall)
b.trace_print()    # 注释掉 用于cat /sys/kernel/debug/tracing/trace_pipe
# while True:
#      sleep(1)  # python 空循环不能 空循环体, 要么sleep, 要么 pass


