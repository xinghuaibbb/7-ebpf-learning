#!/usr/bin/python3  
from bcc import BPF
import ctypes as ct

program = r"""

BPF_PROG_ARRAY(syscall, 300);  // 1

RAW_TRACEPOINT_PROBE(sys_enter)
{
    int opcode = ctx->args[1];  // 3
    syscall.call(ctx, opcode);  // 4
    bpf_trace_printk("Another syscall: %d", opcode);  // 5
    return 0;
}



int hello_exec(void *ctx) {  // 6
    bpf_trace_printk("Executing a program");
    return 0;
}

int hello_timer(struct bpf_raw_tracepoint_args *ctx) {  // 7
    int opcode = ctx->args[1];
    switch (opcode) {
        case 222:
            bpf_trace_printk("Creating a timer");
            break;
        case 226:
            bpf_trace_printk("Deleting a timer");
            break;
        default:
            bpf_trace_printk("Some other timer operation");
            break;
    }
    return 0;
}

int ignore_opcode(void *ctx) {  // 8
    return 0;
}
"""

b = BPF(text=program)
# b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")    # 原始跟踪点 , 不同于之前的  attach_kprobe(event=syscall, fn_name="hello")

ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)
exec_fn = b.load_func("hello_exec", BPF.RAW_TRACEPOINT)
timer_fn = b.load_func("hello_timer", BPF.RAW_TRACEPOINT)

prog_array = b.get_table("syscall")

# Ignore all syscalls initially
for i in range(len(prog_array)):
    prog_array[ct.c_int(i)] = ct.c_int(ignore_fn.fd)

# Only enable few syscalls which are of the interest
prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd)
prog_array[ct.c_int(222)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(223)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(224)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(225)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(226)] = ct.c_int(timer_fn.fd)

b.trace_print()