#!/usr/bin/python3
from bcc import BPF
from time import sleep
program = r"""
BPF_PERF_OUTPUT(output);
struct data_t {
   int pid;
   int uid;
   char command[16];
   char message[30];
};

int hello(void *ctx) {
   struct data_t data = {};
   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    char message1[30] = "Hello World---偶数";
    char message2[30] = "Hello World---奇数";

   // 直接拷贝到 data.message
   if (data.pid % 2 == 0) {
       bpf_probe_read_kernel(&data.message, sizeof(data.message), message1);
   } else {
       bpf_probe_read_kernel(&data.message, sizeof(data.message), message2);
   }

   bpf_get_current_comm(&data.command, sizeof(data.command));
   output.perf_submit(ctx, &data, sizeof(data));
   return 0;
}
"""

b = BPF(text=program)  # 1
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

def print_event(cpu, data, size):  # 2
   data = b["output"].event(data)
   print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")

b["output"].open_perf_buffer(print_event)  # 3
while True:  # 4
   b.perf_buffer_poll()




