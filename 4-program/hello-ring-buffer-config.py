#!/usr/bin/python3  
# -*- coding: utf-8 -*-
from bcc import BPF
import ctypes as ct

program = r"""
struct user_msg_t {
   char message[20];
};

BPF_HASH(config, u32, struct user_msg_t);

// BPF_PERF_OUTPUT(output); 
BPF_RINGBUF_OUTPUT(output, 1);

struct data_t {     
   int pid;
   int uid;
   char command[16];
   char message[20];
};

int hello(void *ctx) {
   struct data_t data = {}; 
   struct user_msg_t *p;
   char message[20] = "Hello World";

   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;


   bpf_get_current_comm(&data.command, sizeof(data.command));

   p = config.lookup(&data.uid);
   if (p != 0) {
      bpf_probe_read_kernel(&data.message, sizeof(data.message), p->message);       
   } else {
      bpf_probe_read_kernel(&data.message, sizeof(data.message), message); 
   }

   // output.perf_submit(ctx, &data, sizeof(data)); 
   output.ringbuf_output(&data, sizeof(data), 0);
   return 0;
}
"""

b = BPF(text=program) 
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")
b["config"][ct.c_int(0)] = ct.create_string_buffer(b"Hey root!")
b["config"][ct.c_int(1000)] = ct.create_string_buffer(b"Hi user 1000!")
 
def print_event(cpu, data, size):  
   data = b["output"].event(data)
   print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")
 
# b["output"].open_perf_buffer(print_event) 
b["output"].open_ring_buffer(print_event)
while True:   
#    b.perf_buffer_poll()
    b.ring_buffer_poll()