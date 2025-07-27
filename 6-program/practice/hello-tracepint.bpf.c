#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../hello-verifier.h"

int c = 1;
char message[12] = "Hello World";

struct
{
   __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
   __uint(key_size, sizeof(u32));
   __uint(value_size, sizeof(u32));
} output SEC(".maps");

struct
{
   __uint(type, BPF_MAP_TYPE_HASH);
   __uint(max_entries, 10240);
   __type(key, u32);
   __type(value, struct msg_t);
} my_config SEC(".maps");



struct my_sysenter_execve
{
   unsigned short common_type;
   unsigned char common_flags;
   unsigned char common_preempt_count;
   int common_pid;
};


SEC("tp/syscalls/sys_enter_execve")
int tp_sys_enter_execve(struct my_sysenter_execve* ctx)
{
   bpf_printk("common_type: %d, common_flags: %c, common_preempt_count: %c, common_pid: %d\n",
      ctx->common_type, ctx->common_flags, ctx->common_preempt_count, ctx->common_pid);
   return 0;
}



// Removing the license section means the verifier won't let you use
// GPL-licensed helpers
char LICENSE[] SEC("license") = "Dual BSD/GPL";