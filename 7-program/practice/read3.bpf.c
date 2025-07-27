#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../hello.h"

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

char messgae[20] = "hello, is ksys_read";
SEC("fentry/ksys_read")
int BPF_PROG(fentry_ksys_read, unsigned int fd, void *buf, size_t count)
{
    struct data_t data = {};
    
    bpf_probe_read_kernel(&data.message, sizeof(data.message), messgae);

    data.pid = bpf_get_current_pid_tgid() >> 32;  // 获取当前进程的 PID, 后32位是线程 ID-pid, 前32位是进程 ID-tid
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF; // 获取当前进程的 UID, 前32位是组id-GID, 后32位是用户id-UID

    bpf_get_current_comm(&data.command, sizeof(data.command)); // 获取当前进程的命令名
    
    // BPF_CORE_READ 是 libbpf 提供的一个辅助宏，用于在 eBPF 程序中安全地读取内核结构体成员，支持 CO-RE（Compile Once, Run Everywhere）特性。    
    // int pid = BPF_CORE_READ(task, pid);  //这表示从 task 结构体安全读取 pid 字段
    if(data.uid == 0) {
        return 0; // 如果 PID 为 0，直接返回
    }
    bpf_printk("%s: fd: %d, count: %ld", messgae, fd, count); // 打印调试信息

    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data)); // 将数据输出到 perf buffer

    return 0;

}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
