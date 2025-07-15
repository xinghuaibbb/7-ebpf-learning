#include "vmlinux.h"
#include <bpf/bpf_helpers.h> // 包含 BPF 辅助函数, 用于 BPF 程序的辅助功能
#include <bpf/bpf_core_read.h> // 包含 BPF 核心读取, 用于读取内核数据结构
#include <bpf/bpf_tracing.h> // 包含 BPF 跟踪函数, 用于跟踪内核事件
#include "hello-buffer-config.h" // 包含自定义头文件, 定义 用到的结构体

char message[12] = "Hello World"; // 定义一个全局字符数组, 用于存储消息

struct  // 对应BCC的BPF_PERF_OUTPUT宏
{
   __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); // 定义一个性能事件数组类型的 BPF map
   __uint(key_size, sizeof(u32)); // 定义 key 的大小为 4 字节
   __uint(value_size, sizeof(u32)); // 定义 value 的大小为 4 字节
}output SEC(".maps"); // 定义一个名为 output 的 BPF map, 用于输出性能事件


struct user_msg_t   // 因为bpf的哈希map不支持字符数组, 所以需要定义一个用户消息结构体
{
   char message[12]; // 定义一个用户消息结构体, 包含一个字符数组
};

struct  // 对应BCC的BPF_HASH宏 
{
   __uint(type, BPF_MAP_TYPE_HASH); // 定义一个哈希类型的 BPF map
   __uint(max_entries, 10240); // 定义哈希 map 的最大条目数为 10240
   __type(key, u32); // 定义 key 的类型为 u32
   __type(value, struct user_msg_t); // 定义 value 的类型为 user_msg_t
}my_config SEC(".maps"); // 定义一个名为 my_config 的 BPF map, 用于存储用户配置

SEC("ksyscall/execve") // 定义一个内核系统调用钩子, 针对 execve 系统调用,  这是libbpf提供的最简单的方法,不用考虑架构

int BPF_KPROBE_SYSCALL(hello, const char *pathname)
{
   struct data_t data = {}; // 定义一个 data_t 结构体实例, 用于存储数据
   struct user_msg_t *p; // 定义一个指向 user_msg_t 的指针, 用于访问哈希 map 中的值

   data.pid = bpf_get_current_pid_tgid() >> 32; // 获取当前进程的 PID
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF; // 获取当前进程的 UID

   bpf_get_current_comm(data.command, sizeof(data.command)); // 获取当前进程的命令名
   bpf_probe_read_user_str(data.path, sizeof(data.path), pathname); // 读取用户空间的路径字符串

   p = bpf_map_lookup_elem(&my_config, &data.pid); // 从 my_config 哈希 map 中查找当前 PID 的配置
   if(p!=0)
   {
      bpf_probe_read_kernel_str(data.message, sizeof(data.message), p->message); // 如果找到配置, 读取内核空间的消息字符串
      // 虽然 map 的内容最初来自用户空间，但 eBPF 访问 map 时，map 已经在内核
   }
   else
   {
      bpf_probe_read_kernel_str(data.message, sizeof(data.message), message); // 如果未找到配置, 使用默认消息
   }

   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data)); // 将数据输出到性能事件数组
   return 0; // 返回 0, 表示钩子函数执行成功

}

char LICENSE[] SEC("license") = "Dual BSD/GPL"; // 定义许可证, 表示该 BPF 程序遵循 GPL 协议


