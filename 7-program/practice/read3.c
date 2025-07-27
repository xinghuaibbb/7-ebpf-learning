#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "../hello.h"
#include "read3.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level,
    const char* format, va_list args)
{
    if (level >= LIBBPF_DEBUG)
        return 0;

    return vfprintf(stderr, format, args);  // 将格式化的输出打印到标准错误, libbpf已经将参数传递给这个函数
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct data_t *m = data;

	printf("%-6d %-6d %-16s %-16s %s\n", m->pid, m->uid, m->command, m->path, m->message);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
	printf("lost event\n");
}

int main()
{
    struct read3_bpf* skel; // 这是 BPF skeleton结构体, 来源于 read3.skel.h
    int err; // 错误码
    struct perf_buffer* pb = NULL; // perf buffer 用于处理事件

    libbpf_set_print(libbpf_print_fn); // 设置 libbpf 的打印函数

    char log_buf[64 * 1024]; // 日志缓冲区    
    LIBBPF_OPTS(bpf_object_open_opts, opts,
        .kernel_log_buf = log_buf,
        .kernel_log_size = sizeof(log_buf),
        .kernel_log_level = 2, // 设置内核日志级别
        );   // 这个宏是 linux 内核的宏, 在linux源码里找

    skel = read3_bpf__open_opts(&opts);   // 打开 BPF skeleton, 传入选项
    if (!skel)
    {
        printf("Failed to open BPF object\n");
        return 1;
    }

    err = read3_bpf__load(skel);    // 加载 BPF skeleton
    // Print the verifier log
    for (int i = 0; i < sizeof(log_buf); i++)
    {
        if (log_buf[i] == 0 && log_buf[i + 1] == 0)
        {
            break;
        }
        printf("%c", log_buf[i]);
    }

    if (err)
    {
        printf("Failed to load BPF object\n");
        read3_bpf__destroy(skel);
        return 1;
    }

    err = read3_bpf__attach(skel);  // 附加 BPF 程序到内核
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        read3_bpf__destroy(skel);
        return 1;
    }

    pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);   // 创建 perf buffer, 监听输出 map
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		read3_bpf__destroy(skel);
        return 1;
	}

	while (true) {    // 轮询 perf buffer
		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

	perf_buffer__free(pb);
	read3_bpf__destroy(skel);
	return -err;

}

