#include <stdio.h> // 包含标准输入输出头文件, 用于打印信息
#include <errno.h> // 包含错误号头文件, 用于处理错误
#include <unistd.h> // 包含 Unix 标准头文件, 用于访问 POSIX 操作系统 API
#include <bpf/libbpf.h> // 包含 libbpf 库头文件
#include "hello-buffer-config.h" // 包含自定义头文件, 定义用到的结构体
#include "hello-buffer-config.skel.h" // 包含生成的 BPF 程序结构体头文件

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) // 参数来源于 `libbpf.h`, 这是 libbpf 提供的 日志打印函数
{
	if(level >= LIBBPF_DEBUG) // 如果日志级别大于等于 LIBBPF_DEBUG
		return 0; // 返回 0, 表示不打印调试信息
	return vfprintf(stderr, format, args); // 否则, 打印到标准错误
	// vfprintf 是一个变参函数, 用于格式化输出到指定的文件流
}

void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
	struct data_t *m = data; // 将传入的数据转换为 data_t 结构体指针
	printf("CPU %d: PID %d, UID %d, Command: %s, Message: %s, Path: %s\n",
		   cpu, m->pid, m->uid, m->command, m->message, m->path);

}

void lost_event(void *ctx, int cpu, __u64 cnt)
{
	printf("Lost %llu events on CPU %d\n", cnt, cpu); // 打印丢失的事件数量和 CPU 编号
}



int main()
{
	struct hello_buffer_config_bpf *skel; // 定义一个指向 `BPF 程序` 结构体的指针, 来源于 `hello-buffer-config.skel.h`
	int err; // 定义一个整数变量用于存储错误码
	struct perf_buffer *pb = NULL; // 定义一个指向性能缓冲区的指针, 初始化为 NULL , 来源于 `bpf/libbpf.h`, 是 libbpf 提供的性能事件缓冲区, 用于处理 BPF 程序输出的事件, 是用户空间与 BPF 程序之间的桥梁

	libbpf_set_print(libbpf_print_fn); // 设置 libbpf 的打印函数, 用于调试输出
	// libbpf_set_print 是 libbpf 提供的函数, 用于设置打印回调函数, 这样可以在 BPF 程序运行时输出调试信息

	skel = hello_buffer_config_bpf__open_and_load();
	if(!skel)
	{
		printf("Failed to open and load BPF skeleton\n");
		return 1; // 如果打开和加载 BPF skeleton 失败, 打印错误
	}

	err = hello_buffer_config_bpf__attach(skel); // 附加 BPF 程序到内核钩子
	if(err)
	{
		fprintf(stderr, "Failed to attach BPF program: %d\n", err); // stderr 是 C 语言标准库中的标准错误输出流，用于输出错误或警告信息。它通常会显示在终端或控制台，与标准输出流 stdout 分开，便于区分正常输出和错误信息。
		hello_buffer_config_bpf__destroy(skel); // 销毁 BPF skeleton
		return 1; // 如果附加 BPF 程序失败, 打印错误
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL); // 创建性能缓冲区, 监听 BPF 程序输出的事件
	if(!pb)
	{
		err = -1;
		fprintf(stderr, "Failed to create perf buffer: %d\n", err); // 如果创建性能缓冲区失败, 打印错误
		hello_buffer_config_bpf__destroy(skel); // 销毁 BPF skeleton
	}

	while (true)
	{
		err = perf_buffer__poll(pb, 100 /* timeout, ms */); // 轮询性能缓冲区, 获取事件
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {   // 为什么返回负值? 不同于一般系统调用函数, 内核和libbpf会返回负值的错误码
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling perf buffer: %d\n", err); // 如果轮询性能缓冲区出错, 打印错误
			break;
		}

	}

	perf_buffer__free(pb); // 释放性能缓冲区
	hello_buffer_config_bpf__destroy(skel); // 销毁 BPF skeleton
	return -err; // 返回错误码, 如果没有错误则返回 0
}