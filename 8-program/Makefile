TARGET = hello    # BPF 程序名称
ARCH ?= x86  # 架构

BPF_OBJ = ${TARGET:=.bpf.o}  # BPF 对象文件

all: $(TARGET) $(BPF_OBJ)    # 编译目标
.PHONY: all    # 清理目标
.PHONY: $(TARGET)    # 清理目标

# 卸载旧的 XDP 程序
# 删除旧的 BPF 程序
# 加载新的 BPF 程序
# 附加到 lo 设备
$(TARGET): $(BPF_OBJ)
	bpftool net detach xdp dev lo    
	rm -f /sys/fs/bpf/$(TARGET)      
	bpftool prog load $(BPF_OBJ) /sys/fs/bpf/$(TARGET)           
	bpftool net attach xdp pinned /sys/fs/bpf/$(TARGET) dev lo   



$(BPF_OBJ): %.o: %.c vmlinux.h       # 生成 BPF 对象文件
	clang \
	    -target bpf \
	    -D __TARGET_ARCH_$(ARCH) \
        -I/usr/include/$(shell uname -m)-linux-gnu \
	    -Wall \
	    -O2 -o $@ -c $<

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h		

clean:
	- bpftool net detach xdp dev lo
	- bpftool net detach xdp dev docker0
	- rm -f /sys/fs/bpf/$(TARGET)
	- rm $(BPF_OBJ)
	- tc filter delete dev docker0 parent ffff: