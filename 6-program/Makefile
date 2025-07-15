ARCH ?= x86
hello-verifier.bpf.o: %.o: %.c
	clang \
        -target bpf \
        -D __TARGET_ARCH_$(ARCH) \
        -I/usr/include/$(shell uname -m)-linux-gnu \
        -Wall \
        -O2 -g \
        -c $< -o $@
	llvm-strip -g $@
clean:
	rm -f *.bpf.o