all: 1-hello.bpf.o 2-hello-func.bpf.o

%.bpf.o: %.bpf.c
	clang \
        -target bpf \
        -I/usr/include/$(shell uname -m)-linux-gnu \
        -g \
        -O2 -o $@ -c $<