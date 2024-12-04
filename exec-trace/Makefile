.PHONY: clean all

all: exectrace.o

exectrace.o: exectrace.bpf.c vmlinux.h 
	clang -g -O3 -target bpf -D__TARGET_ARCH_x86_64 -c exectrace.bpf.c -o exectrace.o

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm -rf *.o *.skel.h vmlinux.h
