
set -x
set -o errexit


PIN_FILE=/sys/fs/bpf/exectrace
BPF_FILE=exectrace.o

bpftool prog load $BPF_FILE $PIN_FILE autoattach

echo "cat /sys/kernel/tracing/trace_pipe"
bash -r 

rm $PIN_FILE
