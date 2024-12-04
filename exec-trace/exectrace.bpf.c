
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

#define ACTION_ALLOW 0 
#define ACTION_BLOCK 1
#define ACTION_AUDIT 2

struct map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 255);
    __type(key, pid_t);  // can_id u32
    __type(value, __u32); // action block, allow, audit
} pidns_maps SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task;
    unsigned fname_off;
    struct event *e;
    pid_t pid;
    pid_t ppid;
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    unsigned int pid_ns;
    struct ns_common ns;
    struct pid_namespace pid_ns4child;
    u32 upid;
    void *ret;
    __u32 opmode;
    long kill_ret = 0;
    
	pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    // task->nsproxy->pid_ns_for_children->ns.inum
    pid_ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    
    ret = bpf_map_lookup_elem(&pidns_maps, &pid_ns);
    if(!ret) // pid_namespace not found in the map
    {
        return 0; // ACTION_ALLOW
    }
    // pid namespace is in the map
    bpf_probe_read_kernel(&opmode, sizeof(__u32), ret);
    // TODO check
    // ACTION_AUDIT
    ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&comm, sizeof(comm));
    fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&filename, sizeof(filename), (void *)ctx + fname_off);
    // task->real_parent->comm);
    BPF_CORE_READ_INTO(&pcomm, task, real_parent, comm);

    bpf_printk("EXEC '%s' [pid=%d, filename='%s', ns=%u] by '%s' [ppid=%d].\n", 
        comm,
        pid, 
        filename, 
        pid_ns,
        pcomm,
        ppid);

    if(opmode == ACTION_BLOCK){
        // kill pings
        if(__builtin_memcmp(comm, "ping", 4) == 0)
        {
            // kill by signal
            kill_ret = bpf_send_signal(9);
        }
    }

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
