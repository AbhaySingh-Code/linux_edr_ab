#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define PTRACE_ATTACH 16
#define PTRACE_SEIZE 0x4206

struct ptrace_event {
    __u32 pid; //tracer's pid (thread id)
    __u32 tgid; // tracer's tgid (process id)
    __u32 ppid; // tracer's parent pid
    __u32 uid;
    __u64 cgroup_id; 
    __s64 request; // used for ptrace attach or sieze
    __s64 target_pid;  // pid being traced
    char comm[16]; // tracer's proces name
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); //256 KB ring buffer
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace_enter(struct trace_event_raw_sys_enter *ctx){
    
    long request = ctx->args[0];

    if (request != PTRACE_ATTACH && request != PTRACE_SEIZE) {
        return 0;
    }

    struct ptrace_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt){
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = pid_tgid >> 32;
    evt->tgid = (__u32)pid_tgid;

    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid = (__u32)uid_gid;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    evt->ppid = BPF_CORE_READ(task, real_parent, tgid);

    evt->cgroup_id = bpf_get_current_cgroup_id();
    evt->request = request;
    evt->target_pid = ctx->args[1];

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt,0);
    return 0;
}