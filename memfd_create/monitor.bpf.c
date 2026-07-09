#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define FNAME_LEN 64

struct event {
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    char fname[FNAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct trace_event_raw_sys_enter_memfd_create {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long   __syscall_nr;
    const char  *uname;
    unsigned int    flags;
};

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int tp_memfd_create(struct trace_event_raw_sys_enter_memfd_create *ctx){
    struct event *e;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    e = bpf_ringbuf_reserve(&events, sizeof(*e),0);
    if (!e)
        return 0;

    e->tgid = pid_tgid >> 32;
    e->pid = (__u32)pid_tgid; 
    e->uid = (__u32)uid_gid;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (ctx->uname) {
        long ret = bpf_probe_read_user_str(&e->fname, sizeof(e->fname), ctx->uname);
        if (ret < 0)
            e->fname[0] = 0;
    } else {
        e->fname[0] = 0;
    }

    bpf_printk("Alert: [%s] memfd_create invoked by PID %d. Name argument: %s\n", e->comm, e->pid, e->fname);

    bpf_ringbuf_submit(e,0);

//    bpf_printk("ALERT: memfd_create invoked by PID %d. Name argument: %s\n", e->tgid, e->fname); -> Cannot have it after bpf_ringbuf_submit

    return 0;
    
}