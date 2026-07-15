#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define PROT_WRITE 0x02
#define PROT_EXEC 0x04

#define NET_CORRELATE_NS (5ULL * 1000000000ULL)

enum rwx_severity { RWX_SEV_MEDIUM = 0, RWX_SEV_HIGH = 1 };
enum rwx_src { RWX_SRC_MMAP = 0 , RWX_SRC_MPROTECT = 1 };

struct event {
    __u32 pid;
    __u32 tgid;
    char comm[16];
    unsigned long prot;
    __u32 severity;
    __u32 source;
    __u64 ns_since_connect; //0 if no recent connect
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} last_connect SEC(".maps");

// struct trace_event_raw_sys_enter {
//     unsigned long long unused;
//     long id;
//     unsigned long args[6];
// };

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx){
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&last_connect, &pid, &now, BPF_ANY);
    return 0;
}

static __always_inline void check_and_report(unsigned long prot, enum rwx_src source){
    if (!((prot & PROT_WRITE) && (prot & PROT_EXEC)))
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    __u64 ns_since_connect = 0;
    __u64 *last = bpf_map_lookup_elem(&last_connect, &pid);
    __u32 severity = RWX_SEV_MEDIUM;
    if (last){
        __u64 now = bpf_ktime_get_ns();
        __u64 delta = now - *last;
        if (delta <= NET_CORRELATE_NS) {
            severity = RWX_SEV_HIGH;
            ns_since_connect = delta;
        }
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e),0);
    if (!e)
        return;
    e->pid = (__u32)pid_tgid;
    e->tgid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->prot = prot;
    e->severity = severity;
    e->source = source;
    e->ns_since_connect = ns_since_connect;

    bpf_printk("RWX ALERT pid=%d comm=%s", e->pid, e->comm);
    bpf_printk("  prot=0x%lx severity=%d source=%d", e->prot, e->severity, e->source);

    bpf_ringbuf_submit(e, 0);
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx){
    unsigned long prot = ctx->args[2];
    check_and_report(prot, RWX_SRC_MMAP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(struct trace_event_raw_sys_enter *ctx){
    unsigned long prot = ctx->args[2];
    check_and_report(prot, RWX_SRC_MPROTECT);
    return 0;
}