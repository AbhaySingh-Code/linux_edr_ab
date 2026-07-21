#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
//#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct event {
    u32 pid;
    u32 uid;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline void check_and_log(void *ctx, const char *filename_ptr){
//int handle_openat(struct trace_event_raw_sys_enter *ctx){
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

//    const char *filename_ptr = (const char *)ctx->args[1];

    char filename[64] = {};
    bpf_probe_read_user_str(&filename, sizeof(filename), filename_ptr);

    char prefix[] = "/dev/input/event";
    int match = 1;

    #pragma unroll

    for (int i = 0; i < sizeof(prefix) - 1; i ++) {
        if (filename[i] != prefix[i]) {
            match = 0;
            break;
        }
    }

    // if (!match) {
    //     return 0;
    // }

    if (match){
    bpf_printk("ALERT: PID %d accessed %s\n", pid, filename);
    }
    // struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    // if (!e) {
    //     continue
    // }

    // e->pid = pid;
    // e->uid = (u32)bpf_get_current_uid_gid();
    // bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    // bpf_ringbuf_submit(e,0);
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx){
    const char *filename_ptr = (const char *)ctx->args[1];
    check_and_log(ctx, filename_ptr);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat2")
int handle_openat2(struct trace_event_raw_sys_enter *ctx){
    const char *filename_ptr = (const char *)ctx->args[1];
    check_and_log(ctx, filename_ptr);
    return 0;
}