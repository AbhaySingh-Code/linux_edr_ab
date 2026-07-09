#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Structure to mirror the tracepoint arguments for sys_enter_memfd_create
struct trace_event_raw_sys_enter {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int __syscall_nr;
    const char *uname; 
    unsigned int flags;
};

char _license[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int bpf_prog(struct trace_event_raw_sys_enter *ctx) {
    // Using __u64 and __u32 explicitly avoids header definition mismatches
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;     // Extract Host PID

    char name_buf[64] = {0};

    // Safely read the name string pointer from user-space
    if (ctx->uname) {
        bpf_probe_read_user_str(&name_buf, sizeof(name_buf), ctx->uname);
    }

    // Print to the tracing pipeline
    bpf_printk("ALERT: memfd_create invoked by PID %d. Name argument: %s\n", pid, name_buf);

    return 0;
}