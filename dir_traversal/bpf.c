//go:build ignore

// 1. Include your freshly generated kernel definition file
#include "vmlinux.h" 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define TASK_COMM_LEN    16
#define MAX_FILENAME_LEN 256

// Note: We removed the duplicate struct definitions for trace_event_raw_* // because they are now safely pulled automatically from vmlinux.h!

struct event {
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__s32 ret;
	__s32 flags;
	char  comm[TASK_COMM_LEN];
	char  pcomm[TASK_COMM_LEN];
	char  filename[MAX_FILENAME_LEN];
};

struct open_args {
	const char *filename;
	int flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct open_args);
} active_opens SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline int stash_args(const char *filename, int flags)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct open_args args = {
		.filename = filename,
		.flags = flags,
	};
	bpf_map_update_elem(&active_opens, &id, &args, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	const char *filename = (const char *)ctx->args[1];
	int flags = (int)ctx->args[2];
	return stash_args(filename, flags);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int tp_sys_enter_openat2(struct trace_event_raw_sys_enter *ctx)
{
	const char *filename = (const char *)ctx->args[1];
	return stash_args(filename, 0);
}

static __always_inline int handle_exit(long ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct open_args *args = bpf_map_lookup_elem(&active_opens, &id);
	if (!args)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bpf_map_delete_elem(&active_opens, &id);
		return 0;
	}

	__u32 pid = (__u32)id;
	__u32 tgid = (__u32)(id >> 32);
	__u64 uid_gid = bpf_get_current_uid_gid();

	e->pid   = pid;
	e->tgid  = tgid;
	e->ret   = (__s32)ret;
	e->flags = args->flags;
	e->uid   = (__u32)uid_gid;
	e->gid   = (__u32)(uid_gid >> 32);

	// Read process fields perfectly now that task_struct definition is known!
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *real_parent = BPF_CORE_READ(task, real_parent);
	
	e->ppid = BPF_CORE_READ(real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	BPF_CORE_READ_STR_INTO(&e->pcomm, real_parent, comm);

	__builtin_memset(e->filename, 0, sizeof(e->filename));
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), args->filename);

	bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&active_opens, &id);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tp_sys_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
	return handle_exit(ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int tp_sys_exit_openat2(struct trace_event_raw_sys_exit *ctx)
{
	return handle_exit(ctx->ret);
}
