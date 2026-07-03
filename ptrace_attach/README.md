# eBPF Ptrace Attach Detector

A lightweight runtime security tool built with eBPF (Extended Berkeley Packet Filter) and Go that detects when a process uses the `ptrace` system call (`PTRACE_ATTACH` or `PTRACE_SEIZE`) to hook into another process. 

This mechanism mimics popular EDR (Endpoint Detection and Response) and CNCF Falco rules to flag potential process injection, credential dumping (e.g., scraping memory strings), or unauthorized debugging artifacts.

## Architecture & Workflow

The workspace consists of three logical roles during validation:
1. **The Detector (`main`)**: The eBPF kernel program attached to the `sys_enter_ptrace` tracepoint alongside a Go runtime that listens on a high-performance kernel `ringbuf`.
2. **The Target (`test/binary`)**: A dummy process holding a secret memory string (`PEEKABOOSECOND`) that goes into an idle loop awaiting external action.
3. **The Attacker (`test/ptrace_attacker`)**: A simulation binary that targets the victim's memory space using process attachments, reads the raw registers/memory bytes, and detaches.

## Repository Layout

```text
├── bpf/
├── ptrace.bpf.c       # Core eBPF kernel source code
├── ptrace.bpf.o       # Compiled eBPF bytecode
├── vmlinux.h          # Kernel type structures definitions
├── main.go            # Simplified Go-based userspace loader & ring buffer reader
├── go.mod / go.sum    # Go module definitions
└── test/              # Simulation Binaries
    ├── binary         # Target victim process holding memory secret
    └── ptrace_attacker# Offensive simulator acting as the tracer
