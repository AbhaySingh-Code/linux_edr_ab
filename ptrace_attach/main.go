package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// 1. Define the structural format sent by your ptrace.bpf.c
type ptraceEvent struct {
	Pid       uint32
	Tgid      uint32
	Ppid      uint32
	Uid       uint32
	CgroupId  uint64
	Request   int64
	TargetPid int64
	Comm      [16]byte
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock rlimit: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec("ptrace.bpf.o")
	if err != nil {
		log.Fatalf("failed to load eBPF ELF file: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Adjust "TracePtraceEnter" to your exact C function name if needed
	prog := coll.Programs["trace_ptrace_enter"]
	if prog == nil {
		log.Fatalf("eBPF program 'TracePtraceEnter' not found in ELF")
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_ptrace", prog, nil)
	if err != nil {
		log.Fatalf("failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	// Adjust "Events" to your exact BPF_MAP_TYPE_RINGBUF map name if needed
	eventsMap := coll.Maps["events"]
	if eventsMap == nil {
		log.Fatalf("eBPF map 'Events' not found in ELF")
	}

	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		log.Fatalf("failed to open ringbuf reader: %v", err)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		rd.Close()
	}()

	log.Println("Monitoring for ptrace events (Ctrl-C to stop)...")

	var evt ptraceEvent
	for {
		record, err := rd.Read()
		if err != nil {
			log.Printf("ringbuf closed or error: %v", err)
			return
		}

		// 2. Parse the raw bytes directly into our Go struct
		// Most modern Linux architectures use Little Endian byte ordering
		err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt)
		if err != nil {
			log.Printf("failed to parse event structure: %v", err)
			continue
		}

		// Clean up the trailing null bytes from the comm string array
		commStr := string(bytes.TrimRight(evt.Comm[:], "\x00"))

		// Translate request code numbers into human-readable action text
		action := "UNKNOWN"
		if evt.Request == 16 {
			action = "PTRACE_ATTACH"
		} else if evt.Request == 0x4206 {
			action = "PTRACE_SEIZE"
		}

		// 3. Print out clean structured event fields
		log.Printf("[ALERT] Process '%s' (PID: %d) called %s on Target PID: %d\n", 
			commStr, evt.Pid, action, evt.TargetPid)
	}
}