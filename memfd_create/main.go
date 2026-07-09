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

type memfdEvent struct {
	Pid   uint32
	Tgid  uint32
	Uid   uint32
	Comm  [16]byte
	Fname [64]byte
}

func main() {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock rlimit: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec("monitor.bpf.o")
	if err != nil {
		log.Fatalf("failed to load bpf object error : %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create ebpf collection : %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["tp_memfd_create"]
	if prog == nil {
		log.Fatalf("eBPF program failed to attached error : %v", err)
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_memfd_create", prog, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	eventsMap := coll.Maps["events"]
	if err != nil {
		log.Fatalf("ebpf map 'events' not found in elf")
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

	log.Println("Monitoring for memfd create events (Cntl + C to stop )......")

	var evt memfdEvent
	for {
		record, err := rd.Read()
		if err != nil {
			log.Printf("ringbuf closed or error : %v", err)
			return
		}

		err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt)
		if err != nil {
			log.Printf("Failed to parse event structure : %v", err)
			continue
		}

		commStr := string(bytes.TrimRight(evt.Comm[:], "\x00"))
		log.Printf("Alert [%s] Process invoked memfd_create with PID: %d on file descriptor %s\n", commStr, evt.Pid, evt.Fname)
	}

}
