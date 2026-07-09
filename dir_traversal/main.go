package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:embed bpf.o
var bpfSpecs []byte

type Event struct {
	Pid      uint32
	Tgid     uint32
	Ppid     uint32
	Uid      uint32
	Gid      uint32
	Ret      int32
	Flags    int32
	Comm     [16]byte
	Pcomm    [16]byte
	Filename [256]byte
}

var shellBinaries = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true, "tmux": true,
}

func main() {
	// 1. Setup OS Signal Channel for clean termination mapping
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfSpecs))
	if err != nil {
		log.Fatalf("loading spec failed: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("creating eBPF collection failed: %v", err)
	}
	defer coll.Close()

	tracepoints := map[string]struct{ group, name string }{
		"tp_sys_enter_openat":  {group: "syscalls", name: "sys_enter_openat"},
		"tp_sys_enter_openat2": {group: "syscalls", name: "sys_enter_openat2"},
		"tp_sys_exit_openat":   {group: "syscalls", name: "sys_exit_openat"},
		"tp_sys_exit_openat2":  {group: "syscalls", name: "sys_exit_openat2"},
	}

	for progName, tpInfo := range tracepoints {
		tp, err := link.Tracepoint(tpInfo.group, tpInfo.name, coll.Programs[progName], nil)
		if err != nil {
			log.Fatalf("failed to attach %s: %v", progName, err)
		}
		defer tp.Close()
	}

	eventsMap := coll.Maps["events"]
	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		log.Fatalf("creating ringbuf reader failed: %v", err)
	}
	defer rd.Close()

	log.Println("EDR Engine running. Press Ctrl+C to exit gracefully...")

	// 2. Data channel to feed our event processor loop
	recordChan := make(chan ringbuf.Record)
	errChan := make(chan error)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				errChan <- err
				return
			}
			recordChan <- record
		}
	}()

	var event Event
	for {
		select {
		case <-stopChan:
			log.Println("\nStopping EDR Engine cleanly...")
			return // Exits main() safely, firing all deferred closes

		case err := <-errChan:
			log.Fatalf("Ringbuffer error: %v", err)

		case record := <-recordChan:
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}

			comm := strings.TrimRight(string(event.Comm[:]), "\x00")
			filename := strings.TrimRight(string(event.Filename[:]), "\x00")

			if shellBinaries[comm] || !strings.Contains(filename, "..") {
				continue
			}

			isTargetLocation := strings.HasPrefix(filename, "/etc") ||
				strings.Contains(filename, "/.ssh") ||
				strings.HasPrefix(filename, "/root/.ssh") ||
				strings.Contains(filename, "id_rsa")

			if isTargetLocation {
				pcomm := strings.TrimRight(string(event.Pcomm[:]), "\x00")
				status := "SUCCESS"
				if event.Ret < 0 {
					status = fmt.Sprintf("FAILED (errno: %d)", -event.Ret)
				}

				fmt.Println("----------------------------------------------------------------------")
				fmt.Printf("[ALERT] Falco Rule Violated!\n")
				fmt.Printf("File Activity: %s [Status: %s]\n", filename, status)
				fmt.Printf("Process Context: %s (PID: %d) -> Parent: %s (PPID: %d)\n", comm, event.Tgid, pcomm, event.Ppid)
				fmt.Println("----------------------------------------------------------------------")
			}
		}
	}
}
