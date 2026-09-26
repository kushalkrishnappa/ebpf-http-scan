//go:build linux

// Command agent captures inbound request bytes on one TCP port and prints
// them. M1 prints raw bytes, header values included; parsing, rules and
// redaction come in M2.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kushalkrishnappa/ebpf-http-scan/internal/capture"
)

func main() {
	port := flag.Uint("port", 8080, "local TCP port to capture (0 disables capture)")
	flag.Parse()
	if *port > 65535 {
		log.Fatalf("invalid -port %d", *port)
	}

	c, err := capture.Open(uint16(*port))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("capturing tcp_recvmsg on port %d (Ctrl-C to stop)", *port)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var events atomic.Uint64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			ch, err := c.Read()
			if errors.Is(err, capture.ErrClosed) {
				return
			}
			if err != nil {
				log.Printf("read: %v", err)
				continue
			}
			events.Add(1)
			fmt.Printf("conn=%x pid=%d comm=%s len=%d trunc=%v\n%q\n",
				ch.ConnID, ch.PID, ch.Comm, ch.Len, ch.Truncated, ch.Data)
		}
	}()

	stats := func() {
		drops, err := c.Drops()
		if err != nil {
			log.Printf("stats: %v", err)
			return
		}
		log.Printf("stats: events=%d drops=%d", events.Load(), drops)
	}

	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			stats()
		case <-ctx.Done():
			stats()
			if err := c.Close(); err != nil {
				log.Printf("close: %v", err)
			}
			<-done
			return
		}
	}
}
