//go:build linux

package capture

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ErrClosed is returned by Read after Close.
var ErrClosed = ringbuf.ErrClosed

// Capture owns the loaded BPF objects, their links and the ringbuf reader.
type Capture struct {
	objs  captureObjects
	links []link.Link
	rd    *ringbuf.Reader
}

// Open loads capture.bpf.c, sets the target port (0 disables capture) and
// attaches the fentry/fexit programs to tcp_recvmsg.
func Open(port uint16) (*Capture, error) {
	if n := binary.Size(captureEvent{}); n != eventSize {
		return nil, fmt.Errorf("struct event is %d bytes, decoder expects %d: update chunk.go", n, eventSize)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	c := &Capture{}
	if err := loadCaptureObjects(&c.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier rejected program:\n%+v", ve)
		}
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	if err := c.objs.ConfigMap.Put(uint32(0), port); err != nil {
		c.Close()
		return nil, fmt.Errorf("write config: %w", err)
	}

	for _, prog := range []*ebpf.Program{c.objs.OnRecvEnter, c.objs.OnRecvExit} {
		l, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("attach %s: %w", prog, err)
		}
		c.links = append(c.links, l)
	}

	rd, err := ringbuf.NewReader(c.objs.Events)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("open ringbuf: %w", err)
	}
	c.rd = rd
	return c, nil
}

// Read blocks until the next event arrives. It returns ErrClosed after Close.
func (c *Capture) Read() (Chunk, error) {
	rec, err := c.rd.Read()
	if err != nil {
		return Chunk{}, err
	}
	return decodeEvent(rec.RawSample)
}

// Drops returns how many events were lost because the ringbuf was full,
// summed across CPUs.
func (c *Capture) Drops() (uint64, error) {
	var perCPU []uint64
	if err := c.objs.Drops.Lookup(uint32(0), &perCPU); err != nil {
		return 0, fmt.Errorf("read drops: %w", err)
	}
	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return sum, nil
}

// Close stops reading, detaches the programs and frees the maps. A blocked
// Read returns ErrClosed.
func (c *Capture) Close() error {
	var errs []error
	if c.rd != nil {
		errs = append(errs, c.rd.Close())
	}
	for i := len(c.links) - 1; i >= 0; i-- {
		errs = append(errs, c.links[i].Close())
	}
	errs = append(errs, c.objs.Close())
	return errors.Join(errs...)
}
