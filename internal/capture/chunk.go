// Package capture loads bpf/capture.bpf.c, attaches it to tcp_recvmsg, and
// turns ringbuf records into Chunks.
//
// This file has no build tag so the decoder can be unit-tested on any OS;
// the loader itself is Linux-only (loader.go).
package capture

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// MaxData mirrors MAX_DATA in bpf/common.h.
const MaxData = 4096

const commLen = 16

// Byte offsets of struct event fields (bpf/common.h). The kernel writes the
// record in host byte order, hence binary.NativeEndian below.
const (
	offTS        = 0
	offPID       = 8
	offLen       = 12
	offConnID    = 16
	offSource    = 24
	offTruncated = 25
	offComm      = 26
	offData      = 42
	eventSize    = 4144 // sizeof(struct event), including tail padding
)

// Source says which hook produced a Chunk.
type Source uint8

const (
	SourceTCP Source = 0
	SourceTLS Source = 1
)

// Chunk is one read() worth of bytes received on a captured socket.
type Chunk struct {
	TS        uint64 // bpf_ktime_get_ns
	PID       uint32
	Len       uint32 // bytes the kernel returned; > len(Data) if Truncated
	ConnID    uint64 // socket cookie
	Source    Source
	Truncated bool
	Comm      string
	Data      []byte
}

func decodeEvent(raw []byte) (Chunk, error) {
	if len(raw) < offData+MaxData {
		return Chunk{}, fmt.Errorf("short event record: %d bytes, want %d", len(raw), eventSize)
	}
	ne := binary.NativeEndian
	c := Chunk{
		TS:        ne.Uint64(raw[offTS:]),
		PID:       ne.Uint32(raw[offPID:]),
		Len:       ne.Uint32(raw[offLen:]),
		ConnID:    ne.Uint64(raw[offConnID:]),
		Source:    Source(raw[offSource]),
		Truncated: raw[offTruncated] != 0,
	}
	comm := raw[offComm : offComm+commLen]
	if i := bytes.IndexByte(comm, 0); i >= 0 {
		comm = comm[:i]
	}
	c.Comm = string(comm)

	n := min(c.Len, MaxData)
	c.Data = bytes.Clone(raw[offData : offData+n])
	return c, nil
}
