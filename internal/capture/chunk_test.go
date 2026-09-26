package capture

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

// rawEvent builds a record laid out like struct event in bpf/common.h.
func rawEvent(ts uint64, pid, n uint32, conn uint64, src, trunc uint8, comm string, data []byte) []byte {
	b := make([]byte, eventSize)
	binary.NativeEndian.PutUint64(b[offTS:], ts)
	binary.NativeEndian.PutUint32(b[offPID:], pid)
	binary.NativeEndian.PutUint32(b[offLen:], n)
	binary.NativeEndian.PutUint64(b[offConnID:], conn)
	b[offSource] = src
	b[offTruncated] = trunc
	copy(b[offComm:offComm+commLen], comm)
	copy(b[offData:offData+MaxData], data)
	return b
}

func TestDecodeEvent(t *testing.T) {
	req := []byte("GET /search?q=x HTTP/1.1\r\nHost: localhost:8080\r\n\r\n")
	big := bytes.Repeat([]byte("a"), MaxData)

	tests := []struct {
		name     string
		raw      []byte
		want     Chunk
		wantData []byte
	}{
		{
			name:     "normal",
			raw:      rawEvent(42, 1234, uint32(len(req)), 0xabc, 0, 0, "testserver", req),
			want:     Chunk{TS: 42, PID: 1234, Len: uint32(len(req)), ConnID: 0xabc, Source: SourceTCP, Comm: "testserver"},
			wantData: req,
		},
		{
			name:     "truncated",
			raw:      rawEvent(1, 1, 6000, 7, 0, 1, "testserver", big),
			want:     Chunk{TS: 1, PID: 1, Len: 6000, ConnID: 7, Source: SourceTCP, Truncated: true, Comm: "testserver"},
			wantData: big,
		},
		{
			name:     "comm fills all 16 bytes",
			raw:      rawEvent(1, 1, 1, 1, 0, 0, "abcdefghijklmnop", []byte("x")),
			want:     Chunk{TS: 1, PID: 1, Len: 1, ConnID: 1, Source: SourceTCP, Comm: "abcdefghijklmnop"},
			wantData: []byte("x"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeEvent(tt.raw)
			if err != nil {
				t.Fatalf("decodeEvent: %v", err)
			}
			tt.want.Data = tt.wantData
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDecodeEventShort(t *testing.T) {
	if _, err := decodeEvent(make([]byte, offData)); err == nil {
		t.Fatal("expected error for short record")
	}
}

func TestDecodeEventCopiesData(t *testing.T) {
	raw := rawEvent(1, 1, 3, 1, 0, 0, "x", []byte("abc"))
	c, err := decodeEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[offData] = 'Z'
	if string(c.Data) != "abc" {
		t.Errorf("Data aliases the ringbuf record: %q", c.Data)
	}
}
