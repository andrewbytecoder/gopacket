package pcapgo

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/andrewbytecoder/gopacket/layers"
)

func TestReaderPreservesHighLinkType(t *testing.T) {
	// Build a minimal classic pcap global header with network/linktype=276.
	// No packet records follow; NewReader should still succeed.
	var ghdr [24]byte
	binary.LittleEndian.PutUint32(ghdr[0:4], magicMicroseconds)
	binary.LittleEndian.PutUint16(ghdr[4:6], versionMajor)
	binary.LittleEndian.PutUint16(ghdr[6:8], versionMinor)
	// timezone (8:12) and sigfigs (12:16) left as 0.
	binary.LittleEndian.PutUint32(ghdr[16:20], 65535) // snaplen
	binary.LittleEndian.PutUint32(ghdr[20:24], 276)   // LINKTYPE_LINUX_SLL2

	r, err := NewReader(bytes.NewReader(ghdr[:]))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if got, want := r.LinkType(), layers.LinkType(276); got != want {
		t.Fatalf("LinkType() = %v, want %v", got, want)
	}
}
