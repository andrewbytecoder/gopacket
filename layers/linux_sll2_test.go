package layers

import (
	"encoding/hex"
	"testing"

	"github.com/google/gopacket"
)

func TestLinuxSLL2DecodeFromBytes(t *testing.T) {
	// 20-byte SLL2 header (see tcpdump LINKTYPE_LINUX_SLL2):
	// protocol(0800) reserved(0000) ifindex(01020304) arphrd(0001)
	// pkttype(04) halen(06) addr(0011223344550000)
	hdr, err := hex.DecodeString("0800000001020304000104060011223344550000")
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	if len(hdr) != 20 {
		t.Fatalf("expected 20 header bytes, got %d", len(hdr))
	}

	var sll2 LinuxSLL2
	if err := sll2.DecodeFromBytes(hdr, gopacket.NilDecodeFeedback); err != nil {
		t.Fatalf("DecodeFromBytes: %v", err)
	}

	if got, want := sll2.ProtocolType, EthernetTypeIPv4; got != want {
		t.Fatalf("ProtocolType = %v, want %v", got, want)
	}
	if got, want := sll2.InterfaceIndex, uint32(0x01020304); got != want {
		t.Fatalf("InterfaceIndex = %#x, want %#x", got, want)
	}
	if got, want := sll2.AddrType, uint16(1); got != want {
		t.Fatalf("AddrType = %d, want %d", got, want)
	}
	if got, want := sll2.PacketType, uint8(4); got != want {
		t.Fatalf("PacketType = %d, want %d", got, want)
	}
	if got, want := sll2.LinkLayerAddrLen, uint8(6); got != want {
		t.Fatalf("LinkLayerAddrLen = %d, want %d", got, want)
	}
	if got, want := sll2.Addr.String(), "00:11:22:33:44:55"; got != want {
		t.Fatalf("Addr = %q, want %q", got, want)
	}
}

func TestLinuxSLL2EndToEndIPv4(t *testing.T) {
	// SLL2 header + minimal IPv4 header.
	sll2Hdr, _ := hex.DecodeString("0800000000000000000104060011223344550000")
	ipv4Hdr, _ := hex.DecodeString(
		"45" + // Version/IHL
			"00" + // TOS
			"0014" + // Total length (20)
			"0000" + // ID
			"0000" + // Flags/frag
			"40" + // TTL
			"11" + // UDP
			"0000" + // checksum (ignored by decoder)
			"7f000001" + // src 127.0.0.1
			"7f000001") // dst 127.0.0.1
	data := append(sll2Hdr, ipv4Hdr...)

	p := gopacket.NewPacket(data, LinkTypeLinuxSLL2, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Fatalf("packet decode error: %v", p.ErrorLayer().Error())
	}
	if p.Layer(LayerTypeLinuxSLL2) == nil {
		t.Fatalf("missing LinuxSLL2 layer")
	}
	if p.Layer(LayerTypeIPv4) == nil {
		t.Fatalf("missing IPv4 layer")
	}
}
