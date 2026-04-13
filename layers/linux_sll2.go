// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/google/gopacket"
)

// LinuxSLL2 is the Linux "cooked" capture encapsulation v2 (SLL2).
//
// Header format: https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html
type LinuxSLL2 struct {
	BaseLayer

	ProtocolType     EthernetType
	InterfaceIndex   uint32
	AddrType         uint16
	PacketType       uint8
	LinkLayerAddrLen uint8
	Addr             net.HardwareAddr
}

func (sll2 *LinuxSLL2) LayerType() gopacket.LayerType { return LayerTypeLinuxSLL2 }

func (sll2 *LinuxSLL2) LinkFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointMAC, sll2.Addr, nil)
}

func (sll2 *LinuxSLL2) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 20 {
		df.SetTruncated()
		return errors.New("Linux SLL2 packet too small")
	}

	sll2.ProtocolType = EthernetType(binary.BigEndian.Uint16(data[0:2]))
	// data[2:4] reserved (MBZ)
	sll2.InterfaceIndex = binary.BigEndian.Uint32(data[4:8])
	sll2.AddrType = binary.BigEndian.Uint16(data[8:10])
	sll2.PacketType = data[10]
	sll2.LinkLayerAddrLen = data[11]

	addrLen := int(sll2.LinkLayerAddrLen)
	if addrLen > 8 {
		addrLen = 8
	}
	if addrLen < 0 {
		addrLen = 0
	}
	sll2.Addr = net.HardwareAddr(data[12 : 12+addrLen])

	sll2.BaseLayer = BaseLayer{Contents: data[:20], Payload: data[20:]}
	return nil
}

func (sll2 *LinuxSLL2) NextLayerType() gopacket.LayerType {
	// If the ARPHRD type indicates Radiotap (803), the payload begins with a
	// Radiotap header regardless of ProtocolType.
	const arphrdIeee80211Radiotap = 803
	if sll2.AddrType == arphrdIeee80211Radiotap {
		return LayerTypeRadioTap
	}
	return sll2.ProtocolType.LayerType()
}

func decodeLinuxSLL2(data []byte, p gopacket.PacketBuilder) error {
	sll2 := &LinuxSLL2{}
	if err := sll2.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(sll2)
	p.SetLinkLayer(sll2)
	return p.NextDecoder(sll2.NextLayerType())
}
