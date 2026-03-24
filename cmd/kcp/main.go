// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// The pcaplay binary load an offline capture (pcap file) and replay
// it on the select interface, with an emphasis on packet timing
package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// 配置参数
const (
	pcapFile    = "capture.pcap" // 替换为你的 pcap 文件路径
	snapLen     = int32(1600)    // 最大读取字节数
	promiscuous = false          // 是否混杂模式 (读取文件时此选项通常被忽略，但需定义)
	readTimeout = time.Duration(30) * time.Second
)

func main() {
	// 1. 打开 pcap 文件
	// 如果文件不存在或格式错误，这里会报错
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatalf("无法打开 pcap 文件 %s: %v", pcapFile, err)
	}
	defer handle.Close()

	fmt.Printf("开始解析文件: %s\n", pcapFile)
	fmt.Println("------------------------------------------------------------")

	// 创建数据包源
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// 2. 遍历每一个数据包
	for packet := range packetSource.Packets() {
		// 3. 解析 UDP 层
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			// 不是 UDP 包，跳过
			continue
		}

		udp, _ := udpLayer.(*layers.UDP)

		// 4. 解析网络层 (通常是 IPv4 或 IPv6) 以获取 IP 地址
		// 我们优先查找 IPv4，如果没有则查找 IPv6
		var ipLayer gopacket.Layer
		if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
			ipLayer = layer
		} else if layer := packet.Layer(layers.LayerTypeIPv6); layer != nil {
			ipLayer = layer
		}

		if ipLayer == nil {
			continue // 没有 IP 层的 UDP 包（极少见，除非是链路层广播等特殊情况）
		}

		// 提取具体的 IP 信息
		var srcIP, dstIP net.IP
		switch ip := ipLayer.(type) {
		case *layers.IPv4:
			srcIP = ip.SrcIP
			dstIP = ip.DstIP
		case *layers.IPv6:
			srcIP = ip.SrcIP
			dstIP = ip.DstIP
		}

		// 5. 获取 UDP 载荷 (Payload)
		payload := udp.Payload

		// 6. 格式化输出
		// 尝试将载荷转换为字符串，如果包含不可打印字符，则显示 Hex
		dataStr := string(payload)
		isPrintable := true
		for _, b := range payload {
			if b < 32 || b > 126 {
				// 简单的启发式判断：如果有非 ASCII 可打印字符，可能不是纯文本
				// 注意：这只是一个简单判断，DNS 等二进制协议会被判定为非文本
				isPrintable = false
				break
			}
		}

		// 为了演示，如果是 DNS (端口 53) 或其他已知二进制协议，强制显示 Hex 或部分信息
		// 这里简单处理：如果长度很短且看起来像文本，打印文本，否则打印 Hex 摘要
		var contentPreview string
		if isPrintable && len(payload) > 0 {
			contentPreview = dataStr
			if len(contentPreview) > 50 {
				contentPreview = contentPreview[:50] + "..."
			}
		} else {
			contentPreview = fmt.Sprintf("<Binary Data> Len:%d Hex:%x", len(payload), getHexPreview(payload))
		}

		// 打印详细信息
		fmt.Printf("[%s] %s:%d -> %s:%d | Payload: %s\n",
			packet.Metadata().Timestamp.Format("15:04:05.000"),
			srcIP, udp.SrcPort,
			dstIP, udp.DstPort,
			contentPreview,
		)
	}
}

// 辅助函数：获取前几个字节的十六进制表示
func getHexPreview(data []byte) []byte {
	if len(data) > 8 {
		return data[:8]
	}
	return data
}
