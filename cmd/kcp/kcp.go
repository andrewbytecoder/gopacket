package main

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)

type Kcp struct {
	filename string
}

func New() *Kcp {
	return &Kcp{}
}

func (k *Kcp) ParseFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&k.filename, "file", "f", "", "pcap file to read from")

}

func (k *Kcp) GetPcapFileName() string {
	return k.filename
}

func (k *Kcp) Run() error {
	// 1. 打开 pcap 文件
	// 如果文件不存在或格式错误，这里会报错
	handle, err := pcap.OpenOffline(k.filename)
	if err != nil {
		log.Fatalf("无法打开 pcap 文件 %s: %v", k.filename, err)
		return err
	}
	defer handle.Close()

	fmt.Printf("开始解析文件: %s\n", k.filename)
	fmt.Println("------------------------------------------------------------")

	// 创建数据包源
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	// 2. 遍历每一个数据包
	for packet := range packetSource.Packets() {

		// A nil packet indicates the end of a pcap file.
		if packet == nil {
			return nil
		}

		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeUDP {
			log.Println("not udp packet continue")
			continue
		}

		// 提取具体的 IP 信息
		var srcIP, dstIP net.IP
		srcIP = packet.NetworkLayer().NetworkFlow().Src().Raw()
		dstIP = packet.NetworkLayer().NetworkFlow().Dst().Raw()

		// 3. 解析 UDP 层
		udp, ok := packet.TransportLayer().(*layers.UDP)
		if !ok {
			log.Println("get udp data failed")
			continue
		}

		// 5. 获取 UDP 载荷 (Payload)
		payload := udp.LayerPayload()

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

	return nil
}

// 辅助函数：获取前几个字节的十六进制表示
func getHexPreview(data []byte) []byte {
	if len(data) > 8 {
		return data[:8]
	}
	return data
}
