package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)

// KCP Protocol Constants
const (
	// Retransmission Timeout (RTO) bounds, in milliseconds
	IKCP_RTO_NDL = 30    // no-delay mode: minimum RTO (ms)
	IKCP_RTO_MIN = 100   // normal mode: minimum RTO (ms)
	IKCP_RTO_DEF = 200   // default RTO (ms)
	IKCP_RTO_MAX = 60000 // maximum RTO (ms), 60 seconds

	// Command types for the KCP segment header (cmd field)
	IKCP_CMD_PUSH = 81 // cmd: push data
	IKCP_CMD_ACK  = 82 // cmd: acknowledge
	IKCP_CMD_WASK = 83 // cmd: window probe request (ask)
	IKCP_CMD_WINS = 84 // cmd: window size response (tell)

	// Probe flags (bitfield), set in kcp.probe to schedule probe commands
	IKCP_ASK_SEND = 1 // schedule sending IKCP_CMD_WASK
	IKCP_ASK_TELL = 2 // schedule sending IKCP_CMD_WINS

	// Default window and MTU sizes
	IKCP_WND_SND = 32   // default send window size (packets)
	IKCP_WND_RCV = 32   // default receive window size (packets)
	IKCP_MTU_DEF = 1400 // default MTU (bytes, not including UDP/IP header)

	// Protocol parameters
	IKCP_ACK_FAST    = 3      // fast retransmit trigger threshold (duplicate ACK count)
	IKCP_INTERVAL    = 100    // default flush interval (ms)
	IKCP_OVERHEAD    = 24     // per-segment header size: conv(4) + cmd(1) + frg(1) + wnd(2) + ts(4) + sn(4) + una(4) + len(4)
	IKCP_DEADLINK    = 20     // max retransmissions before declaring dead link
	IKCP_THRESH_INIT = 2      // initial slow-start threshold (packets)
	IKCP_THRESH_MIN  = 2      // minimum slow-start threshold (packets)
	IKCP_PROBE_INIT  = 500    // initial window probe timeout (ms)
	IKCP_PROBE_LIMIT = 120000 // maximum window probe timeout (ms), 120 seconds
	IKCP_SN_OFFSET   = 12     // byte offset of sequence number (sn) within the segment header
)

type Kcp struct {
	filename string
}

// Segment defines a KCP segment
type Segment struct {
	Conv     uint32 `json:"conv"`     // 会话 ID
	Cmd      uint8  `json:"cmd"`      // 命令类型
	Frg      uint8  `json:"frg"`      // 分片数量
	Wnd      uint16 `json:"wnd"`      // 窗口大小
	Ts       uint32 `json:"ts"`       // 时间戳
	SN       uint32 `json:"sn"`       // 序列号
	Una      uint32 `json:"una"`      // 未确认序号
	Rto      uint32 `json:"rto"`      // 重传超时
	Xmit     uint32 `json:"xmit"`     // 传输次数
	Resendts uint32 `json:"resendts"` // 重传时间戳
	Fastack  uint32 `json:"fastack"`  // 快速确认数
	Acked    uint32 `json:"acked"`    // 是否已确认
	Len      uint32 `json:"len"`      // 数据长度
	Data     []byte `json:"data"`     // 载荷数据
}

func decode(ptr []byte) *Segment {
	_ = ptr[IKCP_OVERHEAD-1] // BCE hint

	seg := &Segment{}

	seg.Conv = binary.LittleEndian.Uint32(ptr)
	seg.Cmd = ptr[4]
	seg.Frg = ptr[5]
	seg.Wnd = binary.LittleEndian.Uint16(ptr[6:])
	seg.Ts = binary.LittleEndian.Uint32(ptr[8:])
	seg.SN = binary.LittleEndian.Uint32(ptr[12:])
	seg.Una = binary.LittleEndian.Uint32(ptr[16:])
	seg.Len = binary.LittleEndian.Uint32(ptr[20:])
	seg.Data = ptr[24:]

	return seg
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

	fmt.Printf("开始解析文件：%s\n", k.filename)
	fmt.Printf("链路层类型：%v (%d)\n", handle.LinkType(), int(handle.LinkType()))
	fmt.Println("------------------------------------------------------------")
	// 创建数据包源
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	// 2. 遍历每一个数据包
	for packet := range packetSource.Packets() {

		// A nil packet indicates the end of a pcap file.
		if packet == nil {
			fmt.Println("文件解析完毕")
			return nil
		}

		if packet.LinkLayer() == nil || packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeUDP {
			log.Println("not udp packet continue", packet)
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

		jsonByte, err := json.Marshal(decode(udp.LayerPayload()))
		if err != nil {
			log.Println("json marshal failed")
			continue
		}

		fmt.Println(string(jsonByte))

		fmt.Print(decode(udp.LayerPayload()))

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
