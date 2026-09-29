// 抓包帧解码：链路层 -> 网络层 -> 传输层 -> 应用层。
//
// 解码只做"这一帧是什么、地址端口是什么、载荷在哪"，
// 统计、抽取与安全发现都在 analyze.go 里做。
package net

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"gyhost/internal/i18n"
	"gyhost/internal/pcap"
)

// 链路类型编号（DLT / pcap 的 network 字段）。
const (
	dltNull      = 0   // BSD loopback
	dltEthernet  = 1   // DLT_EN10MB
	dltPPP       = 9   // DLT_PPP
	dltFDDI      = 10  // DLT_FDDI
	dltLoop      = 108 // OpenBSD loopback
	dltPppSerial = 50  // DLT_PPP_SERIAL
	dltPppHdlc   = 51  // DLT_PPP_HDLC
	dltRaw       = 101 // DLT_RAW (BSD)
	dltRawAlt    = 12  // DLT_RAW (部分系统)
	dltIEEE80211 = 105 // DLT_IEEE802_11
	dltPrism     = 119 // DLT_PRISM_HEADER
	dltRadiotap  = 127 // DLT_IEEE802_11_RADIO
	dltAVS       = 163 // DLT_IEEE802_11_RADIO_AVS
	dltIPv4      = 228 // DLT_IPV4
	dltIPv6      = 229 // DLT_IPV6
	dltLinuxSLL  = 113 // DLT_LINUX_SLL
	dltLinuxSLL2 = 276 // DLT_LINUX_SLL2
)

// EtherType。
const (
	etIPv4      = 0x0800
	etARP       = 0x0806
	etRARP      = 0x8035
	etVLAN      = 0x8100
	etVLANQinQ  = 0x88a8
	etVLANAlt   = 0x9100
	etIPv6      = 0x86dd
	etSlow      = 0x8809 // LACP 等慢速协议
	etMPLS      = 0x8847
	etMPLSMcast = 0x8848
	etPPPoEDis  = 0x8863
	etPPPoESess = 0x8864
	etEAPOL     = 0x888e
	etLLDP      = 0x88cc
	etMACsec    = 0x88e5
	etFCoE      = 0x8906
	etCDP       = 0x2000
)

// 802.11 帧类型与子类型。
const (
	dot11TypeMgmt  = 0
	dot11TypeData  = 2
	dot11SubAssoc  = 0
	dot11SubProbe  = 4
	dot11SubProbeR = 5
	dot11SubBeacon = 8
)

// AF_*（BSD loopback 头里的地址族，不同系统取值不同）。
const (
	afINET  = 2
	afINET6 = 10
	// AF_INET6 在不同 BSD 上分别是 24/28/30
)

// pkt 是一帧解码后的结果。
type pkt struct {
	no      int
	ts      time.Time
	capLen  int
	wireLen int

	link string // 链路层协议名
	l3   string // 网络层协议名（未解出则为空）
	l4   string // 传输层协议名（未解出则为空）
	app  string // 应用层协议名（未识别则为空）

	srcMACRaw, dstMACRaw [6]byte
	hasSrcMAC, hasDstMAC bool
	src, dst             string // 地址（列表显示用）
	srcIP, dstIP         net.IP // 过滤与统计用，链路层帧可能为 nil
	srcPort, dstPort     uint16
	flags                uint8 // TCP 标志位

	// wantInfo 表示本次是否需要生成列表摘要。报告模式不看 info，
	// 跳过它可以省下每帧的字符串格式化（大数据量下是主要开销之一）。
	wantInfo bool
	verbose  bool // -V 详细模式：填充协议树所需的补充字段
	seq, ack uint32
	win      uint16

	// ---- 详细模式（-V）用的补充字段，仅 verbose 时填充 ----
	raw                     []byte   // 整帧原始字节（指向帧缓冲，只在本次回调内有效）
	linkType                uint32   // 链路层类型编号
	etype                   uint16   // 链路层之上的类型字段（EtherType / PPP 协议号 …）
	vlanIDs                 []uint16 // 802.1Q / QinQ 的 VLAN ID 列表（按出现顺序）
	ipVer                   int
	ipIHL                   int   // IPv4 头长（字节）
	ipTOS                   uint8 // IPv4 DSCP+ECN / IPv6 Traffic Class
	ipFlow                  uint32
	ipLen                   int    // IPv4 Total Length / IPv6 Payload Length
	ipID                    uint16 // IPv4 Identification
	ipTTL                   uint8  // IPv4 TTL / IPv6 Hop Limit
	ipProto                 uint8  // IPv4 Protocol / IPv6 Next Header
	ipCksum                 uint16
	arpHwType, arpProtoType uint16
	arpHwSize, arpProtoSize byte
	arpTgtMACRaw            [6]byte
	tcpHdrLen               int
	tcpUrgent               uint16
	tcpCksum                uint16
	tcpOpts                 []byte
	udpLen                  int
	udpCksum                uint16
	icmpType                byte
	icmpCode                byte
	icmpCksum               uint16
	icmpID                  uint16
	icmpSeq                 uint16

	// IP 分片（分片异常检测）：fragOff 以 8 字节为单位
	isFrag   bool
	fragOff  uint16
	fragMore bool
	fragDF   bool // IPv4 的"不分片"标志位（与 MF 相互独立，不能由是否分片推断）
	fragID   uint32
	fragSize int // 该片的数据长度

	payload []byte // 传输层载荷（可能为空，指向帧缓冲）

	// ARP 字段
	arpOp                 uint16
	arpSenderIP, arpTgtIP string

	info string // 列表模式的"信息"列
}

// decodeInto 解析一帧到 p（复用调用方持有的结构体，避免每帧一次堆分配）。
//
// wantInfo 为 false 时不生成列表摘要（报告模式用），可以省下每帧的字符串格式化。
// verbose 为 true 时额外填充协议树字段（-V 详细模式）。
func decodeInto(p *pkt, rec pcap.Record, wantInfo, verbose bool) *pkt {
	*p = pkt{
		no:       rec.Index,
		ts:       rec.Time,
		capLen:   len(rec.Data),
		wireLen:  int(rec.OrigLen),
		wantInfo: wantInfo,
		verbose:  verbose,
		linkType: rec.LinkType,
	}
	if p.verbose {
		p.raw = rec.Data // 只在本次回调内有效（帧缓冲逐帧复用）
	}
	if p.wireLen < p.capLen {
		p.wireLen = p.capLen
	}

	et, rest, ok := stripLink(p, rec.LinkType, rec.Data)
	if ok {
		p.etype = et
	}
	if !ok {
		if p.link == "" {
			p.link = i18n.Tf("net.link.unknown", rec.LinkType)
		}
		return p
	}
	decodeNet(p, et, rest)
	classifyApp(p)
	fillInfo(p)
	return p
}

// decode 解析一帧；无法解出网络层时只填链路层信息。
func decode(rec pcap.Record, wantInfo, verbose bool) *pkt {
	return decodeInto(new(pkt), rec, wantInfo, verbose)
}

// setSrcMAC 记录源 MAC 的原始 6 字节（渲染成字符串推迟到真正需要时）。
func (p *pkt) setSrcMAC(b []byte) {
	if len(b) >= 6 {
		copy(p.srcMACRaw[:], b[:6])
		p.hasSrcMAC = true
	}
}

// setDstMAC 记录目的 MAC 的原始 6 字节。
func (p *pkt) setDstMAC(b []byte) {
	if len(b) >= 6 {
		copy(p.dstMACRaw[:], b[:6])
		p.hasDstMAC = true
	}
}

// srcMAC 按需渲染源 MAC 字符串。
func (p *pkt) srcMAC() string {
	if !p.hasSrcMAC {
		return ""
	}
	return macStr(p.srcMACRaw[:])
}

// dstMAC 按需渲染目的 MAC 字符串。
func (p *pkt) dstMAC() string {
	if !p.hasDstMAC {
		return ""
	}
	return macStr(p.dstMACRaw[:])
}

// ---------------------------------------------------------------------------
// 链路层
// ---------------------------------------------------------------------------

// stripLink 剥掉链路层封装，返回 EtherType 与网络层载荷。
// 链路层无法继续解码（如 802.11 管理帧、未知链路类型）时返回 false。
func stripLink(p *pkt, lt uint32, b []byte) (uint16, []byte, bool) {
	switch lt {
	case dltEthernet:
		p.link = "Ethernet"
		return stripEthernet(p, b)

	case dltNull, dltLoop:
		p.link = "Loopback"
		return stripNull(b)

	case dltRaw, dltRawAlt, dltIPv4, dltIPv6:
		p.link = "Raw IP"
		return stripRawIP(lt, b)

	case dltLinuxSLL:
		p.link = "Linux SLL"
		if len(b) < 16 {
			return 0, nil, false
		}
		return binary.BigEndian.Uint16(b[14:16]), b[16:], true

	case dltLinuxSLL2:
		p.link = "Linux SLL2"
		if len(b) < 20 {
			return 0, nil, false
		}
		return binary.BigEndian.Uint16(b[0:2]), b[20:], true

	case dltPPP, dltPppSerial, dltPppHdlc:
		p.link = "PPP"
		return stripPPP(b)

	case dltFDDI:
		p.link = "FDDI"
		return 0, nil, false

	case dltIEEE80211:
		p.link = "IEEE 802.11"
		return stripDot11(p, b)

	case dltRadiotap:
		p.link = "IEEE 802.11 (radiotap)"
		frame, ok := stripRadiotap(b)
		if !ok {
			return 0, nil, false
		}
		return stripDot11(p, frame)

	case dltPrism:
		p.link = "IEEE 802.11 (Prism)"
		frame, ok := stripPrismAVS(b)
		if !ok {
			return 0, nil, false
		}
		return stripDot11(p, frame)

	case dltAVS:
		p.link = "IEEE 802.11 (AVS)"
		frame, ok := stripPrismAVS(b)
		if !ok {
			return 0, nil, false
		}
		return stripDot11(p, frame)
	}
	return 0, nil, false
}

// stripEthernet 解析以太网头，顺带剥掉 802.1Q / QinQ 标签。
func stripEthernet(p *pkt, b []byte) (uint16, []byte, bool) {
	if len(b) < 14 {
		return 0, nil, false
	}
	p.setDstMAC(b[0:6])
	p.setSrcMAC(b[6:12])
	et := binary.BigEndian.Uint16(b[12:14])
	off := 14
	for et == etVLAN || et == etVLANQinQ || et == etVLANAlt {
		if len(b) < off+4 {
			return 0, nil, false
		}
		if p.verbose {
			p.vlanIDs = append(p.vlanIDs, binary.BigEndian.Uint16(b[off:off+2])&0x0fff)
		}
		et = binary.BigEndian.Uint16(b[off+2 : off+4])
		off += 4
	}
	return et, b[off:], true
}

// stripNull 解析 BSD loopback 头（4 字节地址族，字节序需自行判定）。
func stripNull(b []byte) (uint16, []byte, bool) {
	if len(b) < 4 {
		return 0, nil, false
	}
	af := binary.LittleEndian.Uint32(b[:4])
	if !isAF(af) {
		af = binary.BigEndian.Uint32(b[:4])
		if !isAF(af) {
			return 0, nil, false
		}
	}
	switch af {
	case afINET:
		return etIPv4, b[4:], true
	default: // 10 / 24 / 28 / 30 都是 AF_INET6 的变体
		return etIPv6, b[4:], true
	}
}

// isAF 判断是否是已知的地址族取值。
func isAF(v uint32) bool {
	return v == afINET || v == afINET6 || v == 24 || v == 28 || v == 30
}

// stripRawIP 按链路类型或首字节版本号判定 IP 版本。
func stripRawIP(lt uint32, b []byte) (uint16, []byte, bool) {
	switch lt {
	case dltIPv4:
		return etIPv4, b, true
	case dltIPv6:
		return etIPv6, b, true
	}
	if len(b) == 0 {
		return 0, nil, false
	}
	switch b[0] >> 4 {
	case 4:
		return etIPv4, b, true
	case 6:
		return etIPv6, b, true
	}
	return 0, nil, false
}

// stripPPP 解析 PPP 头：可选的地址/控制域 + 1~2 字节协议域。
func stripPPP(b []byte) (uint16, []byte, bool) {
	if len(b) < 2 {
		return 0, nil, false
	}
	off := 0
	if b[0] == 0xff && b[1] == 0x03 {
		off = 2
	}
	if len(b) <= off {
		return 0, nil, false
	}
	var proto uint16
	if b[off]&0x01 != 0 { // 单字节协议域（压缩）
		proto = uint16(b[off])
		off++
	} else {
		if len(b) < off+2 {
			return 0, nil, false
		}
		proto = binary.BigEndian.Uint16(b[off : off+2])
		off += 2
	}
	switch proto {
	case 0x0021:
		return etIPv4, b[off:], true
	case 0x0057:
		return etIPv6, b[off:], true
	}
	// LCP/PAP/CHAP/IPCP 等控制协议不承载 IP，交给上层按"未解出"处理
	return 0, nil, false
}

// stripRadiotap 剥掉 radiotap 头（长度位于偏移 2，小端 u16）。
func stripRadiotap(b []byte) ([]byte, bool) {
	if len(b) < 4 {
		return nil, false
	}
	n := int(binary.LittleEndian.Uint16(b[2:4]))
	if n < 8 || n > len(b) {
		return nil, false
	}
	return b[n:], true
}

// stripPrismAVS 剥掉 Prism / AVS 头（长度位于偏移 4，小端 u32）。
func stripPrismAVS(b []byte) ([]byte, bool) {
	if len(b) < 8 {
		return nil, false
	}
	n := int(binary.LittleEndian.Uint32(b[4:8]))
	if n < 8 || n > len(b) {
		return nil, false
	}
	return b[n:], true
}

// stripDot11 解析 802.11 头：数据帧走 LLC/SNAP 取 EtherType，
// 管理帧没有网络层，只取信标 / 探测响应里的 SSID 作展示。
func stripDot11(p *pkt, b []byte) (uint16, []byte, bool) {
	if len(b) < 24 {
		return 0, nil, false
	}
	fc := binary.LittleEndian.Uint16(b[0:2])
	// 基本头 addr1/addr2 已知，先按 ToDS/FromDS 还原出真实收发方
	p.setDstMAC(b[4:10])
	p.setSrcMAC(b[10:16])
	toDS, fromDS := fc&0x0100 != 0, fc&0x0200 != 0
	switch {
	case toDS && fromDS:
		if len(b) >= 28 { // WDS：addr3=DA，addr4=SA
			p.setDstMAC(b[16:22])
			p.setSrcMAC(b[22:28])
		}
	case toDS: // addr3=DA
		p.setDstMAC(b[16:22])
	case fromDS: // addr3=SA
		p.setSrcMAC(b[16:22])
	}
	if (fc>>2)&3 != dot11TypeData {
		if p.wantInfo {
			p.info = dot11Info(fc, b)
		}
		return 0, nil, false
	}
	h := dot11DataHeaderLen(fc)
	if len(b) < h+8 {
		return 0, nil, false
	}
	llc := b[h:]
	// LLC/SNAP: AA AA 03 00 00 00 <ethertype>
	if llc[0] != 0xaa || llc[1] != 0xaa || llc[2] != 0x03 ||
		llc[3] != 0x00 || llc[4] != 0x00 || llc[5] != 0x00 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint16(llc[6:8]), llc[8:], true
}

// dot11DataHeaderLen 返回数据帧 MAC 头的长度。
func dot11DataHeaderLen(fc uint16) int {
	n := 24
	if fc&0x0300 == 0x0300 { // toDS 与 fromDS 同时置位 → 含 addr4
		n += 6
	}
	if (fc>>4)&0x08 != 0 { // QoS 子类型
		n += 2
	}
	if fc&0x8000 != 0 { // Order → HT Control
		n += 4
	}
	return n
}

// dot11Info 为 802.11 管理帧生成信息摘要（信标与探测帧带 SSID）。
func dot11Info(fc uint16, b []byte) string {
	if (fc>>2)&3 != dot11TypeMgmt {
		return ""
	}
	sub := (fc >> 4) & 0x0f
	body := b[24:]
	switch sub {
	case dot11SubBeacon, dot11SubProbeR:
		if len(body) < 12 {
			return ""
		}
		return i18n.Tf("net.info.beacon", ssidText(ieValue(body[12:], 0)))
	case dot11SubProbe:
		return i18n.Tf("net.info.probe_req", ssidText(ieValue(body, 0)))
	}
	return ""
}

// ---------------------------------------------------------------------------
// 网络层
// ---------------------------------------------------------------------------

// decodeNet 按 EtherType 分发到网络层解析。
func decodeNet(p *pkt, et uint16, b []byte) {
	switch et {
	case etIPv4:
		decodeIPv4(p, b)
	case etIPv6:
		decodeIPv6(p, b)
	case etARP, etRARP:
		decodeARP(p, b)
	case etEAPOL:
		p.l3 = "EAPOL"
	case etMPLS, etMPLSMcast:
		decodeMPLS(p, b)
	case etPPPoESess:
		decodePPPoE(p, b)
	case etPPPoEDis:
		p.l3 = "PPPoE"
	case etLLDP:
		p.l3 = "LLDP"
	case etSlow:
		p.l3 = "LACP"
	case etMACsec:
		p.l3 = "MACsec"
	case etFCoE:
		p.l3 = "FCoE"
	case etCDP:
		p.l3 = "CDP"
	case 0:
		// 链路层没解出 EtherType
	default:
		p.l3 = i18n.T("net.proto.other")
		if p.wantInfo {
			p.info = fmt.Sprintf("EtherType 0x%04x", et)
		}
	}
}

// noteFrag 记录 IP 分片信息（offset 以 8 字节为单位，more 为 MF 标志）。
//
// 只接受 MF 与 DF 两个标志位，其余位（含保留位）在详细视图里按位展示。
func (p *pkt) noteFrag(id uint32, flags uint16, offset uint16, more bool) {
	p.fragID = id
	p.fragOff = offset
	p.fragMore = more
	p.fragDF = flags&0x4000 != 0
	p.isFrag = offset != 0 || more
}

// decodeIPv4 解析 IPv4 头并继续解析传输层。
func decodeIPv4(p *pkt, b []byte) {
	p.l3 = "IPv4"
	p.ipVer = 4
	if len(b) < 20 {
		return
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return
	}
	frag := binary.BigEndian.Uint16(b[6:8])
	p.srcIP, p.dstIP = net.IP(b[12:16]), net.IP(b[16:20])
	p.src, p.dst = p.srcIP.String(), p.dstIP.String()
	p.noteFrag(uint32(binary.BigEndian.Uint16(b[4:6])), frag, frag&0x1fff, frag&0x2000 != 0)
	if n := int(binary.BigEndian.Uint16(b[2:4])) - ihl; n > 0 {
		p.fragSize = n
	}
	if p.verbose {
		p.ipIHL = ihl
		p.ipTOS = b[1]
		p.ipLen = int(binary.BigEndian.Uint16(b[2:4]))
		p.ipID = binary.BigEndian.Uint16(b[4:6])
		p.ipTTL = b[8]
		p.ipProto = b[9]
		p.ipCksum = binary.BigEndian.Uint16(b[10:12])
	}

	// 非首片没有传输层头，只统计到网络层
	if p.fragOff != 0 {
		if p.wantInfo {
			p.info = i18n.Tf("net.info.ipv4_frag", p.fragOff)
		}
		return
	}
	decodeL4(p, b[9], b[ihl:])
}

// decodeIPv6 解析 IPv6 固定头，逐个跳过扩展头后解析传输层。
func decodeIPv6(p *pkt, b []byte) {
	p.l3 = "IPv6"
	p.ipVer = 6
	if len(b) < 40 {
		return
	}
	p.srcIP, p.dstIP = net.IP(b[8:24]), net.IP(b[24:40])
	p.src, p.dst = p.srcIP.String(), p.dstIP.String()
	if p.verbose {
		p.ipIHL = 40
		p.ipFlow = binary.BigEndian.Uint32(b[:4]) & 0x000fffff
		p.ipTOS = (b[0]<<4 | b[1]>>4) & 0xff // Traffic Class
		p.ipLen = int(binary.BigEndian.Uint16(b[4:6]))
		p.ipProto = b[6]
		p.ipTTL = b[7] // Hop Limit
	}

	off := 40
	nh := b[6]
	// 扩展头：hop-by-hop(0) / routing(43) / fragment(44) / dest opts(60) / AH(51)
	for i := 0; i < 8; i++ {
		switch nh {
		case 0, 43, 60:
			if len(b) < off+2 {
				return
			}
			next := b[off]
			n := (int(b[off+1]) + 1) * 8
			if len(b) < off+n {
				return
			}
			nh, off = next, off+n
		case 44: // 分片头
			if len(b) < off+8 {
				return
			}
			next := b[off]
			fragField := binary.BigEndian.Uint16(b[off+2 : off+4])
			fragOff := fragField >> 3
			p.noteFrag(binary.BigEndian.Uint32(b[off+4:off+8]), fragField, fragOff, b[off+3]&0x01 != 0)
			p.fragSize = len(b) - off - 8
			if fragOff != 0 {
				if p.wantInfo {
					p.info = i18n.Tf("net.info.ipv6_frag", fragOff)
				}
				return
			}
			nh, off = next, off+8
		case 51: // AH
			if len(b) < off+2 {
				return
			}
			next := b[off]
			n := (int(b[off+1]) + 2) * 4
			if len(b) < off+n {
				return
			}
			nh, off = next, off+n
		default:
			decodeL4(p, nh, b[off:])
			return
		}
	}
}

// decodeL4 解析传输层头。
func decodeL4(p *pkt, proto byte, b []byte) {
	switch proto {
	case 6:
		decodeTCP(p, b)
	case 17:
		decodeUDP(p, b)
	case 1:
		p.l4 = "ICMP"
		p.payload = b
		if p.verbose && len(b) >= 4 {
			p.icmpType, p.icmpCode = b[0], b[1]
			p.icmpCksum = binary.BigEndian.Uint16(b[2:4])
			if len(b) >= 8 {
				p.icmpID = binary.BigEndian.Uint16(b[4:6])
				p.icmpSeq = binary.BigEndian.Uint16(b[6:8])
			}
		}
		if p.wantInfo {
			p.info = icmpInfo(false, b)
		}
	case 58:
		p.l4 = "ICMPv6"
		p.payload = b
		if p.verbose && len(b) >= 4 {
			p.icmpType, p.icmpCode = b[0], b[1]
			p.icmpCksum = binary.BigEndian.Uint16(b[2:4])
		}
		if p.wantInfo {
			p.info = icmpInfo(true, b)
		}
	case 2:
		p.l4 = "IGMP"
	case 47:
		p.l4 = "GRE"
	case 50:
		p.l4 = "ESP"
	case 51:
		p.l4 = "AH"
	case 89:
		p.l4 = "OSPF"
	case 88:
		p.l4 = "EIGRP"
	case 103:
		p.l4 = "PIM"
	case 112:
		p.l4 = "VRRP"
	case 132:
		p.l4 = "SCTP"
	default:
		p.l4 = i18n.T("net.proto.other")
		if p.wantInfo {
			p.info = "IP protocol " + strconv.Itoa(int(proto))
		}
	}
}

// decodeTCP 解析 TCP 头（20 字节起，可能带选项）。
func decodeTCP(p *pkt, b []byte) {
	p.l4 = "TCP"
	if len(b) < 20 {
		return
	}
	p.srcPort = binary.BigEndian.Uint16(b[0:2])
	p.dstPort = binary.BigEndian.Uint16(b[2:4])
	h := int(b[12]>>4) * 4
	if h < 20 {
		return
	}
	p.flags = b[13]
	p.seq = binary.BigEndian.Uint32(b[4:8])
	p.ack = binary.BigEndian.Uint32(b[8:12])
	p.win = binary.BigEndian.Uint16(b[14:16])
	if len(b) < h {
		return
	}
	if p.verbose {
		p.tcpHdrLen = h
		p.tcpCksum = binary.BigEndian.Uint16(b[16:18])
		p.tcpUrgent = binary.BigEndian.Uint16(b[18:20])
		if h > 20 {
			p.tcpOpts = b[20:h]
		}
	}
	p.payload = b[h:]
}

// decodeUDP 解析 UDP 头。
func decodeUDP(p *pkt, b []byte) {
	p.l4 = "UDP"
	if len(b) < 8 {
		return
	}
	p.srcPort = binary.BigEndian.Uint16(b[0:2])
	p.dstPort = binary.BigEndian.Uint16(b[2:4])
	n := int(binary.BigEndian.Uint16(b[4:6]))
	end := 8 + n
	if n < 8 || end > len(b) {
		end = len(b) // 长度字段异常或被截断，按实际长度处理
	}
	if p.verbose {
		p.udpLen = n
		if len(b) >= 8 {
			p.udpCksum = binary.BigEndian.Uint16(b[6:8])
		}
	}
	p.payload = b[8:end]
}

// decodeARP 解析 ARP/RARP，记录发送方 IP 与 MAC（用于 ARP 冲突检测）。
func decodeARP(p *pkt, b []byte) {
	p.l3 = "ARP"
	if len(b) < 28 {
		return
	}
	p.arpOp = binary.BigEndian.Uint16(b[6:8])
	senderIP := net.IP(b[14:18])
	targetIP := net.IP(b[24:28])
	p.arpSenderIP = senderIP.String()
	p.arpTgtIP = targetIP.String()
	p.src, p.dst = p.arpSenderIP, p.arpTgtIP
	p.setSrcMAC(b[8:14])
	p.setDstMAC(b[18:24])
	if p.verbose {
		p.arpHwType = binary.BigEndian.Uint16(b[0:2])
		p.arpProtoType = binary.BigEndian.Uint16(b[2:4])
		p.arpHwSize, p.arpProtoSize = b[4], b[5]
		copy(p.arpTgtMACRaw[:], b[18:24])
	}
	if !p.wantInfo {
		return
	}
	switch p.arpOp {
	case 1:
		p.info = i18n.Tf("net.info.arp_req", p.arpTgtIP, p.arpSenderIP)
	case 2:
		p.info = i18n.Tf("net.info.arp_rep", p.arpSenderIP, p.srcMAC())
	default:
		p.info = fmt.Sprintf("op=%d", p.arpOp)
	}
}

// decodeMPLS 剥掉 MPLS 标签栈，按首字节版本号继续解析 IP。
func decodeMPLS(p *pkt, b []byte) {
	p.l3 = "MPLS"
	off := 0
	for i := 0; i < 8 && off+4 <= len(b); i++ {
		bos := b[off+2]&0x01 != 0
		off += 4
		if bos {
			break
		}
	}
	if off >= len(b) {
		return
	}
	switch b[off] >> 4 {
	case 4:
		decodeIPv4(p, b[off:])
	case 6:
		decodeIPv6(p, b[off:])
	}
}

// decodePPPoE 剥掉 PPPoE 会话头（6 字节）后按 PPP 协议域继续解析。
// PPPoE 只是封装，统计上按其承载的 IPv4/IPv6 计数。
func decodePPPoE(p *pkt, b []byte) {
	if len(b) < 6 {
		p.l3 = "PPPoE"
		return
	}
	et, rest, ok := stripPPP(b[6:])
	if !ok {
		p.l3 = "PPPoE"
		return
	}
	decodeNet(p, et, rest)
}

// ---------------------------------------------------------------------------
// 摘要信息
// ---------------------------------------------------------------------------

// fillInfo 在应用层没有给出摘要时，按传输层 / 网络层补一个。
// 仅列表模式需要（wantInfo），报告模式下整段跳过。
func fillInfo(p *pkt) {
	if !p.wantInfo || p.info != "" {
		return
	}
	switch {
	case p.l4 == "TCP":
		if len(p.payload) > 0 {
			p.info = "[" + tcpFlagsStr(p.flags) + "] len=" + strconv.Itoa(len(p.payload))
		} else {
			p.info = "[" + tcpFlagsStr(p.flags) + "]"
		}
	case p.l4 == "UDP":
		p.info = "len=" + strconv.Itoa(len(p.payload))
	}
}

// tcpFlagsStr 把 TCP 标志位渲染成 "SYN,ACK" 这样的字符串。
// 结果只与 8 个标志位有关（256 种），用查表避免每帧拼接与 Join 分配。
//
// 位序按高位在前（CWR,ECE,URG,ACK,PSH,RST,SYN,FIN），与 tshark 的展示一致。
var tcpFlagsNames = [8]string{"CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN"}

// tcpFlagMask 与 tcpFlagsNames 同序的位掩码。
var tcpFlagMask = [8]uint8{0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01}

func tcpFlagsStr(f uint8) string {
	// 常见组合优先（顺序必须与 tcpFlagsNames 的位序一致：ACK 在 SYN/PSH 之前）
	switch f {
	case 0x02:
		return "SYN"
	case 0x12:
		return "ACK,SYN"
	case 0x10:
		return "ACK"
	case 0x18:
		return "ACK,PSH"
	case 0x04:
		return "RST"
	case 0x11:
		return "ACK,FIN"
	case 0x03:
		return "SYN,FIN"
	case 0x00:
		return "none"
	}
	var sb strings.Builder
	for i, name := range tcpFlagsNames {
		if f&tcpFlagMask[i] == 0 {
			continue
		}
		if sb.Len() > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(name)
	}
	if sb.Len() == 0 {
		return "none"
	}
	return sb.String()
}

// icmpInfo 生成 ICMP / ICMPv6 的信息摘要。
func icmpInfo(v6 bool, b []byte) string {
	if len(b) < 2 {
		return ""
	}
	typ, code := b[0], b[1]
	if v6 {
		switch typ {
		case 128:
			return echoInfo("net.info.echo_req", b)
		case 129:
			return echoInfo("net.info.echo_rep", b)
		case 135:
			if len(b) >= 24 {
				return i18n.Tf("net.info.nd_ns", net.IP(b[8:24]).String())
			}
		case 136:
			if len(b) >= 24 {
				return i18n.Tf("net.info.nd_na", net.IP(b[8:24]).String())
			}
		case 133, 134:
			key := "net.info.nd_rs"
			if typ == 134 {
				key = "net.info.nd_ra"
			}
			return i18n.T(key)
		}
		return i18n.Tf("net.info.icmp", typ, code)
	}
	switch typ {
	case 0:
		return echoInfo("net.info.echo_rep", b)
	case 3:
		return i18n.Tf("net.info.icmp_unreach", code)
	case 8:
		return echoInfo("net.info.echo_req", b)
	case 11:
		return i18n.Tf("net.info.icmp_ttl", code)
	}
	return i18n.Tf("net.info.icmp", typ, code)
}

// echoInfo 取出 echo 请求/响应的 id 与 seq。
func echoInfo(key string, b []byte) string {
	if len(b) < 8 {
		return i18n.T(key)
	}
	id := binary.BigEndian.Uint16(b[4:6])
	seq := binary.BigEndian.Uint16(b[6:8])
	return i18n.Tf(key, id, seq)
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

// macStr 把 6 字节 MAC 渲染成 aa:bb:cc:dd:ee:ff。
//
// 手工拼十六进制而不是走 fmt.Sprintf：MAC 在每帧都会被解码到，
// fmt 的反射与参数装箱在这里是明显的热点。
func macStr(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	const hexDigits = "0123456789abcdef"
	var out [17]byte
	j := 0
	for i := 0; i < 6; i++ {
		if i > 0 {
			out[j] = ':'
			j++
		}
		out[j] = hexDigits[b[i]>>4]
		out[j+1] = hexDigits[b[i]&0x0f]
		j += 2
	}
	return string(out[:])
}

// ssidText 把 SSID 渲染成可读文本：可打印 ASCII 原样显示，否则退化为十六进制。
func ssidText(s []byte) string {
	if len(s) == 0 {
		return "<unknown>"
	}
	for _, b := range s {
		if b < 0x20 || b > 0x7e {
			return fmt.Sprintf("%x", s)
		}
	}
	return string(s)
}

// ieValue 返回第一个 tag 匹配的信息元素值；没有匹配返回 nil。
func ieValue(ies []byte, tag byte) []byte {
	for i := 0; i+2 <= len(ies); {
		id := ies[i]
		n := int(ies[i+1])
		if i+2+n > len(ies) {
			return nil
		}
		if id == tag {
			return ies[i+2 : i+2+n]
		}
		i += 2 + n
	}
	return nil
}
