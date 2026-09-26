// pcap / pcapng 抓包容器解析。
//
// 对应 hcxtools 中 hcxpcapngtool 的"读容器"部分：把抓包拆成一条条链路层帧，
// 交给 wifi.go 还原 WPA/WPA2 的 PMKID 与四次握手哈希。
//
// 支持范围：
//   - pcap（libpcap，含大小端与微秒/纳秒两种时间戳精度）
//   - pcapng（Section Header / Interface Description / Enhanced & Simple Packet 块）
//   - 链路类型 802.11(105) / radiotap(127) / Prism(119) / AVS(163)
package hashdump

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"gyhost/internal/i18n"
)

// 链路类型（pcap 的 network 字段 / pcapng 的 IDB linktype）。
const (
	linkTypeIEEE80211    = 105
	linkTypePrism        = 119
	linkTypeRadiotap     = 127
	linkTypeIEEE80211AVS = 163
)

// pcap 魔数：同一常量在文件里可能按小端或大端存放，这里给出"按小端解读"的两种取值。
const (
	pcapMagicMicro = 0xa1b2c3d4 // 微秒时间戳
	pcapMagicNano  = 0xa1b23c4d // 纳秒时间戳
)

// pcapng 块类型。
const (
	pcapngBlockSHB = 0x0a0d0d0a // Section Header Block
	pcapngBlockIDB = 0x00000001 // Interface Description Block
	pcapngBlockSPB = 0x00000003 // Simple Packet Block
	pcapngBlockEPB = 0x00000006 // Enhanced Packet Block

	// pcapngByteOrder 是 SHB 中的字节序标识（0x1A2B3C4D）。
	pcapngByteOrder = 0x1a2b3c4d
)

// 解析上限：snaplen 通常不超过 65535，块长度也不该超过几 MB。
// 越界的长度字段一律视为结构损坏，避免被损坏文件诱导出巨额分配。
const (
	maxPacket = 1 << 20 // 单帧 1 MiB
	maxBlock  = 1 << 24 // 单块 16 MiB
)

// extractCapture 解析 pcap/pcapng 抓包并提取 WPA/WPA2 哈希。
func extractCapture(f io.ReaderAt, size int64, path string) (*Result, error) {
	c := newCollector(path)
	r := bufio.NewReaderSize(io.NewSectionReader(f, 0, size), 1<<16)

	head, err := r.Peek(4)
	if err != nil && len(head) < 4 {
		return nil, errors.New(i18n.Tf("hashdump.err.unrecognized", path))
	}

	switch {
	case isPCAPNGMagic(head):
		err = scanPCAPNG(r, c)
	case isPCAPMagic(head):
		err = scanPCAP(r, c)
	default:
		return nil, errors.New(i18n.Tf("hashdump.err.unrecognized", path))
	}
	if err != nil {
		return nil, errors.New(i18n.Tf("hashdump.err.bad_capture", err))
	}
	return c.result(), nil
}

// isPCAPMagic 判断是否为 pcap 文件（兼容两种字节序与两种时间戳精度）。
func isPCAPMagic(m []byte) bool {
	if len(m) < 4 {
		return false
	}
	v := binary.LittleEndian.Uint32(m[:4])
	return v == pcapMagicMicro || v == bswap32(pcapMagicMicro) ||
		v == pcapMagicNano || v == bswap32(pcapMagicNano)
}

// isPCAPNGMagic 判断是否为 pcapng 文件（魔数为字节回文，与字节序无关）。
func isPCAPNGMagic(m []byte) bool {
	return len(m) >= 4 && binary.LittleEndian.Uint32(m[:4]) == pcapngBlockSHB
}

// bswap32 反转 32 位整数的字节序。
func bswap32(v uint32) uint32 {
	return v<<24 | (v&0xff00)<<8 | (v>>8)&0xff00 | v>>24
}

// pcapByteOrder 由魔数判定文件字节序；无法识别返回 nil。
func pcapByteOrder(m []byte) binary.ByteOrder {
	if len(m) < 4 {
		return nil
	}
	switch {
	case m[0] == 0xd4 && m[1] == 0xc3, m[0] == 0x4d && m[1] == 0x3c:
		return binary.LittleEndian // d4 c3 b2 a1 / 4d 3c b2 a1
	case m[0] == 0xa1 && m[1] == 0xb2:
		return binary.BigEndian // a1 b2 c3 d4 / a1 b2 3c 4d
	}
	return nil
}

// scanPCAP 顺序读取 pcap：全局头 24 字节，之后每条记录为 16 字节头 + 数据。
//
// 尾部截断（抓包在写入过程中被中断）按 EOF 处理，已解析的帧仍然有效。
func scanPCAP(r *bufio.Reader, c *collector) error {
	var gh [24]byte
	if _, err := io.ReadFull(r, gh[:]); err != nil {
		return errors.New("pcap global header truncated")
	}
	order := pcapByteOrder(gh[:4])
	if order == nil {
		return errors.New("pcap magic not recognized")
	}
	linkType := order.Uint32(gh[20:24])

	var rh [16]byte
	for {
		if _, err := io.ReadFull(r, rh[:]); err != nil {
			if isTruncated(err) {
				return nil
			}
			return err
		}
		incl := int64(order.Uint32(rh[8:12]))
		if incl == 0 {
			continue
		}
		if incl > maxPacket {
			return fmt.Errorf("packet length %d exceeds limit", incl)
		}
		pkt := make([]byte, incl)
		if _, err := io.ReadFull(r, pkt); err != nil {
			if isTruncated(err) {
				return nil
			}
			return err
		}
		c.feed(linkType, pkt)
	}
}

// scanPCAPNG 顺序读取 pcapng 块。
//
// 关注四类块：SHB（决定字节序）、IDB（登记接口的 linktype）、
// EPB / SPB（承载数据）。其余块（注释、统计等）直接跳过。
func scanPCAPNG(r *bufio.Reader, c *collector) error {
	var (
		order     binary.ByteOrder
		linkTypes = map[uint32]uint32{} // 接口号 → linktype
		nextID    uint32
		buf       []byte
	)

	for {
		// 先读 12 字节：块类型(4) + 块总长(4) + 块体前 4 字节。
		// 对 SHB 而言这 4 字节正是字节序标识。
		var head [12]byte
		if _, err := io.ReadFull(r, head[:]); err != nil {
			if isTruncated(err) {
				return nil
			}
			return err
		}

		if order == nil {
			if binary.LittleEndian.Uint32(head[0:4]) != pcapngBlockSHB {
				return errors.New("pcapng section header block missing")
			}
			switch binary.LittleEndian.Uint32(head[8:12]) {
			case pcapngByteOrder:
				order = binary.LittleEndian
			case bswap32(pcapngByteOrder):
				order = binary.BigEndian
			default:
				return errors.New("pcapng bad byte-order magic")
			}
		}

		bt := order.Uint32(head[0:4])
		blen := int64(order.Uint32(head[4:8]))
		if blen < 12 || blen > maxBlock {
			return fmt.Errorf("pcapng bad block length %d", blen)
		}

		if int64(cap(buf)) < blen {
			buf = make([]byte, blen)
		}
		block := buf[:blen]
		copy(block[:12], head[:])
		if _, err := io.ReadFull(r, block[12:]); err != nil {
			if isTruncated(err) {
				return nil
			}
			return err
		}
		// 去掉 8 字节块头与尾部 4 字节重复长度，得到块体。
		body := block[8 : blen-4]

		switch bt {
		case pcapngBlockSHB:
			// 新 section：字节序可能改变，接口表随之失效。
			linkTypes = map[uint32]uint32{}
			nextID = 0

		case pcapngBlockIDB:
			if len(body) >= 8 {
				linkTypes[nextID] = uint32(order.Uint16(body[0:2]))
				nextID++
			}

		case pcapngBlockEPB:
			// 块体: iface(4) ts_high(4) ts_low(4) cap_len(4) orig_len(4) data..
			if len(body) < 20 {
				continue
			}
			iface := order.Uint32(body[0:4])
			capLen := int64(order.Uint32(body[12:16]))
			if capLen < 0 || capLen > int64(len(body)-20) {
				capLen = int64(len(body) - 20)
			}
			c.feed(linkTypes[iface], body[20:20+capLen])

		case pcapngBlockSPB:
			// 块体: orig_len(4) data..
			if len(body) < 4 {
				continue
			}
			data := body[4:]
			if n := int64(order.Uint32(body[0:4])); n < int64(len(data)) {
				data = data[:n]
			}
			c.feed(linkTypes[0], data)
		}
	}
}

// isTruncated 判断错误是否表示"读到了文件末尾"（含只读部分的情况）。
func isTruncated(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
