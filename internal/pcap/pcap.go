// Package pcap 读取抓包容器（pcap / pcapng），把文件拆成带时间戳的链路层帧。
//
// 本包只负责"读容器"：识别魔数、按字节序解析记录头、算时间戳、取出链路层帧，
// 不关心帧里装的是什么协议。上层按 Record.LinkType 自行解码：
//
//	hashdump 拿它提取 WPA/WPA2 握手（-m 22000）
//	net      拿它做协议统计、会话与安全分析
//
// 支持范围：
//   - pcap（libpcap，含大小端与微秒/纳秒两种时间戳精度）
//   - pcapng（Section Header / Interface Description / Enhanced & Simple Packet 块，
//     支持 if_tsresol、if_tsoffset 与多 section、多接口）
//   - 尾部截断（抓包在写入过程中被中断）按 EOF 处理，已解析的帧仍然有效
package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// 解析上限：snaplen 通常不超过 65535，块长度也不该超过几 MB。
// 越界的长度字段一律视为结构损坏，避免被损坏文件诱导出巨额分配。
const (
	MaxPacket = 1 << 20 // 单帧 1 MiB
	MaxBlock  = 1 << 24 // 单块 16 MiB
)

// pcap 魔数：同一常量在文件里可能按小端或大端存放，这里给出"按小端解读"的两种取值。
const (
	pcapMagicMicro = 0xa1b2c3d4 // 微秒时间戳
	pcapMagicNano  = 0xa1b23c4d // 纳秒时间戳
)

// pcapng 块类型。
const (
	blockSHB = 0x0a0d0d0a // Section Header Block
	blockIDB = 0x00000001 // Interface Description Block
	blockSPB = 0x00000003 // Simple Packet Block
	blockEPB = 0x00000006 // Enhanced Packet Block

	// byteOrderMagic 是 SHB 中的字节序标识（0x1A2B3C4D）。
	byteOrderMagic = 0x1a2b3c4d
)

// pcapng Interface Description Block 的选项码。
const (
	optIfName    = 2
	optIfTsResol = 9
	optIfTsOffst = 14
)

// ErrNotCapture 表示输入不是受支持的抓包容器（pcap/pcapng）。
var ErrNotCapture = errors.New("not a pcap/pcapng capture")

// Format 容器格式。
type Format byte

// 容器格式取值。
const (
	FormatPCAP Format = iota
	FormatPCAPNG
)

// String 返回格式名（不本地化，属技术标识）。
func (f Format) String() string {
	if f == FormatPCAPNG {
		return "pcapng"
	}
	return "pcap"
}

// Info 抓包容器的元信息，在 Open 时即可读到（pcapng 的接口数随扫描递增）。
type Info struct {
	Format     Format
	BigEndian  bool   // 字节序；pcapng 为当前 section 的字节序
	Version    string // 容器版本，如 "2.4" / "1.0"
	SnapLen    uint32 // 快照长度（pcap 全局头 / IDB，取最后见到的非零值）
	Nano       bool   // pcap 纳秒时间戳（pcapng 按 if_tsresol，见 TsResol）
	Interfaces int    // pcapng 接口数
	TsResol    uint64 // pcapng 时间戳分母（每秒的 tick 数，默认 1e6 微秒）
	TsOffset   int64  // pcapng 时间戳偏移（秒，默认 0）
}

// Record 一条链路层帧。
type Record struct {
	Index    int       // 序号，从 1 开始
	Time     time.Time // 时间戳；无法确定时为零值
	LinkType uint32    // 链路类型（pcap 全局头 / pcapng 接口的 linktype）
	// Data 指向 Reader 内部的复用缓冲，只在下一次 Next 之前有效。
	// 调用方若要跨帧保留内容，必须自行拷贝。
	Data    []byte
	OrigLen uint32 // 线上原始长度，总是 >= len(Data)
	// Ref 是这一帧在文件中的位置，供之后用 FrameData 按需重读
	//（交互式浏览建索引用，避免把整包内容常驻内存）。
	Ref FrameRef
}

// FrameRef 定位一帧在文件中的位置，用于"扫一遍建索引、之后按需重读"。
//
// 大抓包的交互式浏览用它替代"把整包内容拷进内存"：索引只有几十字节一帧，
// 内存占用与文件大小无关；选中某帧时再用 FrameData 读回那一条。
type FrameRef struct {
	Offset    int64  // 记录头（pcap）/ 块头（pcapng）的文件偏移
	Format    Format // 容器格式
	BigEndian bool   // 大端字节序（pcap 看全局头，pcapng 看该块所在 section）
	LinkType  uint32 // 链路类型
	OrigLen   uint32 // 线上原始长度
}

// FrameData 按 ref 从文件中重读一帧的原始字节。
//
// 返回的是新分配的切片，调用方可安全长期持有（这正是它与 Next 的区别）。
// src 必须与最初 Open 时使用的是同一个底层文件。
func FrameData(src io.ReaderAt, ref FrameRef) ([]byte, error) {
	if ref.Format == FormatPCAPNG {
		return frameDataNG(src, ref)
	}
	return frameDataPCAP(src, ref)
}

// pcapGlobalHeaderSize 是 pcap 全局头的长度，首条记录从它之后开始。
const pcapGlobalHeaderSize = 24

// frameDataPCAP 重读 pcap 记录：16 字节记录头 + 数据。
//
// 字节序取自 ref（由扫描时的全局头判定）——记录头里没有魔数可判。
func frameDataPCAP(src io.ReaderAt, ref FrameRef) ([]byte, error) {
	if ref.Offset < pcapGlobalHeaderSize {
		return nil, fmt.Errorf("pcap record offset %d points inside global header", ref.Offset)
	}
	var rh [16]byte
	if _, err := src.ReadAt(rh[:], ref.Offset); err != nil {
		return nil, fmt.Errorf("pcap record header at %d: %w", ref.Offset, err)
	}
	order := binary.ByteOrder(binary.LittleEndian)
	if ref.BigEndian {
		order = binary.BigEndian
	}
	incl := int64(order.Uint32(rh[8:12]))
	if incl == 0 {
		return nil, nil
	}
	if incl > MaxPacket {
		return nil, fmt.Errorf("packet length %d exceeds limit", incl)
	}
	data := make([]byte, incl)
	if _, err := src.ReadAt(data, ref.Offset+16); err != nil {
		return nil, fmt.Errorf("pcap record data at %d: %w", ref.Offset, err)
	}
	return data, nil
}

// frameDataNG 重读 pcapng 的 EPB / SPB 块。
func frameDataNG(src io.ReaderAt, ref FrameRef) ([]byte, error) {
	var head [12]byte
	if _, err := src.ReadAt(head[:], ref.Offset); err != nil {
		return nil, fmt.Errorf("pcapng block header at %d: %w", ref.Offset, err)
	}
	var order binary.ByteOrder = binary.LittleEndian
	if ref.BigEndian {
		order = binary.BigEndian
	}
	blen := int64(order.Uint32(head[4:8]))
	if blen < 12 || blen > MaxBlock {
		return nil, fmt.Errorf("pcapng bad block length %d", blen)
	}
	blk := make([]byte, blen)
	if _, err := src.ReadAt(blk, ref.Offset); err != nil {
		return nil, fmt.Errorf("pcapng block at %d: %w", ref.Offset, err)
	}
	body := blk[8 : blen-4]
	switch order.Uint32(head[0:4]) {
	case blockEPB:
		// 块体: iface(4) ts_high(4) ts_low(4) cap_len(4) orig_len(4) data..
		if len(body) < 20 {
			return nil, fmt.Errorf("pcapng EPB too short at %d", ref.Offset)
		}
		capLen := int64(order.Uint32(body[12:16]))
		if capLen > int64(len(body)-20) {
			capLen = int64(len(body) - 20)
		}
		out := make([]byte, capLen)
		copy(out, body[20:20+capLen])
		return out, nil
	case blockSPB:
		// 块体: orig_len(4) data..
		if len(body) < 4 {
			return nil, fmt.Errorf("pcapng SPB too short at %d", ref.Offset)
		}
		n := int64(order.Uint32(body[0:4]))
		if n > int64(len(body)-4) {
			n = int64(len(body) - 4)
		}
		out := make([]byte, n)
		copy(out, body[4:4+n])
		return out, nil
	}
	return nil, fmt.Errorf("pcapng block at %d carries no frame", ref.Offset)
}

// Read 按 fn 逐帧回调整个抓包。fn 返回错误即中止并原样返回。
func Read(f io.ReaderAt, size int64, fn func(Record) error) error {
	r, err := Open(f, size)
	if err != nil {
		return err
	}
	for {
		rec, err := r.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
}

// IsPCAP 判断是否为 pcap 文件（兼容两种字节序与两种时间戳精度）。
func IsPCAP(m []byte) bool {
	if len(m) < 4 {
		return false
	}
	v := binary.LittleEndian.Uint32(m[:4])
	return v == pcapMagicMicro || v == bswap32(pcapMagicMicro) ||
		v == pcapMagicNano || v == bswap32(pcapMagicNano)
}

// IsPCAPNG 判断是否为 pcapng 文件（魔数为字节回文，与字节序无关）。
func IsPCAPNG(m []byte) bool {
	return len(m) >= 4 && binary.LittleEndian.Uint32(m[:4]) == blockSHB
}

// IsCapture 判断前若干字节是否像一个抓包容器（供调用方做类型识别）。
func IsCapture(m []byte) bool { return IsPCAP(m) || IsPCAPNG(m) }

// bswap32 反转 32 位整数的字节序。
func bswap32(v uint32) uint32 {
	return v<<24 | (v&0xff00)<<8 | (v>>8)&0xff00 | v>>24
}

// isTruncated 判断错误是否表示"读到了文件末尾"（含只读部分的情况）。
func isTruncated(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
