// OLE2 复合文档（Composite Document File）的最小读取器。
//
// 只实现 Office 文档提取所需的那部分：定位 FAT/miniFAT/目录，按需读出
// 命名流（EncryptionInfo、WordDocument、Workbook 等）。不支持写入、
// 不支持嵌套 storage 的完整遍历（office 的目标流都在根目录下）。
//
// 结构速记（见 [MS-CFB]）：
//
//	头512 字节：扇区大小 1<<30、mini 扇区大小 1<<32、mini 流阈值 @56、
//	DIFAT 109 项 @76
//	扇区 n 的文件偏移 = (n+1)*扇区大小（头占第0 个"扇区"）
//	小于 mini 流阈值的流存放在 mini 流（Root Entry 的流）里，
//	由 miniFAT 索引，mini 扇区大小通常只有 64 字节
package hashdump

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// OLE2 文件魔数。
var magicOLE = []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}

// FAT 链特殊值与防环上限。
const (
	oleEndFat    = 0xFFFFFFFE // ENDOFCHAIN
	oleFreeFat   = 0xFFFFFFFF // FREESECT
	oleDifatFat  = 0xFFFFFFFC // DIFSECT
	oleFatFat    = 0xFFFFFFFD // FATSECT
	oleMaxSector = 1 << 22    // 链遍历上限，防止损坏文件死循环
)

// oleEntry 是目录中的一项。
type oleEntry struct {
	name  string
	typ   byte // 1=storage 2=stream 5=root
	start uint32
	size  uint32
}

// oleFile 是已打开的 OLE 容器。
type oleFile struct {
	r        io.ReaderAt
	size     int64
	sectSize int
	miniSize int
	miniCut  uint32
	fat      []uint32
	miniFat  []uint32
	entries  []oleEntry
	mini     []byte // mini 流容器（Root Entry 的流）
}

// openOLE 解析 OLE 头、FAT 与目录，失败时返回带上下文的错误。
func openOLE(r io.ReaderAt, size int64) (*oleFile, error) {
	if size < 512 {
		return nil, errors.New("ole: file too small")
	}
	hdr := make([]byte, 512)
	if _, err := r.ReadAt(hdr, 0); err != nil {
		return nil, fmt.Errorf("ole: header: %w", err)
	}
	if string(hdr[:8]) != string(magicOLE) {
		return nil, errors.New("ole: not a compound file")
	}

	o := &oleFile{r: r, size: size}
	// @30/@32 存的是 2 的指数（shift）：9 → 512 字节扇区
	sectShift := int(binary.LittleEndian.Uint16(hdr[30:32]))
	miniShift := int(binary.LittleEndian.Uint16(hdr[32:34]))
	if sectShift < 9 || sectShift > 12 {
		return nil, fmt.Errorf("ole: bad sector shift %d", sectShift)
	}
	if miniShift < 6 || miniShift > 8 || miniShift > sectShift {
		return nil, fmt.Errorf("ole: bad mini sector shift %d", miniShift)
	}
	o.sectSize = 1 << sectShift
	o.miniSize = 1 << miniShift
	o.miniCut = binary.LittleEndian.Uint32(hdr[56:60])

	dirStart := binary.LittleEndian.Uint32(hdr[48:52])
	miniStart := binary.LittleEndian.Uint32(hdr[60:64])
	miniNum := int(binary.LittleEndian.Uint32(hdr[64:68]))

	// DIFAT：头里 109 项 + 后续 DIFAT 扇区链
	var difat []uint32
	for i := 0; i < 109; i++ {
		n := binary.LittleEndian.Uint32(hdr[76+4*i : 80+4*i])
		if n == oleFreeFat {
			break
		}
		difat = append(difat, n)
	}
	difNext := binary.LittleEndian.Uint32(hdr[68:72])
	difNum := int(binary.LittleEndian.Uint32(hdr[72:76]))
	perDif := o.sectSize/4 - 1 // 最后一项是下一 DIFAT 扇区号
	for i := 0; i < difNum && difNext < oleEndFat; i++ {
		sec, err := o.sector(difNext)
		if err != nil {
			return nil, err
		}
		for j := 0; j < perDif; j++ {
			n := binary.LittleEndian.Uint32(sec[4*j : 4*j+4])
			if n == oleFreeFat {
				break
			}
			difat = append(difat, n)
		}
		difNext = binary.LittleEndian.Uint32(sec[4*perDif:])
	}
	if len(difat) > oleMaxSector {
		return nil, errors.New("ole: too many FAT sectors")
	}

	// FAT 表
	for _, n := range difat {
		sec, err := o.sector(n)
		if err != nil {
			return nil, err
		}
		for k := 0; k+4 <= len(sec); k += 4 {
			o.fat = append(o.fat, binary.LittleEndian.Uint32(sec[k:k+4]))
		}
	}

	// 目录
	dirData, err := o.chainData(dirStart)
	if err != nil {
		return nil, fmt.Errorf("ole: directory: %w", err)
	}
	for i := 0; i+128 <= len(dirData); i += 128 {
		e := dirData[i : i+128]
		nameLen := int(binary.LittleEndian.Uint16(e[64:66]))
		if nameLen < 2 || nameLen > 128 {
			continue
		}
		name := strings.TrimRight(string(utf16Decode(e[:nameLen-2])), "\x00")
		typ := e[66]
		if typ == 0 || typ > 5 {
			continue
		}
		o.entries = append(o.entries, oleEntry{
			name:  name,
			typ:   typ,
			start: binary.LittleEndian.Uint32(e[116:120]),
			size:  binary.LittleEndian.Uint32(e[120:124]), // v3 只用低32 位
		})
	}

	// mini 流与 miniFAT
	for i := range o.entries {
		if o.entries[i].typ == 5 { // Root Entry
			if o.entries[i].size > 0 && o.entries[i].start < oleEndFat {
				o.mini, err = o.chainData(o.entries[i].start)
				if err != nil {
					return nil, fmt.Errorf("ole: mini stream: %w", err)
				}
				if uint32(len(o.mini)) > o.entries[i].size {
					o.mini = o.mini[:o.entries[i].size]
				}
			}
			break
		}
	}
	if miniStart < oleEndFat && miniNum > 0 {
		data, err := o.chainData(miniStart)
		if err != nil {
			return nil, fmt.Errorf("ole: minifat: %w", err)
		}
		for k := 0; k+4 <= len(data) && len(o.miniFat) < miniNum*o.sectSize/4; k += 4 {
			o.miniFat = append(o.miniFat, binary.LittleEndian.Uint32(data[k:k+4]))
		}
	}
	return o, nil
}

// sector 读出第 n 个扇区（文件偏移 (n+1)*扇区大小）。
func (o *oleFile) sector(n uint32) ([]byte, error) {
	if n >= oleEndFat-1 && n != oleFatFat {
		return nil, fmt.Errorf("ole: bad sector %d", n)
	}
	off := int64(n+1) * int64(o.sectSize)
	if off < 0 || off+int64(o.sectSize) > o.size {
		return nil, fmt.Errorf("ole: sector %d out of range", n)
	}
	buf := make([]byte, o.sectSize)
	if _, err := o.r.ReadAt(buf, off); err != nil {
		return nil, fmt.Errorf("ole: sector %d: %w", n, err)
	}
	return buf, nil
}

// chainData 沿 FAT 链收集扇区数据。
func (o *oleFile) chainData(start uint32) ([]byte, error) {
	var out []byte
	n := start
	for i := 0; i < oleMaxSector; i++ {
		if n >= oleEndFat-1 {
			return out, nil // ENDOFCHAIN / FREESECT
		}
		if int(n) >= len(o.fat) {
			return nil, fmt.Errorf("ole: sector %d not in FAT", n)
		}
		sec, err := o.sector(n)
		if err != nil {
			return nil, err
		}
		out = append(out, sec...)
		n = o.fat[n]
	}
	return nil, errors.New("ole: FAT chain too long")
}

// stream 读出根目录下名为 name 的流。
func (o *oleFile) stream(name string) ([]byte, bool) {
	var e *oleEntry
	for i := range o.entries {
		if o.entries[i].typ == 2 && o.entries[i].name == name {
			e = &o.entries[i]
			break
		}
	}
	if e == nil {
		return nil, false
	}
	if e.size == 0 {
		return []byte{}, true
	}
	// mini 流：miniFAT 索引 mini 扇区，数据放在 mini 流容器里
	if e.size < o.miniCut {
		var out []byte
		n := e.start
		for i := 0; i < oleMaxSector && uint32(len(out)) < e.size; i++ {
			if n >= oleEndFat-1 || int(n) >= len(o.miniFat) {
				break
			}
			off := int(n) * o.miniSize
			if off+o.miniSize > len(o.mini) {
				break
			}
			out = append(out, o.mini[off:off+o.miniSize]...)
			n = o.miniFat[n]
		}
		if uint32(len(out)) < e.size {
			return nil, false // 链断裂或数据不足
		}
		return out[:e.size], true
	}
	data, err := o.chainData(e.start)
	if err != nil || uint32(len(data)) < e.size {
		return nil, false
	}
	return data[:e.size], true
}

// hasStream 判断根目录下是否存在某个流。
func (o *oleFile) hasStream(name string) bool {
	for _, e := range o.entries {
		if e.typ == 2 && e.name == name {
			return true
		}
	}
	return false
}

// utf16Decode 把小端 UTF-16 字节解成字符串（目录名是 UTF-16LE）。
func utf16Decode(b []byte) []byte {
	out := make([]byte, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i : i+2])
		if c < 0x80 {
			out = append(out, byte(c))
		} else if c < 0x800 {
			out = append(out, byte(0xC0|c>>6), byte(0x80|c&0x3F))
		} else {
			out = append(out, byte(0xE0|c>>12), byte(0x80|(c>>6)&0x3F), byte(0x80|c&0x3F))
		}
	}
	return out
}
