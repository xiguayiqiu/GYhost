package mem

import (
	"bytes"
	"encoding/binary"
)

// ---- 各格式的长度解析 ----

// pngSize 遍历 PNG 的块结构（长度4 类型4 数据n crc4），累加到 IEND 为止。
func pngSize(d []byte) (int, bool) {
	off := 8
	for off+8 <= len(d) && off < 64<<20 {
		length := int(binary.BigEndian.Uint32(d[off : off+4]))
		if length < 0 || off+12+length > len(d) {
			return 0, false
		}
		typ := string(d[off+4 : off+8])
		off += 12 + length
		if typ == "IEND" {
			return off, true
		}
	}
	return 0, false
}

// zipSize 通过中央目录结束记录（EOCD）推导 zip 大小。
func zipSize(d []byte) (int, bool) {
	idx := bytes.LastIndex(d, zipEOCD)
	if idx < 0 || idx+22 > len(d) {
		return 0, false
	}
	commentLen := int(binary.LittleEndian.Uint16(d[idx+20 : idx+22]))
	return idx + 22 + commentLen, true
}

// bmpSize 读取 BMP 头里的文件大小字段（偏移 2，小端）。
//
// "BM" 只有两个字节，内存里误命中极多，因此额外校验：
//   - 声明的文件大小必须覆盖 DIB 头本身
//   - 偏移 14 处的 DIB 头长度必须是已知取值
//   - 数据偏移字段（偏移 10）必须落在文件范围内
func bmpSize(d []byte) (int, bool) {
	if len(d) < 26 {
		return 0, false
	}
	n := int(binary.LittleEndian.Uint32(d[2:6]))
	if n < 26 {
		return 0, false
	}
	dib := int(binary.LittleEndian.Uint32(d[14:18]))
	switch dib {
	case 12, 16, 40, 52, 56, 64, 108, 124:
	default:
		return 0, false
	}
	off := int(binary.LittleEndian.Uint32(d[10:14]))
	if off != 0 && (off < 14+dib || off > n) {
		return 0, false
	}
	if n < 14+dib {
		return 0, false
	}
	return n, true
}

// elfSize 取 ELF section / program header 覆盖的最大文件末尾。
func elfSize(d []byte) (int, bool) {
	if len(d) < 64 || (d[4] != 1 && d[4] != 2) {
		return 0, false
	}
	le := d[5] == 1
	end := 0
	if d[4] == 2 { // 64 位
		if elf64Sections(d, le, &end) {
			return end, true
		}
		elf64Segments(d, le, &end)
	} else { // 32 位
		elf32Sections(d, le, &end)
		if end == 0 {
			elf32Segments(d, le, &end)
		}
	}
	if end == 0 {
		return 0, false
	}
	return end, true
}

func elf64Sections(d []byte, le bool, end *int) bool {
	shoff := u64(d, le, 0x28)
	shentsize := int(u16(d, le, 0x3a))
	shnum := int(u16(d, le, 0x3c))
	if shentsize < 8 || shnum == 0 {
		return false
	}
	for i := 0; i < shnum; i++ {
		base := int(shoff) + i*shentsize
		if base < 0 || base+shentsize > len(d) {
			break
		}
		if e := int(u64(d, le, uint64(base)+0x18) + u64(d, le, uint64(base)+0x20)); e > *end {
			*end = e
		}
	}
	return *end > 0
}

func elf64Segments(d []byte, le bool, end *int) {
	phoff := u64(d, le, 0x20)
	phentsize := int(u16(d, le, 0x36))
	phnum := int(u16(d, le, 0x38))
	if phentsize < 8 {
		return
	}
	for i := 0; i < phnum; i++ {
		base := int(phoff) + i*phentsize
		if base < 0 || base+phentsize > len(d) {
			break
		}
		if e := int(u64(d, le, uint64(base)+0x08) + u64(d, le, uint64(base)+0x20)); e > *end {
			*end = e
		}
	}
}

func elf32Sections(d []byte, le bool, end *int) {
	shoff := uint64(u32(d, le, 0x20))
	shentsize := int(u16(d, le, 0x2e))
	shnum := int(u16(d, le, 0x30))
	if shentsize < 8 {
		return
	}
	for i := 0; i < shnum; i++ {
		base := int(shoff) + i*shentsize
		if base < 0 || base+shentsize > len(d) {
			break
		}
		if e := int(uint64(u32(d, le, uint64(base)+0x10)) + uint64(u32(d, le, uint64(base)+0x14))); e > *end {
			*end = e
		}
	}
}

func elf32Segments(d []byte, le bool, end *int) {
	phoff := uint64(u32(d, le, 0x1c))
	phentsize := int(u16(d, le, 0x2a))
	phnum := int(u16(d, le, 0x2c))
	if phentsize < 8 {
		return
	}
	for i := 0; i < phnum; i++ {
		base := int(phoff) + i*phentsize
		if base < 0 || base+phentsize > len(d) {
			break
		}
		if e := int(uint64(u32(d, le, uint64(base)+4)) + uint64(u32(d, le, uint64(base)+0x10))); e > *end {
			*end = e
		}
	}
}

// sqliteSize 按页数 × 页大小推导数据库文件大小。
func sqliteSize(d []byte) (int, bool) {
	if len(d) < 32 {
		return 0, false
	}
	pageSize := int(binary.BigEndian.Uint16(d[16:18]))
	if pageSize == 1 {
		pageSize = 65536
	}
	pages := int(binary.BigEndian.Uint32(d[28:32]))
	if pageSize < 512 || pages <= 0 {
		return 0, false
	}
	return pageSize * pages, true
}

// sevenZSize 用 7z 头里的 next header 偏移与长度推导文件大小。
func sevenZSize(d []byte) (int, bool) {
	if len(d) < 32 {
		return 0, false
	}
	nextOff := u64(d, true, 12)
	nextSize := u64(d, true, 20)
	if nextOff == 0 && nextSize == 0 {
		return 0, false
	}
	return int(32 + nextOff + nextSize), true
}

// rarSize 取 RAR4 / RAR5 的结束块标记推导长度。
func rarSize(d []byte) (int, bool) {
	if idx := bytes.Index(d, []byte{0xc4, 0x3d, 0x7b, 0x00, 0x40, 0x07, 0x00}); idx >= 0 {
		return idx + 7, true
	}
	if idx := bytes.Index(d, []byte{0x72, 0xb5, 0x4a, 0x46, 0x07, 0x01}); idx >= 0 {
		return idx + 6, true
	}
	return 0, false
}

// dexSize 读取 dex 头（偏移 0x20）里的 file_size 字段。
func dexSize(d []byte) (int, bool) {
	if len(d) < 36 || string(d[:4]) != "dex\n" || d[7] != '0' {
		return 0, false
	}
	n := int(binary.LittleEndian.Uint32(d[32:36]))
	if n < 36 {
		return 0, false
	}
	return n, true
}

// peSize 遍历 PE 节表，取最后一个节的原始数据末尾作为文件大小。
//
// 内存中的映像常被抹掉节表信息（SizeOfRawData 为 0），此时退回可选头的
// SizeOfImage / SizeOfHeaders，保证不会把整段内存当成一个文件。
func peSize(d []byte) (int, bool) {
	if len(d) < 0x40 {
		return 0, false
	}
	peOff := int(binary.LittleEndian.Uint32(d[0x3c:0x40]))
	if peOff <= 0 || peOff+24 > len(d) || string(d[peOff:peOff+4]) != "PE\x00\x00" {
		return 0, false
	}
	optOff := peOff + 24
	if optOff+2 > len(d) {
		return 0, false
	}
	optMagic := binary.LittleEndian.Uint16(d[optOff : optOff+2])
	sections := int(binary.LittleEndian.Uint16(d[peOff+6 : peOff+8]))
	optSize := int(binary.LittleEndian.Uint16(d[peOff+20 : peOff+22]))
	if optSize <= 0 {
		return 0, false
	}
	end := 0
	if sections > 0 && sections <= 96 {
		table := optOff + optSize
		for i := 0; i < sections; i++ {
			b := table + i*40
			if b+40 > len(d) {
				break
			}
			if e := int(binary.LittleEndian.Uint32(d[b+16:b+20])) +
				int(binary.LittleEndian.Uint32(d[b+20:b+24])); e > end {
				end = e
			}
		}
	}
	if end > 0 {
		return end, true
	}
	// PE32+ 的 SizeOfImage 在可选头偏移 0x38，PE32 在 0x3C
	if optMagic == 0x20b && optOff+0x3c <= len(d) {
		if n := int(binary.LittleEndian.Uint32(d[optOff+56 : optOff+60])); n > 0 {
			return n, true
		}
	}
	if optOff+0x40 <= len(d) {
		if n := int(binary.LittleEndian.Uint32(d[optOff+60 : optOff+64])); n > 0 {
			return n, true
		}
	}
	return 0, false
}

// lnkSize 读取 Shell Link 头 0x10 处的数据长度字段（头部基址 0x4c）。
func lnkSize(d []byte) (int, bool) {
	if len(d) < 0x4c {
		return 0, false
	}
	n := 0x4c + int(binary.LittleEndian.Uint32(d[0x10:0x14]))
	if n < 0x4c {
		return 0, false
	}
	return n, true
}

// ---- 小端/大端读取小工具（越界一律返回 0，由调用方判定失败） ----

func u16(d []byte, le bool, off uint64) uint16 {
	if off+2 > uint64(len(d)) {
		return 0
	}
	if le {
		return binary.LittleEndian.Uint16(d[off:])
	}
	return binary.BigEndian.Uint16(d[off:])
}

func u32(d []byte, le bool, off uint64) uint32 {
	if off+4 > uint64(len(d)) {
		return 0
	}
	if le {
		return binary.LittleEndian.Uint32(d[off:])
	}
	return binary.BigEndian.Uint32(d[off:])
}

func u64(d []byte, le bool, off uint64) uint64 {
	if off+8 > uint64(len(d)) {
		return 0
	}
	if le {
		return binary.LittleEndian.Uint64(d[off:])
	}
	return binary.BigEndian.Uint64(d[off:])
}

// riffSize 按 RIFF 头的长度字段推导（wav / avi / webp 等）。
func riffSize(d []byte) (int, bool) {
	if len(d) < 12 {
		return 0, false
	}
	n := 8 + int(binary.LittleEndian.Uint32(d[4:8]))
	if n < 12 {
		return 0, false
	}
	return n, true
}

// ---- 格式自洽性校验（排除魔数误命中） ----

// jpegValid 校验 SOI 之后的段结构（marker + 长度自洽）。
func jpegValid(d []byte) bool {
	if len(d) < 4 {
		return false
	}
	if d[2] != 0xff {
		return false // SOI 之后必须紧跟一个 marker
	}
	seg := int(binary.BigEndian.Uint16(d[2:4]))
	// 合法段长度 >= 2，且不超过一个合理的上限（512 MiB）
	return seg >= 2 && seg < 512<<20
}

// gifValid 校验逻辑屏幕描述符：宽高必须是合理的正整数。
func gifValid(d []byte) bool {
	if len(d) < 13 {
		return false
	}
	// 完整签名是 GIF87a / GIF89a：d[3] 固定为 '8'，d[4] 是版本，d[5] 固定为 'a'
	if d[3] != '8' || d[5] != 'a' || (d[4] != '7' && d[4] != '9') {
		return false
	}
	w := int(binary.LittleEndian.Uint16(d[6:8]))
	h := int(binary.LittleEndian.Uint16(d[8:10]))
	return w > 0 && h > 0 && w <= 0xffff && h <= 0xffff
}

// zipValid 校验本地文件头的字段自洽性。
func zipValid(d []byte) bool {
	if len(d) < 30 {
		return false
	}
	if binary.LittleEndian.Uint16(d[4:6]) != 0x0403 {
		// 版本必须是 2.0（0x0014）与 4.5（0x002d）之一对应的低字节
		ver := binary.LittleEndian.Uint16(d[4:6])
		if ver != 0x0403 && ver != 0x040b {
			return false
		}
	}
	flags := binary.LittleEndian.Uint16(d[6:8])
	flags &= 0x0009 // 只看 bit0(加密) 与 bit3(数据描述符)
	if flags == 0x0001 {
		return false // 加密的 zip 在内存里无法还原
	}
	nameLen := int(binary.LittleEndian.Uint16(d[26:28]))
	extraLen := int(binary.LittleEndian.Uint16(d[28:30]))
	// 文件名长度必须落在范围内且是合法的 ASCII/UTF-8 片段
	if nameLen == 0 || nameLen > 1024 || 30+nameLen+extraLen > len(d) {
		return false
	}
	for _, c := range d[30 : 30+nameLen] {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// tiffValid 校验字节序标记与首个 IFD 偏移。
func tiffValid(d []byte) bool {
	if len(d) < 8 {
		return false
	}
	le := d[0] == 'I'
	off := int(u32(d, le, 4))
	return off >= 8 && off < 64<<20
}

// riffValid 校验 RIFF 后的 FourCC 是已知容器类型。
func riffValid(d []byte) bool {
	if len(d) < 12 {
		return false
	}
	switch string(d[8:12]) {
	case "WAVE", "AVI ", "WEBP":
		return true
	default:
		return false
	}
}

// tiffSize 按首个 IFD 的偏移与长度推导文件大小。
//
// TIFF 没有固定的头部长度，只能顺着 IFD 一路跳到最后一个偏移字段。
func tiffSize(d []byte) (int, bool) {
	if len(d) < 8 {
		return 0, false
	}
	le := d[0] == 'I'
	if d[0] != 'I' && d[0] != 'M' {
		return 0, false
	}
	off := int(u32(d, le, 4))
	if off < 8 || off+2 > len(d) {
		return 0, false
	}
	count := int(u16(d, le, uint64(off)))
	if count == 0 || count > 4096 {
		return 0, false
	}
	base := off + 2 + count*12
	if base+4 > len(d) {
		return 0, false
	}
	// 最后一个 IFD 条目之后就是下一个 IFD 的偏移，取最大值即文件末尾
	end := base
	for i := 0; i < count; i++ {
		p := uint64(off + 2 + i*12)
		val := int(u32(d, le, p+8))
		if typ := u16(d, le, p+2); typ == 0 || typ == 3 || typ == 4 {
			// 短值内联在偏移字段里，不能当作文件偏移
			continue
		} else if val > end {
			end = val
		}
	}
	return end, true
}

// pdfValid 校验 %PDF- 后面的版本号（1.0 ~ 2.0）。
func pdfValid(d []byte) bool {
	if len(d) < 8 {
		return false
	}
	// "%PDF-" 之后是主版本号.次版本号，例如 "1.4" / "2.0"
	if d[5] != '1' && d[5] != '2' {
		return false
	}
	return d[6] == '.' && d[7] >= '0' && d[7] <= '9'
}

// sevenZValid 校验 7z 的签名版本号与头部长度字段。
func sevenZValid(d []byte) bool {
	if len(d) < 32 {
		return false
	}
	if d[6] != 0 || d[7] != 0 {
		return false // major/minor 必须是 0
	}
	startHdrCRC := u32(d, true, 8)
	if startHdrCRC == 0 || startHdrCRC == 0xffffffff {
		return false
	}
	nextSize := u64(d, true, 20)
	if nextSize > 1<<40 {
		return false
	}
	return true
}
