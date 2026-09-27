package hashdump

import (
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"gyhost/internal/i18n"
)

// ZIP 结构签名（小端序）。
const (
	sigLocal    = 0x04034b50 // 本地文件头
	sigCD       = 0x02014b50 // 中央目录条目
	sigEOCD     = 0x06054b50 // 中央目录结束记录
	sigZip64ECD = 0x06064b50 // Zip64 中央目录结束记录
	sigZip64Loc = 0x07064b50 // Zip64 结束记录定位器
)

// ZIP 加密方法与相关常量。
const (
	methodStored  = 0
	methodDeflate = 8
	methodAESEnc  = 99 // "AE-x" WinZip AES
	aesExtraID    = 0x9901
	flagEncrypted = 0x0001
	flagStrongEnc = 0x0040  // 强加密（非 ZipCrypto / 非 AE-x）
	saltLenBase   = 4 + 4*1 // AES saltLen = 4 + 4*strength
	pwVerifyLen   = 2
	authCodeLen   = 10
)

// zipCD 是中央目录中的一个条目。
type zipCD struct {
	name       string
	flags      uint16
	method     uint16
	time       uint16 // DOS 时间（低 16 位即时间部分）
	crc        uint32
	compSize   int64
	uncompSize int64
	localOff   int64
	dir        bool
	extraData  []byte // 中央目录 extra 字段
}

// extractZip 从 zip 压缩包中提取 ZipCrypto / WinZip AES 两类哈希。
func extractZip(f io.ReaderAt, size int64, path string) (*Result, error) {
	res := &Result{Path: path, Kind: "zip"}

	entries, err := readZipCentralDir(f, size)
	if err != nil {
		return nil, err
	}

	for _, e := range entries {
		if e.flags&flagEncrypted == 0 {
			continue // 未加密，不属于本模块的提取范围
		}
		if strings.HasSuffix(e.name, "/") || strings.HasSuffix(e.name, "\\") {
			continue // 目录条目
		}

		// 本地文件头：取数据区偏移与本地 extra 中的 AES 参数。
		lh, err := readAt(f, size, e.localOff, 30)
		if err != nil {
			res.addSkip(e.name, i18n.T("hashdump.skip.broken"))
			continue
		}
		if binary.LittleEndian.Uint32(lh) != sigLocal {
			res.addSkip(e.name, i18n.T("hashdump.skip.broken"))
			continue
		}
		localVersion := binary.LittleEndian.Uint16(lh[4:6])
		localFlags := binary.LittleEndian.Uint16(lh[6:8])
		localNameLen := int64(binary.LittleEndian.Uint16(lh[26:28]))
		localExtraLen := int64(binary.LittleEndian.Uint16(lh[28:30]))
		dataOff := e.localOff + 30 + localNameLen + localExtraLen

		localExtra, err := readAt(f, size, e.localOff+30+localNameLen, localExtraLen)
		if err != nil {
			localExtra = nil
		}

		switch {
		case e.method == methodAESEnc:
			extractZipAES(f, size, res, e, localExtra, dataOff)
		case e.method == methodStored || e.method == methodDeflate:
			if localFlags&flagStrongEnc != 0 {
				res.addSkip(e.name, i18n.Tf("hashdump.skip.method", fmt.Sprintf("0x%04x", localFlags)))
				continue
			}
			extractZipCrypto(f, size, res, e, localVersion, localFlags, dataOff)
		default:
			res.addSkip(e.name, i18n.Tf("hashdump.skip.method", fmt.Sprintf("%d", e.method)))
		}
	}

	// 既没有可提取的哈希、也没有其它跳过原因时，说明这只是没加密的
	// OOXML 文档（docx/xlsx/pptx 本身就是一个未加密的 zip），给个明确交代。
	if len(res.Entries) == 0 && len(res.Skipped) == 0 && isOOXMLDoc(entries) {
		res.addSkip(filepath.Base(path), i18n.T("hashdump.office.skip.no_encrypt"))
	}
	return res, nil
}

// isOOXMLDoc 判断 zip 是否是 Office Open XML 文档的容器。
func isOOXMLDoc(entries []zipCD) bool {
	var hasTypes, hasPart bool
	for _, e := range entries {
		if e.name == "[Content_Types].xml" {
			hasTypes = true
		}
		if strings.HasPrefix(e.name, "word/") ||
			strings.HasPrefix(e.name, "xl/") ||
			strings.HasPrefix(e.name, "ppt/") {
			hasPart = true
		}
	}
	return hasTypes && hasPart
}

// extractZipCrypto 提取 ZipCrypto（传统 PKWARE 加密）条目。
//
// hashcat -m 17200（deflate, CT=8）/ -m 17210（stored, CT=0），
// 单条哈希只能包含一个条目（hash_count 必须为 1）。
func extractZipCrypto(
	f io.ReaderAt,
	size int64,
	res *Result,
	e zipCD,
	localVersion uint16,
	localFlags uint16,
	dataOff int64,
) {
	_ = localFlags
	if e.compSize <= 12 {
		res.addSkip(e.name, i18n.T("hashdump.skip.short"))
		return
	}
	if e.compSize > maxPKZIPData {
		res.addSkip(e.name, i18n.Tf("hashdump.skip.large", e.compSize))
		return
	}
	data, err := readAt(f, size, dataOff, e.compSize)
	if err != nil {
		res.addSkip(e.name, i18n.T("hashdump.skip.broken"))
		return
	}

	// B: 版本 >= 2.0 只校验第 11 字节（1 字节校验），否则校验 2 字节。
	b := 2
	if localVersion >= 20 {
		b = 1
	}
	// CS 取 CRC32 高 16 位；TC 取 DOS 时间。hashcat 对两者取"或"，
	// 因此条目是否使用数据描述符（本地头 CRC 为 0）都能覆盖。
	cs := uint16(e.crc >> 16)
	tc := e.time

	mode := 17200 // deflate
	if e.method == methodStored {
		mode = 17210
	}

	hash := fmt.Sprintf("$pkzip2$1*%d*2*0*%x*%x*%x*0*%x*%d*%x*%04x*%04x*%s*$/pkzip2$",
		b,
		e.compSize,   // CL
		e.uncompSize, // UL
		e.crc,        // CR
		dataOff,      // OX（OF 恒为 0）
		e.method,     // CT: 8 deflate / 0 stored
		e.compSize,   // DL
		cs,           // CS
		tc,           // TC
		hexLower(data),
	)
	res.addEntry(e.name, mode, hash)
}

// extractZipAES 提取 WinZip AE-x（AES-128/192/256-CBC）条目，对应 hashcat -m 13600。
func extractZipAES(
	f io.ReaderAt,
	size int64,
	res *Result,
	e zipCD,
	localExtra []byte,
	dataOff int64,
) {
	strength, ok := findAESParams(localExtra)
	if !ok {
		strength, ok = findAESParams(e.extra())
	}
	if !ok {
		res.addSkip(e.name, i18n.T("hashdump.skip.broken"))
		return
	}
	if strength < 1 || strength > 3 {
		res.addSkip(e.name, i18n.Tf("hashdump.skip.method", fmt.Sprintf("AES-%d", strength*64)))
		return
	}

	saltLen := int64(saltLenBase + 4*(strength-1))
	if e.compSize <= saltLen+pwVerifyLen+authCodeLen {
		res.addSkip(e.name, i18n.T("hashdump.skip.short"))
		return
	}
	realLen := e.compSize - saltLen - pwVerifyLen - authCodeLen
	if realLen > maxInlineByte {
		res.addSkip(e.name, i18n.Tf("hashdump.skip.large", realLen))
		return
	}
	data, err := readAt(f, size, dataOff, e.compSize)
	if err != nil {
		res.addSkip(e.name, i18n.T("hashdump.skip.broken"))
		return
	}
	salt := data[:saltLen]
	pv := data[saltLen : saltLen+pwVerifyLen]
	cipher := data[saltLen+pwVerifyLen : saltLen+pwVerifyLen+realLen]
	auth := data[saltLen+pwVerifyLen+realLen:]

	// verify_bytes 是两个字节按大端拼成的 u32（hashcat 用 sscanf("%4x") 读取）。
	verify := uint32(pv[0])<<8 | uint32(pv[1])

	hash := fmt.Sprintf("$zip2$*0*%x*0*%s*%04x*%x*%s*%s*$/zip2$",
		strength,
		hexLower(salt),
		verify,
		realLen,
		hexLower(cipher),
		hexLower(auth),
	)
	res.addEntry(e.name, 13600, hash)
}

// ---------------------------------------------------------------------------
// 中央目录
// ---------------------------------------------------------------------------

// extra 返回中央目录条目的 extra 字段（readZipCentralDir 已缓存）。
func (e *zipCD) extra() []byte { return e.extraData }

// readZipCentralDir 定位并解析 ZIP 中央目录。
func readZipCentralDir(f io.ReaderAt, size int64) ([]zipCD, error) {
	// EOCD 最短 22 字节，comment 最长 65535 字节，从文件尾部倒着找。
	tailLen := int64(22 + 65535)
	if tailLen > size {
		tailLen = size
	}
	if tailLen < 22 {
		return nil, errBroken("zip truncated")
	}
	tail, err := readAt(f, size, size-tailLen, tailLen)
	if err != nil {
		return nil, err
	}

	eocdPos := -1
	for i := int64(tailLen - 22); i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:]) != sigEOCD {
			continue
		}
		commentLen := int64(binary.LittleEndian.Uint16(tail[i+20 : i+22]))
		if i+22+commentLen == tailLen {
			eocdPos = int(i)
			break
		}
	}
	if eocdPos < 0 {
		return nil, errBroken("EOCD not found")
	}

	eocd := tail[eocdPos:]
	entries := int64(binary.LittleEndian.Uint16(eocd[10:12]))
	cdSize := int64(binary.LittleEndian.Uint32(eocd[12:16]))
	cdOff := int64(binary.LittleEndian.Uint32(eocd[16:20]))

	needZip64 := entries == 0xffff || cdSize == 0xffffffff || cdOff == 0xffffffff
	if needZip64 {
		// 定位器紧邻 EOCD 之前。
		if eocdPos < 20 {
			return nil, errBroken("zip64 locator missing")
		}
		loc := tail[eocdPos-20 : eocdPos]
		if binary.LittleEndian.Uint32(loc) != sigZip64Loc {
			return nil, errBroken("zip64 locator signature mismatch")
		}
		z64Off := int64(binary.LittleEndian.Uint64(loc[8:16]))
		z64, err := readAt(f, size, z64Off, 56)
		if err != nil {
			return nil, err
		}
		if binary.LittleEndian.Uint32(z64) != sigZip64ECD {
			return nil, errBroken("zip64 eocd signature mismatch")
		}
		entries = int64(binary.LittleEndian.Uint64(z64[32:40]))
		cdSize = int64(binary.LittleEndian.Uint64(z64[40:48]))
		cdOff = int64(binary.LittleEndian.Uint64(z64[48:56]))
	}

	if cdSize == 0 || entries == 0 {
		return nil, nil
	}
	cd, err := readAt(f, size, cdOff, cdSize)
	if err != nil {
		return nil, err
	}

	r := newReader(cd)
	out := make([]zipCD, 0, entries)
	for r.remaining() >= 46 {
		if r.u32() != sigCD {
			break
		}
		var e zipCD
		_ = r.u16() // version made by
		_ = r.u16() // version needed to extract
		e.flags = r.u16()
		e.method = r.u16()
		e.time = r.u16() // modification time
		_ = r.u16()      // modification date
		e.crc = r.u32()
		compSize := int64(r.u32())
		uncompSize := int64(r.u32())
		nameLen := int(r.u16())
		extraLen := int(r.u16())
		commentLen := int(r.u16())
		_ = r.u16() // disk number start
		_ = r.u16() // internal attributes
		_ = r.u32() // external attributes
		localOff := int64(r.u32())

		if r.err != nil {
			break
		}
		nameBytes := r.take(nameLen)
		extraData := r.take(extraLen)
		r.skip(commentLen)
		if r.err != nil {
			break
		}
		e.name = string(nameBytes)
		e.extraData = append([]byte(nil), extraData...)
		e.uncompSize = uncompSize

		// Zip64 extra field（id 0x0001）：被置为 0xffffffff 的字段依次由它提供。
		if compSize == 0xffffffff || uncompSize == 0xffffffff || localOff == 0xffffffff {
			z := newReader(e.extraData)
			for z.remaining() >= 4 && z.err == nil {
				id := z.u16()
				ln := int(z.u16())
				body := z.take(ln)
				if z.err != nil || id != 0x0001 {
					continue
				}
				b := newReader(body)
				if uncompSize == 0xffffffff {
					uncompSize = int64(b.u64())
				}
				if compSize == 0xffffffff {
					compSize = int64(b.u64())
				}
				if localOff == 0xffffffff {
					localOff = int64(b.u64())
				}
			}
		}
		e.compSize = compSize
		e.localOff = localOff
		if strings.HasSuffix(e.name, "/") || strings.HasSuffix(e.name, "\\") {
			e.dir = true
		}
		out = append(out, e)
	}
	if r.err != nil {
		return nil, errBroken("central directory truncated")
	}
	return out, nil
}

// findAESParams 从 extra 字段里找 0x9901（AE-x）记录，
// 返回加密强度 1=128 2=192 3=256。
func findAESParams(extra []byte) (byte, bool) {
	z := newReader(extra)
	for z.remaining() >= 4 && z.err == nil {
		id := z.u16()
		ln := int(z.u16())
		body := z.take(ln)
		if z.err != nil {
			return 0, false
		}
		if id != aesExtraID || ln != 7 {
			continue
		}
		b := newReader(body)
		_ = b.u16() // vendor version (1=AE-1, 2=AE-2)
		vendor := b.u16()
		strength := b.u8()
		_ = b.u16()           // actual compression method
		if vendor != 0x4541 { // "AE"
			return 0, false
		}
		return strength, true
	}
	return 0, false
}
