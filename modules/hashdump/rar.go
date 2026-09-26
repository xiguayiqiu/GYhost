package hashdump

import (
	"fmt"
	"io"

	"gyhost/internal/i18n"
)

// RAR5 头类型（technote.htm / rar2john.h）。
const (
	rarHeadMain    = 1
	rarHeadFile    = 2
	rarHeadService = 3
	rarHeadCrypt   = 4
	rarHeadEndarc  = 5
)

// 通用头标志。
const (
	rarHFLExtra = 1
	rarHFLData  = 2
)

// 文件/服务头 File flags。
const (
	rarFHFLUTime = 0x0002
	rarFHFLCRC32 = 0x0004
)

// FHEXTRA_CRYPT 记录。
const (
	rarExtraCrypt       = 0x01
	rarCryptPSWCheck    = 0x0001
	rarCryptKDFMax      = 24
	rarCryptSaltLen     = 16
	rarCryptIVLen       = 16
	rarCryptCheckLen    = 8
	rarCryptCheckCSMLen = 4
)

// extractRAR5 从 RAR5 压缩包中提取哈希，对应 hashcat -m 13000。
//
// 两类可提取目标：
//   - 文件/服务头的 "file encryption record"（每个加密文件一条）
//   - 头部加密（rar a -hp）的 "archive encryption header"（整个压缩包一条）
func extractRAR5(f io.ReaderAt, size int64, path string) (*Result, error) {
	res := &Result{Path: path, Kind: "rar"}

	const sigLen = 8 // "Rar!\x1a\x07\x01\x00"
	pos := int64(sigLen)

	for pos+4 < size {
		// 区块 = CRC32(4) + HeaderSize(vint) + HeaderSize 字节的内容 + Data 区
		head, err := readAt(f, size, pos, 14)
		if err != nil {
			return res, nil
		}
		r := newReader(head)
		_ = r.u32() // Header CRC32（此处不做校验）
		hdrSize := r.vint()
		if r.err != nil || hdrSize < 1 {
			return res, nil
		}
		sizeLen := r.off - 4
		contentStart := pos + 4 + int64(sizeLen)
		content, err := readAt(f, size, contentStart, int64(hdrSize))
		if err != nil {
			return res, nil
		}

		c := newReader(content)
		hdrType := c.vint()
		flags := c.vint()
		var extraSize, dataSize int64
		if flags&rarHFLExtra != 0 {
			extraSize = int64(c.vint())
		}
		if flags&rarHFLData != 0 {
			dataSize = int64(c.vint())
		}
		if c.err != nil {
			return res, nil
		}

		nextPos := contentStart + int64(hdrSize) + dataSize

		switch hdrType {
		case rarHeadCrypt:
			// 头部加密：salt/迭代次数/校验值在本块内，
			// 其后紧跟 16 字节 IV + 加密的头数据，无法继续解析。
			iv, ivErr := readAt(f, size, nextPos, rarCryptIVLen)
			if ivErr != nil {
				return res, nil
			}
			v, ok := parseRAR5Crypt(c)
			if !ok {
				res.addSkip(i18n.T("hashdump.info.header"), i18n.T("hashdump.skip.no_check"))
				return res, nil
			}
			res.addEntry(i18n.T("hashdump.info.header"), 13000, rar5Hash(v.salt, v.lg2, iv, v.check))
			return res, nil

		case rarHeadFile, rarHeadService:
			name, extra := parseRAR5File(c, content, extraSize, flags)
			if extra == nil {
				break
			}
			v, ok := parseRAR5CryptRecord(extra)
			if !ok {
				if hasCryptRecord(extra) {
					res.addSkip(name, i18n.T("hashdump.skip.no_check"))
				}
				break
			}
			res.addEntry(name, 13000, rar5Hash(v.salt, v.lg2, v.iv, v.check))

		case rarHeadMain, rarHeadEndarc:
			// 普通块，无需处理
		}

		if nextPos <= pos {
			return res, nil // 结构异常，避免死循环
		}
		pos = nextPos
	}
	return res, nil
}

// rar5Crypt 是 RAR5 加密记录中可提取的字段。
type rar5Crypt struct {
	salt  []byte
	iv    []byte
	lg2   int
	check []byte
}

// parseRAR5Crypt 解析 "archive encryption header"（头部加密），
// extra 区在其内容之后，因此直接从内容游标读字段。
func parseRAR5Crypt(c *reader) (rar5Crypt, bool) {
	var v rar5Crypt
	version := c.vint()
	if c.err != nil || version != 0 {
		return v, false
	}
	encFlags := c.vint()
	if c.err != nil {
		return v, false
	}
	lg2 := c.u8()
	if c.err != nil || int(lg2) >= rarCryptKDFMax {
		return v, false
	}
	salt := c.take(rarCryptSaltLen)
	if c.err != nil {
		return v, false
	}
	if encFlags&rarCryptPSWCheck == 0 {
		return v, false
	}
	check := c.take(rarCryptCheckLen)
	if c.err != nil {
		return v, false
	}
	_ = c.take(rarCryptCheckCSMLen) // 额外 4 字节校验和
	v.salt = append([]byte(nil), salt...)
	v.iv = nil
	v.lg2 = int(lg2)
	v.check = append([]byte(nil), check...)
	return v, true
}

// parseRAR5File 解析 file/service header，返回条目名与 extra 区。
func parseRAR5File(c *reader, content []byte, extraSize int64, flags uint64) (string, []byte) {
	fileFlags := c.vint()
	_ = c.vint() // unpacked size
	_ = c.vint() // attributes
	if fileFlags&rarFHFLUTime != 0 {
		_ = c.u32() // mtime
	}
	if fileFlags&rarFHFLCRC32 != 0 {
		_ = c.u32() // data CRC32
	}
	_ = c.vint() // compression information
	_ = c.vint() // host OS
	nameLen := c.vint()
	nameBytes := c.take(int(nameLen))
	if c.err != nil {
		return "", nil
	}
	name := string(nameBytes)

	var extra []byte
	if flags&rarHFLExtra != 0 && extraSize > 0 && int64(len(content)) >= extraSize {
		extra = content[len(content)-int(extraSize):]
	}
	return name, extra
}

// hasCryptRecord 判断 extra 区是否含 FHEXTRA_CRYPT 记录。
func hasCryptRecord(extra []byte) bool {
	_, ok := parseRAR5CryptRecord(extra)
	if ok {
		return true
	}
	z := newReader(extra)
	for z.remaining() >= 3 && z.err == nil {
		_ = z.vint() // 记录长度
		typ := z.vint()
		if z.err != nil {
			return false
		}
		if typ == rarExtraCrypt {
			return true
		}
	}
	return false
}

// parseRAR5CryptRecord 解析 file/service 头 extra 区里的 file encryption record。
func parseRAR5CryptRecord(extra []byte) (rar5Crypt, bool) {
	var v rar5Crypt
	z := newReader(extra)
	for z.remaining() >= 3 && z.err == nil {
		fieldSize := z.vint()
		sizeLen := z.off
		fieldType := z.vint()
		if z.err != nil {
			return v, false
		}
		// 记录长度（FieldSize）自 Type 起算。
		body := z.take(int(fieldSize) - (z.off - sizeLen))
		if z.err != nil {
			return v, false
		}
		if fieldType != rarExtraCrypt {
			continue
		}
		b := newReader(body)
		version := b.vint()
		encFlags := b.vint()
		if b.err != nil || version != 0 {
			return v, false
		}
		lg2 := b.u8()
		if b.err != nil || int(lg2) >= rarCryptKDFMax {
			return v, false
		}
		salt := b.take(rarCryptSaltLen)
		iv := b.take(rarCryptIVLen)
		if b.err != nil {
			return v, false
		}
		if encFlags&rarCryptPSWCheck == 0 {
			return v, false
		}
		check := b.take(rarCryptCheckLen)
		if b.err != nil {
			return v, false
		}
		v.salt = append([]byte(nil), salt...)
		v.iv = append([]byte(nil), iv...)
		v.lg2 = int(lg2)
		v.check = append([]byte(nil), check...)
		return v, true
	}
	return v, false
}

// rar5Hash 拼装 hashcat -m 13000 的哈希串：
//
//	$rar5$16$saltHex$kdfCount$ivHex$8$pswCheckHex
func rar5Hash(salt []byte, lg2 int, iv []byte, check []byte) string {
	return fmt.Sprintf("$rar5$%d$%s$%d$%s$%d$%s",
		len(salt), hexLower(salt),
		lg2, hexLower(iv),
		len(check), hexLower(check))
}
