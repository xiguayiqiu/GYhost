// Office / WPS 文档的哈希提取（hashcat -m 9400/9500/9600/9700/9800）。
//
// 与 john 的 office2john 对齐，覆盖以下几类：
//
//	加密的 OOXML（docx/xlsx/pptx，WPS 以兼容模式保存的同格式也在此列）：
//	EncryptionInfo 流，agile 加密 → $office$*2010/*2013（-m 9500/9600），
//	CryptoAPI 标准加密 → $office$*2007（-m 9400）
//	Word 97-2003（.doc）：WordDocument 的 FIB 标志 + 0Table/1Table 起始的
//	加密头 → $oldoffice$（-m 9700/9800）
//	Excel 97-2003（.xls）：Workbook 里的 FILEPASS 记录 → 同上
//	PPT 与 Access 的加密文档暂不支持，给出明确跳过原因
//
// 未加密的文档（含 WPS 私有格式）不会产出哈希，同样以跳过原因说明。
package hashdump

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"gyhost/internal/i18n"
)

// Office 文档读取上限：提取只需目录与几个小流，整读上限用于兜底防御。
const maxOfficeSize = 512 << 20

// keyEncryptorNS 是 agile 加密 XML 里口令密钥加密器的命名空间。
const keyEncryptorNS = "http://schemas.microsoft.com/office/2006/keyEncryptor/password"

// 其它可识别容器的魔数（非 OLE，但走同一套 XML 元数据解析）。
var (
	magicACE   = []byte("Standard ACE DB")                  // MS Access 2007+
	magicOneNo = []byte{0xe4, 0x52, 0x5c, 0x7b, 0x8c, 0xd8} // OneNote >= 2013
	xmlStart   = []byte(`<?xml version="1.0"`)
	xmlEnd     = []byte(`</encryption>`)
)

// extractOffice 从 Office 文档中提取 hashcat 哈希。
func extractOffice(f io.ReaderAt, size int64, path string) (*Result, error) {
	res := &Result{Path: path, Kind: "office"}
	name := filepath.Base(path)

	if size <= 0 || size > maxOfficeSize {
		res.addSkip(name, i18n.Tf("hashdump.office.skip.size", size))
		return res, nil
	}

	// 先读文件头，识别非 OLE 的容器（Access/OneNote 直接把加密元数据
	// 以 XML 形式写在文件里，与 agile 加密同一套解析）
	headLen := size
	if headLen > 81920 {
		headLen = 81920
	}
	head := make([]byte, headLen)
	if _, err := f.ReadAt(head, 0); err != nil && err != io.EOF {
		return nil, errBroken("office read: %v", err)
	}

	if idx := bytes.Index(head, magicACE); idx >= 0 {
		if body, ok := officeXMLBody(head); ok {
			return officeXMLResult(res, name, body), nil
		}
		// Access 2007 的 CryptoAPI 加密（加密头散在文件里）暂不支持
		res.addSkip(name, i18n.T("hashdump.office.skip.access"))
		return res, nil
	}
	if len(head) >= 6 && bytes.Index(head[:6], magicOneNo) == 0 {
		if body, ok := officeXMLBody(head); ok {
			return officeXMLResult(res, name, body), nil
		}
		res.addSkip(name, i18n.T("hashdump.office.skip.no_streams"))
		return res, nil
	}

	if len(head) < 8 || string(head[:8]) != string(magicOLE) {
		return nil, errors.New(i18n.Tf("hashdump.err.unrecognized", path))
	}

	ole, err := openOLE(f, size)
	if err != nil {
		res.addSkip(name, i18n.Tf("hashdump.office.skip.ole", err))
		return res, nil
	}

	switch {
	case ole.hasStream("EncryptionInfo"):
		officeNewCrypto(res, name, ole)
	case ole.hasStream("Workbook"):
		officeLegacyXLS(res, name, ole)
	case ole.hasStream("WordDocument"):
		officeLegacyDOC(res, name, ole)
	case ole.hasStream("PowerPoint Document"):
		res.addSkip(name, i18n.T("hashdump.office.skip.ppt"))
	default:
		res.addSkip(name, i18n.T("hashdump.office.skip.no_streams"))
	}
	return res, nil
}

// officeXMLBody 从文件头里截出 `<?xml ... </encryption>` 这段加密元数据。
func officeXMLBody(head []byte) ([]byte, bool) {
	start := bytes.Index(head, xmlStart)
	if start < 0 {
		return nil, false
	}
	end := bytes.Index(head[start:], xmlEnd)
	if end < 0 {
		return nil, false
	}
	return head[start : start+end+len(xmlEnd)], true
}

// officeXMLResult 解析一段 encryption XML 并填充结果。
func officeXMLResult(res *Result, name string, data []byte) *Result {
	hash, mode, skip := officeParseAgile(data)
	if skip != "" {
		res.addSkip(name, skip)
		return res
	}
	res.addEntry(name, mode, hash)
	return res
}

// ---------------------------------------------------------------------------
// 加密的 OOXML：EncryptionInfo 流
// ---------------------------------------------------------------------------

// officeNewCrypto 解析 EncryptionInfo 流：
// agile 加密（Office 2010/2013+，含 WPS 兼容保存）或 CryptoAPI 标准加密（2007）。
func officeNewCrypto(res *Result, name string, ole *oleFile) {
	data, ok := ole.stream("EncryptionInfo")
	if !ok || len(data) < 8 {
		res.addSkip(name, i18n.T("hashdump.office.skip.broken"))
		return
	}
	major := binary.LittleEndian.Uint16(data[0:2])
	minor := binary.LittleEndian.Uint16(data[2:4])
	flags := binary.LittleEndian.Uint32(data[4:8])

	if flags == 16 { // fExternal：依赖外部加密提供程序
		res.addSkip(name, i18n.T("hashdump.office.skip.external"))
		return
	}
	if major == 4 && minor == 4 {
		if flags != 0x40 { // fAgile
			res.addSkip(name, i18n.T("hashdump.office.skip.flags"))
			return
		}
		hash, mode, skip := officeParseAgile(data[8:])
		if skip != "" {
			res.addSkip(name, skip)
			return
		}
		res.addEntry(name, mode, hash)
		return
	}

	// Office 2007：CryptoAPI 加密头
	keySize, salt, verifier, vhash, skip := officeParseCryptoAPI(data[8:])
	if skip != "" {
		res.addSkip(name, skip)
		return
	}
	res.addEntry(name, 9400, fmt.Sprintf("$office$*2007*%d*%d*%d*%s*%s*%s",
		len(vhash), keySize, len(salt), hexLower(salt), hexLower(verifier),
		hexLower(vhash[:min(32, len(vhash))])))
}

// officeParseAgile 解析 agile 加密的 XML 元数据，
// 返回 $office$ 哈希、hashcat 模式号与跳过原因（三者至多一个非空）。
//
// $office$*<年份>*<spinCount>*<keyBits>*<saltSize>*<salt>*<校验值>*<校验哈希>
// 年份由哈希算法推断：SHA-1 → 2010，SHA-512 → 2013。
func officeParseAgile(data []byte) (string, int, string) {
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	for {
		tok, err := dec.Token()
		if err != nil {
			// 找不到目标元素即按元数据损坏处理
			return "", 0, i18n.T("hashdump.office.skip.broken")
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "encryptedKey" || start.Name.Space != keyEncryptorNS {
			continue
		}
		attrs := map[string]string{}
		for _, a := range start.Attr {
			attrs[a.Name.Local] = a.Value
		}
		get := func(k string) string { return attrs[k] }

		var mode int
		switch get("hashAlgorithm") {
		case "SHA1":
			mode = 9500
		case "SHA512":
			mode = 9600
		default:
			return "", 0, i18n.Tf("hashdump.office.skip.hash_alg", get("hashAlgorithm"))
		}
		if !strings.Contains(get("cipherAlgorithm"), "AES") {
			return "", 0, i18n.Tf("hashdump.office.skip.cipher", get("cipherAlgorithm"))
		}

		decode := func(k string) ([]byte, bool) {
			b, err := base64.StdEncoding.DecodeString(get(k))
			return b, err == nil
		}
		salt, ok1 := decode("saltValue")
		input, ok2 := decode("encryptedVerifierHashInput")
		value, ok3 := decode("encryptedVerifierHashValue")
		spin, ok4 := atoiOK(get("spinCount"))
		keyBits, ok5 := atoiOK(get("keyBits"))
		saltSize, ok6 := atoiOK(get("saltSize"))
		if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
			return "", 0, i18n.T("hashdump.office.skip.broken")
		}
		hash := fmt.Sprintf("$office$*%d*%d*%d*%d*%s*%s*%s",
			yearOfMode(mode), spin, keyBits, saltSize,
			hexLower(salt), hexLower(input), hexLower(value[:min(32, len(value))]))
		return hash, mode, ""
	}
}

func yearOfMode(mode int) int {
	if mode == 9500 {
		return 2010
	}
	return 2013
}

// ---------------------------------------------------------------------------
// Word / Excel 97-2003：RC4 加密的口令校验值
// ---------------------------------------------------------------------------

// officeLegacyDOC 解析 Word 97-2003 文档。
//
// WordDocument 流的 FIB 标志（第 11 字节）：bit0=fEncrypted、
// bit1=fWhichTblStm、bit7=fObfuscated（XOR 混淆）。加密头位于
// 0Table/1Table 表流起始处。
func officeLegacyDOC(res *Result, name string, ole *oleFile) {
	wd, ok := ole.stream("WordDocument")
	if !ok || len(wd) < 12 {
		res.addSkip(name, i18n.T("hashdump.office.skip.broken"))
		return
	}
	if binary.LittleEndian.Uint16(wd[0:2]) != 0xA5EC {
		res.addSkip(name, i18n.T("hashdump.office.skip.broken"))
		return
	}
	flags := wd[11]
	encrypted := flags&0x01 != 0
	if encrypted && flags&0x80 != 0 {
		res.addSkip(name, i18n.T("hashdump.office.skip.xor"))
		return
	}
	if !encrypted {
		// WPS 私有格式会带自己的加密元数据，但不是 MS 兼容的口令哈希
		if ole.hasStream("WpsEncryptionInfo") {
			res.addSkip(name, i18n.T("hashdump.office.skip.wps"))
		} else {
			res.addSkip(name, i18n.T("hashdump.office.skip.no_encrypt"))
		}
		return
	}

	table := "0Table"
	if flags&0x02 != 0 {
		table = "1Table"
	}
	ts, ok := ole.stream(table)
	if !ok || len(ts) < 4 {
		res.addSkip(name, i18n.T("hashdump.office.skip.broken"))
		return
	}

	major := binary.LittleEndian.Uint16(ts[0:2])
	minor := binary.LittleEndian.Uint16(ts[2:4])
	if major == 1 || minor == 1 {
		// RC4 加密头：salt + verifier + verifierHash 共 48 字节
		body := ts[4:]
		if len(body) < 48 {
			res.addSkip(name, i18n.T("hashdump.office.skip.broken"))
			return
		}
		res.addEntry(name, 9700, oldOfficeHash(1, body[:16], body[16:32], body[32:48]))
		return
	}
	if major >= 2 && minor == 2 {
		// Version(4) + EncryptionFlags(4) 之后才是 CryptoAPI 加密头
		if len(ts) < 8 {
			res.addSkip(name, i18n.T("hashdump.office.skip.broken"))
			return
		}
		keySize, salt, verifier, vhash, skip := officeParseCryptoAPI(ts[8:])
		if skip != "" {
			res.addSkip(name, skip)
			return
		}
		typ, ok := oldOfficeType(keySize)
		if !ok {
			res.addSkip(name, i18n.Tf("hashdump.office.skip.key_size", keySize))
			return
		}
		if len(salt) != 16 || len(vhash) != 20 {
			res.addSkip(name, i18n.T("hashdump.office.skip.broken"))
			return
		}
		res.addEntry(name, 9800, oldOfficeHash(typ, salt, verifier, vhash))
		return
	}
	res.addSkip(name, i18n.T("hashdump.office.skip.doc_header"))
}

// officeLegacyXLS 解析 Excel 97-2003 工作簿：
// 遍历 BIFF 记录，FILEPASS（0x002F）记录里是口令校验值。
func officeLegacyXLS(res *Result, name string, ole *oleFile) {
	wb, ok := ole.stream("Workbook")
	if !ok || len(wb) < 4 {
		res.addSkip(name, i18n.T("hashdump.office.skip.broken"))
		return
	}
	for pos := 0; pos+4 <= len(wb); {
		typ := binary.LittleEndian.Uint16(wb[pos : pos+2])
		ln := int(binary.LittleEndian.Uint16(wb[pos+2 : pos+4]))
		pos += 4
		if pos+ln > len(wb) {
			res.addSkip(name, i18n.T("hashdump.office.skip.broken"))
			return
		}
		data := wb[pos : pos+ln]
		pos += ln

		if typ != 0x002F { // FILEPASS
			continue
		}
		if len(data) >= 2 && data[0] == 0 && data[1] == 0 {
			res.addSkip(name, i18n.T("hashdump.office.skip.xor"))
			return
		}
		if len(data) >= 6 && data[0] == 1 && data[1] == 0 &&
			data[2] == 1 && data[3] == 0 && data[4] == 1 && data[5] == 0 {
			// RC4：verifier 校验块紧跟 6 字节版本头
			if len(data) < 54 {
				res.addSkip(name, i18n.T("hashdump.office.skip.broken"))
				return
			}
			res.addEntry(name, 9700, oldOfficeHash(0, data[6:22], data[22:38], data[38:54]))
			return
		}
		if len(data) >= 6 && data[0] == 1 && data[1] == 0 &&
			(data[2] == 2 || data[2] == 3 || data[2] == 4) && data[3] == 0 {
			// RC4 CryptoAPI：wEncryptionType(2) + Version(4) + EncryptionFlags(4)
			if len(data) < 10 {
				res.addSkip(name, i18n.T("hashdump.office.skip.broken"))
				return
			}
			keySize, salt, verifier, vhash, skip := officeParseCryptoAPI(data[10:])
			if skip != "" {
				res.addSkip(name, skip)
				return
			}
			typ, ok := oldOfficeType(keySize)
			if !ok {
				typ = 4 // Excel 分支：非 40 位一律按 128 位处理（与 office2john 一致）
			}
			if len(salt) != 16 || len(vhash) != 20 {
				res.addSkip(name, i18n.T("hashdump.office.skip.broken"))
				return
			}
			res.addEntry(name, 9800, oldOfficeHash(typ, salt, verifier, vhash))
			return
		}
		res.addSkip(name, i18n.T("hashdump.office.skip.broken"))
		return
	}
	res.addSkip(name, i18n.T("hashdump.office.skip.no_encrypt"))
}

// officeParseCryptoAPI 解析 [MS-OFFCRYPTO] 2.3.5.1 的 RC4 CryptoAPI 加密头，
// 入参从 HeaderLength 字段开始，返回密钥位数与三段校验数据。
func officeParseCryptoAPI(b []byte) (keySize int, salt, verifier, vhash []byte, skip string) {
	need := func(n int) bool { return len(b) >= n }
	if !need(4) {
		return 0, nil, nil, nil, i18n.T("hashdump.office.skip.broken")
	}
	headerLen := int(binary.LittleEndian.Uint32(b[0:4]))
	// SkipFlags/SizeExtra/AlgID/AlgHashID/KeySize/ProviderType/Reserved* 共 8 个字段
	if !need(4+8*4) || headerLen < 32 {
		return 0, nil, nil, nil, i18n.T("hashdump.office.skip.broken")
	}
	cspLen := headerLen - 32
	if !need(4 + 32 + cspLen) {
		return 0, nil, nil, nil, i18n.T("hashdump.office.skip.broken")
	}
	keySize = int(binary.LittleEndian.Uint32(b[20:24])) // KeySize 是第 5 个字段
	rest := b[4+32+cspLen:]

	// 校验块：saltSize(4) salt(16) encryptedVerifier(16) verifierHashSize(4) hash(N)
	if len(rest) < 4+16+16+4 {
		return 0, nil, nil, nil, i18n.T("hashdump.office.skip.broken")
	}
	saltSize := int(binary.LittleEndian.Uint32(rest[0:4]))
	if saltSize != 16 {
		return 0, nil, nil, nil, i18n.T("hashdump.office.skip.broken")
	}
	salt = rest[4 : 4+16]
	verifier = rest[20:36]
	vhashSize := int(binary.LittleEndian.Uint32(rest[36:40]))
	if vhashSize <= 0 || vhashSize > 64 || len(rest) < 40+vhashSize {
		return 0, nil, nil, nil, i18n.T("hashdump.office.skip.broken")
	}
	vhash = rest[40 : 40+vhashSize]
	return keySize, salt, verifier, vhash, ""
}

// oldOfficeType 把 RC4 密钥位数映射成 $oldoffice$ 的类型段。
func oldOfficeType(keySize int) (int, bool) {
	switch keySize {
	case 128:
		return 4, true
	case 40:
		return 3, true
	}
	return 0, false
}

// oldOfficeHash 拼 $oldoffice$ 哈希行（-m 9700/9800）。
func oldOfficeHash(typ int, salt, verifier, vhash []byte) string {
	return fmt.Sprintf("$oldoffice$%d*%s*%s*%s",
		typ, hexLower(salt), hexLower(verifier), hexLower(vhash))
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

// atoiOK 是 strconv.Atoi 的"成功才返回"包装（拒绝负数）。
func atoiOK(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil && n >= 0
}
