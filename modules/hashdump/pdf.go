// 加密 PDF 的哈希提取（hashcat -m 10400/10500/10600/10700）。
//
// 只需要 /Encrypt 字典与 trailer 的 /ID，因此不做完整的 PDF 解析：
// 定位文件末尾的 trailer（或 PDF 1.5+ 的交叉引用流字典），取出 /Encrypt 与 /ID，
// 若 /Encrypt 是间接引用再按 "N G obj" 找到该对象。
//
// 输出格式（与 john 的 pdf2john 一致，已用 hashcat v7.1.2 实测可破）：
//
//	V<=4: $pdf$V*R*Length*P*EncryptMetadata*id0len*id0*ulen*U*olen*O
//	V=5 : $pdf$5*R*Length*P*EncryptMetadata*id0len*id0*ulen*U*olen*O*uelen*UE*oelen*OE
//
// 模式选择（由 V/R 决定，实测确认）：
//
//	V=1/R=2 -> 10400（RC4-40）
//	V=2/R=3 -> 10500（RC4-128）
//	V=4/R=4 -> 10500（AES-128）
//	V=5/R=5 -> 10600（AES-256）
//	V=5/R=6 -> 10700（AES-256，强化 KDF）
package hashdump

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"

	"gyhost/internal/i18n"
)

// maxPDFSize 是 PDF 解析上限。加密字典与 /ID 都靠近文件首尾，
// 超大文件解析没有意义，这里直接拒绝以免占用过多内存。
const maxPDFSize = 64 << 20

// magicPDF 是 PDF 文件头魔数。
var magicPDF = []byte("%PDF-")

// pdfEnc 是 /Encrypt 字典中本模块需要的字段。
type pdfEnc struct {
	v, r    int
	length  int
	p       int64
	encMeta bool
	o, u    []byte
	oe, ue  []byte
	id0     []byte
}

// extractPDF 从加密 PDF 中提取 hashcat $pdf$ 哈希。
func extractPDF(f io.ReaderAt, size int64, path string) (*Result, error) {
	res := &Result{Path: path, Kind: "pdf"}
	name := filepath.Base(path)

	if size <= 0 || size > maxPDFSize {
		res.addSkip(name, i18n.Tf("hashdump.pdf.skip.size", size))
		return res, nil
	}
	data := make([]byte, size)
	if _, err := f.ReadAt(data, 0); err != nil && !errors.Is(err, io.EOF) {
		return nil, errBroken("pdf read: %v", err)
	}
	if !bytes.HasPrefix(data, magicPDF) {
		return nil, errors.New(i18n.Tf("hashdump.err.unrecognized", path))
	}

	enc, ok := pdfParseEncrypt(data)
	if !ok {
		res.addSkip(name, i18n.T("hashdump.pdf.skip.no_encrypt"))
		return res, nil
	}
	if len(enc.id0) == 0 {
		// 有 /Encrypt 却取不到 /ID[0]：拿不到密钥派生要用的文件标识，无法校验口令
		res.addSkip(name, i18n.T("hashdump.pdf.skip.no_id"))
		return res, nil
	}
	mode := pdfMode(enc.v, enc.r)
	if mode == 0 {
		res.addSkip(name, i18n.Tf("hashdump.pdf.skip.version", enc.v, enc.r))
		return res, nil
	}
	line, ok := pdfBuildHash(enc, mode)
	if !ok {
		res.addSkip(name, i18n.Tf("hashdump.pdf.skip.broken", enc.v, enc.r))
		return res, nil
	}
	res.addEntry(name, mode, line)
	return res, nil
}

// pdfMode 按 (V, R) 选择 hashcat 模式号；未知组合返回 0。
func pdfMode(v, r int) int {
	switch {
	case v == 1:
		return 10400
	case v == 5 && r == 6:
		return 10700
	case v == 5:
		return 10600
	case v == 2, v == 3, v == 4:
		return 10500
	}
	return 0
}

// pdfBuildHash 按模式拼出 hashcat 哈希行。
func pdfBuildHash(e *pdfEnc, mode int) (string, bool) {
	if len(e.id0) == 0 || len(e.u) == 0 || len(e.o) == 0 {
		return "", false
	}
	encMeta := 0
	if e.encMeta {
		encMeta = 1
	}
	line := fmt.Sprintf("$pdf$%d*%d*%d*%d*%d*%d*%s*%d*%s*%d*%s",
		e.v, e.r, e.length, e.p, encMeta,
		len(e.id0), hexLower(e.id0),
		len(e.u), hexLower(e.u),
		len(e.o), hexLower(e.o))

	// V=5（AES-256）额外带上 /UE 与 /OE
	if mode == 10600 || mode == 10700 {
		if len(e.ue) == 0 || len(e.oe) == 0 {
			return "", false
		}
		line += fmt.Sprintf("*%d*%s*%d*%s",
			len(e.ue), hexLower(e.ue), len(e.oe), hexLower(e.oe))
	}
	return line, true
}

// ---------------------------------------------------------------------------
// PDF 对象解析
// ---------------------------------------------------------------------------

// pdfParseEncrypt 解析出 /Encrypt 字典与 /ID 中的所需字段。
func pdfParseEncrypt(data []byte) (*pdfEnc, bool) {
	trailer, ok := pdfTrailerDict(data)
	if !ok {
		return nil, false
	}

	// /Encrypt：可能是内联字典，也可能是 "N G R" 间接引用
	val, ok := pdfGet(trailer, "Encrypt")
	if !ok {
		return nil, false
	}
	dict, ok := pdfResolveDict(data, val)
	if !ok {
		return nil, false
	}
	// 只处理标准安全处理器
	if f, ok := pdfGet(dict, "Filter"); !ok || !bytes.Contains(f, []byte("Standard")) {
		return nil, false
	}

	e := &pdfEnc{encMeta: true}
	if v, ok := pdfInt(dict, "V"); ok {
		e.v = int(v)
	}
	if r, ok := pdfInt(dict, "R"); ok {
		e.r = int(r)
	}
	if p, ok := pdfInt(dict, "P"); ok {
		// /P 规范上是有符号 32 位（常为 -4 等），但个别文件写成无符号
		//（4294967292 即 -4）；统一折回有符号，否则本模块自己都解析不了
		e.p = int64(int32(p))
	}
	// /Length 缺失或越界时按 V 取默认密钥长度：V=1 固定 40 位、V=2/3/4 为 128 位、
	// V=5 固定 256 位。少了这一步会输出 "0"，hashcat 的 $pdf$ 字段是定长的
	//（-m 10400 要 2 位、10500/10600/10700 要 3 位），直接报 Token length exception。
	if l, ok := pdfInt(dict, "Length"); ok && l >= 40 && l <= 256 && l%8 == 0 {
		e.length = int(l)
	} else {
		e.length = pdfDefaultLength(e.v)
	}
	if m, ok := pdfGet(dict, "EncryptMetadata"); ok && bytes.Contains(m, []byte("false")) {
		e.encMeta = false
	}
	e.o, _ = pdfString(dict, "O")
	e.u, _ = pdfString(dict, "U")
	e.oe, _ = pdfString(dict, "OE")
	e.ue, _ = pdfString(dict, "UE")

	// /ID 是数组，取第一个元素
	if idv, ok := pdfGet(trailer, "ID"); ok {
		e.id0, _ = pdfFirstArrayStr(idv)
	}
	if e.v == 0 || e.r == 0 {
		return nil, false
	}
	return e, true
}

// pdfDefaultLength 给出 /Length 缺失时的默认密钥长度（位）。
func pdfDefaultLength(v int) int {
	switch v {
	case 1:
		return 40
	case 2, 3, 4:
		return 128
	case 5:
		return 256
	}
	return 0
}

// pdfTrailerDict 定位文件末尾的 trailer 字典。
//
// 经典 PDF 取最后一个 "trailer" 关键字后的字典；PDF 1.5+ 的交叉引用流
// 没有 trailer 关键字，改从 startxref 指向的对象里取字典。
func pdfTrailerDict(data []byte) ([]byte, bool) {
	if i := bytes.LastIndex(data, []byte("trailer")); i >= 0 {
		if d, _, ok := pdfDictAt(data, i); ok {
			return d, true
		}
	}
	if i := bytes.LastIndex(data, []byte("startxref")); i >= 0 {
		if off, ok := pdfIntAt(data, i+len("startxref")); ok && off > 0 && off < int64(len(data)) {
			if d, _, ok := pdfDictAt(data, int(off)); ok {
				return d, true
			}
		}
	}
	return nil, false
}

// pdfResolveDict 把 /Encrypt 的取值解析成字典：内联字典直接返回，
// "N G R" 引用则找到 "N G obj" 对应的对象再取其中的字典。
func pdfResolveDict(data, val []byte) ([]byte, bool) {
	if len(val) >= 2 && val[0] == '<' && val[1] == '<' {
		return val, true
	}
	f := bytes.Fields(val)
	if len(f) == 3 && string(f[2]) == "R" {
		num, err1 := strconv.Atoi(string(f[0]))
		gen, err2 := strconv.Atoi(string(f[1]))
		if err1 != nil || err2 != nil {
			return nil, false
		}
		return pdfFindObject(data, num, gen)
	}
	return nil, false
}

// pdfFindObject 定位 "N G obj" 并返回其中的字典。
func pdfFindObject(data []byte, num, gen int) ([]byte, bool) {
	pat := []byte(fmt.Sprintf("%d %d obj", num, gen))
	i := bytes.Index(data, pat)
	if i < 0 {
		return nil, false
	}
	start := i + len(pat)
	end := bytes.Index(data[start:], []byte("endobj"))
	if end < 0 {
		return nil, false
	}
	if d, _, ok := pdfDictAt(data[start:start+end], 0); ok {
		return d, true
	}
	return nil, false
}

// pdfDictAt 从 data[from:] 找到第一个字典，返回其完整字节（含 << >>）与结束下标。
func pdfDictAt(data []byte, from int) ([]byte, int, bool) {
	for i := from; i+1 < len(data); i++ {
		if data[i] != '<' || data[i+1] != '<' {
			continue
		}
		depth := 0
		for j := i; j < len(data); {
			switch {
			case data[j] == '<' && j+1 < len(data) && data[j+1] == '<':
				depth++
				j += 2
				continue
			case data[j] == '>' && j+1 < len(data) && data[j+1] == '>':
				depth--
				j += 2
				if depth == 0 {
					return data[i:j], j, true
				}
				continue
			case data[j] == '(':
				j = pdfSkipLiteral(data, j)
				continue
			case data[j] == '<':
				j = pdfSkipHex(data, j)
				continue
			case data[j] == '%':
				for j < len(data) && data[j] != '\n' && data[j] != '\r' {
					j++
				}
				continue
			}
			j++
		}
		return nil, 0, false
	}
	return nil, 0, false
}

// pdfSkipLiteral 跳过 (...) 字面量字符串，返回结束后的下标。
func pdfSkipLiteral(data []byte, at int) int {
	depth := 0
	for i := at; i < len(data); i++ {
		switch data[i] {
		case '\\':
			i++
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(data)
}

// pdfSkipHex 跳过 <...> 十六进制字符串，返回结束后的下标。
func pdfSkipHex(data []byte, at int) int {
	for i := at + 1; i < len(data); i++ {
		if data[i] == '>' {
			return i + 1
		}
	}
	return len(data)
}

// pdfSkipArray 跳过 [ ... ]，返回结束后的下标。
func pdfSkipArray(data []byte, at int) (int, bool) {
	depth := 0
	for i := at; i < len(data); i++ {
		switch data[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i + 1, true
			}
		case '(':
			i = pdfSkipLiteral(data, i) - 1
		case '<':
			if i+1 < len(data) && data[i+1] != '<' {
				i = pdfSkipHex(data, i) - 1
			}
		}
	}
	return 0, false
}

// pdfGet 在字典中取出 key 对应的值（原始 token）。
func pdfGet(dict []byte, key string) ([]byte, bool) {
	needle := []byte("/" + key)
	for i := 0; i+len(needle) <= len(dict); i++ {
		if !bytes.HasPrefix(dict[i:], needle) {
			continue
		}
		// 键名后必须是空白或分隔符，避免 /ID 误配 /IDTree 之类
		next := i + len(needle)
		if next < len(dict) && !pdfIsDelim(dict[next]) && !pdfIsSpace(dict[next]) {
			continue
		}
		tok, _, ok := pdfToken(dict, next)
		return tok, ok
	}
	return nil, false
}

// pdfToken 跳过空白后读取一个 PDF 对象 token。
//
// 除字典/数组/字符串外，还会把 "N G R" 形式的间接引用整体读出。
func pdfToken(data []byte, from int) ([]byte, int, bool) {
	i := pdfSkipSpace(data, from)
	if i >= len(data) {
		return nil, 0, false
	}
	switch data[i] {
	case '<':
		if i+1 < len(data) && data[i+1] == '<' {
			return pdfDictAt(data, i)
		}
		end := pdfSkipHex(data, i)
		return data[i:end], end, true
	case '[':
		end, ok := pdfSkipArray(data, i)
		if !ok {
			return nil, 0, false
		}
		return data[i:end], end, true
	case '(':
		end := pdfSkipLiteral(data, i)
		return data[i:end], end, true
	case '/':
		// 名字对象：从 '/' 读到下一个空白或分隔符
		j := i + 1
		for j < len(data) && !pdfIsSpace(data[j]) && !pdfIsDelim(data[j]) {
			j++
		}
		return data[i:j], j, true
	}

	j := i
	for j < len(data) && !pdfIsSpace(data[j]) && !pdfIsDelim(data[j]) {
		j++
	}
	if j == i {
		return nil, 0, false
	}
	// 形如 "N G R" 的间接引用：整体返回，便于调用方识别
	if _, err := strconv.Atoi(string(data[i:j])); err == nil {
		if k, ok := pdfRefEnd(data, j); ok {
			return data[i:k], k, true
		}
	}
	return data[i:j], j, true
}

// pdfRefEnd 在已读入一个数字后，继续匹配 "<num> R"（间接引用的后两段）。
func pdfRefEnd(data []byte, from int) (int, bool) {
	i := pdfSkipSpace(data, from)
	j := i
	for j < len(data) && !pdfIsSpace(data[j]) && !pdfIsDelim(data[j]) {
		j++
	}
	if j == i {
		return 0, false
	}
	if _, err := strconv.Atoi(string(data[i:j])); err != nil {
		return 0, false
	}
	k := pdfSkipSpace(data, j)
	if k < len(data) && data[k] == 'R' {
		return k + 1, true
	}
	return 0, false
}

// pdfSkipSpace 跳过 PDF 空白字符。
func pdfSkipSpace(data []byte, from int) int {
	i := from
	for i < len(data) && pdfIsSpace(data[i]) {
		i++
	}
	return i
}

// pdfString 取字典中某个键的字符串值。
//
// PDF 的字符串有 <hex> 与 (...) 两种写法，/O /U 等字段两者都常见，需都支持。
func pdfString(dict []byte, key string) ([]byte, bool) {
	v, ok := pdfGet(dict, key)
	if !ok || len(v) < 2 {
		return nil, false
	}
	switch v[0] {
	case '<':
		if v[1] == '<' { // 字典，不是字符串
			return nil, false
		}
		return pdfDecodeHex(v[1 : len(v)-1])
	case '(':
		return pdfUnescapeLiteral(v[1 : len(v)-1]), true
	}
	return nil, false
}

// pdfUnescapeLiteral 还原 PDF 字面量字符串中的转义（PDF 32000-1 §7.3.4.2）。
func pdfUnescapeLiteral(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			out = append(out, b[i])
			continue
		}
		i++
		if i >= len(b) {
			break
		}
		switch c := b[i]; c {
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case '(', ')', '\\':
			out = append(out, c)
		case '\n':
			// 反斜杠 + 换行 = 续行，忽略
		case '\r':
			if i+1 < len(b) && b[i+1] == '\n' {
				i++
			}
		default:
			if c >= '0' && c <= '7' {
				// 最多三位八进制
				v, n := 0, 0
				for n < 3 && i < len(b) && b[i] >= '0' && b[i] <= '7' {
					v = v*8 + int(b[i]-'0')
					i++
					n++
				}
				i--
				out = append(out, byte(v))
			} else {
				out = append(out, c)
			}
		}
	}
	return out
}

// pdfInt 取字典中某个键的整数值。
func pdfInt(dict []byte, key string) (int64, bool) {
	v, ok := pdfGet(dict, key)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(string(bytes.TrimSpace(v)), 10, 64)
	return n, err == nil
}

// pdfIntAt 从 data[from:] 读一个整数。
func pdfIntAt(data []byte, from int) (int64, bool) {
	i := pdfSkipSpace(data, from)
	j := i
	for j < len(data) && !pdfIsSpace(data[j]) && !pdfIsDelim(data[j]) {
		j++
	}
	if j == i {
		return 0, false
	}
	n, err := strconv.ParseInt(string(data[i:j]), 10, 64)
	return n, err == nil
}

// pdfHex 取字典中某个键的十六进制字符串值。
func pdfHex(dict []byte, key string) ([]byte, bool) {
	v, ok := pdfGet(dict, key)
	if !ok || len(v) < 2 || v[0] != '<' {
		return nil, false
	}
	return pdfDecodeHex(v[1 : len(v)-1])
}

// pdfFirstArrayStr 取数组里第一个字符串元素：<hex> 与 (literal) 两种写法都要认，
// 少数文件把 /ID[0] 写成带转义的二进制字面量。
func pdfFirstArrayStr(arr []byte) ([]byte, bool) {
	for i := 0; i < len(arr); i++ {
		switch {
		case arr[i] == '<' && (i+1 >= len(arr) || arr[i+1] != '<'):
			end := pdfSkipHex(arr, i)
			if end-1 > i+1 {
				return pdfDecodeHex(arr[i+1 : end-1])
			}
		case arr[i] == '(':
			end := pdfSkipLiteral(arr, i)
			if end-1 > i+1 {
				return pdfUnescapeLiteral(arr[i+1 : end-1]), true
			}
		}
	}
	return nil, false
}

// pdfDecodeHex 解析十六进制串（忽略空白），奇数长度时末尾补 0。
func pdfDecodeHex(b []byte) ([]byte, bool) {
	clean := make([]byte, 0, len(b))
	for _, c := range b {
		if !pdfIsSpace(c) {
			clean = append(clean, c)
		}
	}
	if len(clean)%2 == 1 {
		clean = append(clean, '0')
	}
	out, err := hex.DecodeString(string(clean))
	if err != nil {
		return nil, false
	}
	return out, true
}

// pdfIsSpace 判断 PDF 空白字符。
func pdfIsSpace(c byte) bool {
	switch c {
	case 0x00, 0x09, 0x0A, 0x0C, 0x0D, 0x20:
		return true
	}
	return false
}

// pdfIsDelim 判断 PDF 分隔符。
func pdfIsDelim(c byte) bool {
	switch c {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	}
	return false
}
