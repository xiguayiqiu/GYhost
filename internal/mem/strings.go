package mem

import (
	"unicode/utf8"
)

// StringEnc 表示字符串的编码来源。
type StringEnc uint8

const (
	// EncASCII 单字节 ASCII 串。
	EncASCII StringEnc = iota
	// EncUTF16LE UTF-16LE 串，Windows 宽字符 API 的产物。
	EncUTF16LE
)

// String 返回编码名。
func (e StringEnc) String() string {
	if e == EncUTF16LE {
		return "utf16le"
	}
	return "ascii"
}

// StringHit 是一条被提取出来的字符串。
type StringHit struct {
	Offset uint64    // 相对镜像起点的偏移（虚拟地址）
	Value  string    // 已去掉尾部填充的字符串内容
	Enc    StringEnc // 编码
}

// StringOpts 控制字符串提取行为。
type StringOpts struct {
	// MinLen 是字符串最小长度（默认 4）。
	MinLen int
	// ASCII 是否提取单字节串。
	ASCII bool
	// UTF16 是否提取 UTF-16LE 宽字符串。
	UTF16 bool
	// MinASCII 是一条有效单字节串至少要包含的 ASCII 字符数。
	//
	// 纯高位字节的长串（未初始化的 0xFF 填充、残留的旧数据）没有取证价值，
	// 默认要求至少 4 个真 ASCII 字符；把它设为 0 可以保留全部（如 -A）。
	MinASCII int
	// MaxHit 是单次调用最多返回多少条，0 表示不限。
	MaxHit int
	// Base 是报告里偏移的基准地址（0 表示用绝对偏移）。
	Base uint64
	// Offset 是本次数据块在镜像中的起始地址。
	Offset uint64
}

// DefaultStringOpts 返回默认的字符串提取参数：单字节与 UTF-16LE 都提取。
func DefaultStringOpts() StringOpts {
	return StringOpts{MinLen: 4, ASCII: true, UTF16: true, MinASCII: 4}
}

func (o *StringOpts) normalize() {
	if o.MinLen <= 0 {
		o.MinLen = 4
	}
	if o.MinLen > 4096 {
		o.MinLen = 4096
	}
	if o.MinASCII < 0 {
		o.MinASCII = 0
	}
}

// asciiPrintable 判断字节是否属于“值得提取”的可打印集合。
//
// 保留 ASCII 可打印字符、常见空白（制表/换行/回车）以及 Latin-1 高位区，
// 兼顾中文程序里以单字节存放的 GBK 片段；控制字符一律断开。
func asciiPrintable(b byte) bool {
	switch {
	case b >= 0x20 && b <= 0x7e:
		return true
	case b == '\t' || b == '\n' || b == '\r':
		return true
	case b >= 0x80:
		return true
	default:
		return false
	}
}

// ExtractStrings 从一段内存数据中提取 ASCII（可选 UTF-16LE）字符串，
// 逐条回调给 visit。
//
// 数据块之间可能把一个字符串截断（例如读取窗口切在串中间），
// 因此调用方应把相邻数据块拼接后再调用本函数，或接受边界处漏提取。
// visit 返回错误时立即停止并把该错误向上传递。
func ExtractStrings(data []byte, opt StringOpts, visit func(StringHit) error) error {
	opt.normalize()
	if len(data) == 0 {
		return nil
	}
	hits := 0
	if !opt.ASCII {
		return extractUTF16(data, opt, visit)
	}
	// 单字节扫描：遇到非可打印字节即结算当前串
	var (
		start    int = -1
		buf      []byte
		asciiCnt int
	)
	flushASCII := func(end int) error {
		if start < 0 {
			return nil
		}
		// 纯高位字节的长串（未初始化的 0xFF/0x80 填充）没有取证价值，
		// 要求至少含 MinASCII 个真 ASCII 可打印字符才算一条有效串。
		if end-start >= opt.MinLen && asciiCnt >= minASCII(opt.MinLen, opt.MinASCII) {
			if opt.MaxHit > 0 && hits >= opt.MaxHit {
				start = -1
				return nil
			}
			hits++
			if err := visit(StringHit{
				Offset: opt.Base + opt.Offset + uint64(start),
				Value:  trimString(string(buf)),
				Enc:    EncASCII,
			}); err != nil {
				return err
			}
		}
		start, buf = -1, buf[:0]
		asciiCnt = 0
		return nil
	}
	for i := 0; i < len(data); i++ {
		c := data[i]
		if asciiPrintable(c) {
			if start < 0 {
				start = i
				asciiCnt = 0
			}
			buf = append(buf, c)
			if c >= 0x20 && c <= 0x7e {
				asciiCnt++
			}
			continue
		}
		if err := flushASCII(i); err != nil {
			return err
		}
	}
	if err := flushASCII(len(data)); err != nil {
		return err
	}

	return extractUTF16(data, opt, func(h StringHit) error {
		hits++
		return visit(h)
	})
}

// extractUTF16 提取 UTF-16LE 宽字符串（Windows 宽字符 API 的产物）。
//
// 判定规则很简单：高字节为 0、低字节可打印的码元算作宽字符，
// 遇到不满足的码元即断开当前串。
func extractUTF16(data []byte, opt StringOpts, visit func(StringHit) error) error {
	if !opt.UTF16 {
		return nil
	}
	var (
		start = -1
		hits  int
	)
	flush := func(end int) error {
		if start < 0 {
			return nil
		}
		n := (end - start) / 2
		if n >= opt.MinLen {
			if opt.MaxHit > 0 && hits >= opt.MaxHit {
				start = -1
				return nil
			}
			raw := make([]byte, 0, n*3)
			for i := start; i+1 < end; i += 2 {
				r := rune(data[i]) | rune(data[i+1])<<8
				if r == 0 {
					break
				}
				raw = utf8.AppendRune(raw, r)
			}
			hits++
			if err := visit(StringHit{
				Offset: opt.Base + opt.Offset + uint64(start),
				Value:  trimString(string(raw)),
				Enc:    EncUTF16LE,
			}); err != nil {
				return err
			}
		}
		start = -1
		return nil
	}
	for i := 0; i+1 < len(data); i += 2 {
		lo, hi := data[i], data[i+1]
		if hi != 0 || lo < 0x20 || lo > 0x7e {
			if err := flush(i); err != nil {
				return err
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	return flush(len(data) - 1)
}

// minASCII 返回一条有效单字节串至少要包含的 ASCII 字符数。
//
// 短串（MinLen <= 4）要求全部为 ASCII；长串允许夹杂少量高位字节，
// 以保留 GBK 之类单字节存放的中文片段。
// want <= 0 表示不限制（对应 -A：保留非 ASCII 串）。
func minASCII(minLen, want int) int {
	if want <= 0 {
		return 0
	}
	if minLen <= 4 {
		return minLen
	}
	return want
}

// trimString 去掉字符串首尾的空白字符。
func trimString(s string) string {
	start, end := 0, len(s)
	isSpace := func(b byte) bool {
		return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == 0
	}
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}
