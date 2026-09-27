// Package hashdump 实现 GYhost 的第二个功能模块：
// 从加密的 zip/7z/rar 压缩包与 pcap/pcapng 无线抓包中提取可离线枚举的哈希，
// 交给 hashcat 爆破。
package hashdump

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gyhost/internal/i18n"
)

// hashcat 各模式对"内联数据"的解析上限（与 hashcat 源码保持一致）：
//
//	-m 17200/17210 MAX_DATA        = 320 KiB（同时约束压缩长度与数据长度）
//	-m 13600 token[7] len_max      = 0x200000*4*2-2 个十六进制字符
//	-m 11600 token[10] len_max     = 0x200000*4*2   个十六进制字符
//
// 统一按"十六进制字符数 / 2"换算成字节数。
const (
	maxPKZIPData  = 320 * 1024        // 327680
	maxInlineData = 0x200000*4*2 - 2  // 16777214 个十六进制字符
	maxInlineByte = maxInlineData / 2 // 8388607 字节
)

// 三类压缩包的魔数。
var (
	magicZip = []byte("PK")
	magic7z  = []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}
	magicRar = []byte("Rar!\x1a\x07")
)

// Entry 是从压缩包中提取出的一条可离线枚举的哈希。
type Entry struct {
	Archive string // 压缩包路径
	Kind    string // 压缩包类型: zip / 7z / rar
	Name    string // 条目名（文件名），无法获取时为空
	Mode    int    // hashcat 模式号
	Hash    string // hashcat 兼容哈希串
}

// Skip 记录一个被跳过的条目及原因（文案已按当前语言生成）。
type Skip struct {
	Name   string // 条目名
	Reason string // 跳过原因
}

// Result 是单个压缩包的提取结果。
type Result struct {
	Path    string // 压缩包路径
	Kind    string // 压缩包类型: zip / 7z / rar
	Entries []Entry
	Skipped []Skip
}

// addEntry / addSkip 便于各格式解析器填充结果。
func (r *Result) addEntry(name string, mode int, hash string) {
	r.Entries = append(r.Entries, Entry{
		Archive: r.Path,
		Kind:    r.Kind,
		Name:    name,
		Mode:    mode,
		Hash:    hash,
	})
}

func (r *Result) addSkip(name, reason string) {
	r.Skipped = append(r.Skipped, Skip{Name: name, Reason: reason})
}

// Extract 按魔数识别输入类型并提取其中的哈希。
//
// 压缩包（zip/7z/rar）与无线抓包（pcap/pcapng）都走这里：
// 前者产出 hashcat -m 17200/13600/11600/13000 等哈希，
// 后者产出 WPA/WPA2 的 -m 22000（PMKID / 四次握手）哈希。
//
// 文件打不开是致命错误；格式无法识别/暂不支持由调用方决定是否继续。
func Extract(path string) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New(i18n.Tf("hashdump.err.open", path, err))
	}
	defer f.Close()

	var size int64
	if st, err := f.Stat(); err == nil {
		size = st.Size()
	}

	magic := make([]byte, 8)
	n, _ := f.ReadAt(magic, 0)
	magic = magic[:n]

	switch {
	case len(magic) >= 2 && string(magic[:2]) == string(magicZip):
		return extractZip(f, size, path)
	case len(magic) >= 6 && string(magic[:6]) == string(magic7z):
		return extract7z(f, size, path)
	case len(magic) >= 7 && string(magic[:6]) == string(magicRar):
		// RAR5 签名 = "Rar!\x1a\x07\x01\x00"，RAR4 = "Rar!\x1a\x07\x00"，
		// 区别在第 7 个字节（0x01 vs 0x00）。
		if magic[6] == 0x01 {
			return extractRAR5(f, size, path)
		}
		return nil, errors.New(i18n.Tf("hashdump.err.rar4", path))
	case len(magic) >= 5 && string(magic[:5]) == string(magicPDF):
		return extractPDF(f, size, path)
	case len(magic) >= len(magicOLE) && string(magic[:len(magicOLE)]) == string(magicOLE):
		// 加密的 OOXML 与 Word/Excel/PPT 老格式都是 OLE 复合文档
		return extractOffice(f, size, path)
	case isPCAPMagic(magic) || isPCAPNGMagic(magic):
		return extractCapture(f, size, path)
	default:
		return nil, errors.New(i18n.Tf("hashdump.err.unrecognized", path))
	}
}

// errBroken 封装结构类错误，统一由 i18n 渲染。
func errBroken(format string, a ...any) error {
	return errors.New(i18n.Tf("hashdump.err.bad_header", fmt.Sprintf(format, a...)))
}

// ---------------------------------------------------------------------------
// 读取辅助
// ---------------------------------------------------------------------------

// readAt 从 off 处读取恰好 n 字节，越界或不足一律报错。
func readAt(r io.ReaderAt, size, off, n int64) ([]byte, error) {
	if off < 0 || n < 0 || off+n > size {
		return nil, errBroken("offset %d+%d beyond %d", off, n, size)
	}
	b := make([]byte, n)
	if _, err := r.ReadAt(b, off); err != nil {
		return nil, err
	}
	return b, nil
}

// reader 是带越界保护的小端序游标。
type reader struct {
	b   []byte
	off int
	err error
}

func newReader(b []byte) *reader { return &reader{b: b} }

func (r *reader) fail() {
	if r.err == nil {
		r.err = errors.New("eof")
	}
}

func (r *reader) take(n int) []byte {
	if r.err != nil || n < 0 || r.off+n > len(r.b) {
		r.fail()
		return nil
	}
	s := r.b[r.off : r.off+n]
	r.off += n
	return s
}

func (r *reader) u8() uint8 {
	s := r.take(1)
	if s == nil {
		return 0
	}
	return s[0]
}

func (r *reader) u16() uint16 {
	s := r.take(2)
	if s == nil {
		return 0
	}
	return binary.LittleEndian.Uint16(s)
}

func (r *reader) u32() uint32 {
	s := r.take(4)
	if s == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(s)
}

func (r *reader) u64() uint64 {
	s := r.take(8)
	if s == nil {
		return 0
	}
	return binary.LittleEndian.Uint64(s)
}

// vint 解析 RAR5 的变长整数（LEB128：低 7 位有效，最高位为续位）。
func (r *reader) vint() uint64 {
	var v uint64
	var shift uint
	for i := 0; i < 10; i++ {
		c := r.u8()
		if r.err != nil {
			return 0
		}
		v |= uint64(c&0x7f) << shift
		shift += 7
		if c&0x80 == 0 {
			return v
		}
	}
	r.fail()
	return 0
}

// skip 跳过 n 字节。
func (r *reader) skip(n int) { r.take(n) }

// rest 返回剩余字节。
func (r *reader) rest() []byte {
	s := r.take(len(r.b) - r.off)
	return s
}

func (r *reader) remaining() int {
	if r.err != nil {
		return 0
	}
	return len(r.b) - r.off
}

func (r *reader) eof() bool { return r.err != nil || r.off >= len(r.b) }

// ---------------------------------------------------------------------------
// 路径解析
// ---------------------------------------------------------------------------

// inputExt 是目录扫描时接受的扩展名（压缩包、加密文档与无线抓包）。
var inputExt = map[string]bool{
	".zip": true, ".zipx": true, ".7z": true, ".7za": true, ".rar": true,
	".cap": true, ".pcap": true, ".pcapng": true,
	".pdf": true,
	// Office / WPS 文档（加密时同样是可提取口令哈希的容器）
	".doc": true, ".docx": true, ".docm": true,
	".xls": true, ".xlsx": true, ".xlsm": true,
	".ppt": true, ".pptx": true, ".pps": true, ".ppsx": true,
	".wps": true, ".et": true, ".dps": true,
}

// resolveInputs 展开输入列表：文件原样保留，目录按扩展名扫描。
// 结果按出现顺序去重，避免同一个文件被反复提取。
func resolveInputs(inputs []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range inputs {
		st, err := os.Stat(p)
		if err != nil {
			return nil, errors.New(i18n.Tf("hashdump.err.open", p, err))
		}
		if !st.IsDir() {
			add(p)
			continue
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, errors.New(i18n.Tf("hashdump.err.open", p, err))
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if inputExt[strings.ToLower(filepath.Ext(e.Name()))] {
				add(filepath.Join(p, e.Name()))
			}
		}
	}
	return out, nil
}

// modesOf 汇总结果中出现过的 hashcat 模式（去重排序）。
func modesOf(r *Result) []int {
	seen := map[int]bool{}
	var out []int
	for _, e := range r.Entries {
		if !seen[e.Mode] {
			seen[e.Mode] = true
			out = append(out, e.Mode)
		}
	}
	sortInts(out)
	return out
}

func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// joinModes 把模式列表拼成 "17200,17210"。
func joinModes(modes []int) string {
	s := make([]string, 0, len(modes))
	for _, m := range modes {
		s = append(s, fmt.Sprintf("%d", m))
	}
	return strings.Join(s, ",")
}

// hexLower 统一使用小写十六进制（与 hashcat 编码器一致）。
func hexLower(b []byte) string { return hex.EncodeToString(b) }
