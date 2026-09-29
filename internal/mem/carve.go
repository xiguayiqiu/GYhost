package mem

import (
	"bytes"
	"strings"
)

// MaxCarveSize 是单个被雕取文件的上限，防止误命中魔数后把整段内存读进来。
const MaxCarveSize = 64 << 20 // 64 MiB

// DefaultCarveWindow 是既无长度字段又无尾标记时默认截取的字节数。
const DefaultCarveWindow = 8 << 20 // 8 MiB

// MinCarveScore 是可接受结果的最低置信度。
//
// 90=长度字段自洽，80=尾标记命中，45=长度字段声明超出本块（跨块），
// 25=只能按窗口截断。低于 40 的结果一律不输出。
const MinCarveScore = 40

// CarveType 描述一类可从内存中恢复的文件：魔数 + 长度推导方式。
type CarveType struct {
	// Name 类型标识，如 "png"，用于过滤与报告。
	Name string
	// Ext 恢复出来时的建议扩展名。
	Ext string
	// Magic 魔数（文件头）。
	Magic []byte
	// Offset 魔数在文件内的偏移（部分格式魔数不在第 0 字节）。
	Offset int
	// Footer 文件尾标记；命中后以该标记结束的位置作为文件长度。
	Footer []byte
	// SizeFrom 从文件头解析长度；ok=false 时退回启发式。
	SizeFrom func(head []byte) (size int, ok bool)
	// Validate 做格式自洽性校验，返回 false 表示这是魔数误命中。
	//
	// 只有魔数过短（如 2 字节的 "BM"、4 字节的 "RIFF"）的格式才需要它：
	// 内存里这类字节序列的出现频率远高于真实文件。
	Validate func(head []byte) bool
}

// Carved 是一次雕取的结果。
type Carved struct {
	Type      string
	Ext       string
	Offset    uint64 // 在内存镜像中的偏移
	Size      int
	Data      []byte
	Hash      HashSet
	Truncated bool // 因超过长度上限而被截断
	Score     int  // 0~100 置信度
}

// CarveFilters 解析 -t 参数得到的类型过滤集合（nil 表示不过滤）。
type CarveFilters map[string]bool

// ParseCarveTypes 解析类型过滤串（逗号分隔），支持 all；空串返回 nil。
func ParseCarveTypes(s string) CarveFilters {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "all") {
		return nil
	}
	out := CarveFilters{}
	for _, part := range strings.Split(s, ",") {
		if p := strings.ToLower(strings.TrimSpace(part)); p != "" {
			out[p] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Match 判断给定类型是否命中过滤条件。
func (f CarveFilters) Match(name string) bool {
	if f == nil {
		return true
	}
	return f[strings.ToLower(name)]
}

// CarveTypes 返回支持的雕取类型名（供帮助与报错提示使用）。
func CarveTypes() []string {
	seen := map[string]bool{}
	var out []string
	for _, ct := range carveTypes {
		if !seen[ct.Name] {
			seen[ct.Name] = true
			out = append(out, ct.Name)
		}
	}
	return out
}

// zipEOCD 是 zip 中央目录结束记录。
var zipEOCD = []byte{'P', 'K', 0x05, 0x06}

// lnkHeader 是 Windows Shell Link 的固定 24 字节文件头。
//
// 只用 4 字节的 4C 00 00 00 会命中大量无关数据，
// 因此这里带上后续的固定字段作为强校验。
var lnkHeader = []byte{
	'L', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
}

// carveTypes 是支持的雕取类型表。
//
// 只收录在内存中出现频率高、且魔数足够独特的格式；魔数宽松的格式
// （如裸 "MZ"）配了 SizeFrom 做二次校验，避免把噪声整段切出来。
var carveTypes = []CarveType{
	{Name: "png", Ext: "png", Magic: []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a},
		Footer: []byte("IEND\xae\x42\x60\x82"), SizeFrom: pngSize},
	{Name: "jpg", Ext: "jpg", Magic: []byte{0xff, 0xd8, 0xff}, Footer: []byte{0xff, 0xd9}, Validate: jpegValid},
	{Name: "gif", Ext: "gif", Magic: []byte("GIF8"), Footer: []byte{0x00, 0x3b}, Validate: gifValid},
	{Name: "pdf", Ext: "pdf", Magic: []byte("%PDF-"), Footer: []byte("%%EOF"), Validate: pdfValid},
	{Name: "zip", Ext: "zip", Magic: []byte{'P', 'K', 0x03, 0x04}, Footer: zipEOCD, SizeFrom: zipSize, Validate: zipValid},
	{Name: "gzip", Ext: "gz", Magic: []byte{0x1f, 0x8b, 0x08}},
	{Name: "bmp", Ext: "bmp", Magic: []byte{'B', 'M'}, SizeFrom: bmpSize},
	{Name: "elf", Ext: "elf", Magic: []byte{0x7f, 'E', 'L', 'F'}, SizeFrom: elfSize},
	{Name: "sqlite", Ext: "sqlite", Magic: []byte("SQLite format 3\x00"), SizeFrom: sqliteSize},
	{Name: "7z", Ext: "7z", Magic: []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}, SizeFrom: sevenZSize, Validate: sevenZValid},
	{Name: "rar", Ext: "rar", Magic: []byte("Rar!\x1a\x07"), SizeFrom: rarSize},
	{Name: "dex", Ext: "dex", Magic: []byte("dex\n"), SizeFrom: dexSize},
	{Name: "tiff", Ext: "tiff", Magic: []byte{'I', 'I', 0x2a, 0x00}, SizeFrom: tiffSize, Validate: tiffValid},
	{Name: "tiff", Ext: "tiff", Magic: []byte{'M', 'M', 0x00, 0x2a}, SizeFrom: tiffSize, Validate: tiffValid},
	{Name: "wav", Ext: "wav", Magic: []byte("RIFF"), SizeFrom: riffSize, Validate: riffValid},
	{Name: "pe", Ext: "exe", Magic: []byte{'M', 'Z'}, SizeFrom: peSize},
	{Name: "class", Ext: "class", Magic: []byte{0xca, 0xfe, 0xba, 0xbe}},
	{Name: "lnk", Ext: "lnk", Magic: lnkHeader, SizeFrom: lnkSize},
}

// Carve 在一块内存数据中雕取文件，逐个回调给 visit。
//
// 流程：扫描魔数 → 校验 → 推导长度（头部长度字段优先，其次尾标记，
// 最后退回固定窗口）→ 截取内容 → 计算摘要与置信度。
func Carve(data []byte, base uint64, filters CarveFilters, minSize int, visit func(Carved) error) error {
	if minSize < 1 {
		minSize = 1
	}
	for _, ct := range carveTypes {
		if !filters.Match(ct.Name) {
			continue
		}
		for i := 0; i < len(data); {
			rel := bytes.Index(data[i:], ct.Magic)
			if rel < 0 {
				break
			}
			at := i + rel
			i = at + 1
			start := at - ct.Offset
			if start < 0 {
				continue
			}
			c, ok := carveOne(data, start, ct, minSize)
			if !ok {
				continue
			}
			c.Offset = base + uint64(start)
			if err := visit(c); err != nil {
				return err
			}
		}
	}
	return nil
}

// carveOne 从 data[start:] 雕取一个文件。
func carveOne(data []byte, start int, ct CarveType, minSize int) (Carved, bool) {
	rest := data[start:]
	if len(rest) < minSize {
		return Carved{}, false
	}
	// 格式自洽性校验：魔数短的格式靠它排除误命中
	if ct.Validate != nil && !ct.Validate(rest) {
		return Carved{}, false
	}
	limit := len(rest)
	if limit > MaxCarveSize {
		limit = MaxCarveSize
	}
	size, score := deriveSize(rest, limit, ct)
	if size < minSize || score < MinCarveScore {
		// 置信度过低说明既没有长度字段也没有尾标记，
		// 这样的“文件”多半是魔数误命中，丢弃以免报告被噪声淹没。
		return Carved{}, false
	}
	if size > limit {
		size = limit
	}
	body := make([]byte, size)
	copy(body, rest[:size])
	// 校验：截出来的内容必须仍以魔数开头（保证切片没跑偏）
	if len(body) < ct.Offset+len(ct.Magic) ||
		!bytes.Equal(body[ct.Offset:ct.Offset+len(ct.Magic)], ct.Magic) {
		return Carved{}, false
	}
	return Carved{
		Type:      ct.Name,
		Ext:       ct.Ext,
		Size:      len(body),
		Data:      body,
		Hash:      HashBytes(body),
		Score:     score,
		Truncated: limit == MaxCarveSize && size == limit,
	}, true
}

// deriveSize 推导文件长度与置信度（分数越高越可信）。
func deriveSize(data []byte, limit int, ct CarveType) (int, int) {
	// 1) 头部长度字段最可靠
	if ct.SizeFrom != nil {
		if n, ok := ct.SizeFrom(data); ok && n > 0 {
			if n <= limit {
				return n, 90
			}
			// 声明长度超出本块：可能跨读取块，也可能是魔数误命中
			return limit, 45
		}
	}
	// 2) 尾标记
	if len(ct.Footer) > 0 {
		if idx := bytes.Index(data[:limit], ct.Footer); idx >= 0 {
			return idx + len(ct.Footer), 80
		}
	}
	// 3) 头尾都没有线索：按固定窗口截断，置信度低
	if limit > DefaultCarveWindow {
		limit = DefaultCarveWindow
	}
	return limit, 25
}
