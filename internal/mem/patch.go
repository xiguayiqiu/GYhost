package mem

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// PatchOp 是一次「在内存中操作」请求要执行的动作。
type PatchOp int

const (
	// OpWrite 在指定地址原位写入数据（长度必须与原内容一致）。
	OpWrite PatchOp = iota
	// OpReplace 在指定区域里查找 needle 并替换成 replacement（可不等长）。
	OpReplace
	// OpRestore 按备份记录把内存改回原样（回滚）。
	OpRestore
)

// String 返回动作名。
func (o PatchOp) String() string {
	switch o {
	case OpWrite:
		return "write"
	case OpReplace:
		return "replace"
	case OpRestore:
		return "restore"
	default:
		return "unknown"
	}
}

// PatchSpec 描述一次补丁操作。
type PatchSpec struct {
	Op PatchOp
	// Addr 是 OpWrite 的目标虚拟地址。
	Addr uint64
	// Data 是 OpWrite 要写入的字节。
	Data []byte
	// Region 限定 OpReplace / OpRestore 的作用范围（空 = 全部已选区域）。
	Region string
	// Needle / Replacement 是 OpReplace 的查找与替换内容。
	Needle      []byte
	Replacement []byte
	// MaxCount 限制替换次数，0 表示不限。
	MaxCount int
	// Force 允许写入没有写权限的区域（默认拒绝）。
	Force bool
}

// PatchHit 是一处实际发生的改动。
type PatchHit struct {
	Addr uint64 `json:"addr"`
	// Before / After 是改动前后的内容。
	Before []byte `json:"-"`
	After  []byte `json:"-"`
	// BeforeHex / AfterHex 供报告与备份使用。
	BeforeHex string `json:"before"`
	AfterHex  string `json:"after"`
	// Region 是所在区域描述。
	Region string `json:"region,omitempty"`
	// Applyable 报告改动是否满足写入前提（权限等）。
	Applyable bool `json:"applyable"`
	// Reason 在 Applyable 为 false 时说明原因。
	Reason string `json:"reason,omitempty"`
}

// PatchReport 是一次补丁操作的完整结果。
type PatchReport struct {
	Target string     `json:"target"`
	Op     string     `json:"op"`
	DryRun bool       `json:"dry_run"`
	Hits   []PatchHit `json:"hits"`
	// Skipped 是不满足写入条件的命中数。
	Skipped int `json:"skipped,omitempty"`
	// Written 实际写入的字节数。
	Written int `json:"written,omitempty"`
}

// ParsePatchData 解析 -Y 的取值。
//
// 支持三种写法：
//
//	\\x90\\x90     转义序列（原始字节）
//	@path         从文件读取原始字节
//	hello         其它一律按 UTF-8 原文处理
func ParsePatchData(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, fmt.Errorf("empty patch data")
	}
	if strings.HasPrefix(v, "@") {
		return os.ReadFile(strings.TrimPrefix(v, "@"))
	}
	// 含 \x 转义时按字节解析
	if strings.Contains(v, `\x`) {
		cleaned := unescapeHex(v)
		b, err := hex.DecodeString(cleaned)
		if err != nil {
			return nil, fmt.Errorf("invalid \\x escape sequence: %w", err)
		}
		return b, nil
	}
	return []byte(v), nil
}

// unescapeHex 把 `\xNN` 还原成**十六进制字符串**（如 `\xde\xad` → `dead`）。
//
// 返回的是十六进制文本，交给 hex.DecodeString 再解成字节；
// 这里只做「转义 → 十六进制字符」这一步，避免解两次。
func unescapeHex(v string) string {
	const hexdigits = "0123456789abcdef"
	var sb strings.Builder
	for i := 0; i < len(v); {
		if v[i] == '\\' && i+3 < len(v) && v[i+1] == 'x' {
			hi, ok1 := hexVal(v[i+2])
			lo, ok2 := hexVal(v[i+3])
			if ok1 && ok2 {
				sb.WriteByte(hexdigits[hi])
				sb.WriteByte(hexdigits[lo])
				i += 4
				continue
			}
		}
		sb.WriteByte(v[i])
		i++
	}
	return sb.String()
}

// hexVal 解析一个十六进制字符。
func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// HexOf 把字节渲染成十六进制（带空格分隔，便于人读）。
func HexOf(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02x", c)
	}
	return strings.Join(parts, " ")
}

// FromHex 解析上面 HexOf 的输出（允许空格分隔）。
func FromHex(s string) ([]byte, error) {
	clean := strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	return hex.DecodeString(clean)
}

// Preview 计算补丁会有哪些改动，但不写入。
//
// 纯计算不碰内存，因此可以在没有写权限、甚至没有目标进程存活时预览。
func Preview(t Target, regions []Region, spec PatchSpec) *PatchReport {
	rep := &PatchReport{Op: spec.Op.String(), DryRun: true}
	switch spec.Op {
	case OpWrite:
		rep.Hits = append(rep.Hits, previewWrite(t, regions, spec))
	case OpReplace:
		rep.Hits = append(rep.Hits, findReplace(t, regions, spec)...)
	case OpRestore:
		// 回滚的预览由调用方按备份记录给出
	}
	for i := range rep.Hits {
		if !rep.Hits[i].Applyable {
			rep.Skipped++
		}
	}
	return rep
}

// previewWrite 计算一次原位写入的改动。
func previewWrite(t Target, regions []Region, spec PatchSpec) PatchHit {
	hit := PatchHit{Addr: spec.Addr, After: spec.Data, AfterHex: HexOf(spec.Data)}
	before := make([]byte, len(spec.Data))
	n, err := t.ReadAt(spec.Addr, before)
	switch {
	case err != nil || n < len(spec.Data):
		hit.Reason = "address is not readable"
		return hit
	}
	hit.Before, hit.BeforeHex = before, HexOf(before)
	if r := findRegion(regions, spec.Addr); r != nil {
		hit.Region = r.String()
		if !r.Writable() && !spec.Force {
			hit.Reason = fmt.Sprintf("region %s has no write permission", r.Kind)
			return hit
		}
	}
	if !t.Writable() && !spec.Force {
		hit.Reason = "target is not writable"
		return hit
	}
	hit.Applyable = true
	return hit
}

// findReplace 在各区域里查找 needle 并生成替换列表。
func findReplace(t Target, regions []Region, spec PatchSpec) []PatchHit {
	if len(spec.Needle) == 0 {
		return nil
	}
	var hits []PatchHit
	const chunk = 1 << 20
	for _, r := range regions {
		if !r.Readable() {
			continue
		}
		// 每次读一块，重叠 needle 长度 -1 字节，避免跨块漏匹配
		overlap := len(spec.Needle) - 1
		var carry []byte
		for addr := r.Start; addr < r.End; {
			n := r.End - addr
			if n > chunk {
				n = chunk
			}
			buf := make([]byte, n)
			got, err := t.ReadAt(addr, buf)
			if got <= 0 {
				break
			}
			data := buf[:got]
			scan := data
			scanBase := addr
			if len(carry) > 0 {
				scan = append(carry, data...)
				scanBase = addr - uint64(len(carry))
			}
			off := 0
			for {
				idx := bytes.Index(scan[off:], spec.Needle)
				if idx < 0 {
					break
				}
				at := scanBase + uint64(off+idx)
				hit := PatchHit{Addr: at, Region: r.String()}
				hit.Before, hit.BeforeHex = spec.Needle, HexOf(spec.Needle)
				hit.After, hit.AfterHex = spec.Replacement, HexOf(spec.Replacement)
				if !r.Writable() && !spec.Force {
					hit.Reason = fmt.Sprintf("region %s has no write permission", r.Kind)
				} else if !t.Writable() && !spec.Force {
					hit.Reason = "target is not writable"
				} else {
					hit.Applyable = true
				}
				hits = append(hits, hit)
				if spec.MaxCount > 0 && len(hits) >= spec.MaxCount {
					return hits
				}
				off += idx + 1
			}
			if err != nil {
				break
			}
			if overlap > 0 && len(data) > overlap {
				carry = append([]byte(nil), data[len(data)-overlap:]...)
			} else {
				carry = nil
			}
			addr += n
		}
	}
	return hits
}

// Apply 真正执行补丁，返回执行后的报告。
//
// 只写入 Preview 判定为 Applyable 的命中；其余计入 Skipped。
func Apply(t Target, rep *PatchReport, spec PatchSpec) error {
	if !t.Writable() {
		return ErrNotWritable
	}
	rep.DryRun = false
	for i := range rep.Hits {
		h := &rep.Hits[i]
		if !h.Applyable {
			rep.Skipped++
			continue
		}
		n, err := t.WriteAt(h.Addr, h.After)
		if err != nil {
			h.Applyable = false
			h.Reason = err.Error()
			rep.Skipped++
			continue
		}
		rep.Written += n
	}
	rep.Skipped = 0
	for i := range rep.Hits {
		if !rep.Hits[i].Applyable {
			rep.Skipped++
		}
	}
	return nil
}

// findRegion 返回包含 addr 的区域。
func findRegion(regions []Region, addr uint64) *Region {
	for i := range regions {
		if addr >= regions[i].Start && addr < regions[i].End {
			return &regions[i]
		}
	}
	return nil
}

// BackupRecord 是一条回滚记录。
type BackupRecord struct {
	Target  string `json:"target"`
	Addr    uint64 `json:"addr"`
	Before  string `json:"before"` // 十六进制
	After   string `json:"after"`  // 十六进制
	Time    string `json:"time"`   // ISO8601
	Region  string `json:"region,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// Backup 是回滚记录的集合，落盘为 JSON Lines。
type Backup struct {
	Records []BackupRecord
}

// Append 追加一条记录。
func (b *Backup) Append(r BackupRecord) { b.Records = append(b.Records, r) }

// FromHits 用补丁结果生成回滚记录。
func FromHits(target string, hits []PatchHit, regionOf func(uint64) string, comment string) *Backup {
	b := &Backup{}
	for _, h := range hits {
		if !h.Applyable || h.BeforeHex == "" {
			continue
		}
		b.Append(BackupRecord{
			Target: target, Addr: h.Addr, Before: h.BeforeHex, After: h.AfterHex,
			Region: h.Region, Comment: comment,
		})
	}
	return b
}

// SaveBackup 把回滚记录写入文件（JSON Lines，可增量追加）。
func SaveBackup(path string, b *Backup) error {
	if b == nil || len(b.Records) == 0 {
		return nil
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// LoadBackup 读取回滚记录。
func LoadBackup(path string) (*Backup, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return &Backup{}, nil
	}
	b := &Backup{}
	if err := json.Unmarshal(data, b); err != nil {
		return nil, fmt.Errorf("invalid backup file %s: %w", path, err)
	}
	return b, nil
}
