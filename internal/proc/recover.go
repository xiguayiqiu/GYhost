package proc

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// FileKind 是可恢复文件的来源类别（对应 /proc/<pid> 下的不同入口）。
type FileKind string

// 来源类别。
const (
	// FileExe 是 /proc/<pid>/exe —— 进程正在运行的可执行文件。
	FileExe FileKind = "exe"
	// FileCwd 是 /proc/<pid>/cwd —— 工作目录。
	FileCwd FileKind = "cwd"
	// FileRoot 是 /proc/<pid>/root —— 进程的根目录（chroot 场景）。
	FileRoot FileKind = "root"
	// FileFD 是 /proc/<pid>/fd/<n> —— 打开的文件描述符。
	//
	// 这是取证价值最高的一类：进程持有的文件即使已经从磁盘删除，
	// 只要还有 fd 指向它，inode 就还在，内容照样读得出来。
	FileFD FileKind = "fd"
	// FileMap 是 /proc/<pid>/map_files/<start>-<end> —— 内存映射的文件。
	FileMap FileKind = "map"
)

// FileRef 是一个可恢复文件的引用。
type FileRef struct {
	// Index 是本进程内稳定的编号，供 -r <编号> 精确指定。
	Index int
	// Kind 是来源类别。
	Kind FileKind
	// FD 是文件描述符号（Kind 为 FileFD 时有效）。
	FD int
	// Target 是真实路径。
	Target string
	// Link 是 /proc 里读到的原始软链接内容（Deleted 的标记在这里）。
	Link string
	// Deleted 表示文件已从磁盘删除但仍被进程持有 —— 取证重点。
	Deleted bool
	// Exists 表示目标路径当前在磁盘上是否存在。
	Exists bool
	// IsDir 表示是目录（不可直接恢复为文件）。
	IsDir bool
	// Size 是字节数；无法确定时为 -1。
	Size int64
	// ModTime 是修改时间。
	ModTime string
	// Recoverable 报告能否恢复出内容。
	Recoverable bool
	// Reason 不可恢复时说明原因。
	Reason string
}

// Label 返回来源类别的展示名（技术标识，不走 i18n）。
func (f FileRef) Label() string {
	switch f.Kind {
	case FileExe:
		return "exe"
	case FileCwd:
		return "cwd"
	case FileRoot:
		return "root"
	case FileFD:
		return "fd/" + strconv.Itoa(f.FD)
	case FileMap:
		return "map"
	}
	return string(f.Kind)
}

// Recoverer 是「能从 /proc 恢复文件」的可选能力。
//
// 刻意做成独立于 Backend 的可选接口：/proc 是 Linux 独有的，
// macOS 与 Windows 根本没有这套入口，强行塞进 Backend 会逼着
// 每个平台都实现一堆只能返回错误的空方法。
type Recoverer interface {
	// Scan 枚举该进程下所有可恢复的文件。
	Scan(pid int) ([]FileRef, error)
	// Recover 把某个文件恢复成 destDir 下的普通文件，
	// 返回落盘路径与字节数。
	Recover(pid int, ref FileRef, destDir string) (path string, n int64, err error)
}

// ScanOutcome 是一次「扫描 + 恢复」的结果。
type ScanOutcome struct {
	Target    string // 目标描述
	PID       int
	Refs      []FileRef   // 扫描结果
	Recovered []Recovered // 实际恢复出来的文件
}

// Recovered 是一个已落盘的恢复件。
type Recovered struct {
	Ref  FileRef
	Path string // 落盘路径
	Size int64
}

// MatchRefs 按用户给的取值筛选文件。
//
// 支持三种写法：
//
//	3        按编号精确选
//	*.log    按路径子串/通配选（多个用逗号分隔）
//	all      全部可恢复的
//
// 返回 (选中项, 是否命中)。命中为空时第二个值为 false。
func MatchRefs(refs []FileRef, spec string) ([]FileRef, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, false
	}
	if strings.EqualFold(spec, "all") {
		var out []FileRef
		for _, r := range refs {
			if r.Recoverable {
				out = append(out, r)
			}
		}
		return out, len(out) > 0
	}
	var out []FileRef
	for _, part := range strings.Split(spec, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		// 纯数字 → 按编号
		if idx, err := strconv.Atoi(p); err == nil {
			for _, r := range refs {
				if r.Index == idx {
					out = append(out, r)
				}
			}
			continue
		}
		// 其余按路径子串匹配，忽略大小写
		lp := strings.ToLower(p)
		for _, r := range refs {
			if !r.Recoverable {
				continue
			}
			t := strings.ToLower(r.Target)
			if strings.Contains(t, lp) || strings.Contains(strings.ToLower(r.Link), lp) {
				out = append(out, r)
			}
		}
	}
	// 去重（多个 pattern 可能命中同一条）
	seen := map[int]bool{}
	var uniq []FileRef
	for _, r := range out {
		if !seen[r.Index] {
			seen[r.Index] = true
			uniq = append(uniq, r)
		}
	}
	sort.Slice(uniq, func(i, j int) bool { return uniq[i].Index < uniq[j].Index })
	return uniq, len(uniq) > 0
}

// Stats 汇总一次扫描的统计。
type Stats struct {
	Total       int // 全部条目
	Recoverable int // 可恢复
	Deleted     int // 已删除但仍被持有（取证重点）
}

// Summarize 统计扫描结果。
func Summarize(refs []FileRef) Stats {
	var s Stats
	for _, r := range refs {
		s.Total++
		if r.Recoverable {
			s.Recoverable++
		}
		if r.Deleted {
			s.Deleted++
		}
	}
	return s
}

// RecoverName 生成恢复件的文件名。
//
// 规则：取目标路径的基名；同名冲突时追加序号。
// 已删除的文件保留原名（证据要保留原始文件名），仅在冲突时加后缀。
func RecoverName(ref FileRef, used map[string]bool) string {
	base := BaseName(ref.Target)
	if base == "" || base == "." || base == "/" {
		base = string(ref.Kind)
	}
	name := base
	for i := 2; used[name]; i++ {
		ext := ""
		if dot := strings.LastIndex(base, "."); dot > 0 {
			ext = base[dot:]
			name = fmt.Sprintf("%s-%d%s", base[:dot], i, ext)
		} else {
			name = fmt.Sprintf("%s-%d", base, i)
		}
	}
	used[name] = true
	return name
}
