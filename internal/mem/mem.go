// Package mem 是 GYhost mem 模块的跨平台内存分析内核。
//
// 分层约定：
//   - 本包只定义“数据契约”和与操作系统无关的分析算法（字符串、熵、哈希、文件雕取、行为规则）；
//   - 各平台的内存访问实现放在 modules/mem/os/<goos>，编译时只编目标系统的那一份，
//     但它们实现的都是本包的 Target / Backend 接口，因此上层参数与行为完全一致。
//
// Target 是“一份可随机读取的内存镜像”的抽象：
//   - 活体进程（Linux 的 /proc/<pid>/mem、Windows 的 ReadProcessMemory、macOS 的 mach_vm_read）
//   - 已落盘的内存转储文件（任意平台都能分析）
package mem

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// 通用错误：各平台实现返回这些哨兵错误，上层据此给出统一提示。
var (
	// ErrUnsupported 当前平台没有活体内存读取能力（仍可分析内存转储文件）。
	ErrUnsupported = errors.New("mem: current platform does not support live memory access")
	// ErrPrivilege 权限不足（Linux 需要 root，Windows 需要管理员，macOS 需要 root 或调试权限）。
	ErrPrivilege = errors.New("mem: insufficient privileges")
	// ErrNoProcess 目标进程不存在。
	ErrNoProcess = errors.New("mem: process not found")
	// ErrGone 目标进程已退出或内存不可读。
	ErrGone = errors.New("mem: process exited or memory is not readable")
	// ErrBadSpec -i 参数无法解析。
	ErrBadSpec = errors.New("mem: invalid target")
	// ErrNotWritable 目标不可写（权限不足，或区域本身没有写权限）。
	ErrNotWritable = errors.New("mem: target is not writable")
	// ErrNoBackup 找不到可回滚的备份记录。
	ErrNoBackup = errors.New("mem: no backup record found")
)

// 区域类型：对上层暴露的归一化分类，屏蔽各平台 maps/VirtualQueryEx 的差异。
const (
	RegionImage  = "image"  // 可执行映像（PE/ELF/Mach-O 主程序或共享库）
	RegionHeap   = "heap"   // 堆
	RegionStack  = "stack"  // 栈 / 线程栈
	RegionMapped = "mapped" // 内存映射文件（配置、日志、数据库、资源）
	RegionAnon   = "anon"   // 匿名区域（已申请未提交、线程栈、TLB 等）
	RegionOther  = "other"  // 其它（受保护页、设备映射等）
)

// Region 是一段连续的已映射内存。
type Region struct {
	Start uint64 // 起始虚拟地址
	End   uint64 // 结束虚拟地址（开区间）
	Perm  string // 权限位，如 "r-xp"
	Path  string // 映射的宿主文件路径，空表示匿名
	Kind  string // 见 Region* 常量
}

// Size 返回区域字节数。
func (r Region) Size() uint64 {
	if r.End <= r.Start {
		return 0
	}
	return r.End - r.Start
}

// Readable 判断区域是否可读（POSIX 位串缺 r 视为不可读，Windows 的 PAGE_NOACCESS 同样被屏蔽在 Perm 之外）。
func (r Region) Readable() bool {
	return strings.ContainsRune(r.Perm, 'r')
}

// Executable 判断区域是否带执行权限。
func (r Region) Executable() bool {
	return strings.ContainsRune(r.Perm, 'x')
}

// Writable 判断区域是否可写。
func (r Region) Writable() bool {
	return strings.ContainsRune(r.Perm, 'w')
}

// String 渲染成 "start-end perm kind path" 形式。
func (r Region) String() string {
	s := fmt.Sprintf("%016x-%016x %-4s %-6s", r.Start, r.End, r.Perm, r.Kind)
	if r.Path != "" {
		s += " " + r.Path
	}
	return s
}

// ProcessInfo 是目标进程的基本信息，字段对所有平台统一。
type ProcessInfo struct {
	PID         int
	PPID        int
	Name        string   // 进程名（不含路径）
	Arch        string   // x86_64 / arm64 …
	User        string   // 所属用户
	Exe         string   // 可执行文件路径
	Cmdline     []string // 完整命令行
	StartTime   string   // 启动时间（平台能取到时才有）
	TotalMemory uint64   // 进程占用的总虚拟内存
	ThreadCount int      // 线程数（平台能取到时才有，0 表示未知）
	Modules     []string // 已加载模块（映像文件）
}

// ThreadInfo 是一个线程（轻量级进程）的信息。
//
// 三个平台的线程标识都叫 TID：Linux 是 /proc/<pid>/task/<tid> 里的 tid，
// Windows 是 Thread32 快照里的 th32ThreadID，
// macOS 是 task_threads() 返回的 thread port 对应的线程号。
type ThreadInfo struct {
	TID   int    // 线程 ID
	PID   int    // 所属进程 ID
	Name  string // 线程名（平台能取到时才有）
	State string // 线程状态，如 Linux 的 R/S/D；取不到时为空
}

// Target 是一份可随机读写的内存镜像。
//
// 读取是取证的基础能力；写入用于「在内存中操作程序行为」——
// 即在目标进程运行期间改写它的内存（改配置、改开关、改参数）。
// 只读目标（权限不足、只读区域、只读转储文件）上 Writable() 返回 false，
// WriteAt 返回 ErrNotWritable，读取路径完全不受影响。
type Target interface {
	// Kind 返回 "live"（活体进程）或 "file"（内存转储文件）。
	Kind() string
	// Info 返回目标的基础信息。
	Info() ProcessInfo
	// Regions 返回全部内存区域（已按起始地址升序排列）。
	Regions() ([]Region, error)
	// ReadAt 从虚拟地址 addr 读 len(p) 字节；返回实际读取字节数。
	// 地址不可读时返回错误或 n < len(p) 且 io.EOF 语义由实现保证。
	ReadAt(addr uint64, p []byte) (int, error)
	// Writable 报告当前目标是否具备写入能力。
	Writable() bool
	// WriteAt 从虚拟地址 addr 写 p 的内容，返回实际写入字节数。
	// 不可写时返回 ErrNotWritable。
	WriteAt(addr uint64, p []byte) (int, error)
	// Close 释放底层句柄。
	Close() error
}

// Backend 是一个平台的内存访问能力。
type Backend interface {
	// Name 平台标识：linux / windows / darwin / unsupported。
	Name() string
	// Supported 是否支持活体内存读取。
	Supported() bool
	// PrivilegeHint 返回权限不足时的提示文案。
	PrivilegeHint() string
	// List 列出当前所有可分析的进程。
	List() ([]ProcessInfo, error)
	// OpenLive 按 spec（pid 数字或 "self"）打开活体进程。
	OpenLive(spec string) (Target, error)
	// Threads 列出指定进程的所有线程（“子线程”）。
	// 权限不足或进程已退出时返回错误，调用方据此降级。
	Threads(pid int) ([]ThreadInfo, error)
}

// ThreadLister 是「能枚举线程」的可选能力。
//
// 与 Backend.Threads 分开是为了让第三方实现可以只做内存读取、
// 不实现线程枚举；调用方用支持可选接口的方式探测。
type ThreadLister interface {
	Threads(pid int) ([]ThreadInfo, error)
}

// SpecKind 表示 -i 目标的种类。
type SpecKind int

const (
	// SpecLive 活体进程。
	SpecLive SpecKind = iota
	// SpecFile 内存转储文件。
	SpecFile
)

// Spec 是 -i 参数解析结果。
type Spec struct {
	Kind SpecKind
	PID  int    // SpecLive 时有效
	Self bool   // SpecLive 时表示当前进程
	Path string // SpecFile 时有效
}

// String 回显原始目标串。
func (s Spec) String() string {
	if s.Kind == SpecFile {
		return s.Path
	}
	if s.Self {
		return "self"
	}
	return strconv.Itoa(s.PID)
}

// ParseSpec 解析 -i 参数：纯数字 → 活体进程；self → 当前进程；其余按文件路径处理。
func ParseSpec(s string) (Spec, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return Spec{}, ErrBadSpec
	}
	low := strings.ToLower(t)
	if low == "self" || low == "." {
		return Spec{Kind: SpecLive, Self: true}, nil
	}
	if pid, err := strconv.Atoi(t); err == nil {
		if pid < 0 {
			return Spec{}, ErrBadSpec
		}
		return Spec{Kind: SpecLive, PID: pid}, nil
	}
	return Spec{Kind: SpecFile, Path: t}, nil
}

// Resolve 把 -i 目标解析成可分析的 Target：
// 存在的文件按内存转储打开，其它按活体进程打开（由 backend 实现）。
func Resolve(b Backend, spec Spec) (Target, error) {
	if spec.Kind == SpecFile {
		st, err := os.Stat(spec.Path)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrNoProcess, spec.Path)
		}
		if st.IsDir() {
			return nil, fmt.Errorf("%w: %s is a directory", ErrBadSpec, spec.Path)
		}
		return NewFileTarget(spec.Path)
	}
	return b.OpenLive(spec.String())
}

// SortRegions 按起始地址升序排序（各平台实现都调用它，保证输出一致）。
func SortRegions(rs []Region) {
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0 && rs[j].Start < rs[j-1].Start; j-- {
			rs[j], rs[j-1] = rs[j-1], rs[j]
		}
	}
}

// Classify 根据权限与宿主路径推断区域类型（三个平台共用的归一化规则）。
//
// 规则顺序固定：显式堆/栈标记 → 可执行权限或与主程序同路径 → 有宿主文件 → 匿名。
func Classify(perm, path string, isMainImage bool) string {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "heap"):
		return RegionHeap
	case strings.Contains(p, "stack"):
		return RegionStack
	case isMainImage || strings.ContainsRune(perm, 'x'):
		return RegionImage
	case p == "" || strings.HasPrefix(p, "[") || strings.HasPrefix(p, "<"):
		return RegionAnon
	default:
		return RegionMapped
	}
}

// MatchKind 表示一次程序名匹配命中的强度。
type MatchKind int

const (
	// MatchNone 未命中。
	MatchNone MatchKind = iota
	// MatchPID 按 PID 精确命中。
	MatchPID
	// MatchExePath 按可执行文件全路径精确命中。
	MatchExePath
	// MatchName 按进程名 / 可执行文件名 / 命令行首项精确命中。
	MatchName
	// MatchPartial 按名称子串模糊命中。
	MatchPartial
)

// String 返回匹配强度的中文说明（供上层报错与提示使用）。
func (m MatchKind) String() string {
	switch m {
	case MatchPID:
		return "pid"
	case MatchExePath:
		return "exe"
	case MatchName:
		return "name"
	case MatchPartial:
		return "partial"
	default:
		return "none"
	}
}

// Match 返回进程与查询串的匹配强度。
//
// 依次尝试：纯数字按 PID → 可执行文件全路径 → 进程名/可执行文件名/
// 命令行首项 → 名称子串（模糊）。全部忽略大小写。
func Match(p ProcessInfo, query string) MatchKind {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return MatchNone
	}
	// 纯数字优先按 PID 解释
	if pid, err := strconv.Atoi(q); err == nil {
		if p.PID == pid {
			return MatchPID
		}
		// 数字也可能是线程/子进程号，不做名称匹配，直接判定未命中
		return MatchNone
	}
	if p.Exe != "" && strings.ToLower(p.Exe) == q {
		return MatchExePath
	}
	// 进程名、可执行文件名（含路径）、命令行首项
	candidates := []string{p.Name}
	if p.Exe != "" {
		candidates = append(candidates, p.Exe, baseName(p.Exe))
	}
	if len(p.Cmdline) > 0 {
		candidates = append(candidates, p.Cmdline[0], baseName(p.Cmdline[0]))
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if strings.ToLower(c) == q {
			return MatchName
		}
	}
	// 最后退化为子串匹配
	for _, c := range candidates {
		if c != "" && strings.Contains(strings.ToLower(c), q) {
			return MatchPartial
		}
	}
	return MatchNone
}

// FindProcess 在列表中查找与 query 匹配的所有进程。
//
// 返回结果按“匹配强度 → PID 升序”排序：精确命中的排在前面，
// 便于调用方优先分析用户明确指定的程序。
func FindProcess(list []ProcessInfo, query string) []ProcessInfo {
	var exact, partial []ProcessInfo
	for _, p := range list {
		switch Match(p, query) {
		case MatchNone:
		case MatchPartial:
			partial = append(partial, p)
		default:
			exact = append(exact, p)
		}
	}
	sort.SliceStable(exact, func(i, j int) bool { return exact[i].PID < exact[j].PID })
	sort.SliceStable(partial, func(i, j int) bool { return partial[i].PID < partial[j].PID })
	return append(exact, partial...)
}

// baseName 取路径最后一段，同时兼容 / 与 \ 分隔符（Windows 路径）。
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 && i+1 < len(p) {
		return p[i+1:]
	}
	return p
}
