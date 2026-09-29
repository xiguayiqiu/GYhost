// Package proc 是 proc 模块的跨平台内核：进程数据模型 + 与操作系统无关的分析逻辑。
//
// 分层：
//   - 本包只定义「进程长什么样」和「拿到进程之后怎么筛、怎么排序、怎么建树」；
//   - 各平台的采集实现在 modules/proc/os/<goos>，编译时只编目标系统那一份。
//
// 与 internal/mem 的分工：
//   - mem 关注**内存**（区域、字符串、熵、雕取、改写），进程信息只是副产品；
//   - proc 关注**进程本身**（命令行、环境变量、打开的文件、父子关系、资源占用）。
package proc

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// 通用错误。
var (
	// ErrUnsupported 当前平台不支持进程分析。
	ErrUnsupported = errors.New("proc: not supported on this platform")
	// ErrPrivilege 权限不足。
	ErrPrivilege = errors.New("proc: insufficient privileges")
	// ErrNoProcess 目标进程不存在。
	ErrNoProcess = errors.New("proc: process not found")
	// ErrBadSpec 目标参数无法解析。
	ErrBadSpec = errors.New("proc: invalid target")
)

// State 进程运行状态（取自各平台的原始状态字符）。
type State string

// 常见状态。
const (
	StateRunning  State = "R" // 运行中/可运行
	StateSleeping State = "S" // 可中断睡眠
	StateDiskWait State = "D" // 不可中断睡眠（等 IO）
	StateStopped  State = "T" // 已停止
	StateZombie   State = "Z" // 僵尸
	StateUnknown  State = "?"
)

// Process 是一个进程的完整信息。
//
// 所有字段对 Linux 与 macOS 统一；平台拿不到的字段留零值
// （例如 macOS 没有 /proc/<pid>/environ，Env 会是空）。
type Process struct {
	PID   int
	PPID  int
	Name  string // 进程名（不含路径）
	Exe   string // 可执行文件全路径
	User  string // 所属用户
	State State  // 运行状态
	Cwd   string // 工作目录
	Arch  string // 架构
	Start string // 启动时间

	Cmdline []string // 完整命令行
	Env     []string // 环境变量（部分平台不可得）
	Modules []string // 已加载的可执行映像

	VSize    uint64   // 虚拟内存字节数
	RSize    uint64   // 常驻内存（RSS）字节数
	Threads  int      // 线程数
	FDs      int      // 打开的文件描述符数
	FDList   []string // 打开的文件路径
	MapCount int      // 内存映射区域数
	ExeCount int      // 内存映射的可执行文件数
	Kind     string   // 归类：service / app / kernel …
}

// IsKernel 判断是否为内核线程。
//
// Linux 的内核线程没有 exe 也没有 cmdline；macOS 没有这个概念。
func (p Process) IsKernel() bool {
	return p.Exe == "" && p.Name != "" && strings.HasPrefix(p.Name, "[")
}

// Thread 是一个线程。
type Thread struct {
	TID   int
	PID   int
	Name  string
	State State
}

// Backend 是一个平台的进程分析能力。
type Backend interface {
	// Name 平台标识：linux / darwin / unsupported。
	Name() string
	// Supported 是否支持。
	Supported() bool
	// PrivilegeHint 权限不足时的提示。
	PrivilegeHint() string
	// List 列出所有进程。
	List() ([]Process, error)
	// Threads 列出某进程的线程。
	Threads(pid int) ([]Thread, error)
	// Detail 取单个进程的深度信息（Env / FD / 映射摘要）。
	Detail(pid int) (Process, error)
}

// Spec 是 -i 的解析结果。
type Spec struct {
	PID  int
	Self bool
}

// String 回显原始目标。
func (s Spec) String() string {
	if s.Self {
		return "self"
	}
	return strconv.Itoa(s.PID)
}

// ParseSpec 解析 -i：纯数字 → pid；self → 当前进程。
func ParseSpec(s string) (Spec, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return Spec{}, ErrBadSpec
	}
	if strings.EqualFold(t, "self") || t == "." {
		return Spec{Self: true}, nil
	}
	pid, err := strconv.Atoi(t)
	if err != nil || pid < 0 {
		return Spec{}, ErrBadSpec
	}
	return Spec{PID: pid}, nil
}

// MatchKind 是程序名匹配强度。
type MatchKind int

const (
	MatchNone MatchKind = iota
	MatchPID
	MatchExePath
	MatchName
	MatchPartial
)

// Match 判断进程与查询串的匹配强度：pid → exe 全路径 → 名字/可执行文件名/命令行 → 子串。
func Match(p Process, query string) MatchKind {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return MatchNone
	}
	if pid, err := strconv.Atoi(q); err == nil {
		if p.PID == pid {
			return MatchPID
		}
		return MatchNone
	}
	if p.Exe != "" && strings.ToLower(p.Exe) == q {
		return MatchExePath
	}
	cands := []string{p.Name}
	if p.Exe != "" {
		cands = append(cands, p.Exe, BaseName(p.Exe))
	}
	if len(p.Cmdline) > 0 {
		cands = append(cands, p.Cmdline[0], BaseName(p.Cmdline[0]))
	}
	for _, c := range cands {
		if c != "" && strings.ToLower(c) == q {
			return MatchName
		}
	}
	for _, c := range cands {
		if c != "" && strings.Contains(strings.ToLower(c), q) {
			return MatchPartial
		}
	}
	return MatchNone
}

// FindProcess 在列表中查找匹配 query 的进程，精确命中优先、再按 PID 升序。
func FindProcess(list []Process, query string) []Process {
	var exact, partial []Process
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

// SortField 是排序依据。
type SortField string

// 排序字段。
const (
	SortPID     SortField = "pid"
	SortPPID    SortField = "ppid"
	SortName    SortField = "name"
	SortUser    SortField = "user"
	SortVSize   SortField = "vsize"
	SortRSize   SortField = "rss"
	SortThreads SortField = "threads"
	SortFDs     SortField = "fds"
	SortStart   SortField = "start"
)

// ParseSortField 解析 -t 参数。
func ParseSortField(s string) (SortField, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(SortThreads):
		return SortThreads, nil
	case string(SortPID):
		return SortPID, nil
	case string(SortPPID):
		return SortPPID, nil
	case string(SortName):
		return SortName, nil
	case string(SortUser):
		return SortUser, nil
	case string(SortVSize), "v", "virt":
		return SortVSize, nil
	case string(SortRSize), "r", "mem", "memory":
		return SortRSize, nil
	case string(SortFDs), "fd":
		return SortFDs, nil
	case string(SortStart):
		return SortStart, nil
	}
	return "", fmt.Errorf("unknown sort field: %s", s)
}

// Sort 按指定字段排序；线程/内存/FD 数都相同时回退按 PID，
// 保证输出稳定（否则同分进程顺序会随枚举顺序抖动）。
func Sort(list []Process, field SortField) {
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		switch field {
		case SortPID:
			return a.PID < b.PID
		case SortPPID:
			return a.PPID < b.PPID
		case SortName:
			return a.Name < b.Name
		case SortUser:
			return a.User < b.User
		case SortVSize:
			return a.VSize > b.VSize
		case SortRSize:
			return a.RSize > b.RSize
		case SortFDs:
			return a.FDs > b.FDs
		case SortStart:
			return a.Start < b.Start
		default: // SortThreads
			if a.Threads != b.Threads {
				return a.Threads > b.Threads
			}
			return a.PID < b.PID
		}
	})
}

// Filter 收敛进程集合。
type Filter struct {
	// Query 是按名字/命令行模糊匹配的关键字。
	Query string
	// User 只保留该用户的进程。
	User string
	// Parent 只保留该父进程的**直接子进程**；0 表示不过滤。
	Parent int
	// Root 为 true 时把内核线程剔除。
	NoKernel bool
	// MinThreads / MinRSize 是资源下限过滤。
	MinThreads int
	MinRSize   uint64
}

// Apply 按过滤器筛出进程。
func Apply(list []Process, f Filter) []Process {
	var out []Process
	for _, p := range list {
		if f.NoKernel && p.IsKernel() {
			continue
		}
		if f.User != "" && !strings.EqualFold(p.User, f.User) {
			continue
		}
		if f.Parent > 0 && p.PPID != f.Parent {
			continue
		}
		if f.MinThreads > 0 && p.Threads < f.MinThreads {
			continue
		}
		if f.MinRSize > 0 && p.RSize < f.MinRSize {
			continue
		}
		if f.Query != "" && Match(p, f.Query) == MatchNone {
			continue
		}
		out = append(out, p)
	}
	return out
}

// TreeNode 是进程树的一个节点。
type TreeNode struct {
	Process Process
	Depth   int
}

// BuildTree 按父子关系把进程组织成森林，父进程不在列表里的算根。
//
// 防御性处理：进程可能已经退出导致父进程查不到，或出现环
// （理论上不会，但要保证渲染不会死循环）。
func BuildTree(list []Process) []TreeNode {
	present := make(map[int]bool, len(list))
	for _, p := range list {
		present[p.PID] = true
	}
	children := make(map[int][]Process, len(list))
	var roots []Process
	for _, p := range list {
		switch {
		case p.PPID == p.PID, !present[p.PPID]:
			roots = append(roots, p) // 自己就是根，或父进程已消失
		default:
			children[p.PPID] = append(children[p.PPID], p)
		}
	}
	// 根按 PID 升序，兄弟节点也按 PID 升序：输出稳定可比对
	sort.Slice(roots, func(i, j int) bool { return roots[i].PID < roots[j].PID })
	for k := range children {
		kids := children[k]
		sort.Slice(kids, func(i, j int) bool { return kids[i].PID < kids[j].PID })
		children[k] = kids
	}

	var out []TreeNode
	visited := make(map[int]bool, len(list))
	var walk func(p Process, depth int)
	walk = func(p Process, depth int) {
		if visited[p.PID] || depth > 64 {
			return // 环或异常深的层级：截断
		}
		visited[p.PID] = true
		out = append(out, TreeNode{Process: p, Depth: depth})
		for _, kid := range children[p.PID] {
			walk(kid, depth+1)
		}
	}
	for _, r := range roots {
		walk(r, 0)
	}
	// 理论上不会漏；万一有（比如成环导致被 visited 挡掉）也补上，避免静默丢进程
	for _, p := range list {
		if !visited[p.PID] {
			out = append(out, TreeNode{Process: p, Depth: 0})
		}
	}
	return out
}

// UserStat 是按用户聚合的统计。
type UserStat struct {
	User    string
	Count   int
	Threads int
	VSize   uint64
	RSize   uint64
}

// ByUser 按用户聚合统计，按进程数降序。
func ByUser(list []Process) []UserStat {
	m := map[string]*UserStat{}
	var order []string
	for _, p := range list {
		u := p.User
		if u == "" {
			u = "-"
		}
		s, ok := m[u]
		if !ok {
			s = &UserStat{User: u}
			m[u] = s
			order = append(order, u)
		}
		s.Count++
		s.Threads += p.Threads
		s.VSize += p.VSize
		s.RSize += p.RSize
	}
	out := make([]UserStat, 0, len(m))
	for _, u := range order {
		out = append(out, *m[u])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].User < out[j].User
	})
	return out
}

// BaseName 取路径最后一段，同时兼容 / 与 \ 分隔符。
func BaseName(p string) string {
	if i := strings.LastIndexAny(p, `/\\`); i >= 0 && i+1 < len(p) {
		return p[i+1:]
	}
	return p
}

// SelfPID 返回当前进程 pid（各平台一致由调用方提供，此处用 os.Getpid）。
func SelfPID() int { return os.Getpid() }
