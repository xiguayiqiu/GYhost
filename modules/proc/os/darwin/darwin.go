//go:build darwin

// Package darwin 实现 macOS 平台的进程分析。
//
// macOS 没有完整 procfs，只能经 libSystem 的 libproc / Mach 接口取数，
// 那层无 cgo 绑定统一在 internal/maclite。
//
// 信息来源：
//   - 进程列表：proc_listallpids + proc_pidpath
//   - 父进程/状态/内存/线程数：proc_pidinfo(PROC_PIDTASKALLINFO)
//   - 完整命令行与环境变量：sysctl KERN_PROCARGS2
//   - 线程：task_threads
//   - 打开的文件数：proc_pidinfo(PROC_PIDLISTFDS)
//
// **能力边界**（macOS 的 SIP 与权限模型导致，报告里会标为不可用）：
//   - 他人进程的 fd 完整路径（只有数量；读路径需要 root）
//   - 内核线程（macOS 没有这个概念）
package darwin

import (
	"bytes"
	"fmt"
	"runtime"
	"sort"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"gyhost/internal/maclite"
	"gyhost/internal/proc"
)

// proc_pidinfo 的 flavor。
const (
	procPidListFDs     = 1 // struct proc_fdinfo
	procPidTaskAllInfo = 2 // struct proc_taskallinfo
)

// maxComLen 与 2*maxComLen 是 <sys/proc_info.h> 里的进程名长度上限。
const (
	maxComLen = 16
)

// ---- <sys/proc_info.h> 结构体 ----
//
// 字段顺序与类型严格照抄头文件，让 Go 自己算偏移：
// 早期版本用「硬编码字节偏移」是本模块开发过程中被自己否掉的写法——
// proc_bsdinfo 里没有任何填充字节，猜错一位整张表就全错。
// 用 unsafe.Offsetof 派生则不存在这个风险。

// bsdInfo 对应 struct proc_bsdinfo。
type bsdInfo struct {
	Flags       uint32 // pbsd_flags
	Status      uint32 // pbsd_status
	XStatus     uint32 // pbsd_xstatus
	StateMask   uint32 // pbsd_statemask
	PID         uint32 // pbsd_pid
	PPID        uint32 // pbsd_ppid
	UID         uint32
	GID         uint32
	RUID        uint32
	RGID        uint32
	SVUID       uint32
	SVGID       uint32
	RFU1        uint32
	Comm        [maxComLen]byte
	Name        [2 * maxComLen]byte
	NFiles      uint32
	PGID        uint32
	JOBC        uint32
	TDev        uint32
	TPGID       uint32
	Nice        int32
	_           uint32 // 对齐到 8 字节
	StartTvSec  uint64
	StartTvUsec uint64
}

// taskInfo 对应 struct proc_taskinfo。
type taskInfo struct {
	VirtualSize  uint64
	ResidentSize uint64
	TotalUser    uint64
	TotalSystem  uint64
	ThreadsUser  uint64
	ThreadsSys   uint64
	NumRunning   int32
	State        int32
}

// taskAllInfo 对应 struct proc_taskallinfo = proc_bsdinfo + proc_taskinfo。
type taskAllInfo struct {
	BSD  bsdInfo
	Task taskInfo
}

var taskAllInfoBuf = make([]byte, unsafe.Sizeof(taskAllInfo{}))

// fdInfoBuf 是读取 PROC_PIDLISTFDS 的缓冲。
var fdInfoBuf = make([]byte, 4096)

// BSD 状态位（pbsd_status 的低 8 位）。
const (
	sszombie = 0x0020
	sstopped = 0x0004
)

// Backend 是 macOS 的 proc.Backend 实现。
type Backend struct{}

// New 创建 macOS 后端。
func New() proc.Backend { return &Backend{} }

// Name 返回平台标识。
func (b *Backend) Name() string { return "darwin" }

// Supported 恒为 true：libproc 一直可用。
func (b *Backend) Supported() bool { return true }

// PrivilegeHint 返回权限不足时的提示。
func (b *Backend) PrivilegeHint() string {
	return "full command line and fd paths of other users need root on macOS: sudo ./gyhost proc ..."
}

// archName 归一化架构名。
func archName() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "arm64"
	default:
		return runtime.GOARCH
	}
}

// List 用 proc_listallpids 列出所有进程。
func (b *Backend) List() ([]proc.Process, error) {
	pids := maclite.ListAllPIDs()
	if len(pids) == 0 {
		return nil, fmt.Errorf("%w: proc_listallpids returned nothing", proc.ErrPrivilege)
	}
	out := make([]proc.Process, 0, len(pids))
	for _, pid := range pids {
		out = append(out, readProcess(int(pid), false))
	}
	return out, nil
}

// readProcess 读取进程基本信息。withArgs 为 true 时额外读命令行与环境变量
// （sysctl 比 proc_pidpath 重，列表场景不逐个调用）。
func readProcess(pid int, withArgs bool) proc.Process {
	p := proc.Process{PID: pid, Arch: archName(), State: proc.StateUnknown}
	if exe := maclite.PidPath(pid); exe != "" {
		p.Exe = exe
		p.Name = proc.BaseName(exe)
	}
	if p.Name == "" {
		p.Name = fmt.Sprintf("pid%d", pid)
	}
	if n := maclite.PidInfo(pid, procPidTaskAllInfo, 0, taskAllInfoBuf); n > 0 {
		var t taskAllInfo
		// 只在拿到足够字节时才解引用，避免用未填充的缓冲算偏移
		if n >= int(unsafe.Offsetof(taskAllInfo{}.Task)) {
			t = *(*taskAllInfo)(unsafe.Pointer(&taskAllInfoBuf[0]))
			p.PPID = int(t.BSD.PPID)
			p.VSize = t.Task.VirtualSize
			p.RSize = t.Task.ResidentSize
			p.Threads = int(t.Task.ThreadsUser)
			p.State = darwinState(int(t.BSD.Status))
			if t.BSD.StartTvSec > 0 {
				p.Start = unixTime(t.BSD.StartTvSec, int64(t.BSD.StartTvUsec))
			}
		}
	}
	if withArgs {
		args, env := procargs(pid)
		if len(args) > 0 {
			p.Cmdline = args
		}
		p.Env = env
	}
	if len(p.Cmdline) == 0 {
		p.Cmdline = []string{p.Name}
	}
	return p
}

// Threads 列出进程线程。
func (b *Backend) Threads(pid int) ([]proc.Thread, error) {
	t, err := maclite.TaskForPID(pid)
	if err != nil {
		// 拿不到 task 端口不算致命：交由上层在报告里标注
		return nil, nil
	}
	defer maclite.PortDeallocate(t)
	name := proc.BaseName(maclite.PidPath(pid))
	out := make([]proc.Thread, 0, 8)
	for _, id := range maclite.TaskThreads(t) {
		out = append(out, proc.Thread{TID: int(id), PID: pid, Name: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TID < out[j].TID })
	return out, nil
}

// Detail 取进程深度信息。
func (b *Backend) Detail(pid int) (proc.Process, error) {
	p := readProcess(pid, true)
	if p.PID == 0 {
		return p, fmt.Errorf("%w: pid %d", proc.ErrNoProcess, pid)
	}
	// fd 数量：proc_fdinfo 的第一个 4 字节是 procFDCount
	if n := maclite.PidInfo(pid, procPidListFDs, 0, fdInfoBuf); n >= 4 {
		p.FDs = int(uint32(fdInfoBuf[0]) | uint32(fdInfoBuf[1])<<8 |
			uint32(fdInfoBuf[2])<<16 | uint32(fdInfoBuf[3])<<24)
	}
	if p.Exe != "" {
		p.Modules = []string{p.Exe}
		p.ExeCount = 1
	}
	return p, nil
}

// procargs 用 sysctl KERN_PROCARGS2 取完整命令行与环境变量。
//
// 布局：exec_path "\0" argc(int32) argv... "\0" envp... "\0"
// 这是 macOS 上拿 argv 的标准手段（proc_pidinfo 给不了）。
func procargs(pid int) (args, env []string) {
	raw, err := unix.SysctlRaw(fmt.Sprintf("kern.procargs2.%d", pid))
	if err != nil || len(raw) == 0 {
		return nil, nil
	}
	// 1) 跳过 exec_path 与它后面的 NUL
	sep := bytes.IndexByte(raw, 0)
	if sep < 0 {
		return nil, nil
	}
	rest := raw[sep+1:]
	if len(rest) < 4 {
		return nil, nil
	}
	argc := int(int32(uint32(rest[0]) | uint32(rest[1])<<8 | uint32(rest[2])<<16 | uint32(rest[3])<<24))
	rest = rest[4:]

	// 2) argc 个参数，每个以 NUL 结尾
	for i := 0; i < argc && len(rest) > 0; i++ {
		idx := bytes.IndexByte(rest, 0)
		if idx < 0 {
			break
		}
		args = append(args, string(rest[:idx]))
		rest = rest[idx+1:]
	}
	// 3) 余下的是环境变量
	for len(rest) > 0 {
		idx := bytes.IndexByte(rest, 0)
		if idx < 0 {
			break
		}
		if s := string(rest[:idx]); s != "" {
			env = append(env, s)
		}
		rest = rest[idx+1:]
	}
	return args, env
}

// darwinState 把 BSD 状态位翻译成 proc.State。
func darwinState(status int) proc.State {
	switch status & 0xff {
	case sszombie:
		return proc.StateZombie
	case sstopped:
		return proc.StateStopped
	case 0:
		return proc.StateRunning
	default:
		return proc.StateSleeping
	}
}

// unixTime 把 mach 时间戳格式化成字符串。
func unixTime(sec uint64, usec int64) string {
	if sec == 0 {
		return ""
	}
	return time.Unix(int64(sec), usec).Format("2006-01-02 15:04:05")
}
