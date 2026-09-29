//go:build darwin

// Package darwin 实现 macOS 平台的活体内存访问。
//
// macOS 没有完整 procfs，进程与内存信息只能经 libSystem 的 Mach 接口取得；
// 那层无 cgo 的绑定统一放在 internal/maclite，本包只做语义封装。
//
// 数据来源：
//   - 进程列表：proc_listallpids + proc_pidpath
//   - 进程信息：task_info（TASK_BASIC_INFO_64）
//   - 内存内容：mach_vm_read_overwrite
//   - 内存布局：mach_vm_region（VM_REGION_BASIC_INFO_64）
//   - 子线程：  task_threads
//
// 权限：task_for_id 需要 root，或同用户且开启了开发者模式
// （macOS 10.14 起 SIP 下不再默认放行）。失败时按 mem.ErrPrivilege 返回。
package darwin

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	"gyhost/internal/maclite"
	"gyhost/internal/mem"
)

// Mach / libproc 常量。
const (
	vmRegionBasic64 = 9 // VM_REGION_BASIC_INFO_64
	vmProtRead      = 1
	vmProtWrite     = 2
	vmProtExecute   = 4

	// maxUserAddr 是 64 位用户地址空间上界；内核地址远在此之上且无权限读。
	maxUserAddr = 1 << 47
)

// vmRegionBasicInfo64Data 对应 vm_region_basic_info_data_64。
type vmRegionBasicInfo64Data struct {
	Protection   uint32
	Offset       uint64
	Behavior     int32
	UserWritable int32
	ProtectSize  uint32
	MaxProt      uint32
}

// taskBasicInfo64Data 对应 mach_task_basic_info_data_64。
type taskBasicInfo64Data struct {
	VirtualSize  uint64
	RegionCount  uint32
	PageSize     uint32
	ResidentSize uint64
	SuspendCount int32
	SleepTime    int32
}

// taskInfoBuf 是读取 task_info 的缓冲，足够容纳 TASK_BASIC_INFO_64。
var taskInfoBuf = make([]byte, 128)

// Backend 是 macOS 的 mem.Backend 实现。
type Backend struct{}

// New 创建 macOS 后端。
func New() mem.Backend { return &Backend{} }

// Name 返回平台标识。
func (b *Backend) Name() string { return "darwin" }

// Supported 恒为 true：libSystem 一直提供这些 Mach 服务。
func (b *Backend) Supported() bool { return true }

// PrivilegeHint 返回权限不足时的提示。
func (b *Backend) PrivilegeHint() string {
	return "need root or Developer Mode for the same user: " +
		"sudo ./gyhost mem -i <pid> ... (or analyze a memory dump file instead)"
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

// pidPath 用 proc_pidpath 取进程可执行文件路径。
func pidPath(pid int) string { return maclite.PidPath(pid) }

// threadIDs 用 task_threads 取出目标任务的全部线程端口。
//
// Mach 的线程“端口号”本身就是线程号（TID），
// 与 Linux 的 tid / Windows 的 ThreadID 处在同一层语义上。
func threadIDs(task uint32) []uint32 { return maclite.TaskThreads(task) }

// taskBasicInfo 读虚拟/常驻内存大小。
func taskBasicInfo(task uint32) (taskBasicInfo64Data, bool) {
	var tbi taskBasicInfo64Data
	if _, ok := maclite.TaskInfo(task, taskInfoBuf); !ok {
		return tbi, false
	}
	return *(*taskBasicInfo64Data)(unsafe.Pointer(&taskInfoBuf[0])), true
}

// List 用 proc_listallpids 列出所有进程。
func (b *Backend) List() ([]mem.ProcessInfo, error) {
	pids := maclite.ListAllPIDs()
	if len(pids) == 0 {
		return nil, fmt.Errorf("%w: proc_listallpids returned nothing", mem.ErrPrivilege)
	}
	out := make([]mem.ProcessInfo, 0, len(pids))
	for _, pid := range pids {
		out = append(out, readProcessInfo(int(pid)))
	}
	return out, nil
}

// readProcessInfo 读取进程基本信息。
//
// 拿不到 task 端口时（权限不足）仍能返回进程名与路径，
// 只是内存大小为 0，报告里会显示为不可用。
func readProcessInfo(pid int) mem.ProcessInfo {
	info := mem.ProcessInfo{PID: pid, Arch: archName()}
	if exe := pidPath(pid); exe != "" {
		info.Exe = exe
		info.Name = exe[strings.LastIndexByte(exe, '/')+1:]
	}
	if info.Name == "" {
		info.Name = "?"
	}
	info.Cmdline = []string{info.Name}
	if t, err := maclite.TaskForPID(pid); err == nil {
		if tbi, ok := taskBasicInfo(t); ok {
			info.TotalMemory = tbi.VirtualSize
		}
		info.ThreadCount = len(threadIDs(t))
		maclite.PortDeallocate(t)
	}
	return info
}

// taskFor 取得目标进程的 task 端口，失败时翻译成带权限提示的错误。
func taskFor(pid int) (uint32, error) {
	t, err := maclite.TaskForPID(pid)
	if err != nil {
		return 0, fmt.Errorf("%w: task_for_id(%d) failed: %v", mem.ErrPrivilege, pid, err)
	}
	return t, nil
}

// OpenLive 打开一个活体进程。
func (b *Backend) OpenLive(spec string) (mem.Target, error) {
	pid := os.Getpid()
	if spec != "self" {
		p, err := strconv.Atoi(spec)
		if err != nil || p <= 0 {
			return nil, mem.ErrBadSpec
		}
		pid = p
	}
	t, err := taskFor(pid)
	if err != nil {
		return nil, err
	}
	info := readProcessInfo(pid)
	info.PID = pid
	// 试一次零字节写：成功即说明有写权限
	writable := maclite.VmWrite(t, 0, nil)
	return &Target{pid: pid, info: info, task: t, writable: writable}, nil
}

// Threads 列出进程的“子线程”。
func (b *Backend) Threads(pid int) ([]mem.ThreadInfo, error) {
	t, err := taskFor(pid)
	if err != nil {
		return nil, err
	}
	defer maclite.PortDeallocate(t)
	name := pidName(pid)
	out := make([]mem.ThreadInfo, 0, 8)
	for _, id := range threadIDs(t) {
		out = append(out, mem.ThreadInfo{TID: int(id), PID: pid, Name: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TID < out[j].TID })
	return out, nil
}

// pidName 返回进程名（取不到时回退到可执行文件名）。
func pidName(pid int) string {
	if exe := pidPath(pid); exe != "" {
		return exe[strings.LastIndexByte(exe, '/')+1:]
	}
	return ""
}

// Target 是某个 macOS 进程的内存镜像。
type Target struct {
	pid  int
	info mem.ProcessInfo
	task uint32
	// writable 表示是否已取得可写的任务端口。
	//
	// macOS 对写其它进程的限制比读更严（需要 root / 开发者模式 / 代码签名），
	// 拿不到时自动退回只读，保证只读取证路径不受影响。
	writable bool
}

// Kind 返回 "live"。
func (t *Target) Kind() string { return "live" }

// Info 返回进程信息。
func (t *Target) Info() mem.ProcessInfo { return t.info }

// Regions 用 mach_vm_region 从低地址到高地址枚举可读区域。
func (t *Target) Regions() ([]mem.Region, error) {
	var out []mem.Region
	var addr uint64
	for addr < maxUserAddr {
		size := uint64(16) // 试探性大小
		buf := make([]byte, 64)
		ret, _, _ := maclite.VmRegion(t.task, &addr, &size, vmRegionBasic64, buf)
		if ret != maclite.KernelSuccess || size == 0 {
			break
		}
		info := *(*vmRegionBasicInfo64Data)(unsafe.Pointer(&buf[0]))
		if info.Protection&vmProtRead != 0 {
			perm := protString(info.Protection)
			path := t.imageAt(addr)
			out = append(out, mem.Region{
				Start: addr,
				End:   addr + size,
				Perm:  perm,
				Path:  path,
				Kind:  mem.Classify(perm, path, path != "" && path == t.info.Exe),
			})
		}
		addr += size
	}
	mem.SortRegions(out)
	return out, nil
}

// imageAt 判断地址是否落在主可执行文件的经典低地址区间内。
//
// macOS 10.11 之后系统库几乎都来自 dyld 共享缓存、没有独立路径，
// 因此这里只对主映像给出路径，其余区域留空（归类为匿名）。
func (t *Target) imageAt(addr uint64) string {
	if t.info.Exe != "" && addr < 0x100000000 {
		return t.info.Exe
	}
	return ""
}

// protString 把 VM_PROT_* 翻译成 POSIX 风格权限位串，
// 便于与 Linux 的 maps 输出对照阅读。
func protString(prot uint32) string {
	perm := []byte("---p")
	if prot&vmProtRead != 0 {
		perm[0] = 'r'
	}
	if prot&vmProtWrite != 0 {
		perm[1] = 'w'
	}
	if prot&vmProtExecute != 0 {
		perm[2] = 'x'
	}
	return string(perm)
}

// Writable 报告该目标是否可写。
func (t *Target) Writable() bool { return t.writable }

// WriteAt 用 mach_vm_write 改写目标进程内存。
func (t *Target) WriteAt(addr uint64, p []byte) (int, error) {
	if !t.writable {
		return 0, mem.ErrNotWritable
	}
	if len(p) == 0 {
		return 0, nil
	}
	if !maclite.VmWrite(t.task, addr, p) {
		return 0, fmt.Errorf("mach_vm_write: kern_return != 0")
	}
	return len(p), nil
}

// ReadAt 用 mach_vm_read_overwrite 读目标进程内存。
//
// 该调用要么整块成功要么整块失败，失败返回 0；
// 调用方按区域粒度重试即可跳过读不出来的页。
func (t *Target) ReadAt(addr uint64, p []byte) (int, error) {
	n := maclite.VmRead(t.task, addr, p)
	if n == 0 && len(p) > 0 {
		return 0, fmt.Errorf("mach_vm_read_overwrite: address %#x is not readable", addr)
	}
	return n, nil
}

// Close 归还 task 端口。
func (t *Target) Close() error {
	if t.task != 0 {
		maclite.PortDeallocate(t.task)
		t.task = 0
	}
	return nil
}
