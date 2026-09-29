//go:build windows

// Package windows 实现 Windows 平台的活体内存访问。
//
// 数据来源全部是 Win32 API（golang.org/x/sys/windows 已封装）：
//   - 进程列表：CreateToolhelp32Snapshot + Process32First/Next
//   - 内存布局：VirtualQueryEx 逐页枚举
//   - 内存内容：ReadProcessMemory
//   - 模块归属：EnumProcessModulesEx + GetModuleInformation
//
// 权限：打开其它用户的进程需要管理员（SeDebugPrivilege）权限。
package windows

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"gyhost/internal/mem"
)

// x/sys/windows 未定义的内存状态与类型常量。
const (
	memFree       = 0x00010000
	memImage      = 0x01000000 // MEM_IMAGE：可执行映像
	memMappedFile = 0x00040000 // MEM_MAPPED：文件映射
)

// Windows 线程的基础优先级取值（THREAD_PRIORITY_*），x/sys 未封装。
const (
	priIdle         = 0
	priLowest       = 1
	priBelowNormal  = 2
	priNormal       = 3
	priAboveNormal  = 4
	priHighest      = 5
	priTimeCritical = 15
)

// Backend 是 Windows 的 mem.Backend 实现。
type Backend struct{}

// New 创建 Windows 后端。
func New() mem.Backend { return &Backend{} }

// Name 返回平台标识。
func (b *Backend) Name() string { return "windows" }

// Supported 恒为 true：OpenProcess/VirtualQueryEx/ReadProcessMemory 自 Win9x 起就存在。
func (b *Backend) Supported() bool { return true }

// PrivilegeHint 返回权限不足时的提示。
func (b *Backend) PrivilegeHint() string {
	return "need Administrator (SeDebugPrivilege): run gyhost as administrator to inspect other processes"
}

// archName 归一化当前构建的架构名。
func archName() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "386":
		return "x86"
	case "arm64":
		return "arm64"
	default:
		return runtime.GOARCH
	}
}

// List 用 ToolHelp 快照列出所有进程。
func (b *Backend) List() ([]mem.ProcessInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", mem.ErrPrivilege, err)
	}
	defer windows.CloseHandle(snap)

	// 一次线程快照拿全所有进程的线程数，省得逐个进内核查询
	threads, terr := threadSnapshot()

	var out []mem.ProcessInfo
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := windows.Process32First(snap, &e); err != nil {
		return out, nil
	}
	for {
		pid := int(e.ProcessID)
		info := mem.ProcessInfo{
			PID:  pid,
			PPID: int(e.ParentProcessID),
			Name: windows.UTF16ToString(e.ExeFile[:]),
			Arch: archName(),
		}
		info.Exe = exePath(pid)
		if info.Exe != "" {
			info.Name = filepath.Base(info.Exe)
		}
		info.Cmdline = []string{info.Name}
		info.User = processUser(pid)
		if h, err := openRead(pid); err == nil {
			if v, ok := workingSetSize(h); ok {
				info.TotalMemory = v
			}
			info.Modules = modulePaths(h)
			windows.CloseHandle(h)
		}
		if terr == nil {
			info.ThreadCount = len(threads[pid])
		}
		out = append(out, info)
		if err := windows.Process32Next(snap, &e); err != nil {
			break
		}
	}
	return out, nil
}

// openRead 以“只读内存 + 查询信息”的最小权限打开进程。
func openRead(pid int) (windows.Handle, error) {
	h, _, err := openReadWrite(pid)
	return h, err
}

// openReadWrite 打开进程，并报告是否拿到了写内存的权限。
//
// 先按可写申请，失败再退回只读：这样“有权限就能操作、
// 没权限仍能只读分析”，而不是直接拒绝。
func openReadWrite(pid int) (windows.Handle, bool, error) {
	base := uint32(windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ |
		windows.PROCESS_VM_OPERATION | windows.PROCESS_QUERY_LIMITED_INFORMATION)
	h, err := windows.OpenProcess(base|windows.PROCESS_VM_WRITE, false, uint32(pid))
	if err == nil {
		return h, true, nil
	}
	h, err2 := windows.OpenProcess(base, false, uint32(pid))
	if err2 != nil {
		return 0, false, err
	}
	return h, false, nil
}

// exePath 用 QueryFullProcessImageName 取可执行文件全路径。
func exePath(pid int) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// processUser 由进程令牌取“域\用户名”。
func processUser(pid int) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return ""
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return ""
	}
	account, domain, _, err := tu.User.Sid.LookupAccount("")
	if err != nil {
		return ""
	}
	if domain != "" {
		return domain + `\` + account
	}
	return account
}

// workingSetSize 读进程的工作集大小（常驻内存字节数）。
func workingSetSize(h windows.Handle) (uint64, bool) {
	var min, max uintptr
	windows.GetProcessWorkingSetSizeEx(h, &min, &max, nil)
	if max == 0 {
		return 0, false
	}
	return uint64(max), true
}

// moduleInfo 是一个已加载模块的基址、大小与路径。
type moduleInfo struct {
	base uint64
	size uint64
	path string
}

// modules 枚举进程已加载模块（含基址与大小，用于给区域归属路径）。
func modules(h windows.Handle) []moduleInfo {
	var n uint32
	if err := windows.EnumProcessModulesEx(h, nil, 0, &n, windows.LIST_MODULES_ALL); err != nil || n == 0 {
		return nil
	}
	buf := make([]windows.Handle, n/uint32(unsafe.Sizeof(windows.Handle(0)))+1)
	if err := windows.EnumProcessModulesEx(h, &buf[0], uint32(len(buf))*4, &n, windows.LIST_MODULES_ALL); err != nil {
		return nil
	}
	var out []moduleInfo
	for _, mh := range buf {
		if mh == 0 {
			continue
		}
		var mi windows.ModuleInfo
		if err := windows.GetModuleInformation(h, mh, &mi, uint32(unsafe.Sizeof(mi))); err != nil {
			continue
		}
		name := make([]uint16, windows.MAX_LONG_PATH)
		size := uint32(len(name))
		if err := windows.GetModuleFileNameEx(h, mh, &name[0], size); err != nil {
			continue
		}
		out = append(out, moduleInfo{
			base: uint64(mi.BaseOfDll),
			size: uint64(mi.SizeOfImage),
			path: windows.UTF16ToString(name[:bytesToNull(name)]),
		})
	}
	return out
}

// modulePaths 只取模块路径列表。
func modulePaths(h windows.Handle) []string {
	mods := modules(h)
	out := make([]string, 0, len(mods))
	for _, m := range mods {
		out = append(out, m.path)
	}
	return out
}

// bytesToNull 截断 UTF-16 切片到第一个 NUL。
func bytesToNull(b []uint16) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return len(b)
}

// threadSnapshot 拍一次全系统线程快照，并按 owner 进程号分组。
//
// List() 与 Threads() 都用这个函数：一次快照就能同时拿到
// “每个进程有多少线程”和“指定进程的线程明细”，不必反复进内核。
func threadSnapshot() (map[int][]mem.ThreadInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", mem.ErrPrivilege, err)
	}
	defer windows.CloseHandle(snap)

	groups := map[int][]mem.ThreadInfo{}
	var e windows.ThreadEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := windows.Thread32First(snap, &e); err != nil {
		return groups, nil
	}
	for {
		owner := int(e.OwnerProcessID)
		tid := int(e.ThreadID)
		groups[owner] = append(groups[owner], mem.ThreadInfo{
			TID:   tid,
			PID:   owner,
			State: threadPriorityName(e.BasePri),
		})
		if err := windows.Thread32Next(snap, &e); err != nil {
			break
		}
	}
	return groups, nil
}

// threadPriorityName 把 ThreadEntry32.BasePri 翻译成可读名称。
//
// 线程快照里只有基础优先级，没有 Linux 那种 R/S/D 状态，
// 因此这里用它充当 State 列的语义（“线程调度类别”）。
func threadPriorityName(base int32) string {
	switch base {
	case priIdle:
		return "idle"
	case priLowest:
		return "lowest"
	case priBelowNormal:
		return "below"
	case priNormal:
		return "normal"
	case priAboveNormal:
		return "above"
	case priHighest:
		return "highest"
	case priTimeCritical:
		return "time_critical"
	default:
		return ""
	}
}

// Threads 列出进程的“子线程”。
//
// Windows 用 ToolHelp 的线程快照实现：一次快照拿全系统线程，
// 再按 th32OwnerProcessID 过滤出属于目标进程的那些。
func (b *Backend) Threads(pid int) ([]mem.ThreadInfo, error) {
	if _, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)); err != nil {
		if err == windows.ERROR_ACCESS_DENIED {
			return nil, fmt.Errorf("%w: pid %d: %v", mem.ErrPrivilege, pid, err)
		}
		return nil, fmt.Errorf("%w: pid %d", mem.ErrNoProcess, pid)
	}
	groups, err := threadSnapshot()
	if err != nil {
		return nil, err
	}
	out := groups[pid]
	sort.Slice(out, func(i, j int) bool { return out[i].TID < out[j].TID })
	return out, nil
}

// OpenLive 打开一个活体进程。
func (b *Backend) OpenLive(spec string) (mem.Target, error) {
	pid := int(windows.GetCurrentProcessId())
	if spec != "self" {
		p, err := strconv.Atoi(spec)
		if err != nil || p <= 0 {
			return nil, mem.ErrBadSpec
		}
		pid = p
	}
	h, writable, err := openReadWrite(pid)
	if err != nil {
		switch err {
		case windows.ERROR_ACCESS_DENIED:
			return nil, fmt.Errorf("%w: pid %d: %v", mem.ErrPrivilege, pid, err)
		case windows.ERROR_INVALID_PARAMETER:
			return nil, fmt.Errorf("%w: pid %d", mem.ErrNoProcess, pid)
		default:
			return nil, fmt.Errorf("%w: pid %d: %v", mem.ErrNoProcess, pid, err)
		}
	}
	exe := exePath(pid)
	info := mem.ProcessInfo{
		PID:     pid,
		Name:    filepath.Base(exe),
		Exe:     exe,
		Arch:    archName(),
		Cmdline: []string{filepath.Base(exe)},
		User:    processUser(pid),
	}
	if v, ok := workingSetSize(h); ok {
		info.TotalMemory = v
	}
	mods := modules(h)
	for _, m := range mods {
		info.Modules = append(info.Modules, m.path)
	}
	return &Target{pid: pid, info: info, h: h, mods: mods, writable: writable}, nil
}

// Target 是某个 Windows 进程的内存镜像。
type Target struct {
	pid  int
	info mem.ProcessInfo
	h    windows.Handle
	mods []moduleInfo // 打开时枚举一次，Regions 用它给区域归属路径
	// writable 表示是否以 PROCESS_VM_WRITE|PROCESS_VM_OPERATION 打开。
	//
	// 写别的进程需要 SeDebugPrivilege / 管理员；拿不到时自动退回只读，
	// 这样只读取证路径在任何权限下都照常可用。
	writable bool
}

// Kind 返回 "live"。
func (t *Target) Kind() string { return "live" }

// Info 返回进程信息。
func (t *Target) Info() mem.ProcessInfo { return t.info }

// Regions 用 VirtualQueryEx 从低地址到高地址逐页枚举已提交的内存。
func (t *Target) Regions() ([]mem.Region, error) {
	var out []mem.Region
	var addr uintptr
	// 64 位用户地址空间上界；32 位进程枚举到这里自然结束
	const maxAddr = 1 << 48
	var mbi windows.MemoryBasicInformation
	for addr < maxAddr {
		if err := windows.VirtualQueryEx(t.h, addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break
		}
		base := uint64(mbi.BaseAddress)
		size := uint64(mbi.RegionSize)
		if size == 0 {
			break
		}
		// 只关心已提交的页：MEM_FREE / MEM_RESERVE 里没有内容
		if mbi.State == windows.MEM_COMMIT && mbi.Protect != windows.PAGE_NOACCESS {
			perm := protectionString(mbi.Protect)
			path := ""
			if mbi.Type == memImage || mbi.Type == memMappedFile {
				path = t.moduleAt(base)
			}
			isMain := path != "" && strings.EqualFold(path, t.info.Exe)
			out = append(out, mem.Region{
				Start: base,
				End:   base + size,
				Perm:  perm,
				Path:  path,
				Kind:  mem.Classify(perm, path, isMain),
			})
		}
		next := base + size
		if next <= uint64(addr) {
			break
		}
		addr = uintptr(next)
	}
	mem.SortRegions(out)
	return out, nil
}

// moduleAt 返回覆盖该地址的模块路径（没有则空串）。
func (t *Target) moduleAt(addr uint64) string {
	for _, m := range t.mods {
		if addr >= m.base && addr < m.base+m.size {
			return m.path
		}
	}
	return ""
}

// protectionString 把 PAGE_* 常量翻译成 POSIX 风格权限位串，
// 便于与 Linux 的 maps 输出对照阅读。
func protectionString(protect uint32) string {
	// PAGE_GUARD 是修饰位，不影响实际权限
	p := protect &^ uint32(windows.PAGE_GUARD)
	// PAGE_WRITECOPY / PAGE_EXECUTE_WRITECOPY 语义上等同可写
	switch p {
	case windows.PAGE_READONLY:
		return "r--p"
	case windows.PAGE_READWRITE, windows.PAGE_WRITECOPY:
		return "rw-p"
	case windows.PAGE_EXECUTE:
		return "--xp"
	case windows.PAGE_EXECUTE_READ:
		return "r-xp"
	case windows.PAGE_EXECUTE_READWRITE, windows.PAGE_EXECUTE_WRITECOPY:
		return "rwxp"
	default:
		return "---p"
	}
}

// ReadAt 读目标进程的虚拟内存。
//
// PAGE_GUARD / PAGE_NOACCESS 页会失败；部分成功时返回实际字节数，
// 由调用方决定是否继续读后面的页。
func (t *Target) ReadAt(addr uint64, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	var n uintptr
	err := windows.ReadProcessMemory(t.h, uintptr(addr), &p[0], uintptr(len(p)), &n)
	return int(n), err
}

// Writable 报告该目标是否可写。
func (t *Target) Writable() bool { return t.writable }

// WriteAt 用 WriteProcessMemory 改写目标进程内存。
func (t *Target) WriteAt(addr uint64, p []byte) (int, error) {
	if !t.writable {
		return 0, mem.ErrNotWritable
	}
	if len(p) == 0 {
		return 0, nil
	}
	var n uintptr
	if err := windows.WriteProcessMemory(t.h, uintptr(addr), &p[0], uintptr(len(p)), &n); err != nil {
		return 0, err
	}
	return int(n), nil
}

// Close 关闭进程句柄。
func (t *Target) Close() error { return windows.CloseHandle(t.h) }
