//go:build darwin

// Package maclite 是 macOS 上 libSystem 的轻量绑定层。
//
// 背景：macOS 没有完整 procfs，进程/内存信息只能通过 libSystem 的
// libproc 与 Mach 接口取得；而这些都不是 BSD 系统调用，Go 的 syscall 包
// 也不暴露。纯 Go（CGO_ENABLED=0）环境下用两段式动态绑定：
//
//  1. //go:cgo_import_dynamic 声明 libSystem 中的符号地址；
//  2. darwin_{amd64,arm64}.s 里的 JMP 桩函数跳到该地址。
//
// 抽成独立包是有意的：这些桩函数的 ABI0 栈帧大小是手工校准的
// （错了要靠 go vet 才能发现），复制一份等于复制一份隐患。
// mem 与 proc 两个模块共用这一份绑定。
//
// 运行时仍依赖 macOS 自带的 libSystem（系统组件，不构成额外依赖）。
package maclite

// import "unsafe" 是 //go:linkname 的硬性要求。
import _ "unsafe"

// KernelSuccess 是 kern_return_t 的成功返回值。
const KernelSuccess = 0

// ---- Mach 任务端口 ----

//go:cgo_import_dynamic purego_libc_task_self_trap task_self_trap "libSystem"
//go:linkname purego_libc_task_self_trap purego_libc_task_self_trap
var purego_libc_task_self_trap uintptr

//go:cgo_import_dynamic purego_libc_task_name task_name "libSystem"
//go:linkname purego_libc_task_name purego_libc_task_name
var purego_libc_task_name uintptr

//go:cgo_import_dynamic purego_libc_task_for_id task_for_id "libSystem"
//go:linkname purego_libc_task_for_id purego_libc_task_for_id
var purego_libc_task_for_id uintptr

//go:cgo_import_dynamic purego_libc_task_info task_info "libSystem"
//go:linkname purego_libc_task_info purego_libc_task_info
var purego_libc_task_info uintptr

//go:cgo_import_dynamic purego_libc_task_threads task_threads "libSystem"
//go:linkname purego_libc_task_threads purego_libc_task_threads
var purego_libc_task_threads uintptr

//go:cgo_import_dynamic purego_libc_mach_port_deallocate mach_port_deallocate "libSystem"
//go:linkname purego_libc_mach_port_deallocate purego_libc_mach_port_deallocate
var purego_libc_mach_port_deallocate uintptr

// ---- Mach 内存 ----

//go:cgo_import_dynamic purego_libc_mach_vm_read_overwrite mach_vm_read_overwrite "libSystem"
//go:linkname purego_libc_mach_vm_read_overwrite purego_libc_mach_vm_read_overwrite
var purego_libc_mach_vm_read_overwrite uintptr

//go:cgo_import_dynamic purego_libc_mach_vm_write mach_vm_write "libSystem"
//go:linkname purego_libc_mach_vm_write purego_libc_mach_vm_write
var purego_libc_mach_vm_write uintptr

//go:cgo_import_dynamic purego_libc_mach_vm_region mach_vm_region "libSystem"
//go:linkname purego_libc_mach_vm_region purego_libc_mach_vm_region
var purego_libc_mach_vm_region uintptr

// ---- libproc ----

//go:cgo_import_dynamic purego_libc_proc_listallpids proc_listallpids "libSystem"
//go:linkname purego_libc_proc_listallpids purego_libc_proc_listallpids
var purego_libc_proc_listallpids uintptr

//go:cgo_import_dynamic purego_libc_proc_pidpath proc_pidpath "libSystem"
//go:linkname purego_libc_proc_pidpath purego_libc_proc_pidpath
var purego_libc_proc_pidpath uintptr

//go:cgo_import_dynamic purego_libc_proc_pidinfo proc_pidinfo "libSystem"
//go:linkname purego_libc_proc_pidinfo purego_libc_proc_pidinfo
var purego_libc_proc_pidinfo uintptr

// 下列函数由 darwin_{amd64,arm64}.s 实现（直接跳到上面声明的 libSystem 符号）。

//go:noescape
func libcTaskName(target uint32, name uintptr) int32

//go:noescape
func libcTaskForID(target uint32, name uint32, t *uint32) int32

//go:noescape
func libcTaskInfo(target uint32, flavor int32, t uintptr) int32

//go:noescape
func libcTaskThreads(task uint32, actList uintptr, count *uint32) int32

//go:noescape
func libcMachPortDeallocate(task uint32, name uint32) int32

//go:noescape
func libcMachVMReadOverwrite(target uint32, addr uint64, size uint64, data uintptr, outSize *uint64) int32

//go:noescape
func libcMachVMWrite(target uint32, addr uint64, size uint64, data uintptr) int32

//go:noescape
func libcMachVMRegion(target uint32, addr *uint64, size *uint64, flavor int32, info uintptr, count *uint32) int32

//go:noescape
func libcProcListAllPids(buf uintptr, size int32) int32

//go:noescape
func libcProcPidPath(pid int32, buf uintptr, size uint32) int32

//go:noescape
func libcProcPidInfo(pid int32, flavor int32, arg uint64, buf uintptr, size int32) int32

//go:noescape
func libcTaskSelfTrap() uint32

// TaskSelf 返回当前进程自身的 Mach task 端口。
//
// 头文件里的 mach_task_self() 读取的是全局变量 mach_task_self_，
// 但那是**数据**符号：PC 相对寻址表达不了它的地址，链接期直接报错。
// 因此这里用功能等价的 task_self_trap —— 它是普通函数，跳板能正常处理。
func TaskSelf() uint32 { return libcTaskSelfTrap() }

// TaskName 取某个 task 的名字（mach_task_self 的名字就是自身端口值）。
func TaskName(target uint32) (uint32, bool) {
	nbuf := make([]uint32, 1)
	if libcTaskName(target, ptr(nbuf)) != KernelSuccess || nbuf[0] == 0 {
		return 0, false
	}
	return nbuf[0], true
}

// TaskForPID 通过 task_name + task_for_id 取得目标进程的 task 端口。
//
// 权限不足时 task_for_id 返回 KERN_FAILURE。
func TaskForPID(pid int) (uint32, error) {
	self := TaskSelf()
	name, ok := TaskName(self)
	if !ok {
		return 0, errTaskName
	}
	var t uint32
	if libcTaskForID(self, name, &t) != KernelSuccess || t == 0 {
		return 0, errTaskForID
	}
	return t, nil
}

// errTaskName / errTaskForID 是绑定层能给出的粗粒度原因，
// 上层（mem/proc）会包装成带权限提示的错误。
var (
	errTaskName  = errorString("maclite: task_name failed")
	errTaskForID = errorString("maclite: task_for_id failed")
)

type errorString string

func (e errorString) Error() string { return string(e) }

// ErrTaskForID 供上层用 errors.Is 判断「拿不到 task 端口」。
var ErrTaskForID = errTaskForID

// PortDeallocate 归还 task 端口。
func PortDeallocate(name uint32) { libcMachPortDeallocate(TaskSelf(), name) }

// TaskInfo 用 task_info 读 TASK_BASIC_INFO_64（虚拟/常驻内存、线程数）。
//
// 需要 info 至少有 64 字节空间；返回实际填写的字节数。
func TaskInfo(task uint32, info []byte) (int, bool) {
	if len(info) < 64 {
		return 0, false
	}
	if libcTaskInfo(task, TaskBasicInfo64, ptr(info)) != KernelSuccess {
		return 0, false
	}
	return len(info), true
}

// TaskBasicInfo64 是 TASK_BASIC_INFO_64 的 flavor 号。
const TaskBasicInfo64 = 20

// TaskThreads 返回目标任务的全部线程端口（端口号即线程号 TID）。
func TaskThreads(task uint32) []uint32 {
	var n uint32
	if libcTaskThreads(task, 0, &n) != KernelSuccess || n == 0 {
		return nil
	}
	buf := make([]uint32, n)
	if libcTaskThreads(task, ptr(buf), &n) != KernelSuccess {
		return nil
	}
	return buf[:n]
}

// VmRegion 枚举目标任务的一段内存区域。
//
// 反复调用即可从低地址扫到高地址；info 需能容纳 flavor 指定的结构体。
func VmRegion(task uint32, addr *uint64, size *uint64, flavor int32, info []byte) (int32, int, bool) {
	count := uint32(len(info) / 4)
	ret := libcMachVMRegion(task, addr, size, flavor, ptr(info), &count)
	return ret, int(count), true
}

// VmRead 把目标任务的内存读进 data，返回读到的字节数。
func VmRead(task uint32, addr uint64, data []byte) int {
	if len(data) == 0 {
		return 0
	}
	var outSize uint64
	if libcMachVMReadOverwrite(task, addr, uint64(len(data)), ptr(data), &outSize) != KernelSuccess {
		return 0
	}
	return int(outSize)
}

// VmWrite 把 data 写进目标任务的内存。
func VmWrite(task uint32, addr uint64, data []byte) bool {
	if len(data) == 0 {
		return true
	}
	return libcMachVMWrite(task, addr, uint64(len(data)), ptr(data)) == KernelSuccess
}

// ListAllPIDs 返回系统所有 pid。
func ListAllPIDs() []int32 {
	need := libcProcListAllPids(0, 0)
	if need <= 0 {
		return nil
	}
	buf := make([]int32, need/4+1)
	n := libcProcListAllPids(ptr(buf), int32(len(buf)*4))
	if n <= 0 {
		return nil
	}
	out := make([]int32, 0, n/4)
	for _, p := range buf[:n/4] {
		if p > 0 {
			out = append(out, p)
		}
	}
	return out
}

// PidPathMax 是 proc_pidpath 需要的缓冲区大小。
const PidPathMax = 4096

// PidPath 返回进程的可执行文件路径。
func PidPath(pid int) string {
	buf := make([]byte, PidPathMax)
	n := libcProcPidPath(int32(pid), ptr(buf), PidPathMax)
	if n <= 0 {
		return ""
	}
	return string(buf[:n])
}

// PidInfo 用 proc_pidinfo 读取指定 flavor 的信息，返回填写的字节数。
func PidInfo(pid int, flavor int32, arg uint64, buf []byte) int {
	if len(buf) == 0 {
		return 0
	}
	return int(libcProcPidInfo(int32(pid), flavor, arg, ptr(buf), int32(len(buf))))
}
