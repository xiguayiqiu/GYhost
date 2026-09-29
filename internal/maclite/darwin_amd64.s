// Mach / libproc 调用的汇编跳板（amd64）。
//
// 每个 libcXxx 都是 Go 变量（存着 libSystem 里的函数/数据地址），
// `JMP libcXxx(SB)` 生成一条「读该地址再跳转」的间接指令。
//
// 这样做的原因：macOS 的 Mach 服务不是 BSD 系统调用，只能经 libSystem 调用；
// 而 CGO_ENABLED=0 的交叉构建用不了 cgo 生成桩函数。
// Go 的 ABI0 参数传递约定与 C 在 amd64 macOS 上一致，因此无需搬运参数。
//
// 不要加 #include "textflag.h"：同一包内的多个 .s 文件会重复引入并报宏重定义。

TEXT ·libcTaskName(SB), $0-20
	JMP	purego_libc_task_name(SB)

TEXT ·libcTaskForID(SB), $0-20
	JMP	purego_libc_task_for_id(SB)

TEXT ·libcTaskInfo(SB), $0-20
	JMP	purego_libc_task_info(SB)

TEXT ·libcMachVMReadOverwrite(SB), $0-44
	JMP	purego_libc_mach_vm_read_overwrite(SB)

TEXT ·libcMachVMWrite(SB), $0-36
	JMP	purego_libc_mach_vm_write(SB)

TEXT ·libcMachVMRegion(SB), $0-52
	JMP	purego_libc_mach_vm_region(SB)

TEXT ·libcMachPortDeallocate(SB), $0-12
	JMP	purego_libc_mach_port_deallocate(SB)

TEXT ·libcTaskThreads(SB), $0-28
	JMP	purego_libc_task_threads(SB)

TEXT ·libcProcListAllPids(SB), $0-20
	JMP	purego_libc_proc_listallpids(SB)

TEXT ·libcProcPidPath(SB), $0-28
	JMP	purego_libc_proc_pidpath(SB)

TEXT ·libcProcPidInfo(SB), $0-36
	JMP	purego_libc_proc_pidinfo(SB)

// 当前进程的 Mach task 端口。
TEXT ·libcTaskSelfTrap(SB), $0-4
	JMP	purego_libc_task_self_trap(SB)
