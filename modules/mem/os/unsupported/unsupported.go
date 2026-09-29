// Package unsupported 是 mem 模块在“没有实现活体内存读取的平台”上的降级后端。
//
// 用于 Windows / Linux / macOS 之外的 GOOS（例如部分 BSD、Solaris）：
// 编译照样通过，-i 指向活体进程时给出明确报错，
// -i 指向内存转储文件时仍然可以正常分析。
package unsupported

import "gyhost/internal/mem"

// Backend 是一个不提供活体内存能力的占位后端。
type Backend struct {
	// OS 是当前 GOOS，仅用于报错文案。
	OS string
}

// New 创建降级后端。
func New(osName string) mem.Backend { return &Backend{OS: osName} }

// Name 返回 "unsupported"。
func (b *Backend) Name() string { return "unsupported" }

// Supported 恒为 false。
func (b *Backend) Supported() bool { return false }

// PrivilegeHint 返回统一提示：转储文件仍可分析。
func (b *Backend) PrivilegeHint() string {
	return "live memory access is not implemented for " + b.OS +
		"; you can still analyze a memory dump file with -i <dump>"
}

// List 恒返回空列表（没有可枚举的进程）。
func (b *Backend) List() ([]mem.ProcessInfo, error) { return nil, mem.ErrUnsupported }

// OpenLive 恒返回 mem.ErrUnsupported。
func (b *Backend) OpenLive(string) (mem.Target, error) { return nil, mem.ErrUnsupported }

// Threads 恒返回 mem.ErrUnsupported（没有平台实现可枚举线程）。
func (b *Backend) Threads(int) ([]mem.ThreadInfo, error) { return nil, mem.ErrUnsupported }
