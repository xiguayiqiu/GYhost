//go:build windows

package cuda

import "golang.org/x/sys/windows"

// privileged 报告当前进程是否具备启用 GPU 所需的权限。
//
// Windows 没有 root 概念，等价要求是「以管理员身份运行」（UAC 提升）。
// 通过当前进程令牌的 TokenElevation 判断，未提升时返回 false。
func privileged() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
