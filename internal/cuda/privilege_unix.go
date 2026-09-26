//go:build !windows

package cuda

import "os"

// privileged 报告当前进程是否具备启用 GPU 所需的权限。
//
// 类 Unix 系统（Linux / macOS / Termux）要求以 root（euid 0）运行。
func privileged() bool { return os.Geteuid() == 0 }
