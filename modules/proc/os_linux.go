//go:build linux && !android

// 本文件的构建约束是「模块只在 (linux 且非 android) 或 darwin 上存在」：
//   - Windows 走 WMI/CIM，进程模型与本模块完全不同，不提供该功能
//   - Android / Termux 受限（Android 7+ 起限制访问其它应用的 /proc），
//     procfs 拿不到有用的进程表，不提供该功能
//
// 注意约束里必须显式写 !android：GOOS=android 会同时满足 linux 这个
// 构建标签，只写 linux 的话 Termux 构建仍会把本包编进去。

package proc

import (
	proclinux "gyhost/modules/proc/os/linux"
)

// backend 是当前编译目标平台（Linux / Android-Termux）上的进程分析实现。
//
// 只有这一份会被编入二进制：/proc 是 Linux 内核的 procfs 接口，
// Android 与 Termux 共用它，因此两者走同一套代码、同一套参数。
var backend = proclinux.New()
