//go:build darwin

// 本文件的构建约束是「模块只在 (linux 且非 android) 或 darwin 上存在」：
//   - Windows 走 WMI/CIM，进程模型与本模块完全不同，不提供该功能
//   - Android / Termux 受限（Android 7+ 起限制访问其它应用的 /proc），
//     procfs 拿不到有用的进程表，不提供该功能
//
// 注意约束里必须显式写 !android：GOOS=android 会同时满足 linux 这个
// 构建标签，只写 linux 的话 Termux 构建仍会把本包编进去。

package proc

import (
	procdarwin "gyhost/modules/proc/os/darwin"
)

// backend 是当前编译目标平台（macOS）上的进程分析实现。
//
// 只有这一份会被编入二进制：macOS 没有 procfs，数据来自 libproc
// （经 internal/maclite 的无 cgo 绑定），与 Linux 的实现完全独立，
// 但对外暴露同一套参数与同一份报告。
var backend = procdarwin.New()
