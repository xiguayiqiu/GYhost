//go:build windows

package mem

import (
	memwindows "gyhost/modules/mem/os/windows"
)

// backend 是当前编译目标平台（Windows）上的内存访问实现。
//
// 只有这一份会被编入二进制：Windows 的内存模型（分页 + 提交状态 +
// PAGE_* 保护属性）与 Linux 的 /proc 完全不同，参数则保持一致。
var backend = memwindows.New()
