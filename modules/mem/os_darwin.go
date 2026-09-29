//go:build darwin

package mem

import (
	memdarwin "gyhost/modules/mem/os/darwin"
)

// backend 是当前编译目标平台（macOS）上的内存访问实现。
//
// 只有这一份会被编入二进制：Mach 的 task 端口 + mach_vm_read 模型
// 与其它平台完全不同，参数则保持一致。
var backend = memdarwin.New()
