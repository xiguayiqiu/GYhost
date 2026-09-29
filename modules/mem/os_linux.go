//go:build linux || android

package mem

import (
	memlinux "gyhost/modules/mem/os/linux"
)

// backend 是当前编译目标平台（Linux / Android-Termux）上的内存访问实现。
//
// 只有这一份会被编入二进制：/proc 是 Linux 内核的 procfs 接口，
// Android 与 Termux 共用它，因此两者走同一套代码、同一套参数。
var backend = memlinux.New()
