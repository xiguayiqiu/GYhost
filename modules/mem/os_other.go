//go:build !linux && !android && !windows && !darwin

package mem

import (
	"runtime"

	"gyhost/internal/module"
	memunsupported "gyhost/modules/mem/os/unsupported"
)

// backend 是未实现活体内存读取的平台上的降级实现。
//
// 与上面三个文件互斥：编译时只会命中其中一个，
// 因此新增平台支持时只需再加一个 os_<goos>.go。
var backend = memunsupported.New(runtime.GOOS)

var _ module.Module = (*Module)(nil)
