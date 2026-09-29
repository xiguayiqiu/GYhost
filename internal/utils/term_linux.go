//go:build linux

package utils

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Linux 的 termios 读写 ioctl 请求码。
const (
	ioctlReadTermios  = unix.TCGETS
	ioctlWriteTermios = unix.TCSETS
)

// waitReadable 等到 f 可读或超时，返回是否可读。
//
// 用 epoll 而不是直接 Read：交互式界面解析 ESC 序列时需要"等一小会儿看有没有
// 后续字节"，直接 Read 会把界面卡住。
func waitReadable(f *os.File, timeout time.Duration) bool {
	fd := int(f.Fd())
	ep, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return true // 建不了 epoll 就退化为阻塞读
	}
	defer unix.Close(ep)
	ev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}
	if err := unix.EpollCtl(ep, unix.EPOLL_CTL_ADD, fd, &ev); err != nil {
		return true
	}
	ms := int(timeout.Milliseconds())
	if ms < 1 {
		ms = 1
	}
	out := make([]unix.EpollEvent, 1)
	n, err := unix.EpollWait(ep, out, ms)
	return err == nil && n > 0
}
