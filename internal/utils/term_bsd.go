//go:build unix && !linux

package utils

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// BSD / macOS 的 termios 读写 ioctl 请求码。
const (
	ioctlReadTermios  = unix.TIOCGETA
	ioctlWriteTermios = unix.TIOCSETA
)

// waitReadable 等到 f 可读或超时，返回是否可读（见 term_linux.go 的同名单函数）。
func waitReadable(f *os.File, timeout time.Duration) bool {
	fd := int(f.Fd())
	kq, err := unix.Kqueue()
	if err != nil {
		return true
	}
	defer unix.Close(kq)
	ev := unix.Kevent_t{
		Ident:  uint64(fd),
		Filter: unix.EVFILT_READ,
		Flags:  unix.EV_ADD | unix.EV_ENABLE,
	}
	if _, err := unix.Kevent(kq, []unix.Kevent_t{ev}, nil, nil); err != nil {
		return true
	}
	ts := unix.NsecToTimespec(int64(timeout))
	events := make([]unix.Kevent_t, 1)
	n, err := unix.Kevent(kq, nil, events, &ts)
	return err == nil && n > 0
}
