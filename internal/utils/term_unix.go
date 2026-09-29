//go:build unix

package utils

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// ErrRawUnsupported 表示当前平台或输入不是终端，无法进入 raw 模式。
var ErrRawUnsupported = errors.New("raw mode unsupported")

// SetRaw 把终端切到 raw 模式（关闭回显与行缓冲），返回的函数用于恢复。
//
// raw 模式下按键以字节为单位即时送达，交互式界面才能做到"按一下就响应"。
// 调用方必须 defer 恢复函数，否则终端会停留在无法回显的状态。
func SetRaw(f *os.File) (restore func(), err error) {
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return nil, ErrRawUnsupported
	}
	raw := *old
	// ICANON 关闭行缓冲、ECHO 关闭回显、ISIG 关闭 Ctrl-C 之类信号
	// （退出由界面自己处理），并把输入延迟压到 0。
	raw.Lflag &^= unix.ECHO | unix.ICANON | unix.ISIG
	raw.Iflag &^= unix.IXON | unix.ICRNL | unix.BRKINT | unix.INPCK | unix.ISTRIP
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, ioctlWriteTermios, &raw); err != nil {
		return nil, ErrRawUnsupported
	}
	return func() { _ = unix.IoctlSetTermios(fd, ioctlWriteTermios, old) }, nil
}

// IsTerminalFD 判断 fd 是否指向终端。
func IsTerminalFD(f *os.File) bool {
	if f == nil {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), ioctlReadTermios)
	return err == nil
}

// TerminalWidth 返回终端可见列数；w 不是终端或取值失败时回退到 COLUMNS / 80。
func TerminalWidth(w io.Writer) int {
	cols, _ := TerminalSize(w)
	return cols
}

// TerminalSize 返回终端的列数与行数；取不到时列回退 COLUMNS/80、行回退 24。
func TerminalSize(w io.Writer) (cols, rows int) {
	cols, rows = FallbackWidth, FallbackRows
	f, ok := w.(*os.File)
	if !ok {
		return cols, rows
	}
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil || ws == nil || ws.Col <= 0 {
		return cols, rows
	}
	rows = int(ws.Row)
	if rows <= 0 {
		rows = FallbackRows
	}
	return int(ws.Col), rows
}
