//go:build unix

package utils

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// TerminalWidth 返回终端可见列数；w 不是终端或取值失败时回退到 COLUMNS / 80。
func TerminalWidth(w io.Writer) int {
	f, ok := w.(*os.File)
	if !ok {
		return terminalWidthFallback()
	}
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil || ws == nil || ws.Col <= 0 {
		return terminalWidthFallback()
	}
	return int(ws.Col)
}
