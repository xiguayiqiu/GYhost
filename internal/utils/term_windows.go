//go:build windows

package utils

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// TerminalWidth 返回终端可见列数；w 不是控制台或取值失败时回退到 COLUMNS / 80。
func TerminalWidth(w io.Writer) int {
	f, ok := w.(*os.File)
	if !ok {
		return terminalWidthFallback()
	}
	var info windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(windows.Handle(f.Fd()), &info); err != nil {
		return terminalWidthFallback()
	}
	width := int(info.Window.Right-info.Window.Left) + 1
	if width <= 0 {
		return terminalWidthFallback()
	}
	return width
}
