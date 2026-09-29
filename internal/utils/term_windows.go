//go:build windows

package utils

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// TerminalWidth 返回终端可见列数；w 不是控制台或取值失败时回退到 COLUMNS / 80。
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
	var info windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(windows.Handle(f.Fd()), &info); err != nil {
		return cols, rows
	}
	if w := int(info.Window.Right-info.Window.Left) + 1; w > 0 {
		cols = w
	}
	if h := int(info.Window.Bottom-info.Window.Top) + 1; h > 0 {
		rows = h
	}
	return cols, rows
}
