//go:build !unix && !windows

package utils

import "io"

// TerminalWidth 返回终端可见列数；本平台无法探测，回退到 COLUMNS / 80。
func TerminalWidth(w io.Writer) int { return terminalWidthFallback() }
