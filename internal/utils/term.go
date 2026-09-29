package utils

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// WaitReadable 等到 f 有数据可读或超时，返回是否可读。
//
// 交互式界面解析 ESC 序列时需要"等一小会儿看有没有后续字节"，直接 Read 会
// 把界面卡住，所以提供带超时的可读等待。本平台无对应实现时保守返回 true
// （退化为阻塞读）。
func WaitReadable(f *os.File, timeout time.Duration) bool { return waitReadable(f, timeout) }

// FallbackWidth 是无法判定终端宽度时使用的保守列数。
//
// 取 80 这个传统终端宽度：宁可少显示一点，也不要因超宽折行而刷屏。
const FallbackWidth = 80

// FallbackRows 是无法判定终端高度时使用的保守行数。
const FallbackRows = 24

// terminalWidthFallback 在无法从终端取到宽度时按 COLUMNS 环境变量兜底。
func terminalWidthFallback() int {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("COLUMNS"))); err == nil && v > 0 {
		return v
	}
	return FallbackWidth
}
