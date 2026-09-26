package utils

import (
	"os"
	"strconv"
	"strings"
)

// FallbackWidth 是无法判定终端宽度时使用的保守列数。
//
// 取 80 这个传统终端宽度：宁可少显示一点，也不要因超宽折行而刷屏。
const FallbackWidth = 80

// terminalWidthFallback 在无法从终端取到宽度时按 COLUMNS 环境变量兜底。
func terminalWidthFallback() int {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("COLUMNS"))); err == nil && v > 0 {
		return v
	}
	return FallbackWidth
}
