// Package utils 提供跨模块复用的公共辅助能力。
//
// Color.go 集中管理全部彩色显示能力：
//   - StyleXxx 样式变量：供需要自定义拼装的调用方使用
//   - Style/Stylef：用指定样式返回或打印文本
//   - Success/Warn/Info/Error/Title/Bold/Dim：常用颜色片段
//   - Successf/Warnf/Infof/Errorf/Titlef/Plainf：整行打印
//   - IsTerminal/ClearLine/PadRight：终端辅助
//
// 颜色由 fatih/color 统一控制：--no-color、非 TTY、NO_COLOR 时自动降级为纯文本。
package utils

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/fatih/color"
)

// 全部颜色样式（与 freeclient 配色一致）。
var (
	// StyleArt 横幅艺术字：亮蓝粗体。
	StyleArt = color.New(color.FgHiBlue, color.Bold)
	// StyleSuccess 成功/命中：绿粗体。
	StyleSuccess = color.New(color.FgGreen, color.Bold)
	// StyleWarn 警告/跳过：黄粗体。
	StyleWarn = color.New(color.FgYellow, color.Bold)
	// StyleInfo 一般信息：蓝粗体。
	StyleInfo = color.New(color.FgBlue, color.Bold)
	// StyleError 错误/失败：红粗体。
	StyleError = color.New(color.FgHiRed, color.Bold)
	// StyleTitle 标题/分隔线：青粗体。
	StyleTitle = color.New(color.FgCyan, color.Bold)
	// StyleBold 强调：白粗体。
	StyleBold = color.New(color.FgWhite, color.Bold)
	// StyleDim 次要信息：暗色。
	StyleDim = color.New(color.FgHiBlack)
)

// ---- 样式基础操作 ----

// Style 用指定样式格式化字符串；style 为 nil 时返回纯文本。
func Style(style *color.Color, format string, a ...interface{}) string {
	if style == nil {
		return fmt.Sprintf(format, a...)
	}
	return style.Sprintf(format, a...)
}

// Stylef 用指定样式向 w 打印一整行；style 为 nil 时打印纯文本。
// 先打印着色文本、再单独换行，避免颜色复位码落到下一行行首。
func Stylef(w io.Writer, style *color.Color, format string, a ...interface{}) {
	if style != nil {
		style.Fprintf(w, format, a...)
	} else {
		fmt.Fprintf(w, format, a...)
	}
	fmt.Fprintln(w)
}

// ---- 彩色字符串片段（用于行内拼装） ----

// Success 绿色粗体：命中/成功。
func Success(format string, a ...interface{}) string { return Style(StyleSuccess, format, a...) }

// Warn 黄色粗体：跳过/提醒。
func Warn(format string, a ...interface{}) string { return Style(StyleWarn, format, a...) }

// Info 蓝色粗体：一般信息。
func Info(format string, a ...interface{}) string { return Style(StyleInfo, format, a...) }

// Error 红色粗体：错误/失败。
func Error(format string, a ...interface{}) string { return Style(StyleError, format, a...) }

// Title 青色粗体：标题/进度/分隔线。
func Title(format string, a ...interface{}) string { return Style(StyleTitle, format, a...) }

// Bold 白色粗体：强调（用户名、密码等）。
func Bold(format string, a ...interface{}) string { return Style(StyleBold, format, a...) }

// Dim 暗色：次要信息（哈希、耗时等）。
func Dim(format string, a ...interface{}) string { return Style(StyleDim, format, a...) }

// ---- 整行打印 ----

// Successf 打印绿色成功行。
func Successf(w io.Writer, format string, a ...interface{}) { Stylef(w, StyleSuccess, format, a...) }

// Warnf 打印黄色警告行。
func Warnf(w io.Writer, format string, a ...interface{}) { Stylef(w, StyleWarn, format, a...) }

// Infof 打印蓝色信息行。
func Infof(w io.Writer, format string, a ...interface{}) { Stylef(w, StyleInfo, format, a...) }

// Errorf 打印红色错误行。
func Errorf(w io.Writer, format string, a ...interface{}) { Stylef(w, StyleError, format, a...) }

// Titlef 打印青色标题行。
func Titlef(w io.Writer, format string, a ...interface{}) { Stylef(w, StyleTitle, format, a...) }

// Plainf 打印无颜色行（颜色由调用方用 Success/Warn/... 片段自行拼装）。
func Plainf(w io.Writer, format string, a ...interface{}) { Stylef(w, nil, format, a...) }

// ---- 终端辅助 ----

// IsTerminal 判断 writer 是否为交互式终端。
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// ClearLine 在 TTY 上擦除当前行（非 TTY 无操作）。
func ClearLine(w io.Writer) {
	if IsTerminal(w) {
		fmt.Fprint(w, "\r\033[2K")
	}
}

// PadRight 按可见宽度右对齐填充（忽略 ANSI 转义序列），用于彩色输出的列对齐。
func PadRight(s string, width int) string {
	if diff := width - VisibleLen(s); diff > 0 {
		return s + spaces(diff)
	}
	return s
}

// VisibleLen 计算去掉 ANSI 转义序列后占用的终端列数。
//
// 规则：ASCII 字符算 1 列，其余字符（中文、全角符号等）一律按 2 列计。
// 对东亚宽字符这是精确值；对少数窄的非 ASCII 字符会略微高估——宁可高估，
// 也不要低估，否则进度行会超出终端宽度而折行。
func VisibleLen(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			// 跳过 ESC [ ... 终止字符 组成的控制序列
			i += 2
			for i < len(s) && !(s[i] >= 0x40 && s[i] <= 0x7e) {
				i++
			}
			continue
		}
		if s[i] < utf8.RuneSelf {
			n++
			i++
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		if size <= 0 {
			size = 1
		}
		n += 2
		i += size
	}
	return n
}

func spaces(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = ' '
	}
	return string(b)
}

// TruncateVisible 把字符串按可见宽度截断到至多 max 个可见字符（ANSI 转义序列不计入）。
//
// 截断点可能落在彩色片段中间，此时会补一个 ANSI 复位码，避免颜色泄漏到后续输出；
// 原串不含转义序列时不会凭空插入转义码。max <= 0 表示不限制。
func TruncateVisible(s string, max int) string {
	if max <= 0 || VisibleLen(s) <= max {
		return s
	}

	var (
		b   strings.Builder
		n   int
		esc bool
	)
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			// 整段控制序列原样拷贝，且不计入可见宽度
			j := i + 2
			for j < len(s) && !(s[j] >= 0x40 && s[j] <= 0x7e) {
				j++
			}
			if j < len(s) {
				j++
			}
			b.WriteString(s[i:j])
			esc = true
			i = j
			continue
		}
		if n >= max {
			break
		}
		// 按 UTF-8 边界整体拷贝一个字符，避免把多字节字符截成乱码
		_, size := utf8.DecodeRuneInString(s[i:])
		if size <= 0 {
			size = 1
		}
		if n+size > max {
			break
		}
		b.WriteString(s[i : i+size])
		n += size
		i += size
	}
	if esc {
		b.WriteString("\033[0m")
	}
	return b.String()
}
