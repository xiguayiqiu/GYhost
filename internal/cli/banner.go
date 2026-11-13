package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"

	"gyhost/internal/i18n"
	"gyhost/internal/utils"
)

// artLines 是 "GYhost" 的 ASCII 艺术字：
// figlet standard 字体逐字渲染后按单空隙拼接排版（与 GYscan/Client 同一套版式）。
var artLines = []string{
	`    ____   __   __  _                      _   `,
	`   / ___|  \ \ / / | |__     ___     ___  | |_ `,
	`  | |  _    \ V /  | '_ \   / _ \   / __| | __|`,
	`  | |_| |    | |   | | | | | (_) |  \__ \ | |_ `,
	`   \____|    |_|   |_| |_|  \___/   |___/  \__|`,
}

// separator 横幅分隔线。
const separator = "=============================================="

// bannerInfo 横幅正文的样式（洋红粗体，与 GYscan/Client 的 BoldInfo 一致）。
var bannerInfo = color.New(color.FgMagenta, color.Bold)

// bannerLines 返回横幅的纯文本行（文案来自 i18n，随语言切换）。
func bannerLines(version string) []string {
	lines := make([]string, 0, len(artLines)+9)
	lines = append(lines, "")
	lines = append(lines, artLines...)
	lines = append(lines,
		"",
		separator,
		i18n.T("app.title"),
		i18n.T("app.author"),
		i18n.Tf("app.version", "v"+version),
		i18n.T("app.desc"),
		i18n.T("app.warning"),
		separator,
		i18n.T("app.get_help"),
	)
	return lines
}

// Banner 返回不带颜色控制符的横幅文本（供测试与日志使用）。
func Banner(version string) string {
	return strings.Join(bannerLines(version), "\n")
}

// printBanner 打印启动横幅：渐变艺术字 + 信息块。
func printBanner(w io.Writer) {
	fmt.Fprintln(w)

	printLogo(w, artLines)
	fmt.Fprintln(w)

	bannerInfo.Fprintln(w, separator)
	bannerInfo.Fprintln(w, i18n.T("app.title"))
	bannerInfo.Fprintln(w, i18n.T("app.author"))
	bannerInfo.Fprintln(w, i18n.Tf("app.version", "v"+Version))
	bannerInfo.Fprintln(w, i18n.T("app.desc"))

	redBold := color.New(color.FgHiRed, color.Bold)
	redBold.Fprintln(w, i18n.T("app.warning"))

	bannerInfo.Fprintln(w, separator)
	bannerInfo.Fprintln(w, i18n.T("app.get_help"))
}

// printLogo 打印 ASCII 艺术字。
// 真终端上按横向位置做 RGB 渐变；管道/文件退化为亮青粗体；--no-color 时纯文本。
func printLogo(w io.Writer, lines []string) {
	if color.NoColor {
		for _, line := range lines {
			fmt.Fprintln(w, line)
		}
		return
	}
	if !utils.IsTerminal(w) {
		for _, line := range lines {
			utils.StyleArt.Fprintln(w, line)
		}
		return
	}
	for _, line := range lines {
		printLogoGradient(w, line)
		fmt.Fprint(w, "\x1b[0m\n")
	}
}

// printLogoGradient 按字符横向位置在青色与粉红之间插值，复刻 GYscan/Client 的渐变。
func printLogoGradient(w io.Writer, line string) {
	runes := []rune(line)
	last := len(runes) - 1
	if last < 1 {
		last = 1
	}
	for i, r := range runes {
		if r == ' ' {
			fmt.Fprint(w, " ")
			continue
		}
		blend := float64(i) / float64(last)
		red := 24 + int(231*blend)
		green := 225 - int(195*blend)
		blue := 255 - int(15*blend)
		fmt.Fprintf(w, "\x1b[1;38;2;%d;%d;%dm%c", red, green, blue, r)
	}
}
