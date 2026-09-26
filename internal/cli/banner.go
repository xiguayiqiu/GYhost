package cli

import (
	"io"
	"strings"

	"github.com/fatih/color"

	"gyhost/internal/i18n"
	"gyhost/internal/utils"
)

// artLines 是 "GYhost" 的 ASCII 艺术字：
// figlet standard 字体逐字渲染后按单空隙拼接排版（与 freeclient 同一套排版方式）。
var artLines = []string{
	`    ____  __   __  _                     _`,
	`   / ___| \ \ / / | |__     ___    ___  | |_`,
	`  | |  _   \ V /  | '_ \   / _ \  / __| | __|`,
	`  | |_| |   | |   | | | | | (_) | \__ \ | |_`,
	`   \____|   |_|   |_| |_|  \___/  |___/  \__|`,
}

// separator 横幅分隔线。
const separator = "=============================================="

// bannerLine 横幅中的一行；style 为 nil 时不着色。
type bannerLine struct {
	style *color.Color
	text  string
}

// bannerLines 组装横幅的全部行（文案来自 i18n，随 LANG 切换语言）。
func bannerLines(version string) []bannerLine {
	lines := []bannerLine{{nil, ""}}
	for _, art := range artLines {
		lines = append(lines, bannerLine{utils.StyleArt, art})
	}
	lines = append(lines,
		bannerLine{nil, ""},
		bannerLine{utils.StyleInfo, separator},
		bannerLine{utils.StyleInfo, i18n.T("app.title")},
		bannerLine{utils.StyleInfo, i18n.T("app.author")},
		bannerLine{utils.StyleInfo, i18n.Tf("app.version", "v"+version)},
		bannerLine{utils.StyleInfo, i18n.T("app.desc")},
		bannerLine{utils.StyleError, i18n.T("app.warning")},
		bannerLine{utils.StyleInfo, separator},
		bannerLine{utils.StyleInfo, i18n.T("app.get_help")},
	)
	return lines
}

// Banner 返回不带颜色控制符的横幅文本（供测试与日志使用）。
func Banner(version string) string {
	var b strings.Builder
	for _, l := range bannerLines(version) {
		b.WriteString(l.text)
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

// printBanner 打印带颜色的启动横幅。
func printBanner(w io.Writer) {
	for _, l := range bannerLines(Version) {
		utils.Stylef(w, l.style, "%s", l.text)
	}
}
