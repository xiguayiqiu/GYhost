// Package cli 实现 GYhost 的根命令：模块分发、全局帮助与退出码。
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"

	"gyhost/internal/i18n"
	"gyhost/internal/module"
	"gyhost/internal/utils"
)

// Version GYhost 版本号。
const Version = "0.1.4"

// flagRow 是一行全局参数说明。
// syntax 已经包含 pflag 风格的前导空格，便于直接对齐输出。
type flagRow struct {
	syntax string
	desc   string
}

// globalFlagList 根命令支持的全局参数（同时用于生成帮助信息）。
// 文案取自 i18n，因此在打印时构造，随语言切换。
func globalFlagList() []flagRow {
	return []flagRow{
		{"  -h, --help", i18n.T("flag.help")},
		{"      --lang string", i18n.T("flag.lang")},
		{"      --no-banner", i18n.T("flag.no_banner")},
		{"      --no-color", i18n.T("flag.no_color")},
		{"  -V, --version", i18n.T("flag.version")},
	}
}

// globalOptions 是剥离出来的全局开关。
type globalOptions struct {
	noBanner bool
	noColor  bool
	lang     string
}

// App 根命令。
type App struct {
	registry *module.Registry
	stdout   io.Writer
	stderr   io.Writer
	noBanner bool
}

// New 创建根命令。
func New(reg *module.Registry) *App {
	return &App{registry: reg, stdout: os.Stdout, stderr: os.Stderr}
}

// Run 执行根命令，返回进程退出码（0 表示成功）。
func (a *App) Run(args []string) int {
	// 全局参数先于模块分发处理
	args, opts := extractGlobalFlags(args)
	a.noBanner = opts.noBanner

	lang := i18n.Detect()
	if opts.lang != "" {
		if l := i18n.ParseLang(opts.lang); l != "" {
			lang = l
		}
	}
	i18n.SetLang(lang)

	if opts.noColor {
		color.NoColor = true
	}

	if len(args) == 0 {
		a.printRootHelp()
		return 0
	}

	name := args[0]
	switch name {
	case "-h", "--help", "help":
		if len(args) > 1 {
			return a.helpModule(args[1])
		}
		a.printRootHelp()
		return 0
	case "-v", "-V", "--version", "version":
		fmt.Fprintf(a.stdout, "GYhost version v%s\n", Version)
		return 0
	}

	if strings.HasPrefix(name, "-") {
		utils.Errorf(a.stderr, "%s", i18n.Tf("root.err.unknown_global_flag", name))
		fmt.Fprintln(a.stderr)
		a.printRootHelp()
		return 1
	}

	m, ok := a.registry.Get(name)
	if !ok {
		utils.Errorf(a.stderr, "%s", i18n.Tf("root.err.unknown_module", name))
		fmt.Fprintln(a.stderr)
		a.printRootHelp()
		return 1
	}

	if err := m.Run(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		utils.Errorf(a.stderr, "%s", i18n.Tf("root.err.prefix", err))
		return 1
	}
	return 0
}

// extractGlobalFlags 从参数中剥离全局开关，返回剩余参数与开关状态。
func extractGlobalFlags(args []string) (rest []string, opts globalOptions) {
	rest = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--no-banner":
			opts.noBanner = true
		case arg == "--no-color":
			opts.noColor = true
		case arg == "--lang":
			if i+1 < len(args) {
				opts.lang = args[i+1]
				i++
			} else {
				rest = append(rest, arg)
			}
		case strings.HasPrefix(arg, "--lang="):
			opts.lang = strings.TrimPrefix(arg, "--lang=")
		default:
			rest = append(rest, arg)
		}
	}
	return rest, opts
}

func (a *App) helpModule(name string) int {
	m, ok := a.registry.Get(name)
	if !ok {
		utils.Errorf(a.stderr, "%s", i18n.Tf("root.err.unknown_module", name))
		return 1
	}
	fmt.Fprintln(a.stdout, m.Usage())
	return 0
}

// printRootHelp 打印根帮助（版式对齐 GYscan/Client）：
// 横幅 -> 用法 -> 按分组列出模块 -> 全局参数 -> 获取命令帮助的提示。
func (a *App) printRootHelp() {
	if !a.noBanner {
		printBanner(a.stdout)
		fmt.Fprintln(a.stdout)
	}

	fmt.Fprintln(a.stdout, i18n.T("help.usage"))
	fmt.Fprintln(a.stdout, i18n.T("help.usage_line1"))
	fmt.Fprintln(a.stdout, i18n.T("help.usage_line2"))
	fmt.Fprintln(a.stdout)

	fmt.Fprintln(a.stdout, i18n.T("help.commands"))
	fmt.Fprintln(a.stdout)
	a.printGroups()

	fmt.Fprintln(a.stdout, i18n.T("help.flags"))
	a.printFlagUsages()
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, i18n.T("help.get_cmd_help"))
}

// printFlagUsages 按 pflag 的版式输出全局参数：
// 参数名左侧对齐，描述列从统一位置开始。
func (a *App) printFlagUsages() {
	rows := globalFlagList()
	width := 0
	for _, r := range rows {
		if n := utils.VisibleLen(r.syntax); n > width {
			width = n
		}
	}
	for _, r := range rows {
		gap := width - utils.VisibleLen(r.syntax) + 2
		fmt.Fprintf(a.stdout, "%s%s%s\n", r.syntax, strings.Repeat(" ", gap), r.desc)
	}
}

// printGroups 按分组输出模块列表，分组顺序取首次出现的顺序。
// 版式与 GYscan/Client 一致：彩色组名、灰色分隔线、15 列命令名。
func (a *App) printGroups() {
	var order []string
	grouped := map[string][]module.Module{}

	for _, name := range a.registry.Names() {
		m, _ := a.registry.Get(name)
		g := module.GroupOf(m)
		if _, ok := grouped[g]; !ok {
			order = append(order, g)
		}
		grouped[g] = append(grouped[g], m)
	}

	for _, g := range order {
		groupColor := color.New(helpGroupForeground(g), color.Bold)
		descriptionColor := color.New(helpGroupForeground(g))
		dimColor := color.New(color.FgHiBlack)

		groupColor.Fprintf(a.stdout, "  [ %s ]\n", g)
		if hint := groupHint(g); hint != "" {
			dimColor.Fprintf(a.stdout, "  %s\n", hint)
		}
		dimColor.Fprintln(a.stdout, "  ────────────────────────────────")

		for _, m := range grouped[g] {
			fmt.Fprint(a.stdout, "  ")
			groupColor.Fprintf(a.stdout, "%-15s", m.Name())
			fmt.Fprint(a.stdout, " ")
			descriptionColor.Fprintln(a.stdout, m.Summary())
		}
		fmt.Fprintln(a.stdout)
	}
}

// helpGroupForeground 返回分组主色，沿用 GYscan/Client 的语义配色。
func helpGroupForeground(group string) color.Attribute {
	switch group {
	case i18n.T("shadow.group"), i18n.T("hashdump.group"), i18n.T("hashcat.group"), i18n.T("hashac.group"):
		return color.FgHiMagenta
	case i18n.T("net.group"):
		return color.FgHiBlue
	case i18n.T("mem.group"):
		return color.FgHiGreen
	case i18n.T("proc.group"):
		return color.FgHiCyan
	default:
		return color.FgHiWhite
	}
}

// groupHint 返回分组的提示行；没有提示时返回空字符串（不打印该行）。
func groupHint(group string) string {
	switch group {
	case i18n.T("shadow.group"), i18n.T("hashdump.group"), i18n.T("hashcat.group"), i18n.T("hashac.group"):
		return i18n.T("help.group.local.hint")
	case i18n.T("net.group"):
		return i18n.T("help.group.net.hint")
	case i18n.T("mem.group"):
		return i18n.T("help.group.mem.hint")
	case i18n.T("proc.group"):
		return i18n.T("help.group.proc.hint")
	default:
		return ""
	}
}
