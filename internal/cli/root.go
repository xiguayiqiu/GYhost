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
)

// Version GYhost 版本号。
const Version = "0.1.3"

// globalFlagList 根命令支持的全局参数（同时用于生成帮助信息）。
// 文案取自 i18n，因此在打印时构造，随 LANG 切换语言。
func globalFlagList() []struct {
	name string
	desc string
} {
	return []struct {
		name string
		desc string
	}{
		{"-h, --help", i18n.T("flag.help")},
		{"-v, --version", i18n.T("flag.version")},
		{"--no-banner", i18n.T("flag.no_banner")},
		{"--no-color", i18n.T("flag.no_color")},
	}
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
	args, noBanner, noColor := extractGlobalFlags(args)
	a.noBanner = noBanner
	if noColor {
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
	case "-v", "--version", "version":
		fmt.Fprintf(a.stdout, "GYhost v%s\n", Version)
		return 0
	}

	if strings.HasPrefix(name, "-") {
		fmt.Fprintf(a.stderr, "%s\n\n", i18n.Tf("root.err.unknown_global_flag", name))
		a.printRootHelp()
		return 1
	}

	m, ok := a.registry.Get(name)
	if !ok {
		fmt.Fprintf(a.stderr, "%s\n\n", i18n.Tf("root.err.unknown_module", name))
		a.printRootHelp()
		return 1
	}

	if err := m.Run(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(a.stderr, "%s\n", i18n.Tf("root.err.prefix", err))
		return 1
	}
	return 0
}

// extractGlobalFlags 从参数中剥离全局开关，返回剩余参数与开关状态。
func extractGlobalFlags(args []string) (rest []string, noBanner, noColor bool) {
	rest = make([]string, 0, len(args))
	for _, arg := range args {
		switch arg {
		case "--no-banner":
			noBanner = true
		case "--no-color":
			noColor = true
		default:
			rest = append(rest, arg)
		}
	}
	return rest, noBanner, noColor
}

func (a *App) helpModule(name string) int {
	m, ok := a.registry.Get(name)
	if !ok {
		fmt.Fprintf(a.stderr, "%s\n", i18n.Tf("root.err.unknown_module", name))
		return 1
	}
	fmt.Fprintln(a.stdout, m.Usage())
	return 0
}

// printRootHelp 打印根帮助（结构参考 freeclient）：
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
	for _, f := range globalFlagList() {
		fmt.Fprintf(a.stdout, "  %-14s %s\n", f.name, f.desc)
	}
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, i18n.T("help.get_cmd_help"))
}

// printGroups 按分组输出模块列表，分组顺序取首次出现的顺序。
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
		fmt.Fprintf(a.stdout, "  ==== %s ====\n", g)
		for _, m := range grouped[g] {
			fmt.Fprintf(a.stdout, "  %-14s %s\n", m.Name(), m.Summary())
		}
		fmt.Fprintln(a.stdout)
	}
}
