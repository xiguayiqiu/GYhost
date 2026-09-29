//go:build (linux && !android) || darwin

// 本文件的构建约束是「模块只在 (linux 且非 android) 或 darwin 上存在」：
//   - Windows 走 WMI/CIM，进程模型与本模块完全不同，不提供该功能
//   - Android / Termux 受限（Android 7+ 起限制访问其它应用的 /proc），
//     procfs 拿不到有用的进程表，不提供该功能
//
// 注意约束里必须显式写 !android：GOOS=android 会同时满足 linux 这个
// 构建标签，只写 linux 的话 Termux 构建仍会把本包编进去。

// Package proc 实现 GYhost 的 proc 模块：进程分析。
//
// 与 mem 的分工：
//   - mem  看的是**内存**（区域、字符串、熵、雕取、改写）
//   - proc 看的是**进程**（列表、父子树、命令行、环境变量、打开的文件、线程、资源占用）
//
// 覆盖平台：Linux（含 Android/Termux）与 macOS。
// 两者都有稳定的用户态接口（procfs / libproc），因此能给出结构一致的报告；
// 其余平台（如 Windows）只做明确降级提示，不给残缺实现。
//
// 跨平台设计：参数与上层逻辑在所有平台完全一致，
// 只有「怎么取进程数据」按平台分文件编译（os_linux.go / os_darwin.go /
// os_other.go），各平台实现在 modules/proc/os/<goos>/。
//
// 用法: gyhost proc [选项...]
package proc

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"gyhost/internal/cliflag"
	"gyhost/internal/i18n"
	"gyhost/internal/module"
	"gyhost/internal/proc"
	"gyhost/internal/utils"
)

// Module proc 模块。
type Module struct{}

// New 创建 proc 模块。
func New() module.Module { return &Module{} }

// Name 模块名。
func (m *Module) Name() string { return "proc" }

// Summary 模块简介（已国际化）。
func (m *Module) Summary() string { return i18n.T("proc.summary") }

// Group 模块在帮助信息中的分组（已国际化）。
func (m *Module) Group() string { return i18n.T("proc.group") }

// Usage 模块用法说明（已国际化）。
func (m *Module) Usage() string { return strings.TrimSpace(i18n.T("proc.usage")) }

// NoticeLevel 是运行期提示的级别。
type NoticeLevel int

// 提示级别取值。
const (
	// NoticeInfo 一般提示（蓝色 [*]）。
	NoticeInfo NoticeLevel = iota
	// NoticeOK 成功提示（绿色 [✓]）。
	NoticeOK
	// NoticeWarn 警告（黄色 [!]）。
	NoticeWarn
)

// noticePrinter 返回运行期提示的打印函数（全部写入 stderr，
// 保证 stdout 只有分析结果，便于管道）。w 为 nil 时静默（-q）。
func noticePrinter(w io.Writer) func(NoticeLevel, string) {
	if w == nil {
		return func(NoticeLevel, string) {}
	}
	return func(level NoticeLevel, msg string) {
		switch level {
		case NoticeOK:
			utils.Successf(w, "%s", msg)
		case NoticeWarn:
			utils.Warnf(w, "%s", msg)
		default:
			utils.Infof(w, "%s", msg)
		}
	}
}

// options 是 Run 解析出的全部运行参数。
//
// 与操作系统无关——Linux 与 macOS 参数完全一致，差异只在底层怎么取数。
type options struct {
	// 目标
	spec   string // -i：pid / self / 程序名（用于 detail / thread）
	isName bool   // -i 传的是程序名而不是 pid

	// 动作
	actions map[string]bool

	// 收敛范围
	filter     string         // -k 按名字/命令行模糊匹配
	user       string         // -u 只看某个用户
	parent     int            // -P 只看某个父进程的直接子进程
	sortField  proc.SortField // -t 排序依据
	minThreads int            // --min-threads 线程数下限
	minRSize   uint64         // --min-rss 常驻内存下限（字节）
	noKernel   bool           // -K 排除内核线程
	limit      int            // -n 每张表最多输出条数
	showAll    bool           // -X 不限制条数

	// 从 /proc 恢复文件
	recover *cliflag.Optional // -r 值可省略：不给=只扫描，给=恢复
	outDir  string            // -O 恢复件输出目录

	// 输出
	output  string // -o 报告写入文件
	jsonOut bool   // -j JSON 输出
	verbose bool   // -V 显示完整命令行而非截断
	quiet   bool   // -q 静默
}

// Run 解析参数并执行进程分析。
func (m *Module) Run(args []string) error {
	fs := flag.NewFlagSet("gyhost proc", flag.ContinueOnError)
	fs.SetOutput(new(strings.Builder)) // 由本模块自行输出提示，避免重复打印

	var (
		opt     options
		actions stringList
	)

	// -r 值可省略：单独出现 = 只扫描清单；带值 = 按编号/关键字恢复
	opt.recover = cliflag.New(recoverSentinel)
	fs.StringVar(&opt.spec, "i", "", i18n.T("proc.flag.input"))
	fs.StringVar(&opt.spec, "input", "", i18n.T("proc.flag.input"))
	fs.Var(&actions, "a", i18n.T("proc.flag.action"))
	fs.Var(&actions, "action", i18n.T("proc.flag.action"))
	fs.StringVar(&opt.filter, "k", "", i18n.T("proc.flag.filter"))
	fs.StringVar(&opt.filter, "filter", "", i18n.T("proc.flag.filter"))
	fs.StringVar(&opt.user, "u", "", i18n.T("proc.flag.user"))
	fs.StringVar(&opt.user, "user", "", i18n.T("proc.flag.user"))
	fs.IntVar(&opt.parent, "P", 0, i18n.T("proc.flag.parent"))
	fs.IntVar(&opt.parent, "parent", 0, i18n.T("proc.flag.parent"))
	fs.StringVar((*string)(&opt.sortField), "t", string(proc.SortThreads), i18n.T("proc.flag.sort"))
	fs.StringVar((*string)(&opt.sortField), "sort", string(proc.SortThreads), i18n.T("proc.flag.sort"))
	fs.IntVar(&opt.minThreads, "min-threads", 0, i18n.T("proc.flag.minthreads"))
	fs.Uint64Var(&opt.minRSize, "min-rss", 0, i18n.T("proc.flag.minrss"))
	fs.BoolVar(&opt.noKernel, "K", true, i18n.T("proc.flag.nokernel"))
	fs.BoolVar(&opt.noKernel, "no-kernel", true, i18n.T("proc.flag.nokernel"))
	fs.IntVar(&opt.limit, "n", 30, i18n.T("proc.flag.limit"))
	fs.IntVar(&opt.limit, "limit", 30, i18n.T("proc.flag.limit"))
	fs.BoolVar(&opt.showAll, "X", false, i18n.T("proc.flag.showall"))
	fs.BoolVar(&opt.showAll, "showall", false, i18n.T("proc.flag.showall"))
	fs.Var(opt.recover, "r", i18n.T("proc.flag.recover"))
	fs.Var(opt.recover, "recover", i18n.T("proc.flag.recover"))
	fs.StringVar(&opt.outDir, "O", "", i18n.T("proc.flag.outdir"))
	fs.StringVar(&opt.outDir, "outdir", "", i18n.T("proc.flag.outdir"))
	fs.StringVar(&opt.output, "o", "", i18n.T("proc.flag.out"))
	fs.StringVar(&opt.output, "out", "", i18n.T("proc.flag.out"))
	fs.BoolVar(&opt.jsonOut, "j", false, i18n.T("proc.flag.json"))
	fs.BoolVar(&opt.jsonOut, "json", false, i18n.T("proc.flag.json"))
	fs.BoolVar(&opt.verbose, "V", false, i18n.T("proc.flag.verbose"))
	fs.BoolVar(&opt.verbose, "verbose", false, i18n.T("proc.flag.verbose"))
	fs.BoolVar(&opt.quiet, "q", false, i18n.T("proc.flag.quiet"))
	fs.BoolVar(&opt.quiet, "quiet", false, i18n.T("proc.flag.quiet"))
	fs.Usage = func() { fmt.Println(m.Usage()) }

	if err := fs.Parse(cliflag.Normalize(args, recoverSentinel, "-r", "--recover")); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Println(m.Usage())
			return nil
		}
		return err
	}

	sel, err := resolveActions(actions)
	if err != nil {
		return err
	}
	opt.actions = sel
	if err := m.validate(&opt); err != nil {
		return err
	}

	if !backend.Supported() {
		return errors.New(i18n.Tf("proc.err.unsupported", backend.Name()))
	}

	var noticeStderr io.Writer = os.Stderr
	if opt.quiet {
		noticeStderr = nil
	}
	notice := noticePrinter(noticeStderr)

	dest := io.Writer(os.Stdout)
	if opt.output != "" {
		fh, err := os.Create(opt.output)
		if err != nil {
			return errors.New(i18n.Tf("proc.err.create_out", err))
		}
		defer fh.Close()
		dest = fh
	}

	if err := runAnalysis(dest, notice, opt); err != nil {
		return err
	}
	if opt.output != "" {
		notice(NoticeOK, i18n.Tf("proc.info.saved", opt.output))
	}
	return nil
}

// validate 校验参数组合。
func (m *Module) validate(opt *options) error {
	field, err := proc.ParseSortField(string(opt.sortField))
	if err != nil {
		return errors.New(i18n.Tf("proc.err.bad_sort", opt.sortField))
	}
	opt.sortField = field

	if opt.minThreads < 0 {
		return errors.New(i18n.Tf("proc.err.bad_minthreads", opt.minThreads))
	}
	if opt.limit < 0 {
		return errors.New(i18n.Tf("proc.err.bad_limit", opt.limit))
	}
	if opt.parent < 0 {
		return errors.New(i18n.Tf("proc.err.bad_parent", opt.parent))
	}
	if opt.showAll {
		opt.limit = 0
	}
	// -i 既可能是 pid 也可能是程序名，只看是不是数字。
	//
	// 两个坑：① 必须先显式置 false，validate 可能被重复调用（测试里就是这样），
	// 只在 true 时赋值会让上一次的残留粘住；
	// ② -i 缺省时不能算「程序名」——ParseSpec("") 是失败的，
	// 若据此置 true 就会拿空串去匹配进程表，结果一个都选不中。
	opt.isName = false
	if opt.spec != "" {
		if _, perr := proc.ParseSpec(opt.spec); perr != nil {
			opt.isName = true // 不是 pid，按程序名处理
		}
	}
	// detail / thread 必须有目标
	if (opt.actions[actDetail] || opt.actions[actThread]) && opt.spec == "" {
		return errors.New(i18n.T("proc.err.need_target"))
	}
	return nil
}

// stringList 是可重复的字符串参数。
type stringList []string

// String 实现 flag.Value，用于回显当前取值。
func (l *stringList) String() string { return strings.Join(*l, ",") }

// Set 追加一个参数值。
func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}
