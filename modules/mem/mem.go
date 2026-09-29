// Package mem 实现 GYhost 的 mem 模块：内存取证。
//
// 用途（四个方向）：
//   - 内存分析：内存区域布局、熵分布、哈希
//   - 程序行为分析：从内存字符串里还原 URL/IP/凭据/命令行/注入痕迹等
//   - 内存中恢复文件：按魔数雕取 png/zip/pdf/pe/sqlite 等内嵌文件
//   - 内存导出：把活体进程或镜像落盘成 raw dump，便于离线复核
//
// 跨平台设计：
//
//	参数与上层逻辑（mem.go / analyze.go / report.go）在所有平台完全一致；
//	只有"怎么访问内存"按平台分文件编译（os_linux.go / os_windows.go /
//	os_darwin.go / os_other.go），编译时只编入目标系统的那一份。
//	各平台的具体实现放在 modules/mem/os/<goos>/，都实现同一个
//	internal/mem.Backend 契约。
//
// 用法: gyhost mem -i <pid|self|转储文件> [-a 动作]
package mem

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
	"gyhost/internal/utils"
)

// Module mem 模块。
type Module struct{}

// New 创建 mem 模块。
func New() module.Module { return &Module{} }

// Name 模块名。
func (m *Module) Name() string { return "mem" }

// Summary 模块简介（已国际化）。
func (m *Module) Summary() string { return i18n.T("mem.summary") }

// Group 模块在帮助信息中的分组（已国际化）。
func (m *Module) Group() string { return i18n.T("mem.group") }

// Usage 模块用法说明（已国际化）。
func (m *Module) Usage() string { return strings.TrimSpace(i18n.T("mem.usage")) }

// NoticeLevel 是运行期提示的级别，决定展示配色。
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
// 注意：这个结构体与各平台无关——Windows / Linux / macOS 上参数完全一致，
// 差异只体现在底层 backend 怎么读内存。
type options struct {
	// 目标
	spec    string // -i 原始值：PID / self / 转储文件路径
	program string // -e 要分析的程序：PID 或程序名

	// 程序与线程列表
	list     bool   // -l 是否列出程序与线程
	listOnly string // -l 附带的目标（PID 或程序名）；空表示列出全部程序

	// 在内存中操作（改写目标程序的行为）
	addr     string // --addr 目标地址，支持 0x1234 或 区域名+偏移
	data     string // -Y 要写入/替换的内容（\xNN 字节、@文件、或 UTF-8 原文）
	apply    bool   // --apply 真正执行写入（默认只预览）
	force    bool   // --force 允许写入无写权限的区域/目标
	backup   string // --backup 回滚记录文件路径
	maxCount int    // --max 每次最多改写多少处

	// 动作
	actions  map[string]bool // -a 选中的动作
	actionIn stringList      // -a 原始取值（保持顺序）

	// 恢复文件
	carveDir string // -c 恢复文件的输出目录
	carveExt string // -t 雕取类型过滤

	// 收敛范围
	filter  string // -k 字符串/行为过滤关键字
	region  string // -r 区域过滤（类型名或地址范围）
	minSize int    // -s 区域最小字节数
	maxSize int    // -S 区域最大字节数（0 不限）
	minLen  int    // -L 字符串最小长度
	limit   int    // -n 每类结果最多输出条数
	enc     string // -E 字符串编码：ascii / utf16 / both

	// 输出
	output   string // -o 报告输出文件
	dump     string // -d 内存导出文件
	jsonOut  bool   // -j JSON 输出
	verbose  bool   // -V 详细模式
	quiet    bool   // -q 静默
	nonASCII bool   // -A 保留非 ASCII 串
	showAll  bool   // -X 不做结果条数限制
}

// Run 解析参数并执行内存分析。
func (m *Module) Run(args []string) error {
	fs := flag.NewFlagSet("gyhost mem", flag.ContinueOnError)
	fs.SetOutput(new(strings.Builder)) // 由本模块自行输出提示，避免重复打印

	// listOpt 是 -l 的取值：出现但无值 = 列出全部程序；有值 = 只看该程序
	listOpt := cliflag.New(listAllSentinel)

	var (
		opt     options
		actions stringList
	)
	fs.StringVar(&opt.spec, "i", "", i18n.T("mem.flag.input"))
	fs.StringVar(&opt.spec, "input", "", i18n.T("mem.flag.input"))
	fs.StringVar(&opt.program, "e", "", i18n.T("mem.flag.program"))
	fs.StringVar(&opt.program, "program", "", i18n.T("mem.flag.program"))
	fs.Var(listOpt, "l", i18n.T("mem.flag.list"))
	fs.Var(listOpt, "list", i18n.T("mem.flag.list"))
	fs.Var(&actions, "a", i18n.T("mem.flag.action"))
	fs.Var(&actions, "action", i18n.T("mem.flag.action"))
	fs.StringVar(&opt.carveDir, "c", "", i18n.T("mem.flag.carvedir"))
	fs.StringVar(&opt.carveDir, "carvedir", "", i18n.T("mem.flag.carvedir"))
	fs.StringVar(&opt.carveExt, "t", "all", i18n.T("mem.flag.type"))
	fs.StringVar(&opt.carveExt, "type", "all", i18n.T("mem.flag.type"))
	fs.StringVar(&opt.filter, "k", "", i18n.T("mem.flag.filter"))
	fs.StringVar(&opt.filter, "filter", "", i18n.T("mem.flag.filter"))
	fs.StringVar(&opt.region, "r", "all", i18n.T("mem.flag.region"))
	fs.StringVar(&opt.region, "region", "all", i18n.T("mem.flag.region"))
	fs.IntVar(&opt.minSize, "s", 0, i18n.T("mem.flag.minsize"))
	fs.IntVar(&opt.minSize, "size", 0, i18n.T("mem.flag.minsize"))
	fs.IntVar(&opt.maxSize, "S", 0, i18n.T("mem.flag.maxsize"))
	fs.IntVar(&opt.maxSize, "maxsize", 0, i18n.T("mem.flag.maxsize"))
	fs.IntVar(&opt.minLen, "L", 4, i18n.T("mem.flag.minlen"))
	fs.IntVar(&opt.minLen, "minlen", 4, i18n.T("mem.flag.minlen"))
	fs.IntVar(&opt.limit, "n", 50, i18n.T("mem.flag.limit"))
	fs.IntVar(&opt.limit, "limit", 50, i18n.T("mem.flag.limit"))
	fs.StringVar(&opt.addr, "addr", "", i18n.T("mem.flag.addr"))
	fs.StringVar(&opt.data, "Y", "", i18n.T("mem.flag.data"))
	fs.BoolVar(&opt.apply, "apply", false, i18n.T("mem.flag.apply"))
	fs.BoolVar(&opt.force, "force", false, i18n.T("mem.flag.force"))
	fs.StringVar(&opt.backup, "backup", "", i18n.T("mem.flag.backup"))
	fs.IntVar(&opt.maxCount, "max", 0, i18n.T("mem.flag.max"))
	fs.StringVar(&opt.enc, "E", "both", i18n.T("mem.flag.encoding"))
	fs.StringVar(&opt.enc, "encoding", "both", i18n.T("mem.flag.encoding"))
	fs.StringVar(&opt.output, "o", "", i18n.T("mem.flag.out"))
	fs.StringVar(&opt.output, "out", "", i18n.T("mem.flag.out"))
	fs.StringVar(&opt.dump, "d", "", i18n.T("mem.flag.dump"))
	fs.StringVar(&opt.dump, "dump", "", i18n.T("mem.flag.dump"))
	fs.BoolVar(&opt.jsonOut, "j", false, i18n.T("mem.flag.json"))
	fs.BoolVar(&opt.jsonOut, "json", false, i18n.T("mem.flag.json"))
	fs.BoolVar(&opt.verbose, "V", false, i18n.T("mem.flag.verbose"))
	fs.BoolVar(&opt.verbose, "verbose", false, i18n.T("mem.flag.verbose"))
	fs.BoolVar(&opt.quiet, "q", false, i18n.T("mem.flag.quiet"))
	fs.BoolVar(&opt.quiet, "quiet", false, i18n.T("mem.flag.quiet"))
	fs.BoolVar(&opt.nonASCII, "A", false, i18n.T("mem.flag.nonascii"))
	fs.BoolVar(&opt.nonASCII, "ascii", false, i18n.T("mem.flag.nonascii"))
	fs.BoolVar(&opt.showAll, "X", false, i18n.T("mem.flag.showall"))
	fs.BoolVar(&opt.showAll, "showall", false, i18n.T("mem.flag.showall"))
	fs.Usage = func() { fmt.Println(m.Usage()) }

	if err := fs.Parse(cliflag.Normalize(args, listAllSentinel, "-l", "--list")); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Println(m.Usage())
			return nil
		}
		return err
	}
	opt.list = listOpt.Present()
	opt.listOnly = listOpt.Value()
	// 写类动作必须有分析目标（要改的是某个目标的内存）
	if (opt.actions[actWrite] || opt.actions[actPatch] || opt.actions[actRestore]) &&
		opt.spec == "" && opt.program == "" {
		return errors.New(i18n.T("mem.err.write_need_target"))
	}
	// -l 可以单独使用（列程序/线程），否则必须给出 -i 或 -e
	if opt.spec == "" && opt.program == "" && !opt.list {
		fmt.Println(m.Usage())
		return errors.New(i18n.T("mem.err.missing_input"))
	}
	if opt.spec != "" && opt.program != "" {
		return errors.New(i18n.T("mem.err.target_conflict"))
	}
	if opt.jsonOut && opt.carveDir != "" {
		return errors.New(i18n.T("mem.err.json_carve"))
	}
	sel, err := resolveActions(actions)
	if err != nil {
		return err
	}
	opt.actions = sel
	if err := validateOptions(&opt); err != nil {
		return err
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
			return errors.New(i18n.Tf("mem.err.create_out", err))
		}
		defer fh.Close()
		dest = fh
	}

	if err := runAnalysis(dest, notice, opt); err != nil {
		return err
	}
	if opt.output != "" {
		notice(NoticeOK, i18n.Tf("mem.info.saved", opt.output))
	}
	return nil
}

// validateOptions 校验各参数的组合是否合法。
func validateOptions(opt *options) error {
	if opt.minSize < 0 {
		return errors.New(i18n.Tf("mem.err.bad_minsize", opt.minSize))
	}
	if opt.maxSize < 0 {
		return errors.New(i18n.Tf("mem.err.bad_maxsize", opt.maxSize))
	}
	if opt.maxSize > 0 && opt.minSize > opt.maxSize {
		return errors.New(i18n.Tf("mem.err.size_range", opt.minSize, opt.maxSize))
	}
	if opt.minLen < 1 || opt.minLen > 4096 {
		return errors.New(i18n.Tf("mem.err.bad_minlen", opt.minLen))
	}
	if opt.limit < 0 {
		return errors.New(i18n.Tf("mem.err.bad_limit", opt.limit))
	}
	if opt.showAll {
		opt.limit = 0
	}
	if opt.maxCount < 0 {
		return errors.New(i18n.Tf("mem.err.bad_max", opt.maxCount))
	}
	switch strings.ToLower(opt.enc) {
	case "ascii", "utf16", "utf16le", "both", "all":
	default:
		return errors.New(i18n.Tf("mem.err.bad_encoding", opt.enc))
	}
	if opt.region != "" {
		if _, err := parseRegionFilter(opt.region); err != nil {
			return err
		}
	}
	return nil
}

// listAllSentinel 是 -l 单独出现（不带 PID/程序名）时补上的哨兵值。
const listAllSentinel = "\x00all"

// stringList 是可重复的字符串参数（逗号分隔在解析时再拆）。
type stringList []string

// String 实现 flag.Value，用于回显当前取值。
func (l *stringList) String() string { return strings.Join(*l, ",") }

// Set 追加一个参数值。
func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}
