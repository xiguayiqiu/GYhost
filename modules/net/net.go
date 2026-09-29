// Package net 实现 GYhost 的 net 模块：离线分析 pcap/cap 抓包文件。
//
// 输入一个或多个抓包（pcap/pcapng），输出：
//   - 抓包概览与四层协议分布
//   - 会话 / 主机 / 端口 TOP
//   - DNS 查询、TLS SNI、明文 HTTP 主机与 URI
//   - 安全发现：明文凭据、HTTP 口令字段、ARP 冲突、明文协议
//   - -m 启用的攻击分析：SYN/UDP/ICMP 洪泛、CC 攻击、流量丢包、分片异常
//
// 也可以用 -l 逐包列出，配合 -f 过滤表达式做定点排查。
// 全程只读本地文件，不发包、不联网。
package net

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"

	"gyhost/internal/i18n"
	"gyhost/internal/module"
	"gyhost/internal/pcap"
	"gyhost/internal/utils"
)

// Module net 模块。
type Module struct{}

// New 创建 net 模块。
func New() module.Module { return &Module{} }

// Name 模块名。
func (m *Module) Name() string { return "net" }

// Summary 模块简介（已国际化）。
func (m *Module) Summary() string { return i18n.T("net.summary") }

// Group 模块在帮助信息中的分组（已国际化）。
func (m *Module) Group() string { return i18n.T("net.group") }

// Usage 模块用法说明（已国际化）。
func (m *Module) Usage() string { return strings.TrimSpace(i18n.T("net.usage")) }

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
// 保证 stdout 只有报告，便于管道）。配色按级别区分。
//
// w 为 nil 时静默（-q）。
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

// Run 解析参数并执行网络分析。
func (m *Module) Run(args []string) error {
	fs := flag.NewFlagSet("gyhost net", flag.ContinueOnError)
	fs.SetOutput(new(strings.Builder)) // 由本模块自行输出提示，避免重复打印

	var (
		inputs           inputList
		models           modelList
		output           string
		list             bool
		verbose          bool
		tui              bool
		quiet            bool
		top              int
		limit            int
		filterExp        string
		zs               sectionList
		jsonOut          bool
		timeExp          string
		timelineInterval string
	)
	fs.Var(&inputs, "i", i18n.T("net.flag.input"))
	fs.Var(&inputs, "input", i18n.T("net.flag.input"))
	fs.Var(&models, "m", i18n.T("net.flag.model"))
	fs.Var(&models, "model", i18n.T("net.flag.model"))
	fs.StringVar(&output, "o", "", i18n.T("net.flag.out"))
	fs.StringVar(&output, "out", "", i18n.T("net.flag.out"))
	fs.BoolVar(&list, "l", false, i18n.T("net.flag.list"))
	fs.BoolVar(&list, "list", false, i18n.T("net.flag.list"))
	fs.BoolVar(&verbose, "V", false, i18n.T("net.flag.verbose"))
	fs.BoolVar(&verbose, "verbose", false, i18n.T("net.flag.verbose"))
	fs.BoolVar(&tui, "T", false, i18n.T("net.flag.tui"))
	fs.BoolVar(&tui, "tui", false, i18n.T("net.flag.tui"))
	fs.StringVar(&filterExp, "f", "", i18n.T("net.flag.filter"))
	fs.StringVar(&filterExp, "filter", "", i18n.T("net.flag.filter"))
	fs.IntVar(&top, "top", 10, i18n.T("net.flag.top"))
	fs.IntVar(&limit, "n", 0, i18n.T("net.flag.limit"))
	fs.IntVar(&limit, "limit", 0, i18n.T("net.flag.limit"))
	fs.BoolVar(&quiet, "q", false, i18n.T("net.flag.quiet"))
	fs.BoolVar(&quiet, "quiet", false, i18n.T("net.flag.quiet"))
	fs.Var(&zs, "z", i18n.T("net.flag.section"))
	fs.BoolVar(&jsonOut, "j", false, i18n.T("net.flag.json"))
	fs.BoolVar(&jsonOut, "json", false, i18n.T("net.flag.json"))
	fs.StringVar(&timeExp, "t", "", i18n.T("net.flag.time"))
	fs.StringVar(&timeExp, "time", "", i18n.T("net.flag.time"))
	fs.StringVar(&timelineInterval, "I", "", i18n.T("net.flag.interval"))
	fs.Usage = func() { fmt.Println(m.Usage()) }

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Println(m.Usage())
			return nil
		}
		return err
	}
	if len(inputs) == 0 {
		fmt.Println(m.Usage())
		return errors.New(i18n.T("net.err.missing_args"))
	}
	if top < 1 {
		return errors.New(i18n.Tf("net.err.bad_top", top))
	}
	if limit < 0 {
		return errors.New(i18n.Tf("net.err.bad_limit", limit))
	}
	if verbose && !list {
		// -V 是逐包详细视图，必须配合 -l；单独给 -V 时自动补上列表模式
		list = true
	}
	if tui && output != "" {
		return errors.New(i18n.T("net.err.tui_output"))
	}
	secs, follow, hasFollow, err := resolveSections(zs)
	if err != nil {
		return err
	}
	tr, err := parseTimeRange(timeExp)
	if err != nil {
		return err
	}
	// -j 与 -T 互斥：JSON 是给管道用的，交互界面会把它冲掉
	if jsonOut && tui {
		return errors.New(i18n.T("net.err.json_tui"))
	}
	if list && (hasFollow || len(secs) > 0) {
		// 列表模式是流式逐包输出，章节选择在它之后才生效，语义冲突
		return errors.New(i18n.T("net.err.list_section"))
	}
	flt, err := parseFilter(filterExp)
	if err != nil {
		return err
	}
	atkModels, err := parseModels(models)
	if err != nil {
		return err
	}

	paths, err := resolveInputs(inputs)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New(i18n.T("net.err.no_input"))
	}

	var noticeStderr io.Writer = os.Stderr
	if quiet {
		noticeStderr = nil
	}
	notice := noticePrinter(noticeStderr)

	// 报告写到 stdout；指定 -o 时写入文件（同时去掉 ANSI 颜色码）
	dest := io.Writer(os.Stdout)
	colorless := false
	if output != "" {
		fh, err := os.Create(output)
		if err != nil {
			return errors.New(i18n.Tf("net.err.create_out", err))
		}
		defer fh.Close()
		dest = fh
		colorless = true
	}

	processed := 0
	for _, p := range paths {
		if tui {
			// TUI 接管整个终端：环境不满足时直接报错，不静默降级
			if err := runTUIFile(p, flt); err != nil {
				return err
			}
			processed++
			continue
		}
		if processed > 0 {
			// 多个输入之间留一个空行，避免两份报告糊在一起
			fmt.Fprintln(dest)
		}
		cfg := runCfg{
			flt: flt, models: atkModels, list: list, verbose: verbose,
			limit: limit, top: top, colorless: colorless,
			secs: secs, timeRange: tr, jsonOut: jsonOut,
		}
		// 时间线要逐帧分桶，只有在真的要用时才采集
		// （-j 未指定章节时全都要，所以也要开）
		if wantSec(secs, secTimeline) || jsonOut {
			iv, err := parseInterval(timelineInterval)
			if err != nil {
				return err
			}
			cfg.timeline = &timelineLimits{interval: iv, maxBucket: defaultTimelineBuckets}
		}
		if hasFollow {
			f := follow
			cfg.follow = &f
		}
		if err := runOne(dest, p, cfg); err != nil {
			notice(NoticeWarn, err.Error())
			continue
		}
		processed++
	}
	if processed == 0 {
		return errors.New(i18n.T("net.err.no_input"))
	}
	if output != "" {
		notice(NoticeOK, i18n.Tf("net.info.saved", output))
	}
	return nil
}

// runCfg 是一次分析的运行参数（Run 解析出的选项）。
type runCfg struct {
	flt    *filter
	models modelSet
	// verbose 表示 -V 详细模式（配合 -l 逐包输出协议树）
	verbose   bool
	list      bool
	limit     int
	top       int
	colorless bool
	// secs 是 -z 选中的章节；nil 表示输出完整报告
	secs []string
	// follow 非 nil 时输出 TCP 会话追踪（-z follow,tcp,...）
	follow *followSpec
	// timeline 启用流量时间线（-z timeline）
	timeline *timelineLimits
	// timeRange 是 -t 时间范围过滤
	timeRange *timeRange
	// jsonOut 表示 -j：输出 JSON 而非人读报告
	jsonOut bool
}

// runOne 分析一个抓包：列表模式流式输出逐包信息，否则先扫描再打印报告。
// colorless 为 true 时本次渲染不带颜色（写文件场景）。
func runOne(dest io.Writer, path string, cfg runCfg) error {
	if cfg.list {
		return withColor(cfg.colorless, func() error {
			return runList(dest, path, cfg)
		})
	}
	opts := scanOpts{flt: cfg.flt, models: cfg.models, timeline: cfg.timeline}
	if cfg.follow != nil {
		opts.streams = &streamLimits{
			perDir:  defaultStreamPerDir,
			total:   defaultStreamPerSess,
			perSess: defaultStreamSegs,
		}
	}
	if cfg.timeRange != nil {
		opts.timeRange = cfg.timeRange
	}
	res, err := scanCapture(path, opts)
	if err != nil {
		return err
	}
	return withColor(cfg.colorless, func() error {
		if cfg.jsonOut {
			return writeJSONReport(dest, res, cfg.flt, cfg.top, cfg.secs)
		}
		writeReport(dest, res, cfg.flt, cfg.top, cfg.secs)
		if cfg.follow != nil {
			writeFollowSection(dest, res, *cfg.follow)
		}
		return nil
	})
}

// runList 逐包打印：先出文件信息与列头，再逐行输出，最后给一行小结
// 与（启用时的）攻击分析结论。
func runList(dest io.Writer, path string, cfg runCfg) error {
	var (
		t0     time.Time
		listed int
	)
	res, err := scanCapture(path, scanOpts{
		flt:     cfg.flt,
		models:  cfg.models,
		verbose: cfg.verbose,
		onOpen: func(info pcap.Info) {
			writeListHeader(dest, path, info, cfg.flt, cfg.verbose)
		},
		onPkt: func(p *pkt) error {
			if t0.IsZero() {
				t0 = p.ts
			}
			if cfg.limit > 0 && listed >= cfg.limit {
				return nil
			}
			listed++
			if cfg.verbose {
				if listed > 1 {
					fmt.Fprintln(dest) // 包之间空一行，便于分隔协议树
				}
				writePacketDetail(dest, p, t0)
			} else {
				writePacketRow(dest, p, t0)
			}
			return nil
		},
	})
	if err != nil {
		return err
	}
	utils.Plainf(dest, "    %s", i18n.Tf("net.list.summary",
		res.a.total, res.a.matched, listed))
	writeAttackSection(dest, res.a)
	return nil
}

// withColor 在 fn 执行期间临时关闭颜色（colorless 为 false 时原样执行）。
func withColor(colorless bool, fn func() error) error {
	if !colorless {
		return fn()
	}
	saved := color.NoColor
	color.NoColor = true
	defer func() { color.NoColor = saved }()
	return fn()
}

// inputList 是 -i 参数的取值类型：同时支持逗号分隔与重复指定，并自动去重。
//
//	-i a.pcap,b.cap   /   -i a.pcap -i b.cap
type inputList []string

// String 实现 flag.Value，用于回显当前取值。
func (l *inputList) String() string { return strings.Join(*l, ",") }

// Set 追加一个参数值（内部按逗号拆分）。
func (l *inputList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		dup := false
		for _, existing := range *l {
			if existing == name {
				dup = true
				break
			}
		}
		if !dup {
			*l = append(*l, name)
		}
	}
	return nil
}

// modelList 是 -m 参数的取值类型：逗号分隔、可重复，
// 语义（含别名与 all/flood 组合）由 parseModels 统一解释。
type modelList []string

// String 实现 flag.Value，用于回显当前取值。
func (l *modelList) String() string { return strings.Join(*l, ",") }

// Set 追加一个参数值（逗号拆分留给 parseModels，这里原样保存）。
func (l *modelList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// captureExt 是目录扫描时接受的抓包扩展名。
var captureExt = map[string]bool{
	".pcap": true, ".cap": true, ".pcapng": true, ".dmp": true,
}

// resolveInputs 展开输入列表：文件原样保留，目录按扩展名扫描。
// 结果按出现顺序去重，避免同一个抓包被反复分析。
func resolveInputs(inputs []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range inputs {
		st, err := os.Stat(p)
		if err != nil {
			return nil, errors.New(i18n.Tf("net.err.open", p, err))
		}
		if !st.IsDir() {
			add(p)
			continue
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, errors.New(i18n.Tf("net.err.open", p, err))
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if captureExt[strings.ToLower(filepath.Ext(e.Name()))] {
				add(filepath.Join(p, e.Name()))
			}
		}
	}
	return out, nil
}
