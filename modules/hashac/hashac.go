// Package hashac 的模块声明与命令行入口。
package hashac

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"gyhost/internal/i18n"
	"gyhost/internal/module"
	"gyhost/internal/utils"
)

// Module hashac 模块。
type Module struct{}

// New 创建 hashac 模块。
func New() module.Module { return &Module{} }

// Name 模块名。
func (m *Module) Name() string { return "hashac" }

// Summary 模块简介（已国际化）。
func (m *Module) Summary() string { return i18n.T("hashac.summary") }

// Group 模块在帮助信息中的分组（已国际化）。
func (m *Module) Group() string { return i18n.T("hashac.group") }

// Usage 模块用法说明（已国际化）。
func (m *Module) Usage() string {
	return strings.TrimSpace(i18n.T("hashac.usage"))
}

// Run 解析参数并执行爆破。
func (m *Module) Run(args []string) error {
	fs := flag.NewFlagSet("gyhost hashac", flag.ContinueOnError)
	fs.SetOutput(new(strings.Builder)) // 由本模块自行输出提示，避免重复打印

	var (
		input    string
		pass     string
		maskExpr string
		output   string
		threads  int
		mode     int
		quiet    bool
		gpu      bool
	)
	fs.StringVar(&input, "i", "", i18n.T("hashac.flag.input"))
	fs.StringVar(&input, "input", "", i18n.T("hashac.flag.input"))
	fs.StringVar(&pass, "p", "", i18n.T("hashac.flag.dict"))
	fs.StringVar(&pass, "pass", "", i18n.T("hashac.flag.dict"))
	fs.StringVar(&maskExpr, "m", "", i18n.T("hashac.flag.mask"))
	fs.StringVar(&maskExpr, "mask", "", i18n.T("hashac.flag.mask"))
	fs.StringVar(&output, "o", "", i18n.T("hashac.flag.out"))
	fs.StringVar(&output, "out", "", i18n.T("hashac.flag.out"))
	fs.IntVar(&threads, "t", runtime.NumCPU(), i18n.T("hashac.flag.threads"))
	fs.IntVar(&threads, "threads", runtime.NumCPU(), i18n.T("hashac.flag.threads"))
	// 模式号只保留长选项：-m 已让给掩码（与 shadow 保持一致）
	fs.IntVar(&mode, "mode", 0, i18n.T("hashac.flag.mode"))
	fs.BoolVar(&quiet, "q", false, i18n.T("hashac.flag.quiet"))
	fs.BoolVar(&quiet, "quiet", false, i18n.T("hashac.flag.quiet"))
	fs.BoolVar(&gpu, "gpu", false, i18n.T("hashac.flag.gpu"))
	fs.Usage = func() { fmt.Println(m.Usage()) }

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Println(m.Usage())
			return nil
		}
		return err
	}

	if input == "" || (pass == "" && maskExpr == "") {
		fmt.Println(m.Usage())
		return errors.New(i18n.T("hashac.err.missing_args"))
	}
	if pass != "" && maskExpr != "" {
		return errors.New(i18n.T("hashac.err.mask_conflict"))
	}
	if threads < 1 {
		return errors.New(i18n.Tf("hashac.err.threads", threads))
	}
	if mode < 0 {
		return errors.New(i18n.Tf("hashac.err.mode", mode))
	}

	var progress io.Writer = os.Stderr
	if quiet {
		progress = nil
	}

	report, err := Crack(Options{
		InputPath:    input,
		WordlistPath: pass,
		Mask:         maskExpr,
		Threads:      threads,
		OutputPath:   output,
		Mode:         mode,
		GPU:          gpu,
		Progress:     progress,
		OnCrack:      hitPrinter(os.Stdout),
		OnNotice:     noticePrinter(os.Stderr),
	})
	if err != nil {
		return err
	}

	printReport(os.Stdout, report)
	return nil
}

// noticePrinter 返回运行期提示的打印函数（进度行已擦除，输出到 stderr，
// 这样 2>/dev/null 仍然只看得到结果与统计）。配色按级别区分：[*] 蓝、[✓] 绿、[!] 黄。
func noticePrinter(w io.Writer) func(NoticeLevel, string) {
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

// hitPrinter 返回命中结果的打印函数，形如：
//
//	[+] Test1234   rar5  -m 13000
//
// 密码用粗体强调并对齐到固定列宽，类型/模式用彩色标注。
func hitPrinter(w io.Writer) func(Result) {
	return func(r Result) {
		label := utils.PadRight(utils.Bold("%s", r.Password), 24)
		utils.Plainf(w, "%s", i18n.Tf("hashac.hit.format",
			utils.Success("[+]"),
			label,
			utils.Info("%s", i18n.T("hashac.algo."+string(r.Kind))),
			utils.Dim("-m %d", r.Mode)))
	}
}

// printReport 输出彩色的爆破统计与未破解/跳过目标（文案已国际化）。
func printReport(w io.Writer, r *Report) {
	utils.Titlef(w, "%s", strings.Repeat("-", 60))
	utils.Infof(w, i18n.T("hashac.report.summary"),
		utils.Success("%d", r.Targets),
		utils.Warn("%d", len(r.Skipped)),
		utils.Success("%d", r.Cracked()))
	statsKey := "hashac.report.stats"
	if r.Masked {
		statsKey = "hashac.report.stats_mask"
	}
	utils.Infof(w, i18n.T(statsKey),
		utils.Title("%d", r.WordlistLen),
		utils.Title("%d", r.Attempts),
		utils.Dim("%s", fmt.Sprintf("%.2fs", r.Duration.Seconds())),
		utils.Success("%.0f", r.Speed()))
	if r.GPU != "" {
		utils.Infof(w, i18n.T("hashac.report.gpu"),
			utils.Success("%s", r.GPU),
			utils.Title("%d", r.GPUMemMB))
	}

	for _, s := range r.Skipped {
		utils.Warnf(w, i18n.T("hashac.report.skip"),
			utils.Dim("%s", s.Hash), s.Reason)
	}

	if len(r.Pending) > 0 {
		utils.Errorf(w, i18n.T("hashac.report.pending"),
			utils.Error("%d", len(r.Pending)),
			utils.Warn("%s", clip(strings.Join(r.Pending, ", "))))
		utils.Warnf(w, "%s", i18n.T("hashac.report.hint"))
	} else if r.Cracked() > 0 {
		utils.Successf(w, "%s", i18n.T("hashac.report.all_done"))
	}
}
