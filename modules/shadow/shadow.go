// Package shadow 实现 GYhost 的第一个功能模块：
// 离线爆破 shadow 文件中的密码哈希。
//
// 用法: gyhost shadow -i [shadow文件] -p [密码字典]
package shadow

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

// Module shadow 模块。
type Module struct{}

// New 创建 shadow 模块。
func New() module.Module { return &Module{} }

// Name 模块名。
func (m *Module) Name() string { return "shadow" }

// Summary 模块简介（已国际化）。
func (m *Module) Summary() string {
	return i18n.T("shadow.summary")
}

// Group 模块在帮助信息中的分组（已国际化）。
func (m *Module) Group() string { return i18n.T("shadow.group") }

// Usage 模块用法说明（已国际化）。
func (m *Module) Usage() string {
	return strings.TrimSpace(i18n.T("shadow.usage"))
}

// Run 解析参数并执行爆破。
func (m *Module) Run(args []string) error {
	fs := flag.NewFlagSet("gyhost shadow", flag.ContinueOnError)
	fs.SetOutput(new(strings.Builder)) // 由本模块自行输出提示，避免重复打印

	var (
		input    string
		pass     string
		maskExpr string
		threads  int
		output   string
		quiet    bool
		gpu      bool
		users    userList
	)
	fs.StringVar(&input, "i", "", i18n.T("shadow.flag.input"))
	fs.StringVar(&input, "input", "", i18n.T("shadow.flag.input"))
	fs.StringVar(&pass, "p", "", i18n.T("shadow.flag.dict"))
	fs.StringVar(&pass, "pass", "", i18n.T("shadow.flag.dict"))
	fs.StringVar(&maskExpr, "m", "", i18n.T("shadow.flag.mask"))
	fs.StringVar(&maskExpr, "mask", "", i18n.T("shadow.flag.mask"))
	fs.Var(&users, "u", i18n.T("shadow.flag.user"))
	fs.Var(&users, "user", i18n.T("shadow.flag.user"))
	fs.IntVar(&threads, "t", runtime.NumCPU(), i18n.T("shadow.flag.threads"))
	fs.IntVar(&threads, "threads", runtime.NumCPU(), i18n.T("shadow.flag.threads"))
	fs.StringVar(&output, "o", "", i18n.T("shadow.flag.out"))
	fs.StringVar(&output, "out", "", i18n.T("shadow.flag.out"))
	fs.BoolVar(&quiet, "q", false, i18n.T("shadow.flag.quiet"))
	fs.BoolVar(&quiet, "quiet", false, i18n.T("shadow.flag.quiet"))
	fs.BoolVar(&gpu, "gpu", false, i18n.T("shadow.flag.gpu"))
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
		return errors.New(i18n.T("shadow.err.missing_args"))
	}
	if pass != "" && maskExpr != "" {
		return errors.New(i18n.T("shadow.err.mask_conflict"))
	}
	if threads < 1 {
		return errors.New(i18n.Tf("shadow.err.threads", threads))
	}

	var progress io.Writer = os.Stderr
	if quiet {
		progress = nil
	}

	report, err := Crack(Options{
		ShadowPath:   input,
		WordlistPath: pass,
		Mask:         maskExpr,
		Threads:      threads,
		OutputPath:   output,
		Users:        users,
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
// 这样 2>/dev/null 仍然只看得到结果与统计）。
//
// 配色按级别区分：[*] 蓝、[✓] 绿、[!] 黄。
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

// hitPrinter 返回命中结果的打印函数。
//
// 输出形如：
//
//	[+] root:Root#2026      ($6$saltsalt$...)
//
// 用户名与密码用粗体/绿色强调并对齐到固定列宽，哈希用暗色弱化。
func hitPrinter(w io.Writer) func(Result) {
	return func(r Result) {
		label := utils.PadRight(
			utils.Bold("%s", r.User)+":"+utils.Success("%s", r.Password), 24)
		utils.Plainf(w, "%s", i18n.Tf("shadow.hit.format",
			utils.Success("[+]"), label, utils.Dim("(%s)", r.Hash)))
	}
}

// userList 是 -u 参数的取值类型：同时支持逗号分隔与重复指定，并自动去重。
//
//	-u root,alice   /   -u root -u alice
type userList []string

// String 实现 flag.Value，用于回显当前取值。
func (u *userList) String() string { return strings.Join(*u, ",") }

// Set 实现 flag.Value，追加一个参数值（内部按逗号拆分）。
func (u *userList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		dup := false
		for _, existing := range *u {
			if existing == name {
				dup = true
				break
			}
		}
		if !dup {
			*u = append(*u, name)
		}
	}
	return nil
}
