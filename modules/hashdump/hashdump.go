// Package hashdump 实现 GYhost 的 hashdump 模块：
// 从加密的 zip/7z/rar 压缩包中提取可离线枚举的哈希，交给 hashcat 爆破。
//
// 用法: gyhost hashdump -i [压缩包]
//
// 输出约定：哈希走 stdout（可直接管道），统计与提示走 stderr，
// 这样 `2>/dev/null | sort -u` 拿到的就是纯净的哈希列表。
package hashdump

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"gyhost/internal/i18n"
	"gyhost/internal/module"
	"gyhost/internal/utils"
)

// Module hashdump 模块。
type Module struct{}

// New 创建 hashdump 模块。
func New() module.Module { return &Module{} }

// Name 模块名。
func (m *Module) Name() string { return "hashdump" }

// Summary 模块简介（已国际化）。
func (m *Module) Summary() string { return i18n.T("hashdump.summary") }

// Group 模块在帮助信息中的分组（已国际化）。
func (m *Module) Group() string { return i18n.T("hashdump.group") }

// Usage 模块用法说明（已国际化）。
func (m *Module) Usage() string {
	return strings.TrimSpace(i18n.T("hashdump.usage"))
}

// NoticeLevel 是运行期提示的级别。
type NoticeLevel int

// 提示级别常量。
const (
	NoticeInfo NoticeLevel = iota
	NoticeOK
	NoticeWarn
)

// Run 解析参数并提取哈希。
func (m *Module) Run(args []string) error {
	fs := flag.NewFlagSet("gyhost hashdump", flag.ContinueOnError)
	fs.SetOutput(new(strings.Builder)) // 由本模块自行输出提示，避免重复打印

	var (
		inputs inputList
		output string
		quiet  bool
	)
	fs.Var(&inputs, "i", i18n.T("hashdump.flag.input"))
	fs.Var(&inputs, "input", i18n.T("hashdump.flag.input"))
	fs.StringVar(&output, "o", "", i18n.T("hashdump.flag.out"))
	fs.StringVar(&output, "out", "", i18n.T("hashdump.flag.out"))
	fs.BoolVar(&quiet, "q", false, i18n.T("hashdump.flag.quiet"))
	fs.BoolVar(&quiet, "quiet", false, i18n.T("hashdump.flag.quiet"))
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
		return errors.New(i18n.T("hashdump.err.missing_args"))
	}

	paths, err := resolveInputs(inputs)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New(i18n.T("hashdump.err.no_archive"))
	}

	var noticeW io.Writer = os.Stderr
	if quiet {
		noticeW = nil
	}
	notice := noticePrinter(noticeW)

	var hashes []string
	processed := 0
	for _, p := range paths {
		res, err := Extract(p)
		if err != nil {
			notice(NoticeWarn, err.Error())
			continue
		}
		processed++

		switch {
		case len(res.Entries) > 0:
			notice(NoticeOK, i18n.Tf("hashdump.info.archive",
				p, res.Kind, len(res.Entries), joinModes(modesOf(res))))
			for _, e := range res.Entries {
				notice(NoticeInfo, i18n.Tf("hashdump.info.entry", e.Name, e.Mode))
			}
		case len(res.Skipped) == 0:
			notice(NoticeWarn, i18n.Tf("hashdump.info.empty", p))
		}
		for _, s := range res.Skipped {
			notice(NoticeWarn, i18n.Tf("hashdump.warn.skip", p, s.Name, s.Reason))
		}
		for _, e := range res.Entries {
			hashes = append(hashes, e.Hash)
		}
	}

	if processed == 0 {
		return errors.New(i18n.T("hashdump.err.no_archive"))
	}

	if output != "" {
		var sb strings.Builder
		for _, h := range hashes {
			sb.WriteString(h)
			sb.WriteByte('\n')
		}
		fh, err := os.Create(output)
		if err != nil {
			return errors.New(i18n.Tf("hashdump.err.create_out", err))
		}
		if _, err := fh.WriteString(sb.String()); err != nil {
			fh.Close()
			return errors.New(i18n.Tf("hashdump.err.write_out", err))
		}
		if err := fh.Close(); err != nil {
			return errors.New(i18n.Tf("hashdump.err.write_out", err))
		}
		notice(NoticeOK, i18n.Tf("hashdump.info.saved", len(hashes), output))
		return nil
	}

	// 纯哈希直接落 stdout，便于管道
	for _, h := range hashes {
		fmt.Println(h)
	}
	notice(NoticeInfo, i18n.Tf("hashdump.info.total", len(hashes)))
	return nil
}

// noticePrinter 返回运行期提示的打印函数（全部写入 stderr，
// 保证 stdout 只有哈希）。配色按级别区分：[*] 蓝、[✓] 绿、[!] 黄。
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

// inputList 是 -i 参数的取值类型：同时支持逗号分隔与重复指定，并自动去重。
//
//	-i a.zip,b.7z   /   -i a.zip -i b.7z
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
