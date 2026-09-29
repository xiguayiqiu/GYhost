//go:build (linux && !android) || darwin

// 本文件的构建约束是「模块只在 (linux 且非 android) 或 darwin 上存在」：
//   - Windows 走 WMI/CIM，进程模型与本模块完全不同，不提供该功能
//   - Android / Termux 受限（Android 7+ 起限制访问其它应用的 /proc），
//     procfs 拿不到有用的进程表，不提供该功能
//
// 注意约束里必须显式写 !android：GOOS=android 会同时满足 linux 这个
// 构建标签，只写 linux 的话 Termux 构建仍会把本包编进去。

// 报告渲染：把分析结果按章节输出到 writer。
//
// 约定与 net / mem 一致：结果走 stdout、提示走 stderr；
// 所有面向用户的标题与列名走 i18n，pid/路径/命令等技术标识保持原样。
package proc

import (
	"fmt"
	"io"
	"strings"

	"gyhost/internal/i18n"
	"gyhost/internal/proc"
	"gyhost/internal/utils"
)

// humanBytes 把字节数渲染成 B/KiB/MiB/GiB/TiB。
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}

// writer 封装输出并处理列对齐。
type writer struct{ dest io.Writer }

// title 输出一节标题。
func (w *writer) title(name string) { utils.Titlef(w.dest, "== %s ==", name) }

// kv 输出一行「键: 值」。
func (w *writer) kv(key, format string, a ...interface{}) {
	utils.Plainf(w.dest, "   %-18s %s", utils.PadRight(key+":", 20), fmt.Sprintf(format, a...))
}

// row 输出一行普通文本。
func (w *writer) row(format string, a ...interface{}) {
	utils.Plainf(w.dest, "   "+format, a...)
}

// blank 输出一行空行。
func (w *writer) blank() { fmt.Fprintln(w.dest) }

// wantsProcessTable 判断是否选了要遍历进程表的动作。
func wantsProcessTable(opt options) bool {
	return opt.actions[actList] || opt.actions[actTree] || opt.actions[actUser]
}

// cmdlineOf 拼出完整命令行，超长时截断（-V 下不截断）。
func cmdlineOf(p proc.Process, verbose bool) string {
	if len(p.Cmdline) == 0 {
		return "-"
	}
	s := strings.Join(p.Cmdline, " ")
	if verbose {
		return s
	}
	return utils.TruncateVisible(s, 60)
}

// dash 空值占位。
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// renderReport 按所选动作输出报告章节。
func renderReport(dest io.Writer, res *result, opt options) error {
	w := &writer{dest: dest}
	sec := 0
	next := func() {
		if sec > 0 {
			fmt.Fprintln(dest)
		}
		sec++
	}

	// 概览始终先打：它是所有章节的上下文
	next()
	w.title(i18n.T("proc.sec.overview"))
	writeOverview(w, res, opt)

	if opt.actions[actList] {
		next()
		w.title(i18n.T("proc.sec.list"))
		writeList(w, res, opt)
	}
	if opt.actions[actTree] {
		next()
		w.title(i18n.T("proc.sec.tree"))
		writeTree(w, res, opt)
	}
	if opt.actions[actUser] {
		next()
		w.title(i18n.T("proc.sec.user"))
		writeUsers(w, res, opt)
	}
	if opt.actions[actThread] {
		next()
		w.title(i18n.T("proc.sec.thread"))
		writeThreads(w, res, opt)
	}
	if opt.actions[actDetail] {
		next()
		w.title(i18n.T("proc.sec.detail"))
		writeDetail(w, res, opt)
	}
	return nil
}

// writeOverview 输出概览。
func writeOverview(w *writer, res *result, opt options) {
	w.kv(i18n.T("proc.col.platform"), "%s", res.Platform)
	w.kv(i18n.T("proc.col.total"), "%d", res.Total)
	// 只看 thread/detail 时，进程表没参与分析，
	// 此时的「参与分析 / 合计」是噪声，不输出
	if !wantsProcessTable(opt) {
		return
	}
	if res.Target != "" {
		w.kv(i18n.T("proc.col.target"), "%s", res.Target)
	}
	sel := len(res.Selected)
	if sel > 0 {
		w.kv(i18n.T("proc.col.selected"), "%s", i18n.Tf("proc.info.selected", sel, res.Skipped))
	} else if res.Skipped > 0 {
		w.blank()
		w.row("%s", i18n.T("proc.info.no_match_filter"))
		return
	}
	var thr, fds int
	var rss, vsz uint64
	for _, p := range res.Selected {
		thr += p.Threads
		fds += p.FDs
		rss += p.RSize
		vsz += p.VSize
	}
	// 合计里的常驻内存是逐进程 RSS 之和：共享页（libc、共享库）会被重复计入，
	// 只能当粗略的量级参考，不是系统真实物理内存占用。
	w.kv(i18n.T("proc.col.agg"), "%s", i18n.Tf("proc.info.agg", thr, fds, humanBytes(vsz), humanBytes(rss)))
	w.blank()
	// 合计的虚拟内存是各进程 VSZ 之和，共享页在 RSS 里也会被重复计入；
	// 这两个数只能量级参考，不能当系统真实物理内存占用看。
	w.row("%s", i18n.T("proc.info.agg_note"))
	// 生效的过滤条件要显式回显，否则用户不知道为什么少了进程
	var cond []string
	if opt.filter != "" {
		cond = append(cond, i18n.Tf("proc.cond.k", opt.filter))
	}
	if opt.user != "" {
		cond = append(cond, i18n.Tf("proc.cond.u", opt.user))
	}
	if opt.parent > 0 {
		cond = append(cond, i18n.Tf("proc.cond.p", opt.parent))
	}
	if opt.minThreads > 0 {
		cond = append(cond, i18n.Tf("proc.cond.t", opt.minThreads))
	}
	if opt.minRSize > 0 {
		cond = append(cond, i18n.Tf("proc.cond.rss", humanBytes(opt.minRSize)))
	}
	if opt.noKernel {
		cond = append(cond, i18n.T("proc.cond.kernel"))
	}
	if len(cond) > 0 {
		w.kv(i18n.T("proc.col.cond"), "%s", strings.Join(cond, ", "))
	}
}

// writeList 输出进程列表。
func writeList(w *writer, res *result, opt options) {
	list := res.Selected
	utils.Plainf(w.dest, "   %s", i18n.Tf("proc.list.header",
		i18n.T("proc.col.pid"), i18n.T("proc.col.ppid"), i18n.T("proc.col.state"),
		i18n.T("proc.col.user"), i18n.T("proc.col.threads"), i18n.T("proc.col.fds"),
		i18n.T("proc.col.rss"), i18n.T("proc.col.vsize"), i18n.T("proc.col.cmd")))
	shown := list
	if opt.limit > 0 && len(shown) > opt.limit {
		shown = shown[:opt.limit]
	}
	for _, p := range shown {
		w.row("%7d  %7d  %-5s %-12s %5d  %5d  %9s  %9s  %s",
			p.PID, p.PPID, string(p.State), utils.PadRight(dash(p.User), 12),
			p.Threads, p.FDs, humanBytes(p.RSize), humanBytes(p.VSize),
			cmdlineOf(p, opt.verbose))
	}
	if opt.limit > 0 && len(list) > opt.limit {
		w.row("... %s", i18n.Tf("proc.more", len(list)-opt.limit))
	}
}

// writeTree 输出父子树。
func writeTree(w *writer, res *result, opt options) {
	nodes := res.Tree
	utils.Plainf(w.dest, "   %s", i18n.T("proc.tree.hint"))
	shown := nodes
	if opt.limit > 0 && len(shown) > opt.limit {
		shown = shown[:opt.limit]
	}
	for _, n := range shown {
		// 缩进用 │ 与 ├─ 表达层级，深度上限由 BuildTree 保证
		prefix := ""
		if n.Depth > 0 {
			prefix = strings.Repeat("│  ", n.Depth-1) + "└─ "
		}
		w.row("%s%d  %-5s %-16s %s", prefix, n.Process.PID, string(n.Process.State),
			utils.PadRight(dash(n.Process.Name), 16), dash(n.Process.Exe))
	}
	if opt.limit > 0 && len(nodes) > opt.limit {
		w.row("... %s", i18n.Tf("proc.more", len(nodes)-opt.limit))
	}
}

// writeUsers 输出按用户聚合的统计。
func writeUsers(w *writer, res *result, opt options) {
	stats := res.Users
	if len(stats) == 0 {
		w.row("%s", i18n.T("proc.user.none"))
		return
	}
	utils.Plainf(w.dest, "   %s", i18n.Tf("proc.user.header",
		i18n.T("proc.col.user"), i18n.T("proc.col.count"),
		i18n.T("proc.col.threads"), i18n.T("proc.col.rss"), i18n.T("proc.col.vsize")))
	shown := stats
	if opt.limit > 0 && len(shown) > opt.limit {
		shown = shown[:opt.limit]
	}
	for _, s := range shown {
		w.row("%-16s %6d  %8d  %9s  %9s", s.User, s.Count, s.Threads,
			humanBytes(s.RSize), humanBytes(s.VSize))
	}
}

// writeThreads 输出线程列表。
func writeThreads(w *writer, res *result, opt options) {
	if len(res.Threads) == 0 {
		w.row("%s", i18n.T("proc.thread.none"))
		return
	}
	utils.Plainf(w.dest, "   %s", i18n.Tf("proc.thread.header",
		i18n.T("proc.col.tid"), i18n.T("proc.col.state"), i18n.T("proc.col.name")))
	shown := res.Threads
	if opt.limit > 0 && len(shown) > opt.limit {
		shown = shown[:opt.limit]
	}
	for _, t := range shown {
		w.row("%8d  %-5s  %s", t.TID, string(t.State), dash(t.Name))
	}
	if opt.limit > 0 && len(res.Threads) > opt.limit {
		w.row("... %s", i18n.Tf("proc.more", len(res.Threads)-opt.limit))
	}
}

// writeDetail 输出单进程详情。
func writeDetail(w *writer, res *result, opt options) {
	if res.Detail == nil {
		w.row("%s", i18n.T("proc.detail.none"))
		return
	}
	d := *res.Detail
	w.kv(i18n.T("proc.col.pid"), "%d (ppid %d)", d.PID, d.PPID)
	w.kv(i18n.T("proc.col.name"), "%s", dash(d.Name))
	w.kv(i18n.T("proc.col.exe"), "%s", dash(d.Exe))
	w.kv(i18n.T("proc.col.state"), "%s", string(d.State))
	w.kv(i18n.T("proc.col.user"), "%s", dash(d.User))
	w.kv(i18n.T("proc.col.arch"), "%s", dash(d.Arch))
	w.kv(i18n.T("proc.col.cwd"), "%s", dash(d.Cwd))
	if d.Start != "" {
		w.kv(i18n.T("proc.col.start"), "%s", d.Start)
	}
	w.kv(i18n.T("proc.col.mem"), "%s", i18n.Tf("proc.detail.mem", humanBytes(d.RSize), humanBytes(d.VSize), d.Threads, d.FDs))
	if d.MapCount > 0 {
		w.kv(i18n.T("proc.col.maps"), "%s", i18n.Tf("proc.detail.maps", d.MapCount, d.ExeCount))
	}
	w.blank()

	w.kv(i18n.T("proc.col.cmdline"), "%s", cmdlineOf(d, true))
	w.blank()

	// 环境变量
	if len(d.Env) > 0 {
		utils.Plainf(w.dest, "   %s", i18n.Tf("proc.detail.env", len(d.Env)))
		for _, e := range d.Env {
			w.row("%s", utils.TruncateVisible(e, 100))
		}
	} else {
		w.row("%s", i18n.T("proc.detail.env_na"))
	}
	w.blank()

	// 打开的文件
	if len(d.FDList) > 0 {
		utils.Plainf(w.dest, "   %s", i18n.Tf("proc.detail.fd", len(d.FDList)))
		shown := d.FDList
		if opt.limit > 0 && len(shown) > opt.limit {
			shown = shown[:opt.limit]
		}
		for _, f := range shown {
			w.row("%s", utils.TruncateVisible(f, 100))
		}
		if len(d.FDList) > len(shown) {
			w.row("... %s", i18n.Tf("proc.more", len(d.FDList)-len(shown)))
		}
	} else if d.FDs > 0 {
		w.row("%s", i18n.Tf("proc.detail.fd_count_only", d.FDs))
	} else {
		w.row("%s", i18n.T("proc.detail.fd_na"))
	}
	w.blank()

	// 加载的映像
	if len(d.Modules) > 0 {
		utils.Plainf(w.dest, "   %s", i18n.Tf("proc.detail.modules", len(d.Modules)))
		shown := d.Modules
		if opt.limit > 0 && len(shown) > opt.limit {
			shown = shown[:opt.limit]
		}
		for _, m := range shown {
			w.row("%s", m)
		}
		if len(d.Modules) > len(shown) {
			w.row("... %s", i18n.Tf("proc.more", len(d.Modules)-len(shown)))
		}
	}
}
