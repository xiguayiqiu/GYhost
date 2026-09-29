// 程序与线程列表（-l）。
//
// 语义：
//
//	-l              列出全部程序，并逐个显示它们的“子线程”
//	-l <PID|程序名>  只显示该程序的子线程
//
// 三个平台的线程模型不同（Linux 的 task、Windows 的 Thread、
// macOS 的 thread port），但都被 internal/mem.Threads 归一成同一份结果。
package mem

import (
	"errors"
	"io"
	"sort"
	"strings"

	"gyhost/internal/i18n"
	memcore "gyhost/internal/mem"
	"gyhost/internal/utils"
)

// procListResult 是一次程序/线程列举的产出。
type procListResult struct {
	// Query 是 -l 附带的过滤目标，空表示列出全部程序。
	Query string
	// All 为 true 时 Programs/Threads 覆盖全部程序；为 false 时只覆盖命中目标。
	All bool
	// Programs 是列出的程序。
	Programs []memcore.ProcessInfo
	// Threads 按程序分组，键为 PID。
	Threads map[int][]memcore.ThreadInfo
	// TotalPrograms / TotalThreads 是本次列举覆盖到的总数。
	TotalPrograms int
	TotalThreads  int
	// Truncated 表示因 -n 截断了输出。
	Truncated int
	// Unsupported 表示当前平台无法枚举线程。
	Unsupported bool
}

// collectProcesses 枚举程序，并按 -l 的过滤目标决定范围。
func collectProcesses(opt options, notice func(NoticeLevel, string)) (*procListResult, error) {
	procs, err := backend.List()
	if err != nil {
		return nil, errors.New(i18n.Tf("mem.err.list_processes", backend.Name(), err))
	}
	// 线程数多的排前面：取证时更值得先看
	sort.SliceStable(procs, func(i, j int) bool {
		if procs[i].ThreadCount != procs[j].ThreadCount {
			return procs[i].ThreadCount > procs[j].ThreadCount
		}
		return procs[i].PID < procs[j].PID
	})

	res := &procListResult{Query: opt.listOnly, All: opt.listOnly == "", Threads: map[int][]memcore.ThreadInfo{}}
	res.TotalPrograms = len(procs)
	if !res.All {
		procs = memcore.FindProcess(procs, opt.listOnly)
		if len(procs) == 0 {
			return nil, errors.New(i18n.Tf("mem.err.no_match", opt.listOnly))
		}
		if len(procs) > 1 {
			notice(NoticeWarn, i18n.Tf("mem.info.multi_match", opt.listOnly, len(procs)))
		}
	}
	res.Programs = procs

	// 逐个枚举线程；个别进程无权限时只提示，不影响其它进程
	var unsupported int
	for _, p := range procs {
		ths, err := backend.Threads(p.PID)
		if err != nil {
			unsupported++
			notice(NoticeWarn, i18n.Tf("mem.info.thread_fail", p.PID, p.Name, err))
			continue
		}
		res.Threads[p.PID] = ths
		res.TotalThreads += len(ths)
	}
	res.Unsupported = unsupported == len(procs) && len(procs) > 0
	if res.Unsupported {
		notice(NoticeWarn, i18n.Tf("mem.err.threads_unsupported", backend.Name()))
	}
	return res, nil
}

// cmdlineOf 拼出进程的完整命令行，超长时截断。
//
// 同名进程（例如 Electron 的多个 zygote）只能靠参数区分，
// 所以这一列对定位具体进程很有用。
func cmdlineOf(p memcore.ProcessInfo) string {
	if len(p.Cmdline) == 0 {
		return "-"
	}
	return utils.TruncateVisible(strings.Join(p.Cmdline, " "), 60)
}

// runProcessList 输出 -l 的结果。
func runProcessList(dest io.Writer, notice func(NoticeLevel, string), opt options) error {
	res, err := collectProcesses(opt, notice)
	if err != nil {
		return err
	}
	if opt.jsonOut {
		return writeProcessListJSON(dest, res, opt)
	}

	w := &writer{dest: dest}
	utils.Titlef(dest, "== %s ==", i18n.T("mem.sec.procs"))
	if res.All {
		w.kv(i18n.T("mem.col.scope"), "%s", i18n.Tf("mem.info.all_procs", res.TotalPrograms))
	} else {
		w.kv(i18n.T("mem.col.scope"), "%s", i18n.Tf("mem.info.only_proc", res.Query, len(res.Programs)))
	}
	w.kv(i18n.T("mem.col.threads"), "%d", res.TotalThreads)
	w.blank()

	if len(res.Programs) == 0 {
		w.row("%s", i18n.T("mem.proc.none"))
		return nil
	}

	// 程序表
	utils.Plainf(dest, "   %s", i18n.Tf("mem.proc.header",
		i18n.T("mem.col.threads"), i18n.T("mem.col.pid"),
		i18n.T("mem.col.ppid"), i18n.T("mem.col.arch"),
		i18n.T("mem.col.user"), i18n.T("mem.col.proc"), i18n.T("mem.col.cmd")))
	shown := res.Programs
	if opt.limit > 0 && len(shown) > opt.limit {
		shown = shown[:opt.limit]
		res.Truncated = len(res.Programs) - len(shown)
	}
	for _, p := range shown {
		threads := len(res.Threads[p.PID])
		if threads == 0 && p.ThreadCount > 0 {
			// 线程枚举失败时退回 List() 拿到的线程数，避免显示成 0 误导
			threads = p.ThreadCount
		}
		user := p.User
		if user == "" {
			user = "-"
		}
		w.row("%5d  %7d  %7d  %-7s %-12s %-20s %s", threads, p.PID, p.PPID, p.Arch, user,
			utils.TruncateVisible(p.Name, 20), cmdlineOf(p))
	}
	if res.Truncated > 0 {
		w.row("... %s", i18n.Tf("mem.more", res.Truncated))
	}
	w.blank()

	// 线程表：逐程序列出它的子线程
	utils.Plainf(dest, "   %s", i18n.T("mem.thread.title"))
	for _, p := range shown {
		ths := res.Threads[p.PID]
		if len(ths) == 0 {
			w.row("%s", i18n.Tf("mem.thread.none", p.PID, p.Name))
			continue
		}
		w.row("%s", i18n.Tf("mem.thread.of", p.PID, p.Name, len(ths)))
		utils.Plainf(dest, "     %s", i18n.Tf("mem.thread.header",
			i18n.T("mem.col.tid"), i18n.T("mem.col.state"), i18n.T("mem.col.name")))
		list := ths
		truncated := 0
		if opt.limit > 0 && len(list) > opt.limit {
			truncated = len(ths) - opt.limit
			list = list[:opt.limit]
		}
		for _, th := range list {
			state, name := th.State, th.Name
			if state == "" {
				state = "-"
			}
			if name == "" {
				name = "-"
			}
			w.row("     %7d  %-11s %s", th.TID, state, name)
		}
		if truncated > 0 {
			w.row("     ... %s", i18n.Tf("mem.more", truncated))
		}
	}
	return nil
}
