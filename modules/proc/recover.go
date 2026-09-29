//go:build (linux && !android) || darwin

// 本文件的构建约束是「模块只在 (linux 且非 android) 或 darwin 上存在」：
//   - Windows 走 WMI/CIM，进程模型与本模块完全不同，不提供该功能
//   - Android / Termux 受限（Android 7+ 起限制访问其它应用的 /proc），
//     procfs 拿不到有用的进程表，不提供该功能
//
// 注意约束里必须显式写 !android：GOOS=android 会同时满足 linux 这个
// 构建标签，只写 linux 的话 Termux 构建仍会把本包编进去。

// 从 /proc 恢复文件（-r）。
//
// 两段式：先扫出候选清单（带编号），再用编号/关键字指定要恢复哪些。
//
//	gyhost proc -i 1234 -r              → 扫描并列出可恢复文件
//	gyhost proc -i 1234 -r 3            → 恢复第 3 项
//	gyhost proc -i 1234 -r '*.log'      → 恢复路径含 .log 的全部
//	gyhost proc -i 1234 -r 3,7 -O ./ev  → 恢复多项并指定输出目录
//
// 取证价值最高的一类是「已从磁盘删除、但进程仍持有 fd」的文件：
// 磁盘上看不见了，只要 /proc/<pid>/fd/<n> 还在，内容照样能取回来。
package proc

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"gyhost/internal/i18n"
	"gyhost/internal/proc"
	"gyhost/internal/utils"
)

// recoverSentinel 是 -r 单独出现（不带编号/关键字）时补的哨兵值。
const recoverSentinel = "\x00scan"

// runRecover 处理 -r：扫描 / 恢复 两段式。
func runRecover(dest io.Writer, notice func(NoticeLevel, string), opt options) error {
	rc, ok := backend.(proc.Recoverer)
	if !ok {
		// /proc 是 Linux 独有的；别给一个残缺实现，直接说清楚
		notice(NoticeWarn, backend.PrivilegeHint())
		return errors.New(i18n.Tf("proc.err.recover_unsupported", backend.Name()))
	}

	pid, err := resolveTarget(optionsWithSpec(opt), true)
	if err != nil {
		return err
	}
	refs, err := rc.Scan(pid)
	if err != nil {
		return errors.New(i18n.Tf("proc.err.scan", pid, err))
	}
	res := &scanResult{
		Platform: backend.Name(),
		Target:   i18n.Tf("proc.info.target", pid),
		PID:      pid,
		Refs:     refs,
	}
	st := proc.Summarize(refs)
	w := &writer{dest: dest}
	utils.Titlef(dest, "== %s ==", i18n.T("proc.sec.recover"))
	w.kv(i18n.T("proc.col.target"), "%s", res.Target)
	// 标签用「扫描结果」而不是 proc.col.total（那个键是给进程总览当「进程总数」用的），
	// 放在这里语义对不上：这一行是文件候选的统计，不是进程数
	w.kv(i18n.T("proc.rec.summary"), "%s", i18n.Tf("proc.rec.stat", st.Total, st.Recoverable, st.Deleted))
	w.blank()

	if len(refs) == 0 {
		w.row("%s", i18n.T("proc.rec.scan_failed"))
		return errors.New(i18n.Tf("proc.err.scan", pid, i18n.T("proc.rec.scan_failed")))
	}
	if st.Recoverable == 0 {
		writeRefTable(w, res, opt)
		w.blank()
		w.row("%s", i18n.T("proc.rec.none"))
		return nil
	}

	// 扫描模式：只列清单，等用户再指定
	if !opt.recover.Present() || !opt.recover.HasValue() {
		writeRefTable(w, res, opt)
		w.blank()
		w.row("%s", i18n.T("proc.rec.hint"))
		return nil
	}

	// 恢复模式：按用户指定挑出来逐个恢复
	picked, ok := proc.MatchRefs(refs, opt.recover.Value())
	if !ok {
		return errors.New(i18n.Tf("proc.err.no_ref_match", opt.recover.Value(), st.Recoverable))
	}
	dir := opt.outDir
	if dir == "" {
		dir = defaultRecoverDir(pid)
	}
	used := map[string]bool{}
	// 恢复完把清单也打出来，便于核对编号与结果
	for _, ref := range picked {
		path, n, err := rc.Recover(pid, ref, dir)
		if err != nil {
			notice(NoticeWarn, i18n.Tf("proc.warn.recover", ref.Index, ref.Target, err))
			continue
		}
		res.Recovered = append(res.Recovered, proc.Recovered{Ref: ref, Path: path, Size: n})
		used[filepath.Base(path)] = true
		notice(NoticeOK, i18n.Tf("proc.info.recovered", ref.Index, path, humanBytes(uint64(n))))
	}
	writeRefTable(w, res, opt)
	if len(res.Recovered) == 0 {
		return errors.New(i18n.T("proc.err.recover_failed"))
	}
	w.blank()
	w.row("%s", i18n.Tf("proc.rec.done", len(res.Recovered), dir))
	return nil
}

// optionsWithSpec 复制一份 options，强制走「需要精确目标」的解析路径。
func optionsWithSpec(opt options) options {
	o := opt
	o.actions = map[string]bool{actDetail: true}
	return o
}

// scanResult 是一次扫描/恢复的产出。
type scanResult struct {
	Platform  string
	Target    string
	PID       int
	Refs      []proc.FileRef
	Recovered []proc.Recovered
}

// writeRefTable 输出可恢复文件清单。
func writeRefTable(w *writer, res *scanResult, opt options) {
	utils.Plainf(w.dest, "   %s", i18n.Tf("proc.rec.header",
		i18n.T("proc.col.idx"), i18n.T("proc.col.source"),
		i18n.T("proc.col.size"), i18n.T("proc.col.flag"), i18n.T("proc.col.path")))

	list := res.Refs
	// 有恢复结果时，把它们也带进清单并标注状态
	status := map[int]string{}
	for _, r := range res.Recovered {
		status[r.Ref.Index] = i18n.Tf("proc.rec.done_one", filepath.Base(r.Path), humanBytes(uint64(r.Size)))
	}
	shown := list
	if opt.limit > 0 && len(shown) > opt.limit {
		shown = shown[:opt.limit]
	}
	for _, r := range shown {
		flags := ""
		if r.Deleted {
			flags = i18n.T("proc.rec.deleted")
		}
		size := "-"
		if r.Size >= 0 {
			size = humanBytes(uint64(r.Size))
		}
		path := r.Target
		if !r.Recoverable {
			// 不可恢复的条目保留在清单里，但把原因说清楚，
			// 否则用户会以为「没列出来 = 不存在」
			path = r.Target
			if r.Reason != "" {
				path += "  (" + r.Reason + ")"
			}
		}
		mark := flags
		if s, ok := status[r.Index]; ok {
			if mark != "" {
				mark += " "
			}
			mark += s
		}
		w.row("%4d  %-8s %10s  %-10s %s", r.Index, r.Label(), size, mark, path)
	}
	if opt.limit > 0 && len(list) > opt.limit {
		w.row("... %s", i18n.Tf("proc.more", len(list)-opt.limit))
	}
}

// defaultRecoverDir 生成默认恢复目录。
func defaultRecoverDir(pid int) string {
	return filepath.Join(".", fmt.Sprintf("gyhost-proc-%d-recovered", pid))
}
