// 报告渲染：把分析结果按章节输出到 writer。
//
// 约定与 net 模块一致：
//   - 结果走 stdout，提示走 stderr（-q 可关掉）
//   - 所有面向用户的标题、列名走 i18n；地址、哈希、类型等技术标识保持原样
package mem

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"gyhost/internal/i18n"
	"gyhost/internal/utils"
)

// humanBytes 把字节数渲染成 B/KiB/MiB/GiB/TiB。
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}

// renderReport 按所选动作输出报告章节。
func renderReport(dest io.Writer, res *result, opt options) error {
	if opt.jsonOut {
		return writeJSON(dest, res, opt)
	}
	w := &writer{dest: dest}
	sec := 0
	next := func() {
		if sec > 0 {
			fmt.Fprintln(dest)
		}
		sec++
	}

	// 概览始终先打：它是所有其它章节的上下文
	if opt.actions[actInfo] || opt.actions[actMaps] || opt.actions[actStrings] ||
		opt.actions[actBehavior] || opt.actions[actCarve] || opt.actions[actHash] ||
		opt.actions[actEntropy] {
		next()
		w.title(i18n.T("mem.sec.overview"))
		writeOverview(w, res, opt)
	}
	if opt.actions[actMaps] {
		next()
		w.title(i18n.T("mem.sec.maps"))
		writeMaps(w, res, opt)
	}
	if opt.actions[actEntropy] {
		next()
		w.title(i18n.T("mem.sec.entropy"))
		writeEntropy(w, res, opt)
	}
	if opt.actions[actHash] {
		next()
		w.title(i18n.T("mem.sec.hash"))
		writeHashes(w, res, opt)
	}
	if opt.actions[actBehavior] {
		next()
		w.title(i18n.T("mem.sec.behavior"))
		writeBehavior(w, res, opt)
	}
	if opt.actions[actStrings] {
		next()
		w.title(i18n.T("mem.sec.strings"))
		writeStrings(w, res, opt)
	}
	if opt.actions[actCarve] {
		next()
		w.title(i18n.T("mem.sec.carve"))
		writeCarved(w, res, opt)
	}
	return nil
}

// writer 封装输出，自动处理对齐。
type writer struct{ dest io.Writer }

// title 输出一节标题。
func (w *writer) title(name string) {
	utils.Titlef(w.dest, "== %s ==", name)
}

// kv 输出一行“键: 值”。
func (w *writer) kv(key, format string, a ...interface{}) {
	utils.Plainf(w.dest, "   %-16s %s", utils.PadRight(key+":", 18), fmt.Sprintf(format, a...))
}

// row 输出一行普通文本。
func (w *writer) row(format string, a ...interface{}) {
	utils.Plainf(w.dest, "   "+format, a...)
}

// blank 输出一行空行。
func (w *writer) blank() { fmt.Fprintln(w.dest) }

// writeOverview 输��目标概览。
func writeOverview(w *writer, res *result, opt options) {
	i := res.Info
	kindLabel := i18n.T("mem.kind.live")
	if res.Kind == "file" {
		kindLabel = i18n.T("mem.kind.file")
	}
	w.kv(i18n.T("mem.col.kind"), "%s", kindLabel)
	w.kv(i18n.T("mem.col.target"), "%s", res.Target)
	if i.PID > 0 {
		w.kv(i18n.T("mem.col.pid"), "%d (ppid %d)", i.PID, i.PPID)
	}
	if i.Name != "" {
		w.kv(i18n.T("mem.col.proc"), "%s", i.Name)
	}
	if i.Exe != "" {
		w.kv(i18n.T("mem.col.exe"), "%s", i.Exe)
	}
	if i.Arch != "" {
		w.kv(i18n.T("mem.col.arch"), "%s", i.Arch)
	}
	if i.User != "" {
		w.kv(i18n.T("mem.col.user"), "%s", i.User)
	}
	if i.StartTime != "" {
		w.kv(i18n.T("mem.col.started"), "%s", i.StartTime)
	}
	if i.TotalMemory > 0 {
		w.kv(i18n.T("mem.col.vsize"), "%s", humanBytes(int64(i.TotalMemory)))
	}
	w.blank()

	// 区域统计
	byKind := map[string]int{}
	var byKindBytes = map[string]uint64{}
	var rwx int
	for _, r := range res.Regions {
		byKind[r.Kind]++
		byKindBytes[r.Kind] += r.Size()
		if r.Executable() {
			rwx++
		}
	}
	w.kv(i18n.T("mem.col.regions"), "%d", len(res.Regions))
	w.kv(i18n.T("mem.col.selected"), "%s", i18n.Tf("mem.info.selected", len(res.Selected), res.Skipped))
	w.kv(i18n.T("mem.col.exec"), "%d", rwx)
	w.kv(i18n.T("mem.col.scanned"), "%s", i18n.Tf("mem.info.scanned",
		humanBytes(int64(res.ScannedBytes)), res.ScannedRegion, res.FailedRegion))
	if !res.TotalHash.Empty() {
		w.kv(i18n.T("mem.col.total"), "%s", strings.Join(res.TotalHash.HashStrings()[:min(3, len(res.TotalHash.HashStrings()))], " "))
	}
	w.blank()

	// 区域类型分布
	utils.Plainf(w.dest, "   %s", i18n.T("mem.bykind"))
	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		w.row("%-8s %5d  %s", k, byKind[k], humanBytes(int64(byKindBytes[k])))
	}

	if opt.verbose && len(i.Modules) > 0 {
		w.blank()
		utils.Plainf(w.dest, "   %s", i18n.Tf("mem.modules", len(i.Modules)))
		shown := i.Modules
		if len(shown) > 40 {
			shown = shown[:40]
		}
		for _, m := range shown {
			w.row("    %s", m)
		}
		if len(i.Modules) > len(shown) {
			w.row("    ... %s", i18n.Tf("mem.more", len(i.Modules)-len(shown)))
		}
	}
}

// writeMaps 输出内存区域列表。
func writeMaps(w *writer, res *result, opt options) {
	list := res.Selected
	if opt.verbose {
		// -V 时连未选中的区域也列出来，方便对照
		list = res.Regions
	}
	if len(list) > opt.limit && opt.limit > 0 {
		list = list[:opt.limit]
	}
	utils.Plainf(w.dest, "   %s", i18n.Tf("mem.maps.header",
		i18n.T("mem.col.start"), i18n.T("mem.col.end"),
		i18n.T("mem.col.size"), i18n.T("mem.col.perm"),
		i18n.T("mem.col.type"), i18n.T("mem.col.path")))
	for _, r := range list {
		path := r.Path
		if path == "" {
			path = "-"
		}
		w.row("%016x %016x %10s  %-4s %-6s %s",
			r.Start, r.End, humanBytes(int64(r.Size())), r.Perm, r.Kind, path)
	}
	if opt.limit > 0 && len(res.Selected) > opt.limit {
		w.row("... %s", i18n.Tf("mem.more", len(res.Selected)-opt.limit))
	}
}

// writeEntropy 输出区域熵（-a entropy）。
func writeEntropy(w *writer, res *result, opt options) {
	list := res.RegionEntropy
	sort.Slice(list, func(i, j int) bool { return list[i].Entropy > list[j].Entropy })
	if opt.limit > 0 && len(list) > opt.limit {
		list = list[:opt.limit]
	}
	utils.Plainf(w.dest, "   %s", i18n.Tf("mem.entropy.header",
		i18n.T("mem.col.entropy"), i18n.T("mem.col.class"),
		i18n.T("mem.col.size"), i18n.T("mem.col.type"), i18n.T("mem.col.path")))
	for _, m := range list {
		path := m.Region.Path
		if path == "" {
			path = "-"
		}
		w.row("%8.4f %-7s %10s  %-6s %s",
			m.Entropy, m.Class, humanBytes(int64(m.Region.Size())), m.Region.Kind, path)
	}
	if len(res.RegionEntropy) == 0 {
		w.row("%s", i18n.T("mem.none"))
	}
}

// writeHashes 输出区域哈希（-a hash）。
func writeHashes(w *writer, res *result, opt options) {
	if !res.TotalHash.Empty() {
		w.kv(i18n.T("mem.col.total"), "%s", strings.Join(res.TotalHash.HashStrings()[:2], " "))
		w.blank()
	}
	list := res.RegionHash
	if opt.limit > 0 && len(list) > opt.limit {
		list = list[:opt.limit]
	}
	utils.Plainf(w.dest, "   %s", i18n.Tf("mem.hash.header",
		i18n.T("mem.col.start"), i18n.T("mem.col.size"),
		i18n.T("mem.col.type"), "md5", "sha256"))
	for _, m := range list {
		w.row("%016x %10s  %-6s %s %s", m.Region.Start,
			humanBytes(int64(m.Region.Size())), m.Region.Kind, m.Hash.MD5, m.Hash.SHA256)
	}
	if opt.limit > 0 && len(res.RegionHash) > opt.limit {
		w.row("... %s", i18n.Tf("mem.more", len(res.RegionHash)-opt.limit))
	}
}

// writeBehavior 输出程序行为痕迹（-a behavior）。
func writeBehavior(w *writer, res *result, opt options) {
	if len(res.Behaviors) == 0 {
		w.row("%s", i18n.T("mem.behavior.none"))
		return
	}
	// 先给分类统计，便于快速判断这个进程在干什么
	utils.Plainf(w.dest, "   %s", i18n.T("mem.behavior.stats"))
	for _, s := range res.BehaviorStats {
		w.row("%-12s %s %d", s.Kind, i18n.T("mem.behavior.count"), s.Count)
	}
	w.blank()

	list := res.Behaviors
	// 高危优先展示：取证时先看风险 3 的痕迹
	sort.SliceStable(list, func(i, j int) bool { return list[i].Risk > list[j].Risk })
	if opt.limit > 0 && len(list) > opt.limit {
		list = list[:opt.limit]
	}
	utils.Plainf(w.dest, "   %s", i18n.Tf("mem.behavior.header",
		i18n.T("mem.col.risk"), i18n.T("mem.col.type"),
		i18n.T("mem.col.offset"), i18n.T("mem.col.value")))
	for _, b := range list {
		risk := riskLabel(b.Risk)
		val := utils.TruncateVisible(b.Value, 160)
		w.row("%-6s %-12s %016x  %s", risk, b.Kind, b.Offset, val)
	}
	if opt.limit > 0 && len(res.Behaviors) > opt.limit {
		w.row("... %s", i18n.Tf("mem.more", len(res.Behaviors)-opt.limit))
	}
}

// writeStrings 输出提取到的字符串（-a strings）。
func writeStrings(w *writer, res *result, opt options) {
	if len(res.Strings) == 0 {
		w.row("%s", i18n.T("mem.strings.none"))
		return
	}
	list := res.Strings
	if opt.limit > 0 && len(list) > opt.limit {
		list = list[:opt.limit]
	}
	utils.Plainf(w.dest, "   %s", i18n.Tf("mem.strings.header",
		i18n.T("mem.col.offset"), i18n.T("mem.col.enc"), i18n.T("mem.col.value")))
	for _, s := range list {
		w.row("%016x  %-7s  %s", s.Offset, s.Enc, utils.TruncateVisible(s.Value, 200))
	}
	if opt.limit > 0 && len(res.Strings) > opt.limit {
		w.row("... %s", i18n.Tf("mem.more", len(res.Strings)-opt.limit))
	}
}

// writeCarved 输出恢复出来的文件（-a carve）。
func writeCarved(w *writer, res *result, opt options) {
	if len(res.Carved) == 0 {
		w.row("%s", i18n.T("mem.carve.none"))
		return
	}
	utils.Plainf(w.dest, "   %s", i18n.Tf("mem.carve.header",
		i18n.T("mem.col.type"), i18n.T("mem.col.offset"),
		i18n.T("mem.col.size"), i18n.T("mem.col.score"),
		"sha256", i18n.T("mem.col.saved")))
	for i, c := range res.Carved {
		saved := "-"
		if i < len(res.CarveSaved) {
			saved = res.CarveSaved[i]
		}
		flag := ""
		if c.Truncated {
			flag = "*"
		}
		w.row("%-8s %016x %10s  %3d %s %s",
			c.Type, c.Offset, humanBytes(int64(c.Size)), c.Score, c.Hash.SHA256, saved+flag)
	}
	if len(res.CarveSaved) > 0 {
		w.blank()
		w.row("%s", i18n.Tf("mem.carve.saved", len(res.CarveSaved), opt.carveDir))
	}
}

// riskLabel 返回风险等级对应的文案。
//
// 刻意不用 i18n.Tf("mem.risk.%d", n)：T/Tf 的 key 是完整字符串，
// 形如 "mem.risk.3" 的 key 必须在表里逐条登记。
func riskLabel(risk int) string {
	switch risk {
	case 0:
		return i18n.T("mem.risk.0")
	case 1:
		return i18n.T("mem.risk.1")
	case 2:
		return i18n.T("mem.risk.2")
	case 3:
		return i18n.T("mem.risk.3")
	default:
		return i18n.T("mem.risk.1")
	}
}

// min 返回两个整数中的较小值。
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
