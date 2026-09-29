// 在内存中操作目标程序：write / patch / restore。
//
// 设计上的几条硬规则（都是为了避免「手一滑把目标改坏」）：
//
//  1. **默认只预览**：不加 --apply 就只算不写，报告里逐条给出 before/after。
//  2. **可回滚**：真正写入前把原始字节存进备份文件，-a restore ���以一键还原。
//  3. **不越权**：只写「本来就读得到」的内存；没权限就明确拒绝，而不是硬来。
//  4. **默认不碰只读区域**：目标没有写权限的区域需要 --force 才写。
//  5. **不会被 -a all 顺带触发**：write/patch/restore 必须显式点名。
package mem

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"gyhost/internal/i18n"
	memcore "gyhost/internal/mem"
	"gyhost/internal/utils"
)

// runWrite 处理 write / patch / restore 三个动作。
func runWrite(dest io.Writer, tgt memcore.Target, regions []memcore.Region,
	opt options, notice func(NoticeLevel, string)) error {

	op, err := writeOpOf(opt)
	if err != nil {
		return err
	}
	spec, err := buildPatchSpec(op, regions, opt)
	if err != nil {
		return err
	}

	// 回滚没有目标可「搜」，直接按备份记录逐条构造
	if op == memcore.OpRestore {
		return runRestore(dest, tgt, regions, opt, notice)
	}

	label := targetLabelFor(tgt)
	rep := memcore.Preview(tgt, regions, spec)
	rep.Target = label

	if !opt.apply {
		renderPatch(dest, rep, opt, notice)
		return writeGuardError(rep, tgt)
	}
	// --apply：先落备份再写，保证任何时候都能回滚
	if err := memcore.Apply(tgt, rep, spec); err != nil {
		if errors.Is(err, memcore.ErrNotWritable) {
			return errors.New(i18n.Tf("mem.err.not_writable", backend.Name()))
		}
		return err
	}
	backupPath := opt.backup
	if backupPath == "" {
		backupPath = defaultBackupPath(label, op)
	}
	bk := memcore.FromHits(label, rep.Hits, nil, describePatch(op))
	for i := range bk.Records {
		bk.Records[i].Time = time.Now().Format(time.RFC3339)
	}
	if err := memcore.SaveBackup(backupPath, bk); err != nil {
		notice(NoticeWarn, i18n.Tf("mem.warn.backup_failed", backupPath, err))
	} else {
		notice(NoticeOK, i18n.Tf("mem.info.backup_saved", backupPath, len(bk.Records)))
	}
	renderPatch(dest, rep, opt, notice)
	return writeGuardError(rep, tgt)
}

// runRestore 按备份记录把内存改回补丁前的样子。
func runRestore(dest io.Writer, tgt memcore.Target, regions []memcore.Region,
	opt options, notice func(NoticeLevel, string)) error {

	path := opt.backup
	if path == "" {
		return errors.New(i18n.T("mem.err.restore_need_backup"))
	}
	bk, err := memcore.LoadBackup(path)
	if err != nil {
		return err
	}
	if len(bk.Records) == 0 {
		return errors.New(i18n.T("mem.err.no_backup"))
	}
	label := targetLabelFor(tgt)

	// 逐条还原：每条记录在各自地址写回原始字节
	var hits []memcore.PatchHit
	written := 0
	for _, r := range bk.Records {
		before, err := memcore.FromHex(r.After)
		if err != nil {
			notice(NoticeWarn, i18n.Tf("mem.warn.bad_record", r.Addr, err))
			continue
		}
		orig, err := memcore.FromHex(r.Before)
		if err != nil {
			notice(NoticeWarn, i18n.Tf("mem.warn.bad_record", r.Addr, err))
			continue
		}
		cur := make([]byte, len(before))
		if n, err := tgt.ReadAt(r.Addr, cur); err != nil || n < len(before) {
			notice(NoticeWarn, i18n.Tf("mem.warn.restore_unreadable", r.Addr))
			continue
		}
		hit := memcore.PatchHit{
			Addr: r.Addr, Region: r.Region,
			Before: cur, BeforeHex: memcore.HexOf(cur),
			After: orig, AfterHex: r.Before,
		}
		if !opt.apply {
			hit.Applyable = tgt.Writable() || opt.force
			if !hit.Applyable {
				hit.Reason = "target is not writable"
			}
			hits = append(hits, hit)
			continue
		}
		n, err := tgt.WriteAt(r.Addr, orig)
		if err != nil {
			hit.Reason = err.Error()
			notice(NoticeWarn, i18n.Tf("mem.warn.restore_failed", r.Addr, err))
			hits = append(hits, hit)
			continue
		}
		hit.Applyable = true
		written += n
		hits = append(hits, hit)
	}

	rep := &memcore.PatchReport{
		Target: label, Op: memcore.OpRestore.String(),
		DryRun: !opt.apply, Hits: hits, Written: written,
	}
	for i := range rep.Hits {
		if !rep.Hits[i].Applyable {
			rep.Skipped++
		}
	}
	renderPatch(dest, rep, opt, notice)
	if !opt.apply && rep.Skipped > 0 {
		return errors.New(i18n.T("mem.err.restore_preview_only"))
	}
	return nil
}

// writeOpOf 根据所选动作决定补丁类型。
func writeOpOf(opt options) (memcore.PatchOp, error) {
	switch {
	case opt.actions[actWrite]:
		return memcore.OpWrite, nil
	case opt.actions[actPatch]:
		return memcore.OpReplace, nil
	case opt.actions[actRestore]:
		return memcore.OpRestore, nil
	}
	return 0, errors.New(i18n.T("mem.err.no_write_action"))
}

// buildPatchSpec 把命令行参数组装成补丁描述。
func buildPatchSpec(op memcore.PatchOp, regions []memcore.Region, opt options) (memcore.PatchSpec, error) {
	spec := memcore.PatchSpec{Op: op, Force: opt.force, MaxCount: opt.maxCount}
	switch op {
	case memcore.OpWrite:
		if opt.addr == "" {
			return spec, errors.New(i18n.T("mem.err.write_need_addr"))
		}
		addr, err := parsePatchAddr(opt.addr, regions)
		if err != nil {
			return spec, err
		}
		spec.Addr = addr
		if opt.data == "" {
			return spec, errors.New(i18n.T("mem.err.write_need_data"))
		}
		data, err := memcore.ParsePatchData(opt.data)
		if err != nil {
			return spec, errors.New(i18n.Tf("mem.err.bad_data", err))
		}
		if len(data) == 0 {
			return spec, errors.New(i18n.T("mem.err.write_need_data"))
		}
		spec.Data = data
	case memcore.OpReplace:
		if opt.data == "" {
			return spec, errors.New(i18n.T("mem.err.patch_need_data"))
		}
		needle, err := memcore.ParsePatchData(opt.filter)
		if err != nil || len(needle) == 0 {
			return spec, errors.New(i18n.T("mem.err.patch_need_needle"))
		}
		repl, err := memcore.ParsePatchData(opt.data)
		if err != nil {
			return spec, errors.New(i18n.Tf("mem.err.bad_data", err))
		}
		spec.Needle, spec.Replacement = needle, repl
	}
	return spec, nil
}

// parsePatchAddr 解析目标地址。
//
// 支持三种写法：
//
//	0x7f0000001000     绝对地址
//	1234               十进制地址
//	heap+0x40          区域名 + 偏移（第一块同名区域，最常用）
func parsePatchAddr(s string, regions []memcore.Region) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New(i18n.T("mem.err.write_need_addr"))
	}
	if i := strings.Index(s, "+"); i > 0 {
		kind := strings.ToLower(strings.TrimSpace(s[:i]))
		offStr := strings.TrimSpace(s[i+1:])
		for _, r := range regions {
			if r.Kind != kind {
				continue
			}
			off, err := strconv.ParseUint(strings.TrimPrefix(offStr, "0x"), baseOf(offStr), 64)
			if err != nil {
				return 0, errors.New(i18n.Tf("mem.err.bad_addr", s))
			}
			if r.Start+off >= r.End {
				return 0, errors.New(i18n.Tf("mem.err.addr_out_of_region", kind, off, r.String()))
			}
			return r.Start + off, nil
		}
		return 0, errors.New(i18n.Tf("mem.err.no_such_region", kind))
	}
	v, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), baseOf(s), 64)
	if err != nil {
		return 0, errors.New(i18n.Tf("mem.err.bad_addr", s))
	}
	return v, nil
}

// baseOf 判断字符串是十六进制还是十进制。
func baseOf(s string) int {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return 16
	}
	return 10
}

// renderPatch 输出补丁报告（预览与执行共用一套渲染）。
func renderPatch(dest io.Writer, rep *memcore.PatchReport, opt options, notice func(NoticeLevel, string)) {
	w := &writer{dest: dest}
	mode := i18n.T("mem.patch.preview")
	if !rep.DryRun {
		mode = i18n.T("mem.patch.applied")
	}
	utils.Titlef(dest, "== %s ==", i18n.T("mem.sec.patch"))
	w.kv(i18n.T("mem.col.target"), "%s", rep.Target)
	w.kv(i18n.T("mem.col.op"), "%s", rep.Op)
	w.kv(i18n.T("mem.col.mode"), "%s", mode)
	w.kv(i18n.T("mem.col.hits"), "%d", len(rep.Hits))
	if rep.Skipped > 0 {
		w.kv(i18n.T("mem.col.skipped"), "%d", rep.Skipped)
	}
	if !rep.DryRun {
		w.kv(i18n.T("mem.col.written"), "%s", humanBytes(int64(rep.Written)))
	}
	w.blank()

	if len(rep.Hits) == 0 {
		w.row("%s", i18n.T("mem.patch.none"))
		return
	}
	list := rep.Hits
	if opt.limit > 0 && len(list) > opt.limit {
		list = list[:opt.limit]
	}
	utils.Plainf(dest, "   %s", i18n.Tf("mem.patch.header",
		i18n.T("mem.col.addr"), i18n.T("mem.col.before"),
		i18n.T("mem.col.after"), i18n.T("mem.col.status")))
	for _, h := range list {
		status := i18n.T("mem.patch.ok")
		if !h.Applyable {
			status = utils.TruncateVisible(h.Reason, 40)
		}
		w.row("%016x  %-22s -> %-22s %s", h.Addr,
			utils.TruncateVisible(h.BeforeHex, 22),
			utils.TruncateVisible(h.AfterHex, 22), status)
	}
	if opt.limit > 0 && len(rep.Hits) > opt.limit {
		w.row("... %s", i18n.Tf("mem.more", len(rep.Hits)-opt.limit))
	}
	if rep.DryRun {
		w.blank()
		w.row("%s", i18n.T("mem.patch.hint"))
	}
}

// writeGuardError 在「有命中但一处都没能写」时给出明确错误。
func writeGuardError(rep *memcore.PatchReport, tgt memcore.Target) error {
	if len(rep.Hits) == 0 {
		return nil
	}
	if rep.Skipped == len(rep.Hits) && rep.Skipped > 0 && !tgt.Writable() {
		return errors.New(i18n.Tf("mem.err.not_writable", backend.Name()))
	}
	return nil
}

// targetLabelFor 生成补丁报告里的目标标识。
func targetLabelFor(tgt memcore.Target) string {
	info := tgt.Info()
	if info.PID > 0 {
		return i18n.Tf("mem.info.proc_target", info.Name, info.PID)
	}
	return info.Exe
}

// describePatch 生成备份记录里的动作说明。
func describePatch(op memcore.PatchOp) string {
	return fmt.Sprintf("mem %s", op)
}

// defaultBackupPath 生成默认备份文件名。
func defaultBackupPath(label string, op memcore.PatchOp) string {
	name := strings.NewReplacer(" ", "_", "/", "_", "\\", "_", ":", "_").Replace(label)
	return fmt.Sprintf("mem-%s-%s-%d.bak", name, op, time.Now().Unix())
}
