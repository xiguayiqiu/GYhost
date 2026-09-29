// 分析编排：打开目标 → 选区 → 流式扫描 → 汇总结果 → 渲染报告。
//
// 这一层与操作系统无关：所有内存读取都通过 internal/mem.Target 抽象完成，
// 因此同一套代码在 Linux(/proc)、Windows(ReadProcessMemory)、
// macOS(mach_vm_read) 上产出的是同一份报告。
package mem

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gyhost/internal/i18n"
	memcore "gyhost/internal/mem"
)

// 动作标识（-a）。
const (
	actInfo     = "info"     // 目标概览
	actMaps     = "maps"     // 内存区域列表
	actStrings  = "strings"  // 字符串提取
	actBehavior = "behavior" // 程序行为痕迹
	actCarve    = "carve"    // 从内存恢复文件
	actHash     = "hash"     // 区域哈希
	actEntropy  = "entropy"  // 区域熵
	actDump     = "dump"     // 导出内存镜像
	actWrite    = "write"    // 按地址写入
	actPatch    = "patch"    // 搜索替换
	actRestore  = "restore"  // 回滚到补丁前的原始内容
	actAll      = "all"      // 除 dump 外的全部动作
)

// allActions 是 -a all 展开后的动作集合。
//
// 刻意不含 dump：默认导出整块内存会产生几百 MB 的文件，
// 需要时显式写 -a dump 更安全。
var allActions = []string{actInfo, actMaps, actStrings, actBehavior, actCarve, actHash, actEntropy}

// writeActions 是会真正改写目标内存的动作。
//
// 刻意不并入 -a all：改写活体进程必须显式点名，不能被 all 顺带触发。
var writeActions = []string{actWrite, actPatch, actRestore}

// allNames 是 -a 可取的全部动作名（只读动作 + 写类动作 + dump）。
var allNames = func() []string {
	out := []string{actAll}
	out = append(out, allActions...)
	out = append(out, actDump)
	return append(out, writeActions...)
}()

// ActionNames 返回 -a 的全部合法取值（供帮助文案使用）。
func ActionNames() []string { return allNames }

func isValidAction(a string) bool {
	for _, n := range allNames {
		if n == a {
			return true
		}
	}
	return false
}

// hasWriteAction 判断是否选了会改写内存的动作。
func hasWriteAction(opt options) bool {
	for _, a := range writeActions {
		if opt.actions[a] {
			return true
		}
	}
	return false
}

// resolveActions 解析 -a，返回选中的动作集合。
func resolveActions(list []string) (map[string]bool, error) {
	if len(list) == 0 {
		// 默认动作：概览 + 行为分析（最常用，且完全只读）
		return map[string]bool{actInfo: true, actBehavior: true}, nil
	}
	sel := map[string]bool{}
	for _, item := range list {
		for _, part := range strings.Split(item, ",") {
			p := strings.ToLower(strings.TrimSpace(part))
			switch {
			case p == "":
			case p == actAll:
				for _, a := range allActions {
					sel[a] = true
				}
			case isValidAction(p):
				sel[p] = true
			default:
				return nil, errors.New(i18n.Tf("mem.err.bad_action", p))
			}
		}
	}
	if len(sel) == 0 {
		sel[actInfo] = true
	}
	return sel, nil
}

// readChunkSize 是逐块读取内存的块大小。
//
// 4 MiB 是权衡结果：足够大以摊薄系统调用开销，又不会让峰值内存占用过高。
const readChunkSize = 4 << 20

// regionMetric 是单个区域的度量结果（哈希或熵）。
type regionMetric struct {
	Region  memcore.Region
	Hash    memcore.HashSet
	Entropy float64
	Class   memcore.EntropyClass
}

// result 是一次分析的全部产出。
type result struct {
	// Target 是本次分析实际命中的目标描述（-i 原始值，或 -e 解析出的程序）。
	Target  string
	Kind    string
	Info    memcore.ProcessInfo
	Regions []memcore.Region

	Selected []memcore.Region // 经过 -r/-s/-S 过滤后参与分析的区域
	Skipped  int              // 被过滤掉的区域数

	Strings       []memcore.StringHit
	Behaviors     []memcore.BehaviorHit
	BehaviorStats []memcore.KindStat
	Carved        []memcore.Carved
	CarveSaved    []string // 实际落盘的路径
	RegionHash    []regionMetric
	RegionEntropy []regionMetric

	TotalHash     memcore.HashSet
	ScannedBytes  uint64
	ScannedRegion int // 完整读完的区域数
	FailedRegion  int // 读取中断的区域数

	DumpPath  string
	DumpBytes uint64
}

// runAnalysis 是主流程：解析目标 → 打开 → 选区 → 流式扫描 → 渲染报告。
func runAnalysis(dest io.Writer, notice func(NoticeLevel, string), opt options) error {
	// 只有 -l、没有 -i/-e 时：只列程序与线程，不做内存分析
	if opt.spec == "" && opt.program == "" {
		return runProcessList(dest, notice, opt)
	}

	// 1) 解析目标：-e 走「程序名/PID」解析，-i 走「PID/self/转储文件」
	_, targets, err := resolveTarget(opt, notice)
	if err != nil {
		return err
	}
	// 2) 多目标（-e 命中多个同名进程）时逐个出报告，行为与 net 的多输入一致
	for i, sp := range targets {
		if i > 0 {
			fmt.Fprintln(dest)
		}
		if err := analyzeOne(dest, notice, opt, sp); err != nil {
			return err
		}
	}

	// 3) -l：额外列出程序与线程（可与内存分析同跑）
	if opt.list {
		fmt.Fprintln(dest)
		return runProcessList(dest, notice, opt)
	}
	return nil
}

// resolveTarget 把 -i / -e 解析成待分析的目标列表。
//
// -e 允许直接给程序名（不必先查 PID），因此需要先枚举进程再按名字匹配；
// 命中多个时全部返回，交给上层逐个分析。
func resolveTarget(opt options, notice func(NoticeLevel, string)) (memcore.Spec, []memcore.Spec, error) {
	// -e：按程序名 / PID 找进程
	if opt.program != "" {
		procs, err := backend.List()
		if err != nil {
			return memcore.Spec{}, nil, errors.New(i18n.Tf("mem.err.list_processes", backend.Name(), err))
		}
		matched := memcore.FindProcess(procs, opt.program)
		if len(matched) == 0 {
			return memcore.Spec{}, nil, errors.New(i18n.Tf("mem.err.no_match", opt.program))
		}
		if len(matched) > 1 {
			notice(NoticeWarn, i18n.Tf("mem.info.multi_match", opt.program, len(matched)))
		}
		specs := make([]memcore.Spec, 0, len(matched))
		for _, p := range matched {
			notice(NoticeInfo, i18n.Tf("mem.info.matched", p.PID, p.Name))
			specs = append(specs, memcore.Spec{Kind: memcore.SpecLive, PID: p.PID})
		}
		return specs[0], specs, nil
	}

	// -i：PID / self / 转储文件
	spec, err := memcore.ParseSpec(opt.spec)
	if err != nil {
		return memcore.Spec{}, nil, errors.New(i18n.Tf("mem.err.bad_target", opt.spec))
	}
	return spec, []memcore.Spec{spec}, nil
}

// analyzeOne 对单个目标执行完整分析并输出报告。
func analyzeOne(dest io.Writer, notice func(NoticeLevel, string), opt options, spec memcore.Spec) error {
	if spec.Kind == memcore.SpecLive && !backend.Supported() {
		notice(NoticeWarn, backend.PrivilegeHint())
		return errors.New(i18n.Tf("mem.err.unsupported", backend.Name()))
	}
	notice(NoticeInfo, i18n.Tf("mem.info.opening", spec.String()))

	tgt, err := memcore.Resolve(backend, spec)
	if err != nil {
		return wrapOpenError(err, spec)
	}
	defer tgt.Close()

	regions, err := tgt.Regions()
	if err != nil {
		return errors.New(i18n.Tf("mem.err.regions", err))
	}
	if len(regions) == 0 {
		return errors.New(i18n.T("mem.err.no_regions"))
	}

	res := &result{
		Target:  targetLabel(spec, tgt.Info()),
		Kind:    tgt.Kind(),
		Info:    tgt.Info(),
		Regions: regions,
	}
	sel, skipped, err := selectRegions(regions, opt)
	if err != nil {
		return err
	}
	res.Selected, res.Skipped = sel, skipped
	if len(sel) == 0 {
		return errors.New(i18n.T("mem.err.no_selected"))
	}

	// 写类动作：在分析之前/之后独立成段，不与只读章节混排
	if hasWriteAction(opt) {
		return runWrite(dest, tgt, sel, opt, notice)
	}

	// 导出内存镜像：要么留证据、要么出报告，不混在一起
	if opt.actions[actDump] || opt.dump != "" {
		return runDump(tgt, sel, dest, notice, opt)
	}
	if err := scanTarget(tgt, sel, opt, res, notice); err != nil {
		return err
	}
	if len(res.Carved) > 0 && opt.carveDir != "" {
		saved, err := saveCarved(res.Carved, opt.carveDir, notice)
		if err != nil {
			return err
		}
		res.CarveSaved = saved
	}
	return renderReport(dest, res, opt)
}

// targetLabel 生成报告里的「目标」一行文案。
//
// -e 解析出来的目标要显示成 "程序名 (pid N)"，否则用户看到的是空字符串，
// 不知道到底分析的是哪个进程。
func targetLabel(spec memcore.Spec, info memcore.ProcessInfo) string {
	switch {
	case spec.Kind == memcore.SpecFile:
		return spec.Path
	case spec.Self:
		return i18n.Tf("mem.info.self_target", info.PID, info.Name)
	case info.PID > 0:
		return i18n.Tf("mem.info.proc_target", info.Name, info.PID)
	default:
		return spec.String()
	}
}

// wrapOpenError 把底层错误翻译成带平台提示的用户可读错误。
func wrapOpenError(err error, spec memcore.Spec) error {
	switch {
	case errors.Is(err, memcore.ErrPrivilege):
		return errors.New(i18n.Tf("mem.err.privilege", backend.Name(), backend.PrivilegeHint()))
	case errors.Is(err, memcore.ErrUnsupported):
		return errors.New(i18n.Tf("mem.err.unsupported", backend.Name()))
	case errors.Is(err, memcore.ErrNoProcess):
		if spec.Kind == memcore.SpecFile {
			return errors.New(i18n.Tf("mem.err.open_file", spec.Path, err))
		}
		return errors.New(i18n.Tf("mem.err.no_process", spec.String()))
	case errors.Is(err, memcore.ErrGone):
		return errors.New(i18n.Tf("mem.err.gone", spec.String(), err))
	case errors.Is(err, memcore.ErrBadSpec):
		return errors.New(i18n.Tf("mem.err.bad_target", spec.String()))
	default:
		if spec.Kind == memcore.SpecFile {
			return errors.New(i18n.Tf("mem.err.open_file", spec.Path, err))
		}
		return errors.New(i18n.Tf("mem.err.open_target", spec.String(), err))
	}
}

// selectRegions 按 -r/-s/-S 过滤区域，返回选中集合与被跳过数量。
func selectRegions(all []memcore.Region, opt options) ([]memcore.Region, int, error) {
	rf, err := parseRegionFilter(opt.region)
	if err != nil {
		return nil, 0, err
	}
	var out []memcore.Region
	skipped := 0
	for _, r := range all {
		if !rf.match(r) {
			skipped++
			continue
		}
		if opt.minSize > 0 && r.Size() < uint64(opt.minSize) {
			skipped++
			continue
		}
		if opt.maxSize > 0 && r.Size() > uint64(opt.maxSize) {
			skipped++
			continue
		}
		out = append(out, r)
	}
	return out, skipped, nil
}

// scanTarget 逐区域流式读取内存并执行所选分析。
func scanTarget(tgt memcore.Target, regions []memcore.Region, opt options, res *result, notice func(NoticeLevel, string)) error {
	needStrings := opt.actions[actStrings] || opt.actions[actBehavior]
	needCarve := opt.actions[actCarve]
	needHash := opt.actions[actHash]
	needEntropy := opt.actions[actEntropy]

	strOpts := memcore.DefaultStringOpts()
	strOpts.MinLen = opt.minLen
	switch strings.ToLower(opt.enc) {
	case "ascii": // 只要单字节串
		strOpts.ASCII, strOpts.UTF16 = true, false
	case "utf16", "utf16le": // 只要宽字符串
		strOpts.ASCII, strOpts.UTF16 = false, true
	default: // both / all
		strOpts.ASCII, strOpts.UTF16 = true, true
	}
	if !opt.nonASCII {
		// 默认过滤掉纯高位字节的填充噪声；-A 保留它们
		strOpts.MinASCII = 4
	} else {
		strOpts.MinASCII = 0
	}
	var scanner *memcore.BehaviorScanner
	if opt.actions[actBehavior] {
		scanner = memcore.NewBehaviorScanner(nil, 0)
	}
	carveFilters := memcore.ParseCarveTypes(opt.carveExt)
	filter := strings.ToLower(opt.filter)

	totalHash := memcore.NewHasher()
	var totalHist histogram

	for _, r := range regions {
		regionHash := memcore.NewHasher()
		// carry 保存本区域末尾未闭合的可打印串，避免跨读取块时被切断
		var (
			hist  histogram
			read  uint64
			carry []byte
		)
		for addr := r.Start; addr < r.End; {
			n := r.End - addr
			if n > readChunkSize {
				n = readChunkSize
			}
			buf := make([]byte, n)
			got, err := tgt.ReadAt(addr, buf)
			if got > 0 {
				chunk := buf[:got]
				regionHash.Write(chunk)
				if needEntropy {
					hist.add(chunk)
				}
				totalHash.Write(chunk)
				totalHist.add(chunk)
				read += uint64(got)

				if needStrings {
					carry = handleChunk(chunk, addr, r, carry,
						strOpts, scanner, filter, res)
				}
				if needCarve {
					if err := memcore.Carve(chunk, addr, carveFilters, 1, func(c memcore.Carved) error {
						res.Carved = append(res.Carved, c)
						return nil
					}); err != nil {
						return err
					}
				}
			}
			if err != nil {
				// 读不动（已换出、受保护页、进程中途退出）：记录后放弃本区域余下部分
				break
			}
			addr += n
		}
		res.ScannedBytes += read
		if read < r.Size() {
			res.FailedRegion++
		} else {
			res.ScannedRegion++
		}
		if needHash {
			res.RegionHash = append(res.RegionHash, regionMetric{Region: r, Hash: regionHash.Sum()})
		}
		if needEntropy {
			e := hist.entropy()
			res.RegionEntropy = append(res.RegionEntropy, regionMetric{
				Region: r, Entropy: e, Class: memcore.ClassifyEntropy(e),
			})
		}
		notice(NoticeInfo, i18n.Tf("mem.info.region", r.String(), humanBytes(int64(read))))
	}
	res.TotalHash = totalHash.Sum()
	if scanner != nil {
		res.Behaviors = scanner.Hits()
		res.BehaviorStats = scanner.Count()
	}
	return nil
}

// handleChunk 处理一块内存数据：提取字符串并喂给行为扫描器，
// 返回需要带到下一块的未闭合串尾巴。
func handleChunk(chunk []byte, addr uint64, r memcore.Region, carry []byte,
	strOpts memcore.StringOpts, scanner *memcore.BehaviorScanner, filter string, res *result) []byte {

	data, base := chunk, addr
	if len(carry) > 0 {
		// 把上一块的尾巴接到本块前面，地址基准相应前移
		data = append(carry, chunk...)
		base = addr - uint64(len(carry))
	}
	so := strOpts
	so.Base = base
	_ = memcore.ExtractStrings(data, so, func(h memcore.StringHit) error {
		if filter != "" && !strings.Contains(strings.ToLower(h.Value), filter) {
			return nil
		}
		res.Strings = append(res.Strings, h)
		if scanner != nil {
			scanner.Feed(h, r.Kind)
		}
		return nil
	})
	// 尾部连续可打印字节可能是被切断的串，带到下一块继续
	return trailingPrintable(data)
}

// maxCarry 是跨块保留的最大尾巴长度。
const maxCarry = 8 << 10

// trailingPrintable 返回数据末尾连续的可打印字节（UTF-8 安全）。
func trailingPrintable(data []byte) []byte {
	n := trailingLen(data)
	if n == 0 {
		return nil
	}
	return data[len(data)-n:]
}

// trailingLen 计算末尾连续可打印字节的长度，上限 maxCarry。
func trailingLen(data []byte) int {
	limit := len(data)
	if limit > maxCarry {
		limit = maxCarry
	}
	n := 0
	for i := len(data) - 1; i >= len(data)-limit; i-- {
		if !printableByte(data[i]) {
			break
		}
		n++
	}
	return n
}

// printableByte 与 internal/mem 的判定保持一致（可打印 + 常见空白 + 高位）。
func printableByte(b byte) bool {
	switch {
	case b >= 0x20 && b <= 0x7e:
		return true
	case b == '\t' || b == '\n' || b == '\r':
		return true
	case b >= 0x80:
		return true
	default:
		return false
	}
}

// saveCarved 把雕取到的文件写入目录，文件名带偏移与类型便于人工核对。
func saveCarved(files []memcore.Carved, dir string, notice func(NoticeLevel, string)) (saved []string, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, errors.New(i18n.Tf("mem.err.create_dir", dir, err))
	}
	for i, c := range files {
		path := filepath.Join(dir, carveFileName(i, c))
		if err := os.WriteFile(path, c.Data, 0o644); err != nil {
			notice(NoticeWarn, i18n.Tf("mem.err.write_file", path, err))
			continue
		}
		saved = append(saved, path)
	}
	return saved, nil
}

// carveFileName 生成恢复文件的文件名：序号_类型_偏移.扩展名。
//
// 带偏移是为了能对应回报告里的虚拟地址；带类型便于直接肉眼分类。
func carveFileName(i int, c memcore.Carved) string {
	return fmt.Sprintf("%04d_%s_%08x.%s", i, c.Type, c.Offset, c.Ext)
}

// parseRegionFilter 解析 -r：区域类型名（image/heap/stack/mapped/anon）、
// all，或 "<起始>-<结束>" 的地址范围。
func parseRegionFilter(s string) (regionFilter, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "", "all", "*":
		return regionFilter{kind: "all"}, nil
	case memcore.RegionImage, memcore.RegionHeap, memcore.RegionStack,
		memcore.RegionMapped, memcore.RegionAnon:
		return regionFilter{kind: s}, nil
	}
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		lo, err1 := parseAddr(parts[0])
		hi, err2 := parseAddr(parts[1])
		if err1 == nil && err2 == nil && lo < hi {
			return regionFilter{lo: lo, hi: hi, hasR: true}, nil
		}
	}
	return regionFilter{}, errors.New(i18n.Tf("mem.err.bad_region", s))
}

// parseAddr 解析十六进制（带 0x 前缀）或十进制地址。
func parseAddr(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s, base = s[2:], 16
	}
	return strconv.ParseUint(s, base, 64)
}

// regionFilter 是 -r 解析结果。
type regionFilter struct {
	kind string // 区域类型或 all
	lo   uint64 // 地址范围下界（kind 为空时生效）
	hi   uint64
	hasR bool
}

// match 判断区域是否命中过滤条件。
func (f regionFilter) match(r memcore.Region) bool {
	if f.hasR {
		return r.End > f.lo && r.Start < f.hi
	}
	return f.kind == "all" || r.Kind == f.kind
}
