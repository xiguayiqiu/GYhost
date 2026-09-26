package hashac

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gyhost/internal/cuda"
	"gyhost/internal/i18n"
	"gyhost/internal/mask"
)

// Options 爆破参数。
type Options struct {
	InputPath    string // 哈希文件路径
	WordlistPath string // 密码字典路径；与 Mask 二选一
	Mask         string // 掩码表达式（hashcat 风格，如 ?l?l?d?d）；与 WordlistPath 二选一
	Threads      int    // 并发线程数
	OutputPath   string // 可选，结果输出文件
	Mode         int    // 可选，强制 hashcat 模式号（0 表示自动识别）
	GPU          bool   // 可选，尝试用 GPU (CUDA) 加速；不可用时提示并回退 CPU

	// Progress 实时进度输出目标（通常为 os.Stderr）；nil 表示不显示进度。
	Progress io.Writer

	// OnCrack 每破解出一个目标时回调（工作协程中调用，已与进度行互斥）。
	OnCrack func(Result)

	// OnNotice 运行期提示回调（进度行已擦除）；nil 表示忽略。
	OnNotice func(NoticeLevel, string)
}

// NoticeLevel 运行期提示的级别，决定展示配色。
type NoticeLevel int

// 提示级别。
const (
	// NoticeInfo 信息类提示（蓝色 [*]）。
	NoticeInfo NoticeLevel = iota
	// NoticeOK 成功类提示（绿色 [✓]）。
	NoticeOK
	// NoticeWarn 警告类提示（黄色 [!]）。
	NoticeWarn
)

// Result 一条破解结果。
type Result struct {
	Hash     string // 原始哈希
	Kind     Kind   // 目标类型
	Mode     int    // hashcat 模式号
	Password string // 猜中的明文密码
}

// Skipped 被跳过的目标及原因（原因文案已按当前语言生成）。
type Skipped struct {
	Hash   string
	Reason string
}

// Report 一次爆破的完整报告。
type Report struct {
	Targets     int       // 参与爆破的目标数
	Results     []Result  // 破解结果
	Pending     []string  // 未破解的目标（原始哈希）
	Skipped     []Skipped // 跳过的目标
	Attempts    int64     // 总校验次数
	Duration    time.Duration
	WordlistLen int64  // 读取到的候选数（字典行数或掩码候选数）
	Masked      bool   // 候选来自掩码枚举而非字典文件
	GPU         string // 实际使用的 GPU 设备名；空表示 CPU 爆破
	GPUMemMB    int64  // GPU 显存（MB）
}

// Cracked 返回破解数量。
func (r *Report) Cracked() int { return len(r.Results) }

// Speed 每秒校验次数。
func (r *Report) Speed() float64 {
	if r.Duration <= 0 {
		return 0
	}
	return float64(r.Attempts) / r.Duration.Seconds()
}

// target 一个运行期的待爆破目标。
type target struct {
	t        *Target
	cracked  atomic.Bool
	attempts atomic.Int64
}

// wordBatch 一批候选密码；同一批会同时投递给 GPU 与 CPU 消费者，
// once 保证「字典消耗」只计一次。
type wordBatch struct {
	pw   []string
	once atomic.Bool
}

// consume 计入字典消耗（每批至多一次）。
func (b *wordBatch) consume(dst *atomic.Int64) {
	if b.once.CompareAndSwap(false, true) {
		dst.Add(int64(len(b.pw)))
	}
}

// session 一次爆破运行期间的共享状态。
type session struct {
	opts     Options
	targets  []*target
	progress *reporter
	cancel   context.CancelFunc

	checked   atomic.Int64
	resultsMu sync.Mutex
	results   []Result
}

// hit 记录一次命中（并发安全）：登记结果、打印、必要时立即收工。
func (s *session) hit(t *target, password string) {
	if !t.cracked.CompareAndSwap(false, true) {
		return
	}
	r := Result{Hash: t.t.Raw, Kind: t.t.Kind, Mode: t.t.Mode, Password: password}
	s.resultsMu.Lock()
	s.results = append(s.results, r)
	s.resultsMu.Unlock()

	s.progress.emit(func() {
		if s.opts.OnCrack != nil {
			s.opts.OnCrack(r)
		}
	})
	if allCracked(s.targets) {
		s.cancel()
	}
}

// notice 输出一条运行期提示（已与进度行互斥）。
func (s *session) notice(level NoticeLevel, msg string) {
	if s.opts.OnNotice == nil {
		return
	}
	s.progress.emit(func() {
		s.opts.OnNotice(level, msg)
	})
}

func allCracked(targets []*target) bool {
	for _, t := range targets {
		if !t.cracked.Load() {
			return false
		}
	}
	return true
}

// loadTargets 读取哈希文件并解析全部目标。
func loadTargets(path string, mode int) ([]*target, []Skipped, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", i18n.Tf("hashac.err.open_input", path), err)
	}
	defer f.Close()

	var (
		targets []*target
		skipped []Skipped
	)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		t, err := Parse(line, mode)
		if err != nil {
			skipped = append(skipped, Skipped{Hash: clip(line), Reason: err.Error()})
			continue
		}
		targets = append(targets, &target{t: t})
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", i18n.T("hashac.err.read_input"), err)
	}
	return targets, skipped, nil
}

// Crack 使用字典对哈希文件中的目标进行离线并发爆破。
func Crack(opts Options) (*Report, error) {
	targets, skipped, err := loadTargets(opts.InputPath, opts.Mode)
	if err != nil {
		return nil, err
	}
	report := &Report{Skipped: skipped}
	if len(targets) == 0 {
		return report, errors.New(i18n.Tf("hashac.err.no_targets", len(skipped)))
	}
	report.Targets = len(targets)

	// 候选来源：字典文件或掩码枚举
	src, maskExpr, err := openSource(opts)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	report.Masked = maskExpr != nil

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	progress := newReporter(opts.Progress)
	start := time.Now()
	s := &session{opts: opts, targets: targets, progress: progress, cancel: cancel}

	progress.start(func(maxCols int) string { return progressLine(start, s, maxCols) })

	if maskExpr != nil {
		s.notice(NoticeInfo, i18n.Tf("hashac.mask.keyspace",
			maskExpr.String(), keyspaceText(maskExpr)))
	}

	plan := s.planGPU(targets)
	if plan.enabled {
		report.GPU, report.GPUMemMB = plan.name, plan.memory
		s.runMixed(ctx, src, plan, threadsOf(opts))
	} else {
		s.runCPU(ctx, src, threadsOf(opts))
	}
	progress.stopAndWait()

	report.Duration = time.Since(start)
	report.WordlistLen = s.checked.Load()

	s.resultsMu.Lock()
	report.Results = s.results
	s.resultsMu.Unlock()

	for _, t := range targets {
		report.Attempts += t.attempts.Load()
		if !t.cracked.Load() {
			report.Pending = append(report.Pending, t.t.Raw)
		}
	}

	if opts.OutputPath != "" && len(s.results) > 0 {
		if err := writeResults(opts.OutputPath, s.results); err != nil {
			return report, err
		}
	}
	return report, nil
}

// threadsOf 取归一化后的并发线程数。
func threadsOf(opts Options) int {
	if opts.Threads < 1 {
		return 1
	}
	return opts.Threads
}

// ---------------------------------------------------------------------------
// GPU / CPU 分工
// ---------------------------------------------------------------------------

// gpuPlan GPU/CPU 分工方案。
type gpuPlan struct {
	enabled bool
	device  int
	name    string
	memory  int64
	gpu     []*target
	cpu     []*target
}

// planGPU 决定 GPU/CPU 分工（会输出相应的国际化提示）。
func (s *session) planGPU(targets []*target) *gpuPlan {
	all := &gpuPlan{cpu: targets}
	if !s.opts.GPU {
		return all
	}

	var gpuT, cpuT []*target
	for _, t := range targets {
		if t.t.GPU != nil {
			gpuT = append(gpuT, t)
		} else {
			cpuT = append(cpuT, t)
		}
	}
	if len(gpuT) == 0 {
		s.notice(NoticeWarn, i18n.T("hashac.gpu.unsupported"))
		return all
	}
	if !cuda.Privileged() {
		s.notice(NoticeWarn, i18n.T("hashac.gpu.needs_root"))
		return all
	}
	if !cuda.Compiled() {
		s.notice(NoticeWarn, i18n.T("hashac.gpu.not_compiled"))
		return all
	}
	dev, err := cuda.DefaultDevice()
	if err != nil {
		s.notice(NoticeWarn, i18n.T("hashac.gpu.no_device"))
		return all
	}

	s.notice(NoticeOK, i18n.Tf("hashac.gpu.enabled", dev.Name, dev.MemoryMB))
	if len(cpuT) > 0 {
		s.notice(NoticeInfo, i18n.Tf("hashac.gpu.partial", len(gpuT), len(cpuT)))
	}
	return &gpuPlan{
		enabled: true,
		device:  dev.Index,
		name:    dev.Name,
		memory:  dev.MemoryMB,
		gpu:     gpuT,
		cpu:     cpuT,
	}
}

// ---------------------------------------------------------------------------
// 爆破管线
// ---------------------------------------------------------------------------

// openSource 按「字典文件 / 掩码」二选一构造候选来源。
//
// 返回的 *mask.Mask 非 nil 表示来源是掩码枚举（供提示 keyspace 用）。
func openSource(opts Options) (mask.Source, *mask.Mask, error) {
	if opts.Mask != "" {
		m, err := mask.Parse(opts.Mask)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", i18n.T("hashac.err.mask"), err)
		}
		return mask.NewEnumerator(m), m, nil
	}
	f, err := os.Open(opts.WordlistPath)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", i18n.T("hashac.err.open_dict"), err)
	}
	return mask.NewFileSource(f), nil, nil
}

// keyspaceText 把 keyspace 渲染为文本；饱和时追加 "+" 表示实际更多。
func keyspaceText(m *mask.Mask) string {
	s := strconv.FormatUint(m.Keyspace(), 10)
	if m.Saturated() {
		s += "+"
	}
	return s
}

// checkAll 用单个候选依次校验给定目标集合。
func (s *session) checkAll(targets []*target, pw string) {
	for _, t := range targets {
		if t.cracked.Load() {
			continue
		}
		t.attempts.Add(1)
		if t.t.Check.Check(pw) {
			s.hit(t, pw)
		}
	}
}

// runCPU 单读者 + 多工作协程的纯 CPU 爆破（默认路径）。
func (s *session) runCPU(ctx context.Context, src mask.Source, threads int) {
	jobs := make(chan string, 4096)
	go func() {
		defer close(jobs)
		src.Each(func(pw string) bool {
			select {
			case <-ctx.Done():
				return false
			case jobs <- pw:
				return true
			}
		})
	}()

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pw := range jobs {
				if ctx.Err() != nil {
					return
				}
				s.checked.Add(1)
				s.checkAll(s.targets, pw)
			}
		}()
	}
	wg.Wait()
}

// runMixed GPU + CPU 混合管线：读者按批读字典/枚举掩码，分发协程把同一批候选
// 同时投递给 GPU 消费者（单协程）与 CPU 工作协程（多协程）。
func (s *session) runMixed(ctx context.Context, src mask.Source, plan *gpuPlan, threads int) {
	const batchSize = 2048

	raw := make(chan *wordBatch, 4)
	var gpuCh, cpuCh chan *wordBatch
	if len(plan.gpu) > 0 {
		gpuCh = make(chan *wordBatch, 2)
	}
	if len(plan.cpu) > 0 {
		cpuCh = make(chan *wordBatch, 8)
	}

	// 读者：按批读入候选
	go func() {
		defer close(raw)
		batch := make([]string, 0, batchSize)
		flush := func() bool {
			if len(batch) == 0 {
				return true
			}
			send := batch
			batch = make([]string, 0, batchSize)
			select {
			case <-ctx.Done():
				return false
			case raw <- &wordBatch{pw: send}:
				return true
			}
		}
		src.Each(func(pw string) bool {
			batch = append(batch, pw)
			if len(batch) >= batchSize {
				return flush()
			}
			return true
		})
		flush()
	}()

	// 分发：同一批候选同时投给两侧（只读共享，无需拷贝）
	go func() {
		defer func() {
			if gpuCh != nil {
				close(gpuCh)
			}
			if cpuCh != nil {
				close(cpuCh)
			}
		}()
		for b := range raw {
			if gpuCh != nil {
				select {
				case <-ctx.Done():
					return
				case gpuCh <- b:
				}
			}
			if cpuCh != nil {
				select {
				case <-ctx.Done():
					return
				case cpuCh <- b:
				}
			}
		}
	}()

	var wg sync.WaitGroup
	if gpuCh != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.gpuLoop(ctx, gpuCh, plan)
		}()
	}
	if cpuCh != nil {
		for i := 0; i < threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for b := range cpuCh {
					if ctx.Err() != nil {
						return
					}
					b.consume(&s.checked)
					for _, pw := range b.pw {
						s.checkAll(plan.cpu, pw)
					}
				}
			}()
		}
	}
	wg.Wait()
}

// gpuLoop GPU 消费者：每批候选整体下发给 GPU，超长候选与 GPU 故障时走 CPU 兜底。
func (s *session) gpuLoop(ctx context.Context, ch <-chan *wordBatch, plan *gpuPlan) {
	gpuOn := true
	fallbackNoticed := false

	for b := range ch {
		if ctx.Err() != nil {
			return
		}
		b.consume(&s.checked)

		// 超过 GPU 单候选上限的密码只能由 CPU 校验
		var send, over []string
		for _, pw := range b.pw {
			if len(pw) > cuda.MaxPasswordLen {
				over = append(over, pw)
			} else {
				send = append(send, pw)
			}
		}

		for _, t := range plan.gpu {
			if ctx.Err() != nil {
				return
			}
			if t.cracked.Load() {
				continue
			}
			t.attempts.Add(int64(len(b.pw)))

			// CPU 兜底时校验的候选集：GPU 关闭 → 整批；否则 → 仅超长候选
			cands := over

			if gpuOn && len(send) > 0 {
				hit, err := s.confirmGPU(t, send, plan.device)
				switch {
				case err != nil:
					// 本批及后续批次改由 CPU 处理，只提示一次
					gpuOn = false
					cands = b.pw
					if !fallbackNoticed {
						fallbackNoticed = true
						s.notice(NoticeWarn, i18n.Tf("hashac.gpu.runtime_error", err))
					}
				case hit:
					continue
				default:
					// GPU 的弱校验已排除本批的 send：头部校验是完整校验的
					// 必要条件，故无需再用 CPU 重复校验这些候选。
				}
			} else if !gpuOn {
				cands = b.pw
			}

			for _, pw := range cands {
				if t.t.Check.Check(pw) {
					s.hit(t, pw)
					break
				}
			}
		}
	}
}

// confirmGPU 向 GPU 索取命中候选并用 CPU 复核，确认后登记结果。
//
// GPU 对 ZipCrypto 之类只能做弱校验（头部 1~2 字节），命中可能是误报；
// 因此逐个 CPU 复核，把误报的候选剔除后重新扫描本批剩余部分。返回：
//   - (true, nil)  已确认命中并登记
//   - (false, nil) 本批已扫完且无真实命中
//   - (false, err) GPU 出错，调用方应回退 CPU
func (s *session) confirmGPU(t *target, batch []string, device int) (bool, error) {
	cands := batch
	for len(cands) > 0 {
		idx, err := cuda.VerifyHash(*t.t.GPU, cands, device)
		if err != nil {
			return false, err
		}
		if idx < 0 {
			return false, nil
		}
		if t.t.Check.Check(cands[idx]) {
			s.hit(t, cands[idx])
			return true, nil
		}
		cands = append(cands[:idx], cands[idx+1:]...)
	}
	return false, nil
}

// writeResults 把破解结果按 hashcat 的 hash:password 形式写入文件。
func writeResults(path string, results []Result) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("hashac.err.create_out"), err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, r := range results {
		if _, err := fmt.Fprintf(w, "%s:%s\n", r.Hash, r.Password); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("hashac.err.write_out"), err)
		}
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("hashac.err.write_out"), err)
	}
	return nil
}
