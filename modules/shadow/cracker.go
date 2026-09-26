package shadow

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
	"gyhost/internal/pwdhash"
)

// Options 爆破参数。
type Options struct {
	ShadowPath   string   // shadow 文件路径
	WordlistPath string   // 密码字典路径；与 Mask 二选一
	Mask         string   // 掩码表达式（hashcat 风格，如 ?l?l?d?d）；与 WordlistPath 二选一
	Threads      int      // 并发线程数
	OutputPath   string   // 可选，结果输出文件
	Users        []string // 可选，只爆破这些用户；空表示全部
	GPU          bool     // 可选，尝试用 GPU (CUDA) 加速；不可用时提示并回退 CPU

	// Progress 实时进度输出目标（通常为 os.Stderr）；nil 表示不显示进度。
	Progress io.Writer

	// OnCrack 每破解出一个账户时回调（在工作协程中调用，已与进度行互斥）。
	OnCrack func(Result)

	// OnNotice 运行期提示回调（进度行已擦除，随后恢复）；nil 表示忽略。
	// 提示内容已按当前语言生成，level 决定展示配色。
	OnNotice func(NoticeLevel, string)
}

// NoticeLevel 运行期提示的级别，决定展示配色。
type NoticeLevel int

const (
	// NoticeInfo 信息类提示（蓝色 [*]）。
	NoticeInfo NoticeLevel = iota
	// NoticeOK 成功类提示（绿色 [✓]）。
	NoticeOK
	// NoticeWarn 警告类提示（黄色 [!]），如 GPU 不可用回退 CPU。
	NoticeWarn
)

// Result 一条破解结果。
type Result struct {
	User     string // 用户名
	Hash     string // 原始哈希
	Password string // 猜中的明文密码
}

// Skipped 被跳过的账户及原因。
type Skipped struct {
	User   string
	Hash   string
	Reason string
}

// target 一个待爆破的账户；统计字段由多个工作协程并发访问（仅原子操作/无共享可变态）。
type target struct {
	user    string
	encoded string
	algo    string

	// gpu 该目标在 GPU 上校验所需的参数；nil 表示只能走 CPU。
	// 仅在请求了 --gpu 时填充，读写均发生在爆破开始前的规划阶段。
	gpu *cuda.Target

	cracked  atomic.Bool
	attempts atomic.Int64
}

// Report 一次爆破的完整报告。
type Report struct {
	Targets     int       // 参与爆破的目标数
	Results     []Result  // 破解结果
	Pending     []string  // 未破解的用户名
	Skipped     []Skipped // 跳过的账户（锁定/不支持的算法）
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

// wordBatch 一批候选密码。同一份批会同时投递给 GPU 与 CPU 消费者，
// once 保证“字典消耗”只在第一次被取走时计一次。
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

	checked   atomic.Int64 // 字典中已消费的候选密码数
	resultsMu sync.Mutex
	results   []Result
}

// hit 记录一次命中（并发安全）：登记结果、打印、必要时立即收工。
func (s *session) hit(t *target, password string) {
	if !t.cracked.CompareAndSwap(false, true) {
		return
	}
	r := Result{User: t.user, Hash: t.encoded, Password: password}
	s.resultsMu.Lock()
	s.results = append(s.results, r)
	s.resultsMu.Unlock()

	// 先擦除进度行再打印结果，避免与状态条互相穿插
	s.progress.emit(func() {
		if s.opts.OnCrack != nil {
			s.opts.OnCrack(r)
		}
	})

	if allCracked(s.targets) {
		s.cancel() // 全部破解完成，立即收工
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

// Crack 使用字典对 shadow 文件中的哈希进行离线并发爆破。
func Crack(opts Options) (*Report, error) {
	entries, err := Parse(opts.ShadowPath)
	if err != nil {
		return nil, err
	}

	// 1. 按 -u 指定的用户名过滤（保留文件原有顺序）
	if len(opts.Users) > 0 {
		kept, missing := filterUsers(entries, opts.Users)
		if len(missing) > 0 {
			return nil, errors.New(i18n.Tf("shadow.err.user_not_found", strings.Join(missing, ", ")))
		}
		entries = kept
	}

	// 2. 分拣：跳过锁定账户，校验哈希是否受支持
	report := &Report{}
	var targets []*target

	for _, e := range entries {
		if e.lockedHash() {
			report.Skipped = append(report.Skipped, Skipped{
				User: e.User, Hash: e.Hash, Reason: i18n.T("shadow.skip.locked"),
			})
			continue
		}
		// 提前校验算法是否支持，避免爆破到最后才发现
		encoded := strings.TrimSpace(e.Hash)
		if _, err := pwdhash.NewChecker(encoded); err != nil {
			report.Skipped = append(report.Skipped, Skipped{
				User: e.User, Hash: e.Hash, Reason: i18n.Tf("shadow.skip.unsupported", pwdhash.AlgoOf(encoded)),
			})
			continue
		}
		t := &target{
			user:    e.User,
			encoded: encoded,
			algo:    pwdhash.AlgoOf(encoded),
		}
		// 请求了 GPU 时，顺带解析出该哈希的重算参数（解析失败则留在 CPU）
		if opts.GPU {
			if gp, ok := gpuTarget(encoded); ok {
				t.gpu = &gp
			}
		}
		targets = append(targets, t)
	}
	report.Targets = len(targets)

	if len(targets) == 0 {
		return report, errors.New(i18n.Tf("shadow.err.no_targets", len(entries)))
	}

	// 3. 准备候选来源（字典文件或掩码枚举），确认可用
	src, maskExpr, err := openSource(opts)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	report.Masked = maskExpr != nil

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 4. 实时进度渲染
	progress := newReporter(opts.Progress)
	start := time.Now()

	s := &session{
		opts:     opts,
		targets:  targets,
		progress: progress,
		cancel:   cancel,
	}
	data := progressData{
		start:    start,
		targets:  targets,
		masked:   maskExpr != nil,
		dictRead: s.checked.Load,
		attempts: func() int64 {
			var n int64
			for _, t := range targets {
				n += t.attempts.Load()
			}
			return n
		},
	}
	progress.start(data.line)

	if maskExpr != nil {
		s.notice(NoticeInfo, i18n.Tf("shadow.mask.keyspace",
			maskExpr.String(), keyspaceText(maskExpr)))
	}

	// 5. GPU/CPU 分工（会输出相应的国际化提示）
	plan := s.planGPU()

	// 6. 爆破管线
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

	// 7. 统计未破解的目标
	for _, t := range targets {
		if !t.cracked.Load() {
			report.Pending = append(report.Pending, t.user)
		}
	}
	report.Attempts = 0
	for _, t := range targets {
		report.Attempts += t.attempts.Load()
	}

	// 8. 可选输出到文件
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

// gpuTarget 把 $1$/$5$/$6$ 编码哈希转换成 GPU 校验参数。
// 格式不支持、盐/轮数超限或参数非法时返回 false，该目标留在 CPU。
func gpuTarget(encoded string) (cuda.Target, bool) {
	p, ok := pwdhash.ParseCrypt(encoded)
	if !ok {
		return cuda.Target{}, false
	}
	id, ok := cuda.AlgoID(p.Algo)
	if !ok {
		return cuda.Target{}, false
	}
	t := cuda.Target{Algo: id, Salt: p.Salt, Rounds: p.Rounds, Key: p.Key}
	if err := t.Validate(); err != nil {
		return cuda.Target{}, false
	}
	return t, true
}

// gpuPlan GPU / CPU 的分工方案。
type gpuPlan struct {
	enabled bool      // 是否真正启用 GPU
	device  int       // 使用的设备编号
	name    string    // 设备名（写入报告）
	memory  int64     // 显存（MB，写入报告）
	gpu     []*target // 交给 GPU 的目标
	cpu     []*target // 只能走 CPU 的目标
}

// planGPU 决定哪些目标走 GPU，并输出相应的提示。
//
// 不启用 GPU 的情形（请求了但不可用）一律打印警告并整体回退 CPU，
// 爆破照常进行，只是没有加速。
func (s *session) planGPU() *gpuPlan {
	all := &gpuPlan{cpu: s.targets}
	if !s.opts.GPU {
		return all
	}

	var gpuT, cpuT []*target
	for _, t := range s.targets {
		if t.gpu != nil {
			gpuT = append(gpuT, t)
		} else {
			cpuT = append(cpuT, t)
		}
	}

	// 先看“有没有值得上 GPU 的目标”，这样提示与当前构建/硬件无关、稳定可预期
	if len(gpuT) == 0 {
		// 目标全是 bcrypt/yescrypt 等不支持 GPU 的算法
		s.notice(NoticeWarn, i18n.T("shadow.gpu.unsupported"))
		return all
	}
	if !cuda.Privileged() {
		s.notice(NoticeWarn, i18n.T("shadow.gpu.needs_root"))
		return all
	}
	if !cuda.Compiled() {
		s.notice(NoticeWarn, i18n.T("shadow.gpu.not_compiled"))
		return all
	}
	dev, err := cuda.DefaultDevice()
	if err != nil {
		s.notice(NoticeWarn, i18n.T("shadow.gpu.no_device"))
		return all
	}

	s.notice(NoticeOK, i18n.Tf("shadow.gpu.enabled", dev.Name, dev.MemoryMB))
	if len(cpuT) > 0 {
		s.notice(NoticeInfo, i18n.Tf("shadow.gpu.partial", len(gpuT), len(cpuT)))
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

// openSource 按「字典文件 / 掩码」二选一构造候选来源。
//
// 返回的 *mask.Mask 非 nil 表示来源是掩码枚举（供提示 keyspace 用）。
func openSource(opts Options) (mask.Source, *mask.Mask, error) {
	if opts.Mask != "" {
		m, err := mask.Parse(opts.Mask)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", i18n.T("shadow.err.mask"), err)
		}
		return mask.NewEnumerator(m), m, nil
	}
	f, err := os.Open(opts.WordlistPath)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", i18n.T("shadow.err.open_dict"), err)
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

// scanBatches 按批产出候选并交给 emit；emit 返回 false 表示停止。
func scanBatches(src mask.Source, size int, emit func([]string) bool) {
	batch := make([]string, 0, size)
	stopped := false
	src.Each(func(pw string) bool {
		batch = append(batch, pw)
		if len(batch) >= size {
			if !emit(batch) {
				stopped = true
				return false
			}
			batch = make([]string, 0, size)
		}
		return true
	})
	if !stopped && len(batch) > 0 {
		emit(batch)
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

			// 每个协程自行解析哈希，确保零共享可变状态
			checkers := make([]pwdhash.Checker, len(s.targets))
			for i, t := range s.targets {
				if c, err := pwdhash.NewChecker(t.encoded); err == nil {
					checkers[i] = c
				}
			}

			for password := range jobs {
				if ctx.Err() != nil {
					return
				}
				s.checked.Add(1)
				for i, t := range s.targets {
					if t.cracked.Load() || checkers[i] == nil {
						continue
					}
					t.attempts.Add(1)
					if !checkers[i].Check(password) {
						continue
					}
					s.hit(t, password)
				}
			}
		}()
	}
	wg.Wait()
}

// runMixed GPU + CPU 混合管线：读者按批读入字典/枚举掩码，分发协程把同一批候选
// 同时投递给 GPU 消费者（单协程）与 CPU 工作协程（多协程）。
func (s *session) runMixed(ctx context.Context, src mask.Source, plan *gpuPlan, threads int) {
	const batchSize = 4096

	var raw = make(chan *wordBatch, 4)
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
		scanBatches(src, batchSize, func(batch []string) bool {
			select {
			case <-ctx.Done():
				return false
			case raw <- &wordBatch{pw: batch}:
				return true
			}
		})
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
				s.cpuLoop(ctx, cpuCh, plan.cpu)
			}()
		}
	}
	wg.Wait()
}

// gpuLoop GPU 消费者：每批候选先整体拍平后按目标逐个下发 GPU，
// 超长候选与 GPU 故障时的目标走 CPU 兜底校验。
func (s *session) gpuLoop(ctx context.Context, ch <-chan *wordBatch, plan *gpuPlan) {
	// GPU 目标的 CPU 校验器：用于超长候选、以及 GPU 故障后的回退
	checkers := make([]pwdhash.Checker, len(plan.gpu))
	for i, t := range plan.gpu {
		if c, err := pwdhash.NewChecker(t.encoded); err == nil {
			checkers[i] = c
		}
	}

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

		for i, t := range plan.gpu {
			if ctx.Err() != nil {
				return
			}
			if t.cracked.Load() {
				continue
			}
			t.attempts.Add(int64(len(b.pw)))
			if checkers[i] == nil {
				continue
			}

			if gpuOn && len(send) > 0 {
				idx, err := cuda.Verify(*t.gpu, send, plan.device)
				if err != nil {
					// 本批及后续批次改由 CPU 处理，只提示一次
					gpuOn = false
					if !fallbackNoticed {
						fallbackNoticed = true
						s.notice(NoticeWarn, i18n.Tf("shadow.gpu.runtime_error", err))
					}
				} else if idx >= 0 {
					s.hit(t, send[idx])
					continue
				}
			}

			// CPU 兜底：GPU 关闭时校验整批，否则只校验超长候选
			cands := over
			if !gpuOn {
				cands = b.pw
			}
			for _, pw := range cands {
				if !checkers[i].Check(pw) {
					continue
				}
				s.hit(t, pw)
				break
			}
		}
	}
}

// cpuLoop 混合管线中的 CPU 工作协程：只负责 plan.cpu 那部分目标。
func (s *session) cpuLoop(ctx context.Context, ch <-chan *wordBatch, targets []*target) {
	if len(targets) == 0 {
		return
	}
	checkers := make([]pwdhash.Checker, len(targets))
	for i, t := range targets {
		if c, err := pwdhash.NewChecker(t.encoded); err == nil {
			checkers[i] = c
		}
	}

	for b := range ch {
		if ctx.Err() != nil {
			return
		}
		b.consume(&s.checked)

		for _, password := range b.pw {
			for i, t := range targets {
				if t.cracked.Load() || checkers[i] == nil {
					continue
				}
				t.attempts.Add(1)
				if !checkers[i].Check(password) {
					continue
				}
				s.hit(t, password)
			}
			if ctx.Err() != nil {
				return
			}
		}
	}
}

// allCracked 判断是否已全部破解。
func allCracked(targets []*target) bool {
	for _, t := range targets {
		if !t.cracked.Load() {
			return false
		}
	}
	return true
}

func writeResults(path string, results []Result) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("shadow.err.create_out"), err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, r := range results {
		if _, err := fmt.Fprintf(w, "%s:%s\n", r.User, r.Password); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("shadow.err.write_out"), err)
		}
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("shadow.err.write_out"), err)
	}
	return nil
}
