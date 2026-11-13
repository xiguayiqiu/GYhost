package shadow

import (
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"time"

	"gyhost/internal/i18n"
	"gyhost/internal/utils"
)

// reporter 负责实时进度渲染：
//   - TTY：每 200ms 用 \r 覆盖同一行，形成“实时刷新”的状态条
//   - 非 TTY（管道/重定向）：起始渲染一次，之后每 2s 整行输出一次，避免刷屏
//
// 进度行会按终端宽度自适应：先裁剪「尝试中」目标列表，再兜底截断整行，
// 保证不折行——一旦折行，\r 就只能覆盖最后一行，看起来就是刷屏。
//
// 所有写操作共用一把锁，保证进度行与破解结果行不会互相穿插打断。
type reporter struct {
	w        io.Writer
	tty      bool
	interval time.Duration

	mu      sync.Mutex
	drawn   bool
	started bool
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
}

// newReporter 创建进度渲染器；w 为 nil 时返回 nil（所有方法对 nil 安全）。
func newReporter(w io.Writer) *reporter {
	if w == nil {
		return nil
	}
	r := &reporter{
		w:    w,
		tty:  utils.IsTerminal(w),
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	if r.tty {
		r.interval = 200 * time.Millisecond
	} else {
		r.interval = 2 * time.Second
	}
	return r
}

// start 启动渲染循环，并立即渲染一帧。
//
// snap 接收「整行可用的最大可见列数」（0 表示不限），据此裁剪行内内容。
func (r *reporter) start(snap func(maxCols int) string) {
	if r == nil {
		return
	}
	r.started = true
	go func() {
		defer close(r.done)
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()

		r.render(snap)
		for {
			select {
			case <-r.stop:
				return
			case <-ticker.C:
				r.render(snap)
			}
		}
	}()
}

// stopAndWait 停止渲染循环并擦除进度行（为最终统计让路）。
func (r *reporter) stopAndWait() {
	if r == nil {
		return
	}
	r.once.Do(func() { close(r.stop) })
	if r.started {
		<-r.done
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clearLocked()
}

// emit 在清除进度行的状态下执行 fn（用于打印破解结果），结束后由下一次渲染恢复进度行。
func (r *reporter) emit(fn func()) {
	if r == nil {
		fn()
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clearLocked()
	fn()
}

func (r *reporter) render(snap func(maxCols int) string) {
	cols := r.columns()
	s := snap(cols)

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tty {
		// 兜底截断：进度行一旦折行，\r 覆盖就会失效并刷屏
		fmt.Fprintf(r.w, "\r\033[2K%s", utils.TruncateVisible(s, cols))
	} else {
		fmt.Fprintln(r.w, s)
	}
	r.drawn = true
}

// columns 返回进度行可用的最大可见列数。
//
// 取终端宽度减 1，避免正好写满最后一列触发终端的“待折行”状态；
// 非 TTY（管道/重定向）返回 0，表示不做宽度限制。
func (r *reporter) columns() int {
	if !r.tty {
		return 0
	}
	if w := utils.TerminalWidth(r.w); w > 1 {
		return w - 1
	}
	return 0
}

func (r *reporter) clearLocked() {
	if r.tty && r.drawn {
		utils.ClearLine(r.w)
		r.drawn = false
	}
}

// progressData 渲染进度行所需的快照数据源。
type progressData struct {
	start    time.Time
	targets  []*target
	dictRead func() int64          // 已读入的候选数（字典行数或掩码候选数）
	total    func() (uint64, bool) // 候选总数；第二个返回值为 false 表示总数未知
	attempts func() int64          // 总校验次数
	masked   bool                  // 候选来自掩码枚举
}

// maxTrying 是「尝试中」列表最多展示的目标数。
const maxTrying = 3

// line 生成当前进度行（含颜色，文案已国际化）。
//
// maxCols 为整行可用的最大可见列数（0 表示不限）。行内最不关键的「尝试中」
// 目标列表会按可用宽度自适应裁剪，保证整行不折行——折行会让 \r 覆盖失效并刷屏。
func (d progressData) line(maxCols int) string {
	var (
		cracked int
		pending []string
		checks  int64
	)
	for _, t := range d.targets {
		checks += t.attempts.Load()
		if t.cracked.Load() {
			cracked++
			continue
		}
		// 每个待破解目标：用户名(黄) + 哈希类型(蓝) + 已尝试次数(青)
		pending = append(pending, fmt.Sprintf("%s(%s) %s",
			utils.Warn("%s", t.user),
			utils.Info("%s", algoLabel(t.algo)),
			utils.Title("%s", humanCount(u64(t.attempts.Load())))))
	}

	elapsed := time.Since(d.start).Seconds()
	speed := float64(0)
	if elapsed > 0 {
		speed = float64(d.attempts()) / elapsed
	}

	headKey := "shadow.progress.head"
	if d.masked {
		headKey = "shadow.progress.head_mask"
	}
	head := i18n.Tf(headKey,
		utils.Success("%s", i18n.Tf("shadow.progress.cracked", cracked, len(d.targets))),
		utils.Title("%s", d.sourceSeg()),
		utils.Info("%s", humanCount(u64(checks))))

	rateTxt := utils.Info("%s", i18n.Tf("shadow.progress.rate", humanRate(speed)))
	elapsedTxt := utils.Title("%.1fs", elapsed)
	tailKey := "shadow.progress.tail"
	tailArgs := []interface{}{rateTxt, elapsedTxt}
	if eta, ok := d.etaSec(); ok {
		// 总数已知时多给一个「剩余时间」，比光看已枚举数量更知道还要等多久
		tailKey = "shadow.progress.tail_eta"
		tailArgs = []interface{}{rateTxt, utils.Warn("%s", i18n.Tf("shadow.progress.eta", humanDuration(eta))), elapsedTxt}
	}
	tail := i18n.Tf(tailKey, tailArgs...)

	mid := " " + i18n.T("shadow.progress.finished")
	if len(pending) > 0 {
		// 头尾是关键信息，先扣掉它们占用的宽度，余下的留给「尝试中」列表
		mid = fitTrying(pending, maxCols, utils.VisibleLen(head)+1+utils.VisibleLen(tail))
	}
	return utils.TruncateVisible(head+mid+" "+tail, maxCols)
}

// sourceSeg 渲染「字典/掩码」片段：已枚举数量 + 总数 + 完成百分比。
//
// read 是「所有待破解目标都已扫过」的候选数（由最慢的目标决定），
// -1 表示全部目标已破解。
//
// 总数未知时只显示已枚举数量——字典文件的总行数要读完整个文件才知道，
// 在后台数完之前这里拿不到精确值。
func (d progressData) sourceSeg() string {
	read := d.dictRead()
	total, known := uint64(0), false
	if d.total != nil {
		total, known = d.total()
	}
	if read < 0 {
		// 全部目标已破解：字典进度按完成计
		if known && total > 0 {
			return fmt.Sprintf("%s/%s (100.0%%)", humanCount(total), humanCount(total))
		}
		return "100%"
	}
	seg := humanCount(u64(read))
	if !known || total == 0 {
		return seg
	}
	// 读数超过总数说明字典被改动过，百分比按 100% 封顶
	pct := float64(read) / float64(total) * 100
	if pct > 100 {
		pct = 100
	}
	return fmt.Sprintf("%s/%s (%.1f%%)", seg, humanCount(total), pct)
}

// etaSec 估算枚举完整个候选源还需多久（秒）。
//
// 第二个返回值为 false 表示算不出来（总数未知、还没开始或速率为零）。
func (d progressData) etaSec() (float64, bool) {
	if d.total == nil {
		return 0, false
	}
	total, ok := d.total()
	if !ok || total == 0 {
		return 0, false
	}
	read := d.dictRead()
	if read < 0 {
		return 0, true // 已经枚举完了
	}
	if read <= 0 {
		return 0, false
	}
	if u64(read) >= total {
		return 0, true // 已经枚举完了
	}
	elapsed := time.Since(d.start).Seconds()
	if elapsed <= 0 {
		return 0, false
	}
	rate := float64(read) / elapsed // 候选/秒
	if rate <= 0 {
		return 0, false
	}
	return float64(total-u64(read)) / rate, true
}

// fitTrying 拼出「尝试中」片段，最多展示 maxTrying 个目标。
//
// used 为头尾已占用的可见列数；放不下任何目标时整段省略，
// 这样窄终端下仍能保住进度、速率与耗时这些关键信息。
func fitTrying(pending []string, maxCols, used int) string {
	limit := len(pending)
	if limit > maxTrying {
		limit = maxTrying
	}
	for n := limit; n >= 1; n-- {
		suffix := ""
		if n < len(pending) {
			suffix = i18n.Tf("shadow.progress.more", humanCount(uint64(len(pending))))
		}
		seg := " " + i18n.Tf("shadow.progress.trying", strings.Join(pending[:n], ", ")+suffix)
		if maxCols <= 0 || used+utils.VisibleLen(seg) <= maxCols {
			return seg
		}
	}
	return ""
}

// humanRate 把速率压缩成 42、15.2k、3.4M 形式（单位由文案提供）。
func humanRate(speed float64) string {
	switch {
	case speed >= 1_000_000:
		return fmt.Sprintf("%.1fM", speed/1_000_000)
	case speed >= 1_000:
		return fmt.Sprintf("%.1fk", speed/1_000)
	default:
		return fmt.Sprintf("%.0f", speed)
	}
}

// algoLabel 把算法标识渲染成 shadow 中的可读前缀。
func algoLabel(algo string) string {
	switch {
	case algo == "1" || algo == "5" || algo == "6" || algo == "y":
		return "$" + algo + "$"
	case algo == "2a" || algo == "2b" || algo == "2y":
		return "$" + algo + "$"
	case algo == "unknown":
		return "?"
	}
	return algo
}

// humanCount 把数字压缩成 1.2k / 3.4M / 5.6G 形式。
func humanCount(n uint64) string {
	switch {
	case n >= 1e18:
		return fmt.Sprintf("%.1fE", float64(n)/1e18)
	case n >= 1e15:
		return fmt.Sprintf("%.1fP", float64(n)/1e15)
	case n >= 1e12:
		return fmt.Sprintf("%.1fT", float64(n)/1e12)
	case n >= 1e9:
		return fmt.Sprintf("%.1fG", float64(n)/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1e3:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	default:
		return fmt.Sprintf("%d", n)
	}
}

// u64 把计数器转成无符号数；负数（不该出现）按 0 处理。
func u64(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

// humanDuration 把时长渲染成 45秒 / 12分 / 1时23分 / 2天3时 形式。
//
// 分钟及以上四舍五入而不是截断：截断会把「还剩 1分56秒」显示成「1分」，
// 少报将近一分钟，看着比实际乐观。
func humanDuration(sec float64) string {
	if sec < 0 {
		sec = 0
	}
	d := time.Duration(sec * float64(time.Second))
	switch {
	case d < time.Minute:
		return i18n.Tf("shadow.progress.dur.sec", int(d.Seconds()))
	case d < time.Hour:
		return i18n.Tf("shadow.progress.dur.min", int(math.Round(d.Minutes())))
	case d < 24*time.Hour:
		h := int(d.Hours())
		m := int(d.Minutes()) - h*60
		return i18n.Tf("shadow.progress.dur.hour", h, m)
	default:
		days := int(d.Hours()) / 24
		h := int(d.Hours()) % 24
		return i18n.Tf("shadow.progress.dur.day", days, h)
	}
}
