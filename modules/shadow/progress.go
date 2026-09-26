package shadow

import (
	"fmt"
	"io"
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
	dictRead func() int64 // 已读入的候选数（字典行数或掩码候选数）
	attempts func() int64 // 总校验次数
	masked   bool         // 候选来自掩码枚举
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
		total   int64
	)
	for _, t := range d.targets {
		total += t.attempts.Load()
		if t.cracked.Load() {
			cracked++
			continue
		}
		// 每个待破解目标：用户名(黄) + 哈希类型(蓝) + 已尝试次数(青)
		pending = append(pending, fmt.Sprintf("%s(%s) %s",
			utils.Warn("%s", t.user),
			utils.Info("%s", algoLabel(t.algo)),
			utils.Title("%s", humanCount(t.attempts.Load()))))
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
		utils.Title("%s", humanCount(d.dictRead())),
		utils.Info("%s", humanCount(total)))

	tail := i18n.Tf("shadow.progress.tail",
		utils.Info("%s", i18n.Tf("shadow.progress.rate", humanRate(speed))),
		utils.Title("%.1fs", elapsed))

	mid := " " + i18n.T("shadow.progress.finished")
	if len(pending) > 0 {
		// 头尾是关键信息，先扣掉它们占用的宽度，余下的留给「尝试中」列表
		mid = fitTrying(pending, maxCols, utils.VisibleLen(head)+1+utils.VisibleLen(tail))
	}
	return utils.TruncateVisible(head+mid+" "+tail, maxCols)
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
			suffix = i18n.Tf("shadow.progress.more", humanCount(int64(len(pending))))
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

// humanCount 把数字压缩成 1.2k / 3.4M 形式。
func humanCount(n int64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.1fk", float64(n)/1_000)
	default:
		return fmt.Sprintf("%d", n)
	}
}
