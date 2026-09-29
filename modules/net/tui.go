// 交互式全屏 TUI（Wireshark/tShark 风格三栏布局）。
//
// 与 -V 的分工：
//   - -V 把协议树打印到 stdout（可重定向、可进管道）
//   - -T 接管终端做"抓包浏览器"：可滚动、选中、实时改过滤表达式
//
// 前置条件：stdin 与 stdout 都必须是终端（raw 模式 + 备用屏幕 + 键盘读取）。
// 不满足时给出明确错误，提示改用 -l / -V。
//
// 本模块是纯离线的（只读本地 pcap，不发包），所以这里不是"实时抓包"，
// 而是加载已有抓包后的交互式查看。
package net

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"

	"gyhost/internal/i18n"
	"gyhost/internal/pcap"
	"gyhost/internal/utils"
)

// 包内 ANSI 控制序列。
//
// 交互式界面直接写这些序列，不经过 color 包：color 会按 TTY/NO_COLOR 自动
// 降级，而 TUI 必须始终输出控制序列（否则无法定位光标、清屏、切换缓冲区）。
const (
	escEnterAlt = "\x1b[?1049h" // 进入备用屏幕（退出时还原原屏幕内容）
	escExitAlt  = "\x1b[?1049l"
	escHideCur  = "\x1b[?25l" // 隐藏光标
	escShowCur  = "\x1b[?25h"
	escHome     = "\x1b[H"  // 光标移到左上角
	escClearEOL = "\x1b[K"  // 清到行尾
	escClear    = "\x1b[2J" // 清整屏
	escReset    = "\x1b[0m" // 复位颜色/属性
)

// tuiKey 表示一次按键。
type tuiKey struct {
	code rune // 普通字符；控制键用下方常量
	name string
}

// 按键常量。
const (
	keyNone = iota
	keyUp
	keyDown
	keyLeft
	keyRight
	keyPgUp
	keyPgDn
	keyHome
	keyEnd
	keyEnter
	keyEsc
	keyBackspace
	keyCtrlC
	keyTab
	keyBacktab
)

// escTimeout 是"ESC 序列后续字节"的等待上限。
//
// 终端一次性吐出整个转义序列（ESC [ 5 ~），但网络/负载较高的终端可能把
// 它拆成几次读写。没有这个上限，一个孤立的 ESC（比如用户想取消过滤输入）
// 会把界面卡住，直到用户再按一次键。
const escTimeout = 50 * time.Millisecond

// tuiPollInterval 是主循环等待输入的轮询间隔。
//
// 取值权衡：太大则窗口尺寸变化后界面反应迟钝，太小则在空闲时空转烧 CPU。
// 100ms 足以让人察觉不到延迟，又几乎不占 CPU。
const tuiPollInterval = 100 * time.Millisecond

// tuiPkt 是一帧在 TUI 里的索引条目。
//
// 只保存"这一帧在文件里的位置"和时间戳，帧内容在需要时才按偏移重读
// （见 (*tui).frame）。这样内存占用与包数成正比而与文件大小无关——
// 几百 MB 的抓包也能流畅浏览，而不必把整包内容拷进内存。
//
// 刻意保持紧凑：这是唯一按包数线性增长的常驻结构，460 万帧的抓包会同时
// 载入内存，所以不放任何可以现算的字段（帧序号就是下标 +1）。
type tuiPkt struct {
	ref pcap.FrameRef // 该帧在文件中的位置
	ts  int64         // 时间戳（Unix 纳秒）
}

// tuiRow 是一帧渲染成列表行所需的数据，按需解码后返回。
type tuiRow struct {
	no     int
	rel    time.Duration // 相对首包
	src    string
	dst    string
	proto  string
	length int
	info   string
}

// pane 标识当前焦点在哪个面板（Wireshark 用鼠标点选，这里用 Tab 切换）。
type pane int

const (
	paneList pane = iota
	paneTree
	paneBytes
	paneStats
)

// treeNode 是协议树在 TUI 里的一个可见节点（已按折叠状态展开成行）。
type treeNode struct {
	label    string
	name     string // 字段名（section 为空），用于给 "键: 值" 上色
	key      string // 折叠状态的记忆键
	depth    int
	hasKids  bool
	collapsd bool
	sec      bool // 是否是协议层标题
}

// tui 是交互式抓包浏览器的状态。
type tui struct {
	path  string
	info  pcap.Info
	total int // 文件总包数

	// f 保持打开：详情面板与列表解码都按偏移从这里重读帧（见 (*tui).frame）。
	f      *os.File
	frames []tuiPkt // 全部帧的索引（每帧几十字节）
	view   []int32  // 当前过滤后可见的帧在 frames 中的下标
	first  int64    // 首帧时间戳（纳秒），用于算相对时间

	sel      int  // 选中项在 view 中的下标
	top      int  // 列表可视区第一行对应的 view 下标
	rowH     int  // 列表可视区行数
	expanded bool // 是否显示详情面板

	// 协议树状态。tree 是当前选中帧的树（按需重建），treeRows 是按折叠状态
	// 展开后的可见行；collapsed 用节点标识记住折叠状态，换包后仍保持。
	tree      *dTree
	treeFor   int // tree 对应的帧在 frames 中的下标，-1 表示未构建
	treeRows  []treeNode
	treeSel   int
	treeTop   int
	collapsed map[string]bool

	// bytes 面板：独立滚动，与协议树分开
	bytesLines []string
	bytesTop   int

	// 统计面板（s 键开关）：按当前过滤结果统计
	showStats bool
	stats     *tuiStats
	statsFor  int // 统计对应的过滤版本号
	statTop   int
	filterGen int // 每次过滤变化 +1，用来判断统计是否过期

	focus pane // 当前焦点面板

	flt      *filter
	fltExpr  string
	editing  bool     // 正在输入过滤表达式
	input    []byte   // 输入缓冲
	hist     []string // 过滤表达式历史（最近在前）
	histIdx  int      // 历史游标，-1 表示不在历史里
	showHelp bool     // 帮助面板
	helpTop  int      // 帮助面板滚动位置
	msg      string   // 状态栏提示
	quit     bool

	w, h  int
	style tuiStyle
}

// readTuiKey 把一个字节序列解析成按键（处理 ESC 序列）。
func readTuiKey(br *bufio.Reader) (tuiKey, error) {
	b, err := br.ReadByte()
	if err != nil {
		return tuiKey{}, err
	}
	switch b {
	case 0x03: // Ctrl-C
		return tuiKey{code: keyCtrlC, name: "ctrl-c"}, nil
	case '\r', '\n':
		return tuiKey{code: keyEnter, name: "enter"}, nil
	case 0x7f, 0x08:
		return tuiKey{code: keyBackspace, name: "backspace"}, nil
	case '\t':
		return tuiKey{code: keyTab, name: "tab"}, nil
	case 0x1b: // ESC 序列或单独的 ESC
		return readTuiEscape(br)
	}
	return tuiKey{code: rune(b), name: string(b)}, nil
}

// readTuiEscape 解析 ESC 开头的转义序列。
//
// 关键点是"取不到后续字节就当作独立 ESC"：这既让 ESC 键本身可用，
// 也容忍了终端把序列拆开慢速送达的情况。
func readTuiEscape(br *bufio.Reader) (tuiKey, error) {
	nb, ok := readSeqByte(br)
	if !ok {
		return tuiKey{code: keyEsc, name: "esc"}, nil
	}
	if nb != '[' && nb != 'O' {
		// ESC 后跟的是普通字符：这是 Alt+字符，界面不绑定，当作 ESC 处理
		return tuiKey{code: keyEsc, name: "esc"}, nil
	}
	c, ok := readSeqByte(br)
	if !ok {
		return tuiKey{code: keyEsc, name: "esc"}, nil
	}
	switch c {
	case 'A':
		return tuiKey{code: keyUp, name: "up"}, nil
	case 'B':
		return tuiKey{code: keyDown, name: "down"}, nil
	case 'C':
		return tuiKey{code: keyRight, name: "right"}, nil
	case 'D':
		return tuiKey{code: keyLeft, name: "left"}, nil
	case 'H':
		return tuiKey{code: keyHome, name: "home"}, nil
	case 'F':
		return tuiKey{code: keyEnd, name: "end"}, nil
	case 'Z':
		return tuiKey{code: keyBacktab, name: "backtab"}, nil
	case '1', '4', '7':
		// Home / End / PageUp 的变体：ESC [ 1 ~ / ESC [ 4 ~ / ESC [ 7 ~
		if f, ok := readSeqByte(br); ok && f == '~' {
			switch c {
			case '4':
				return tuiKey{code: keyEnd, name: "end"}, nil
			default:
				return tuiKey{code: keyHome, name: "home"}, nil
			}
		}
	case '5', '6', '8':
		// PageUp / PageDown / End 都以 '~' 结尾，必须把它一并消费掉，
		// 否则残留的 '~' 会被当成一次普通按键，在过滤输入里留下一个字符。
		if f, ok := readSeqByte(br); ok && f == '~' {
			switch c {
			case '5':
				return tuiKey{code: keyPgUp, name: "pgup"}, nil
			case '6':
				return tuiKey{code: keyPgDn, name: "pgdn"}, nil
			default:
				return tuiKey{code: keyEnd, name: "end"}, nil
			}
		}
	}
	return tuiKey{code: keyNone}, nil
}

// waitStdin 等待 stdin 可读或超时。
func waitStdin(timeout time.Duration) bool {
	return utils.WaitReadable(os.Stdin, timeout)
}

// readSeqByte 读转义序列的下一个字节，先看缓冲里有没有，没有才带超时地等一下。
//
// stdin 是 *os.File 而不是 net.Conn，没有 SetReadDeadline 可用；Unix 下用
// poll 等待可读事件来实现超时，这样孤立的 ESC 不会把界面卡住。
func readSeqByte(br *bufio.Reader) (byte, bool) {
	if br.Buffered() > 0 {
		b, err := br.ReadByte()
		return b, err == nil
	}
	if !waitStdin(escTimeout) {
		return 0, false
	}
	b, err := br.ReadByte()
	return b, err == nil
}

// tuiStyle 控制各区域使用的配色。
type tuiStyle struct {
	header   *color.Color
	title    *color.Color
	selected *color.Color
	colKey   *color.Color
	colVal   *color.Color
	dim      *color.Color
	warn     *color.Color
	ok       *color.Color
	line     *color.Color
}

// 布局常量。
const (
	tuiMinRows  = 12 // 低于这个高度就只显示包列表
	tuiListHdr  = 1  // 列表列头行
	tuiStatusH  = 1  // 底部状态栏
	tuiHeaderH  = 1  // 顶部标题栏
	tuiSep      = 1  // 区域分隔线
	tuiTreeMin  = 4  // 协议树面板最小高度
	tuiBytesMin = 4  // 字节面板最小高度
)

// tuiTheme 返回 TUI 使用的配色。
func tuiTheme() tuiStyle {
	return tuiStyle{
		header:   color.New(color.BgHiBlue, color.FgWhite, color.Bold),
		title:    color.New(color.FgCyan, color.Bold),
		selected: color.New(color.BgHiBlue, color.FgWhite),
		colKey:   color.New(color.FgHiBlack),
		colVal:   color.New(color.FgWhite),
		dim:      color.New(color.FgHiBlack),
		warn:     color.New(color.FgHiYellow),
		ok:       color.New(color.FgGreen),
		line:     color.New(color.FgHiBlack),
	}
}

// tuiAvailable 判断当前环境是否具备运行 TUI 的条件。
func tuiAvailable() bool {
	return utils.IsTerminal(os.Stdin) && utils.IsTerminal(os.Stdout)
}

// tuiProto 返回包列表里显示的协议名（与应用层判定口径一致）。
func tuiProto(p *pkt) string {
	for _, n := range []string{p.app, p.l4, p.l3, p.link} {
		if n != "" {
			return n
		}
	}
	return "?"
}

// loadTUI 扫描抓包并载入 TUI 所需的帧索引。
//
// 这里只记录每一帧在文件中的偏移与时间戳，帧内容不驻留内存：列表行与详情面板
// 真正要用到某一帧时，再用 pcap.FrameData 按偏移重读（见 (*tui).frame）。
// 因此内存占用约为每帧 36 字节，与文件大小无关，几百 MB 的抓包同样能打开。
//
// 代价是过滤需要重新扫一遍文件（大抓包约 0.7 秒，见 rebuildView），
// 换来的是不必为交互浏览准备与文件等量的内存。
func loadTUI(path string, flt *filter) (*tui, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New(i18n.Tf("net.err.open", path, err))
	}
	size := int64(0)
	if st, err := f.Stat(); err == nil {
		size = st.Size()
	}
	r, err := pcap.Open(f, size)
	if err != nil {
		f.Close()
		if errors.Is(err, pcap.ErrNotCapture) {
			return nil, errors.New(i18n.Tf("net.err.unrecognized", path))
		}
		return nil, errors.New(i18n.Tf("net.err.bad_capture", err))
	}

	t := &tui{path: path, info: r.Info(), flt: flt, style: tuiTheme(),
		f: f, treeFor: -1, histIdx: -1}
	t.frames = growPkt(nil, 1024)
	for {
		rec, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			f.Close()
			return nil, errors.New(i18n.Tf("net.err.bad_capture", err))
		}
		if t.frames == nil {
			t.first = rec.Time.UnixNano()
		}
		t.frames = append(t.frames, tuiPkt{ref: rec.Ref, ts: rec.Time.UnixNano()})
	}
	// append 的倍增会留下最多一倍的空余容量（460 万帧 ≈ 多占 70 MiB），
	// 这里收缩到实际长度。索引是常驻内存，值得这一次拷贝。
	if c := cap(t.frames); c-len(t.frames) > 1024 {
		t.frames = append(make([]tuiPkt, 0, len(t.frames)), t.frames...)
	}
	t.total = len(t.frames)
	t.fltExpr = filterExprOf(flt)
	t.pushHistory(t.fltExpr)
	if err := t.rebuildView(); err != nil {
		f.Close()
		return nil, err
	}
	return t, nil
}

// filterExprOf 返回过滤器的规范化表达式（供标题栏显示）。
func filterExprOf(f *filter) string {
	if f == nil {
		return ""
	}
	return f.String()
}

// frame 按索引重读并解码某一帧。
//
// verbose 为真时填充详情面板需要的额外字段（原始字节、头长等）；列表行只需要
// 摘要，用 false 可以省掉这部分开销。
func (t *tui) frame(i int, verbose bool) (*pkt, error) {
	if i < 0 || i >= len(t.frames) {
		return nil, errors.New(i18n.Tf("net.err.frame_range", i))
	}
	fp := &t.frames[i]
	data, err := pcap.FrameData(t.f, fp.ref)
	if err != nil {
		return nil, err
	}
	return decodeInto(new(pkt), pcap.Record{
		Index: i + 1, Time: time.Unix(0, fp.ts),
		LinkType: fp.ref.LinkType, Data: data, OrigLen: fp.ref.OrigLen,
	}, verbose, verbose), nil
}

// row 返回第 i 帧的列表行数据（按需解码）。
func (t *tui) row(i int) (tuiRow, error) {
	p, err := t.frame(i, true)
	if err != nil {
		return tuiRow{}, err
	}
	src, dst := p.addrPair()
	return tuiRow{
		no:     p.no,
		rel:    time.Duration(p.ts.UnixNano() - t.first),
		src:    endpointAddr(src, p.srcPort),
		dst:    endpointAddr(dst, p.dstPort),
		proto:  tuiProto(p),
		length: p.wireLen,
		info:   p.info,
	}, nil
}

// ensureTree 按需为当前选中帧构建协议树与 hex 行。
//
// 帧内容不驻留内存，所以换包时才重读并重建；同一帧内反复移动只重算可见行。
func (t *tui) ensureTree() {
	idx := t.safeSelFrame()
	if idx < 0 {
		t.tree, t.treeRows, t.bytesLines = nil, nil, nil
		t.treeFor = -1
		return
	}
	if t.treeFor == idx && t.tree != nil {
		return
	}
	p, err := t.frame(idx, true)
	if err != nil {
		t.tree, t.treeRows, t.bytesLines = nil, nil, nil
		t.treeFor = idx
		t.msg = err.Error()
		return
	}
	t.tree = buildPacketDetail(p, time.Unix(0, t.frames[idx].ts))
	t.bytesLines = t.tree.hexLines
	t.treeFor = idx
	t.treeSel, t.treeTop = 0, 0
	t.bytesTop = 0
	t.rebuildTreeRows()
}

// safeSelFrame 返回当前选中帧在 frames 中的下标（无选中时返回 -1）。
func (t *tui) safeSelFrame() int {
	if len(t.view) == 0 {
		return -1
	}
	vi := t.safeSel()
	if vi < 0 || vi >= len(t.view) {
		return -1
	}
	return int(t.view[vi])
}

// rebuildTreeRows 按折叠状态把协议树展开成可见行。
func (t *tui) rebuildTreeRows() {
	t.treeRows = t.treeRows[:0]
	if t.tree == nil {
		return
	}
	if t.collapsed == nil {
		t.collapsed = map[string]bool{}
	}
	var walk func(n *dnode, depth int)
	walk = func(n *dnode, depth int) {
		hasKids := len(n.children) > 0
		// 折叠状态按"层级 + 节点标识"记忆：每帧都有的同名协议层（如 IPv4）
		// 在换包后仍保持一致的展开状态。
		key := collapseKey(n, depth)
		collapsed := hasKids && t.collapsed[key]
		t.treeRows = append(t.treeRows, treeNode{
			label:    n.label,
			name:     n.name,
			key:      key,
			depth:    depth,
			hasKids:  hasKids,
			collapsd: collapsed,
			sec:      n.isSection,
		})
		if collapsed {
			return
		}
		for _, c := range n.children {
			walk(c, depth+1)
		}
	}
	for _, n := range t.tree.roots {
		walk(n, 0)
	}
	if t.treeSel >= len(t.treeRows) {
		t.treeSel = max(len(t.treeRows)-1, 0)
	}
}

// collapseKey 生成折叠状态的记忆键。
func collapseKey(n *dnode, depth int) string {
	return strconv.Itoa(depth) + "\x00" + n.Key()
}

// setCollapsed 设置某行的折叠状态并重算可见行。
func (t *tui) setCollapsed(i int, v bool) {
	if i < 0 || i >= len(t.treeRows) || !t.treeRows[i].hasKids {
		return
	}
	if t.collapsed == nil {
		t.collapsed = map[string]bool{}
	}
	t.collapsed[t.treeRows[i].key] = v
	t.rebuildTreeRows()
	// 折叠会把子行收起来，选中项要落在仍然存在的位置上
	if t.treeSel >= len(t.treeRows) {
		t.treeSel = max(len(t.treeRows)-1, 0)
	}
}

// toggleAll 全部折叠 / 全部展开。
func (t *tui) toggleAll(expand bool) {
	t.ensureTree()
	if t.collapsed == nil {
		t.collapsed = map[string]bool{}
	}
	var walk func(n *dnode, depth int)
	walk = func(n *dnode, depth int) {
		if len(n.children) > 0 {
			t.collapsed[collapseKey(n, depth)] = !expand
		}
		for _, c := range n.children {
			walk(c, depth+1)
		}
	}
	for _, n := range t.tree.roots {
		walk(n, 0)
	}
	t.rebuildTreeRows()
	if expand {
		t.msg = i18n.T("net.tui.expand_all")
	} else {
		t.msg = i18n.T("net.tui.collapse_all")
	}
}

// runTUI 接管终端运行交互式浏览器，直到用户退出。
func runTUI(t *tui, out *os.File) error {
	restore, err := utils.SetRaw(os.Stdin)
	if err != nil {
		return errors.New(i18n.T("net.err.no_tty"))
	}
	defer restore()

	fmt.Fprint(out, escEnterAlt+escHideCur+escClear)
	defer fmt.Fprint(out, escShowCur+escExitAlt)

	// 窗口尺寸变化要立刻重排，而不是等用户下一次按键才生效。
	// 信号处理函数里不能安全地做 ioctl/渲染，所以这里用 channel 传递，
	// 由主循环实际执行重排。
	resizeCh, stopResize := utils.NotifyResize()
	defer stopResize()

	br := bufio.NewReader(os.Stdin)
	t.resize(out)
	t.render(out)
	for !t.quit {
		// 轮询：既能第一时间收到窗口尺寸变化，也避免阻塞在读上时收不到信号
		if !utils.WaitReadable(os.Stdin, tuiPollInterval) {
			select {
			case <-resizeCh:
				t.resize(out)
				t.render(out)
			default:
			}
			continue
		}
		k, err := readTuiKey(br)
		if err != nil {
			break // stdin 结束（Ctrl-D / 管道断开）按退出处理
		}
		t.handleKey(k)
		if t.quit {
			break
		}
		t.render(out)
	}
	return nil
}

// resize 重新读取终端尺寸。
func (t *tui) resize(out *os.File) {
	w, h := utils.TerminalSize(out)
	if w < 40 {
		w = 40
	}
	if h < tuiMinRows {
		h = tuiMinRows
	}
	t.w, t.h = w, h
}

// handleKey 处理一次按键。
func (t *tui) handleKey(k tuiKey) {
	// 过滤输入态优先：此时 / 和 ? 都要当普通字符收下
	if t.editing {
		t.handleEditKey(k)
		return
	}
	// 帮助面板是全屏覆盖层，除退出类按键外都归它处理
	if t.showHelp {
		t.helpKeys(k)
		return
	}
	// ? 是全局帮助入口：任何面板下都应能打开，
	// 否则用户在看统计或字节面板时按 ? 没有任何反应
	if k.code == '?' {
		t.showHelp = true
		t.helpTop = 0
		return
	}
	// 统计面板是全屏覆盖层，大部分按键由它自己处理
	if t.showStats {
		t.handleStatsKey(k)
		return
	}
	// 面板切换与折叠/展开不依赖焦点，先于导航处理
	switch k.code {
	case keyTab:
		t.cycleFocus(1)
		return
	case keyBacktab:
		t.cycleFocus(-1)
		return
	case 's', 'S':
		t.showStats = true
		t.focus = paneStats
		t.msg = ""
		return
	case keyRight:
		if t.focus == paneTree {
			t.setCollapsed(t.treeSel, false)
			// 展开后选中项下移到第一个子节点（Wireshark 的行为）
			if t.treeSel < len(t.treeRows)-1 {
				t.treeSel++
			}
			return
		}
		t.move(1)
		return
	case keyLeft:
		if t.focus == paneTree {
			t.setCollapsed(t.treeSel, true)
			return
		}
		t.move(-1)
		return
	}
	// 其余按键按当前焦点分发
	switch t.focus {
	case paneTree:
		t.handleTreeKey(k)
	case paneBytes:
		t.handleBytesKey(k)
	default:
		t.handleListKey(k)
	}
}

// cycleFocus 在包列表 / 协议树 / 字节面板之间循环切换焦点。
func (t *tui) cycleFocus(d int) {
	// 没展开详情时只有列表可聚焦
	if !t.expanded {
		t.focus = paneList
		return
	}
	panes := []pane{paneList, paneTree, paneBytes}
	idx := 0
	for i, p := range panes {
		if p == t.focus {
			idx = i
		}
	}
	next := (idx + d) % len(panes)
	if next < 0 {
		next += len(panes)
	}
	t.focus = panes[next]
	t.msg = ""
}

// focusPane 设置焦点到指定面板（若该面板不可见则先展开详情）。
func (t *tui) focusPane(p pane) {
	if !t.expanded && p != paneList {
		t.expanded = true
	}
	t.focus = p
}

// handleListKey 处理包列表焦点下的按键。
func (t *tui) handleListKey(k tuiKey) {
	switch k.code {
	case keyCtrlC, 'q', 'Q':
		t.quit = true
	case keyUp, 'k':
		t.move(-1)
	case keyDown, 'j':
		t.move(1)
	case keyPgUp:
		t.move(-max(t.rowH, 1))
	case keyPgDn, ' ':
		t.move(max(t.rowH, 1))
	case keyHome, 'g':
		t.sel, t.top = 0, 0
	case keyEnd, 'G':
		t.sel = len(t.view) - 1
		if t.sel < 0 {
			t.sel = 0
		}
		t.scrollToSel()
	case keyEnter, 'e':
		t.expanded = !t.expanded
		if t.expanded && t.focus == paneList {
			t.focus = paneTree
		}
		if !t.expanded {
			t.focus = paneList
		}
	case 'a':
		t.toggleAll(true)
	case 'z', 'Z':
		t.toggleAll(false)
	case '/':
		t.editing = true
		t.input = nil
		t.histIdx = -1
	case 'r':
		t.applyFilter(t.fltExpr)
	case 'c':
		t.applyFilter("")
	}
}

// handleTreeKey 处理协议树焦点下的按键。
func (t *tui) handleTreeKey(k tuiKey) {
	t.ensureTree()
	switch k.code {
	case keyCtrlC, 'q', 'Q':
		t.quit = true
	case keyUp, 'k':
		t.moveTree(-1)
	case keyDown, 'j':
		t.moveTree(1)
	case keyPgUp:
		t.moveTree(-10)
	case keyPgDn, ' ':
		t.moveTree(10)
	case keyHome, 'g':
		t.treeSel, t.treeTop = 0, 0
	case keyEnd, 'G':
		t.treeSel = max(len(t.treeRows)-1, 0)
	case 'a':
		t.toggleAll(true)
	case 'z', 'Z':
		t.toggleAll(false)
	case 'b', 'B':
		t.focusPane(paneBytes)
	case 'e', keyEnter:
		t.focusPane(paneList)
	}
}

// handleBytesKey 处理字节面板焦点下的按键。
func (t *tui) handleBytesKey(k tuiKey) {
	switch k.code {
	case keyCtrlC, 'q', 'Q':
		t.quit = true
	case keyUp, 'k':
		t.bytesTop--
	case keyDown, 'j':
		t.bytesTop++
	case keyPgUp:
		t.bytesTop -= 5
	case keyPgDn, ' ':
		t.bytesTop += 5
	case keyHome, 'g':
		t.bytesTop = 0
	case keyEnd, 'G':
		t.bytesTop = max(len(t.bytesLines)-1, 0)
	case 'e', keyEnter:
		t.focusPane(paneTree)
	}
	if t.bytesTop < 0 {
		t.bytesTop = 0
	}
	if t.bytesTop > max(len(t.bytesLines)-1, 0) {
		t.bytesTop = max(len(t.bytesLines)-1, 0)
	}
}

// handleStatsKey 处理统计面板的按键（它是全屏覆盖层）。
func (t *tui) handleStatsKey(k tuiKey) {
	switch k.code {
	case keyCtrlC, 'q', 'Q', 's', 'S', keyEsc:
		t.showStats = false
		t.focus = paneList
		t.msg = ""
	case keyUp, 'k':
		t.scrollStats(-1)
	case keyDown, 'j':
		t.scrollStats(1)
	case keyPgUp:
		t.scrollStats(-10)
	case keyPgDn, ' ':
		t.scrollStats(10)
	case keyHome, 'g':
		t.statTop = 0
	case keyEnd, 'G':
		t.statTop = 1 << 30 // 到底部，渲染时会被夹到实际长度
	}
}

// moveTree 在协议树可见行里移动选中项。
func (t *tui) moveTree(d int) {
	if len(t.treeRows) == 0 {
		return
	}
	t.treeSel += d
	if t.treeSel < 0 {
		t.treeSel = 0
	}
	if t.treeSel >= len(t.treeRows) {
		t.treeSel = len(t.treeRows) - 1
	}
}

// handleEditKey 处理过滤表达式输入态的按键。
func (t *tui) handleEditKey(k tuiKey) {
	switch k.code {
	case keyEnter:
		t.editing = false
		t.applyFilter(string(t.input))
	case keyEsc:
		// ESC 总是先退出输入态；若当前有过滤，再按一次才清空（与 Wireshark 一致）
		t.editing = false
		t.histIdx = -1
		if t.fltExpr != "" {
			t.applyFilter("")
			t.msg = i18n.T("net.tui.filter_cleared")
			return
		}
		t.msg = i18n.T("net.tui.filter_canceled")
	case keyBackspace:
		if n := len(t.input); n > 0 {
			t.input = t.input[:n-1]
		}
		t.histIdx = -1
	case keyUp:
		t.recallHistory(-1)
	case keyDown:
		t.recallHistory(1)
	case keyTab:
		t.acceptSuggestion()
	case '?':
		t.showHelp = true
		t.helpTop = 0
	case keyCtrlC:
		t.quit = true
	default:
		if k.code >= 0x20 && k.code != 0x7f {
			t.input = append(t.input, string(k.code)...)
			t.histIdx = -1 // 改动输入即脱离历史游标
		}
	}
}

// acceptSuggestion 用 Tab 接受当前阶段的第一个补全。
//
// 只在"正在写字段名"这一阶段有意义：其他阶段补的是运算符或取值说明，
// 直接照抄没有意义。补全后接着补一个空格，直接就能写运算符。
func (t *tui) acceptSuggestion() {
	ctx := analyzeFilterInput(string(t.input))
	if ctx.stage != stageField {
		return
	}
	cands := matchFields(ctx.word, 1)
	if len(cands) == 0 {
		return
	}
	// 替换掉正在输入的那个词
	head := strings.TrimRight(string(t.input)[:len(string(t.input))-len(ctx.word)], " \t")
	t.input = []byte(head + cands[0] + " ")
	t.histIdx = -1
}

// recallHistory 在过滤历史里前后移动（d<0 更早，d>0 更新）。
func (t *tui) recallHistory(d int) {
	if len(t.hist) == 0 {
		return
	}
	if t.histIdx == -1 {
		if d < 0 {
			t.histIdx = 0 // 第一次按 ↑ 进入历史
		} else {
			return
		}
	} else {
		t.histIdx += d
		if t.histIdx < 0 {
			t.histIdx = 0
		}
	}
	if t.histIdx >= len(t.hist) {
		// 越过最新一条：回到自由输入
		t.histIdx = -1
		t.input = nil
		return
	}
	t.input = []byte(t.hist[t.histIdx])
}

// pushHistory 把一条用过的表达式记入历史（最近在前，去重）。
func (t *tui) pushHistory(expr string) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return
	}
	for _, h := range t.hist {
		if h == expr {
			return
		}
	}
	const maxHist = 32
	t.hist = append([]string{expr}, t.hist...)
	if len(t.hist) > maxHist {
		t.hist = t.hist[:maxHist]
	}
	t.histIdx = -1
}

// applyFilter 重新应用过滤表达式并回到列表顶部。
func (t *tui) applyFilter(expr string) {
	// 先校验再改状态：解析失败时保持原过滤不变，只在状态栏提示
	if strings.TrimSpace(expr) == "" {
		t.flt, t.fltExpr = nil, ""
	} else {
		f, err := parseFilter(expr)
		if err != nil {
			t.msg = err.Error()
			return
		}
		t.flt, t.fltExpr = f, expr
	}
	if err := t.rebuildView(); err != nil {
		t.msg = err.Error()
		return
	}
	t.pushHistory(expr)
	t.filterGen++ // 统计面板据此判断需要重算
	t.sel, t.top = 0, 0
}

// rebuildView 依据当前过滤器重建可见下标。
//
// 过滤要判断协议/地址/端口，必须解码每一帧，而帧内容不驻留内存，所以这里重新
// 扫一遍文件（顺序读，比按偏移随机读快得多）。没有过滤时直接取全量下标，
// 一次文件扫描都不用做。
func (t *tui) rebuildView() error {
	t.view = t.view[:0]
	if t.flt == nil || (t.flt.root == nil && t.flt.legacy == nil) {
		t.view = growInt32(t.view, len(t.frames))
		for i := range t.frames {
			t.view = append(t.view, int32(i))
		}
		return nil
	}
	r, err := pcap.Open(t.f, t.fileSize())
	if err != nil {
		return errors.New(i18n.Tf("net.err.bad_capture", err))
	}
	// 表达式引用了 ip.ttl / tcp.hdr_len 这类字段时必须详细解码，
	// 否则它们恒为 0，过滤会静默给出错误结果。
	verbose := t.flt.needsVerbose()
	var dp pkt
	i := 0
	for {
		rec, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New(i18n.Tf("net.err.bad_capture", err))
		}
		if t.flt.match(decodeInto(&dp, rec, false, verbose)) {
			t.view = append(t.view, int32(i))
		}
		i++
	}
	// 同 loadTUI：命中率高时倍增余量可观，收缩掉
	if c := cap(t.view); c-len(t.view) > 1024 {
		t.view = append(make([]int32, 0, len(t.view)), t.view...)
	}
	return nil
}

// fileSize 返回抓包文件大小（重建过滤器时需要重新 Open）。
func (t *tui) fileSize() int64 {
	if st, err := t.f.Stat(); err == nil {
		return st.Size()
	}
	return 0
}

// growInt32 确保 s 有至少 n 的余量，避免逐个 append 反复扩容。
func growInt32(s []int32, n int) []int32 {
	if cap(s)-len(s) >= n {
		return s
	}
	return make([]int32, 0, n)
}

// growPkt 同 growInt32，用于帧索引。
func growPkt(s []tuiPkt, n int) []tuiPkt {
	if cap(s)-len(s) >= n {
		return s
	}
	return make([]tuiPkt, 0, n)
}

// move 上下移动选中项。
func (t *tui) move(d int) {
	if len(t.view) == 0 {
		return
	}
	t.sel += d
	if t.sel < 0 {
		t.sel = 0
	}
	if t.sel >= len(t.view) {
		t.sel = len(t.view) - 1
	}
	t.scrollToSel()
}

// scrollToSel 让选中项始终落在可视区内。
func (t *tui) scrollToSel() {
	if t.sel < t.top {
		t.top = t.sel
	}
	if t.sel >= t.top+t.rowH && t.rowH > 0 {
		t.top = t.sel - t.rowH + 1
	}
	if t.top < 0 {
		t.top = 0
	}
}

// runTUIFile 载入并进入某个抓包的交互式浏览界面。
//
// 不是终端（管道、重定向、CI）时直接给出明确错误，提示改用 -l / -V。
func runTUIFile(path string, flt *filter) error {
	if !tuiAvailable() {
		return errors.New(i18n.T("net.err.no_tty"))
	}
	t, err := loadTUI(path, flt)
	if err != nil {
		return err
	}
	defer t.f.Close()
	if len(t.view) == 0 {
		return errors.New(i18n.T("net.tui.empty"))
	}
	return runTUI(t, os.Stdout)
}

// tuiSelected 返回当前选中包的解码结果（供详情面板渲染协议树）。
func (t *tui) tuiSelected() (*pkt, bool) {
	if len(t.view) == 0 {
		return nil, false
	}
	p, err := t.frame(int(t.view[t.safeSel()]), true)
	if err != nil {
		t.msg = err.Error()
		return nil, false
	}
	return p, true
}

// safeSel 返回落在合法范围内的选中下标。
func (t *tui) safeSel() int {
	if len(t.view) == 0 {
		return 0
	}
	if t.sel < 0 || t.sel >= len(t.view) {
		return 0
	}
	return t.sel
}

// layout 划分各区域高度，模拟 Wireshark 的三栏布局：
//
//	包列表（上） / 协议树（中） / 原始字节（下）
//
// 空间不足时按"字节 → 树 → 列表"的顺序退让，保证列表始终可见。
func (t *tui) layout() (listRows, treeRows, bytesRows int) {
	avail := t.h - tuiHeaderH - tuiStatusH
	// 输入态的提示框要占掉三行，否则渲染时会把列表顶出屏幕
	if t.editing {
		avail -= filterBarH
		if avail < tuiListHdr+1 {
			avail = tuiListHdr + 1
		}
	}

	// 统计面板与浏览区互斥：统计是整体概览，浏览是逐包细看
	if t.showStats {
		return 0, 0, avail
	}

	if t.expanded && avail < tuiMinRows-2 {
		// 终端太矮，退回只显示包列表
		t.expanded = false
	}
	if !t.expanded {
		t.rowH = max(avail-tuiListHdr, 1)
		if len(t.view) > 0 && t.sel >= len(t.view) {
			t.sel = len(t.view) - 1
		}
		t.scrollToSel()
		return avail, 0, 0
	}

	// 列表保底 4 行数据 + 1 行列头；其余在树与字节之间分配
	listRows = tuiListHdr + 5
	rest := avail - listRows - 2 // 减去两条分隔线
	if rest < tuiTreeMin+tuiBytesMin {
		// 空间不够同时容纳三个区域：放弃展开，只显示列表
		t.expanded = false
		t.rowH = max(avail-tuiListHdr, 1)
		if len(t.view) > 0 && t.sel >= len(t.view) {
			t.sel = len(t.view) - 1
		}
		t.scrollToSel()
		return avail, 0, 0
	}
	treeRows = rest / 2
	bytesRows = rest - treeRows
	if bytesRows < tuiBytesMin {
		bytesRows = tuiBytesMin
	}
	if treeRows < tuiTreeMin {
		treeRows = tuiTreeMin
	}
	// 仍然放不下就从树/字节里匀给列表，列表不可压缩
	for treeRows+bytesRows+2 > avail-tuiListHdr-1 {
		if treeRows > tuiTreeMin {
			treeRows--
		} else if bytesRows > tuiBytesMin {
			bytesRows--
		} else {
			break
		}
	}
	listRows = avail - treeRows - bytesRows - 2
	if listRows < tuiListHdr+1 {
		listRows = tuiListHdr + 1
	}
	t.rowH = max(listRows-tuiListHdr, 1)
	if len(t.view) > 0 && t.sel >= len(t.view) {
		t.sel = len(t.view) - 1
	}
	t.scrollToSel()
	return listRows, treeRows, bytesRows
}

// paint 把整帧画到 w：先定位到左上角再逐行覆盖，最后擦掉行尾残留。
func (t *tui) paint(w io.Writer, lines []string) {
	var b strings.Builder
	b.WriteString(escHome)
	for i, ln := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(ln)
		b.WriteString(escClearEOL)
	}
	// 上一帧可能更长，剩余行统一擦干净
	for i := len(lines); i < t.h; i++ {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(escClearEOL)
	}
	b.WriteString(escReset)
	fmt.Fprint(w, b.String())
}

// render 渲染一帧完整界面。
func (t *tui) render(out io.Writer) {
	listRows, treeRows, bytesRows := t.layout()
	lines := make([]string, 0, t.h)
	lines = append(lines, t.headerLine())
	if t.showHelp {
		lines = append(lines, t.helpLines(t.h-2)...)
		for len(lines) < t.h-1 {
			lines = append(lines, "")
		}
		lines = append(lines, t.statusLine())
		t.paint(out, lines)
		return
	}
	if t.showStats {
		lines = append(lines, t.statLines(bytesRows)...)
	} else {
		lines = append(lines, t.listLines(listRows)...)
		if treeRows > 0 {
			lines = append(lines, t.sepLine())
			lines = append(lines, t.treeLines(treeRows)...)
		}
		if bytesRows > 0 {
			lines = append(lines, t.sepLine())
			lines = append(lines, t.bytesPaneLines(bytesRows)...)
		}
	}
	// 高度预算：标题 1 + 状态栏 1 + （输入态时）提示框 filterBarH
	bottom := 1 + tuiStatusH
	if t.editing {
		bottom += filterBarH
	}
	for len(lines) < t.h-bottom {
		lines = append(lines, "")
	}
	lines = append(lines, t.statusLine())
	if t.editing {
		// 提示框画在状态栏之上：输入行 + 实时校验 + 语法示例
		lines = append(lines, t.filterBar(filterBarH)...)
	}
	t.paint(out, lines)
}

// headerLine 顶部标题栏：文件名、格式、过滤条件与包计数。
func (t *tui) headerLine() string {
	flt := t.fltExpr
	if flt == "" {
		flt = i18n.T("net.tui.no_filter")
	}
	left := fmt.Sprintf(" %s  %s", utils.TruncateVisible(t.path, 28), t.info.Format.String())
	// 统计面板是全屏覆盖层，标题栏显示它的汇总而不是过滤命中数
	right := fmt.Sprintf("%s %d/%d %s ", flt, len(t.view), t.total, i18n.T("net.tui.packets"))
	if t.showStats {
		right = fmt.Sprintf("%s %s ", i18n.T("net.tui.stats"), t.statHint())
	}
	pad := t.w - utils.VisibleLen(left) - utils.VisibleLen(right)
	if pad < 1 {
		return utils.TruncateVisible(left, t.w)
	}
	return t.style.header.Sprintf("%s%s%s", left,
		strings.Repeat(" ", pad), right)
}

// listLines 渲染包列表（列头 + 可视区）。
func (t *tui) listLines(rows int) []string {
	// 列宽随终端宽度自适应：编号 + 相对时间 + 源 + 目的 + 协议 + 长度 + 信息
	wNo, wTime, wSrc, wDst := 7, 9, 20, 20
	wInfo := t.w - (wNo + wTime + wSrc + wDst + 2 + 2 + 2 + 6 + 2 + 4)
	if wInfo < 12 {
		wInfo = 12
	}
	// 终端太窄时先收窄地址列，保证编号与信息始终可见
	if wInfo < 24 && t.w >= 100 {
		wSrc, wDst = 16, 16
		wInfo = t.w - (wNo + wTime + wSrc + wDst + 2 + 2 + 2 + 6 + 2 + 4)
	}
	hdr := fmt.Sprintf("%s %s %s  %s  %s %6s  %s",
		padLeft(i18n.T("net.tui.no"), wNo),
		padLeft(i18n.T("net.tui.time"), wTime),
		utils.PadRight(i18n.T("net.tui.source"), wSrc),
		utils.PadRight(i18n.T("net.tui.dest"), wDst),
		utils.PadRight(i18n.T("net.tui.proto"), 6),
		i18n.T("net.tui.length"),
		utils.PadRight(i18n.T("net.tui.info"), wInfo))
	out := []string{t.style.colKey.Sprint(utils.TruncateVisible(hdr, t.w))}

	if len(t.view) == 0 {
		// 过滤后无匹配：给出明确提示，而不是留一片空白
		out = append(out, t.style.warn.Sprintf(" %s",
			utils.TruncateVisible(i18n.T("net.tui.no_match"), t.w-1)))
		return append(out, blankLines(rows-len(out))...)
	}

	for i := 0; i < t.rowH; i++ {
		vi := t.top + i
		if vi >= len(t.view) {
			out = append(out, "")
			continue
		}
		row, err := t.row(int(t.view[vi]))
		if err != nil {
			// 单行解码失败（文件被截断/中途改动）不应中断整个界面
			row = tuiRow{no: int(t.view[vi]) + 1}
		}
		ln := fmt.Sprintf("%s %s %s  %s  %s %6d  %s",
			padLeft(strconv.Itoa(row.no), wNo),
			padLeft(relTimeText(row.rel), wTime),
			utils.PadRight(utils.TruncateVisible(row.src, wSrc), wSrc),
			utils.PadRight(utils.TruncateVisible(row.dst, wDst), wDst),
			utils.PadRight(utils.TruncateVisible(row.proto, 6), 6),
			row.length,
			utils.PadRight(utils.TruncateVisible(row.info, wInfo), wInfo))
		ln = utils.TruncateVisible(ln, t.w)
		if vi == t.sel && t.focus == paneList {
			ln = t.style.selected.Sprint(ln)
		} else if row.no%2 == 0 {
			ln = t.style.dim.Sprint(ln) // 隔行淡色，便于横向扫读
		}
		out = append(out, ln)
	}
	// 补齐到固定高度，避免界面抖动
	for len(out) < rows {
		out = append(out, "")
	}
	return out[:rows]
}

// relTimeText 把相对时间格式化成 Wireshark 风格的秒.微秒。
func relTimeText(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	sec := d / time.Second
	usec := (d % time.Second) / time.Microsecond
	return fmt.Sprintf("%d.%06d", sec, usec)
}

// sepLine 区域分隔线。
func (t *tui) sepLine() string {
	return t.style.line.Sprint(strings.Repeat("─", max(t.w-1, 0)))
}

// treeLines 渲染协议树面板（可折叠，选中行高亮）。
func (t *tui) treeLines(rows int) []string {
	t.ensureTree()
	title := i18n.T("net.tui.tree")
	if len(t.view) == 0 {
		return append([]string{t.paneTitle(title)}, blankLines(rows-1)...)
	}
	title = fmt.Sprintf("%s %s", title,
		i18n.Tf("net.tui.detail_sel", t.safeSelFrame()+1, len(t.view)))
	out := []string{t.paneTitle(title)}
	body := rows - 1
	if body < 1 {
		return out
	}
	if len(t.treeRows) == 0 {
		return append(out, blankLines(body)...)
	}

	// 视口跟随选中行
	if t.treeSel < t.treeTop {
		t.treeTop = t.treeSel
	}
	if t.treeSel >= t.treeTop+body {
		t.treeTop = t.treeSel - body + 1
	}
	if t.treeTop < 0 {
		t.treeTop = 0
	}
	for i := 0; i < body; i++ {
		ri := t.treeTop + i
		if ri >= len(t.treeRows) {
			out = append(out, "")
			continue
		}
		ln := t.treeLine(t.treeRows[ri])
		if t.focus == paneTree && ri == t.treeSel {
			ln = t.style.selected.Sprint(ln)
		}
		out = append(out, utils.TruncateVisible(ln, t.w))
	}
	return append(out, blankLines(rows-len(out))...)
}

// treeLine 渲染协议树的一行：缩进 + 折叠标记 + "键: 值"。
func (t *tui) treeLine(n treeNode) string {
	indent := strings.Repeat("  ", n.depth)
	mark := " "
	if n.hasKids {
		if n.collapsd {
			mark = "▸" // ▸ 已折叠
		} else {
			mark = "▾" // ▾ 已展开
		}
	}
	if n.sec {
		return t.style.title.Sprint(indent + mark + n.label)
	}
	return indent + mark + t.styleTreeField(n.label)
}

// styleTreeField 给 "键: 值" 上色（键淡色、值高亮）。
func (t *tui) styleTreeField(label string) string {
	i := strings.Index(label, ": ")
	if i <= 0 {
		return label
	}
	return t.style.colKey.Sprint(label[:i+1]) + t.style.colVal.Sprint(label[i+1:])
}

// bytesPaneLines 渲染原始字节面板（独立滚动）。
func (t *tui) bytesPaneLines(rows int) []string {
	t.ensureTree()
	out := []string{t.paneTitle(i18n.T("net.tui.bytes"))}
	body := rows - 1
	if body < 1 {
		return out
	}
	if len(t.bytesLines) == 0 {
		return append(out, t.style.dim.Sprintf(" %s", i18n.T("net.tui.no_bytes")))
	}
	if t.bytesTop > len(t.bytesLines)-1 {
		t.bytesTop = max(len(t.bytesLines)-1, 0)
	}
	if t.bytesTop < 0 {
		t.bytesTop = 0
	}
	for i := 0; i < body; i++ {
		li := t.bytesTop + i
		if li >= len(t.bytesLines) {
			break
		}
		out = append(out, utils.TruncateVisible(t.bytesLines[li], t.w))
	}
	return append(out, blankLines(rows-len(out))...)
}

// paneTitle 渲染带焦点标记的面板标题。
func (t *tui) paneTitle(title string) string {
	if t.focus == paneTree || t.focus == paneBytes {
		return t.style.title.Sprint("▶ " + title) // ▶ 当前焦点面板
	}
	return t.style.title.Sprint(" " + title)
}

// helpLines 渲染帮助面板（覆盖层）：上半是按键说明，下半是过滤字段。
//
// 状态栏只放得下几个最关键的键，完整清单在这里——用户按 ? 就能看到
// "过滤用 /、字段说明在下面"，不会以为功能不存在。
func (t *tui) helpLines(rows int) []string {
	out := []string{t.style.title.Sprintf(" %s", i18n.T("net.tui.filter_help"))}
	out = append(out, t.style.dim.Sprintf(" %s", i18n.T("net.tui.filter_help_hint")))
	body := rows - 2
	if body < 1 {
		return out
	}
	lines := append(strings.Split(t.keyHelpText(), "\n"),
		strings.Split(strings.TrimRight(fieldHelp(), "\n"), "\n")...)
	lines = append(lines, "")
	// 先把游标夹到有效范围，keyEnd 设的极大值要在本次渲染就生效
	if t.helpTop > len(lines)-1 {
		t.helpTop = max(len(lines)-1, 0)
	}
	if t.helpTop < 0 {
		t.helpTop = 0
	}
	for i := 0; i < body; i++ {
		li := t.helpTop + i
		if li >= len(lines) {
			out = append(out, "")
			continue
		}
		out = append(out, utils.TruncateVisible(lines[li], t.w))
	}
	return append(out, blankLines(rows-len(out))...)
}

// keyHelpText 返回完整的按键说明（帮助面板上半部分）。
func (t *tui) keyHelpText() string {
	rows := [][2]string{
		{"/", i18n.T("net.tui.help_filter")},
		{"↑ ↓", i18n.T("net.tui.help_history")},
		{"Esc", i18n.T("net.tui.help_esc")},
		{"?", i18n.T("net.tui.help_help")},
		{"↑ ↓ / j k", i18n.T("net.tui.help_move")},
		{"← →", i18n.T("net.tui.help_fold")},
		{"z / a", i18n.T("net.tui.help_fold_all")},
		{"Tab / Shift-Tab", i18n.T("net.tui.help_pane")},
		{"Enter / e", i18n.T("net.tui.help_enter")},
		{"s", i18n.T("net.tui.help_stats")},
		{"c", i18n.T("net.tui.help_clear")},
		{"r", i18n.T("net.tui.help_reapply")},
		{"g / G", i18n.T("net.tui.help_jump")},
		{"PgUp / PgDn", i18n.T("net.tui.help_page")},
		{"q / Ctrl-C", i18n.T("net.tui.help_quit")},
	}
	var b strings.Builder
	b.WriteString("\n " + i18n.T("net.tui.help_title") + "\n")
	for _, r := range rows {
		b.WriteString(fmt.Sprintf("   %-16s %s\n", r[0], r[1]))
	}
	b.WriteString("\n " + i18n.T("net.tui.help_filter_fields") + "\n")
	return b.String()
}

// helpKeys 处理帮助面板的按键。
func (t *tui) helpKeys(k tuiKey) {
	switch k.code {
	case keyCtrlC, 'q', 'Q', '?', keyEsc, keyEnter:
		t.showHelp = false
	case keyUp, 'k':
		t.helpTop--
	case keyDown, 'j':
		t.helpTop++
	case keyPgUp:
		t.helpTop -= 10
	case keyPgDn, ' ':
		t.helpTop += 10
	case keyHome, 'g':
		t.helpTop = 0
	case keyEnd, 'G':
		t.helpTop = 1 << 30
	}
	if t.helpTop < 0 {
		t.helpTop = 0
	}
}

// statusLine 底部状态栏：过滤输入框、统计面板提示或按键提示。
func (t *tui) statusLine() string {
	if t.editing {
		// 输入态的完整内容由 filterBar 渲染（多行，含语法提示）
		return ""
	}
	if t.msg != "" {
		return t.style.warn.Sprintf(" %s", utils.TruncateVisible(t.msg, t.w-2))
	}
	if t.showStats {
		if h := t.statHint(); h != "" {
			return t.style.dim.Sprintf(" %s", h)
		}
	}
	return t.style.dim.Sprintf(" %s", t.keysHint())
}

// filterBarH 是过滤输入态下提示框占用的高度。
//
// 三行分别是：表达式输入、实时校验/错误、语法示例。
const filterBarH = 3

// filterBar 渲染过滤输入提示框。
//
// 用户刚按 / 时最容易卡住的两件事：不知道能写什么语法、写了不知道对不对。
// 所以这里把校验结果和语法示例都摆在输入框正下方，边打边看，不用先记住
// 一套语法再去猜哪里写错了。
func (t *tui) filterBar(rows int) []string {
	if rows < 1 {
		return nil
	}
	input := string(t.input)
	// 1) 输入行
	line1 := t.style.warn.Sprintf(" %s%s_", i18n.T("net.tui.filter_prompt"), input)
	out := []string{utils.TruncateVisible(line1, t.w)}
	if rows == 1 {
		return out
	}

	// 2) 校验行：实时解析当前输入，合法给绿色对勾，非法给出错在哪
	msg, ok := t.filterCheck()
	if ok {
		out = append(out, utils.TruncateVisible(
			t.style.ok.Sprintf(" %s", msg), t.w))
	} else {
		out = append(out, utils.TruncateVisible(
			t.style.warn.Sprintf(" %s", msg), t.w))
	}
	if rows == 2 {
		return out
	}

	// 3) 实时提示行：跟着当前输入所处的语法阶段变化
	// （正在写字段名就补字段名，写完字段名就提示运算符，依此类推）
	out = append(out, utils.TruncateVisible(
		t.style.dim.Sprintf(" %s", t.filterSuggest()), t.w))
	for len(out) < rows {
		out = append(out, "")
	}
	return out[:rows]
}

// filterCheck 实时校验当前输入，返回提示文案与是否合法。
func (t *tui) filterCheck() (string, bool) {
	s := strings.TrimSpace(string(t.input))
	if s == "" {
		return i18n.T("net.tui.filter_hint_empty"), true
	}
	if _, err := parseFilter(s); err != nil {
		return err.Error(), false
	}
	return i18n.T("net.tui.filter_hint_ok"), true
}

// filterExamples 返回与当前输入相关的语法示例。
//
// 输入为空时给几条最常用的；已经敲了字段名时优先给该字段的示例，
// 这样用户照着补上运算符和值就行，不必去翻帮助。
func (t *tui) filterExamples() string {
	s := strings.ToLower(string(t.input))
	if s == "" {
		return i18n.T("net.tui.filter_ex_empty")
	}
	// 找出输入里已经出现的完整字段名，给出该字段的用法。
	// 必须按"完整词"匹配而不是子串包含：否则 "ip.addr == x" 里的 "ip"
	// 会先命中 ip（无点号的协议名），给出错误的示例。
	toks := fieldTokens(s)
	for _, name := range fieldNames() {
		if toks[name] {
			if ex, ok := fieldExample(name); ok {
				return ex
			}
		}
	}
	// 没匹配到字段：按已输入的片段猜意图
	switch {
	case strings.Contains(s, "port"):
		return i18n.T("net.tui.filter_ex_port")
	case strings.Contains(s, "host") || strings.Contains(s, "addr") ||
		strings.Contains(s, "ip"):
		return i18n.T("net.tui.filter_ex_ip")
	case strings.Contains(s, "len") || strings.Contains(s, "size"):
		return i18n.T("net.tui.filter_ex_len")
	}
	return i18n.T("net.tui.filter_ex_generic")
}

// fieldTokens 把表达式切成"词"，返回出现过的字段名集合。
//
// 词的定义是：两端不是字母/数字/点/下划线的片段。像 "ip.addr" 这种带点
// 的要保持完整，否则会被拆成 "ip" + "addr" 而误判为协议名 ip。
func fieldTokens(s string) map[string]bool {
	out := map[string]bool{}
	isWord := func(c byte) bool {
		return c == '.' || c == '_' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9')
	}
	start := -1
	for i := 0; i < len(s); i++ {
		if isWord(s[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			out[strings.ToLower(s[start:i])] = true
			start = -1
		}
	}
	if start >= 0 {
		out[strings.ToLower(s[start:])] = true
	}
	return out
}

// fieldExample 返回某字段的用法示例。
func fieldExample(name string) (string, bool) {
	spec, ok := fieldTable[name]
	if !ok {
		return "", false
	}
	switch spec.kind {
	case valIP:
		return i18n.Tf("net.tui.filter_ex_ipfield", name), true
	case valInt:
		return i18n.Tf("net.tui.filter_ex_intfield", name, name, name, name), true
	case valStr, valMAC:
		return i18n.Tf("net.tui.filter_ex_strfield", name), true
	case valBool:
		return i18n.Tf("net.tui.filter_ex_boolfield", name), true
	}
	return "", false
}

// keysHint 返回按终端宽度自适应的按键提示。
//
// 之前是一整句固定文案：英文 115 列，80 列终端下尾部被截掉，
// 而被截掉的恰好是"过滤/帮助"这类关键提示——用户因此不知道有 / 和 ?。
//
// 做法是把提示拆成若干段并分优先级：必留段（过滤、帮助、退出）永远排在最前，
// 保证任何终端宽度下过滤入口都可见；宽屏再逐段补上导航与面板操作。
func (t *tui) keysHint() string {
	type seg struct {
		key, text string
		priority  int // 0=必留 1=常用 2=补充
	}
	segs := []seg{
		{"/", i18n.T("net.tui.key_filter"), 0},
		{"?", i18n.T("net.tui.key_help"), 0},
		{"q", i18n.T("net.tui.key_quit"), 0},
		{"↑↓", i18n.T("net.tui.key_move"), 1},
		{"Tab", i18n.T("net.tui.key_pane"), 1},
		{"↵", i18n.T("net.tui.key_enter"), 2},
		{"←→", i18n.T("net.tui.key_fold"), 2},
		{"s", i18n.T("net.tui.key_stats"), 2},
	}
	// 协议树/字节面板下，把折叠/展开段换成该面板特有操作
	if t.focus == paneTree {
		segs[6] = seg{"z/a", i18n.T("net.tui.key_fold_all"), 2}
		segs[7] = seg{"b", i18n.T("net.tui.key_bytes"), 2}
	} else if t.focus == paneBytes {
		segs[5] = seg{"↑↓", i18n.T("net.tui.key_scroll"), 1}
	}

	avail := t.w - 3
	// 必留段排前面，保证窄屏也能看到过滤入口
	ordered := make([]seg, 0, len(segs))
	for pr := 0; pr <= 2; pr++ {
		for _, sg := range segs {
			if sg.priority == pr {
				ordered = append(ordered, sg)
			}
		}
	}
	parts := make([]string, 0, len(ordered))
	used := 0
	for _, sg := range ordered {
		piece := sg.key + " " + sg.text
		if len(parts) > 0 {
			piece = "  " + piece
		}
		wid := utils.VisibleLen(piece)
		// 必留段即使挤也要放（终端最小 40 列，三段必留放得下）；
		// 放不下就跳到下一段必留，而不是直接结束。
		if used+wid > avail {
			if sg.priority == 0 && used < avail {
				parts = append(parts, piece)
				used += wid
			}
			continue
		}
		used += wid
		parts = append(parts, piece)
	}
	return strings.Join(parts, " ")
}

// blankLines 返回 n 个空行。
func blankLines(n int) []string {
	if n <= 0 {
		return nil
	}
	out := make([]string, n)
	return out
}

// max 返回两数中的较大者。
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// 过滤输入的实时提示
// ---------------------------------------------------------------------------

// filterStage 表示光标当前处在表达式的哪个语法阶段。
//
// 提示的内容完全由阶段决定：正在写字段名就补字段名，写完字段名就提示运算符，
// 写完运算符就提示该字段要什么类型的值，写完一个条件就提示逻辑运算符。
// 这样用户边打边知道下一步该写什么，不必先背语法。
type filterStage int

const (
	stageField    filterStage = iota // 正在写字段名
	stageOperator                    // 字段名已写完，该写运算符
	stageValue                       // 运算符已写完，该写值
	stageLogic                       // 一个条件已完整，该写逻辑运算符
	stageNone                        // 空输入
)

// filterCtx 是一次分析的结论。
type filterCtx struct {
	stage   filterStage
	word    string    // 正在输入中的（不完整的）词
	field   string    // 上下文中的字段名
	spec    fieldSpec // 该字段的定义
	afterOp string    // 触发本阶段的运算符
}

// isFieldWord 判断一个字符是否属于"字段名"词。
//
// '.' 必须算在内：ip.addr、tcp.port 这类字段名是整体一个词，
// 拆开就没法按前缀补全了。
func isFieldWord(c byte) bool {
	return c == '.' || c == '_' || c == '-' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9')
}

// analyzeFilterInput 分析输入串所处的语法阶段。
//
// 做法：剥掉尾部空白后，判断最后一段非空白内容是什么——
//   - 后面紧跟运算符  -> 正在写值（stageValue）
//   - 本身是已知字段名 -> 字段写完，该写运算符（stageOperator）
//   - 是第一个词       -> 正在写字段名（stageField）
//   - 以上都不是       -> 条件已完整（stageLogic）
//
// 不复用 splitFilterWords：它按"完整词"切分，会把 "tcp.port ==" 里的运算符
// 和值粘连，判不出"已写运算符、还没写值"这一档。
func analyzeFilterInput(s string) filterCtx {
	ctx := filterCtx{}

	// 剥掉尾部空白
	i := len(s)
	for i > 0 && isFilterSpace(s[i-1]) {
		i--
	}
	if i == 0 {
		ctx.stage = stageNone
		return ctx
	}

	// 末尾这段连续字符
	wordEnd := i
	for wordEnd > 0 && isFieldWord(s[wordEnd-1]) {
		wordEnd--
	}
	word := s[wordEnd:i]

	// 词前面紧邻运算符（如 "== 4" 里的 4）：那它是值，不是字段名。
	// 但 '!' 紧贴（"!tcp"）是逻辑非，后面跟的仍是字段名，不算。
	prevIsOp := wordEnd > 0 && isFilterOp(string(s[wordEnd-1])) &&
		!(wordEnd >= 1 && s[wordEnd-1] == '!' && !prevIsUnaryBang(s, wordEnd))

	// --- 运算符阶段：最后完整词是字段名，且它后面什么都没写 ---
	//    覆盖 "tcp.port"（没空格）和 "tcp.port "（有空格）两种
	if word == "" || !prevIsOp {
		if sp, ok := lastCompleteField(s, i); ok && !hasTrailingOp(s, i) {
			ctx.stage = stageOperator
			ctx.field, ctx.spec = sp.name, sp.spec
			return ctx
		}
	}

	// --- 值阶段：末尾运算符（可带或不带空格）---
	if hasTrailingOp(s, i) {
		ctx.stage = stageValue
		// 找运算符前面那个字段名
		if sp, ok := fieldBeforeOp(s, i); ok {
			ctx.field, ctx.spec = sp.name, sp.spec
		}
		return ctx
	}

	// --- 字段阶段：正在写字段名 ---
	//    两种情况：这是第一个词；或前面刚写完 && / || / !，
	//    后者是最常见的连续输入（"tcp.port == 443 && " 之后接着敲下一个字段）。
	if !prevIsOp && word != "" {
		// head 取"这个词之前"的部分（中间可能隔着空格）
		head := strings.TrimRight(s[:wordEnd], " \t")
		if head == "" || endsWithLogicalOp(head) {
			ctx.stage = stageField
			ctx.word = word
			return ctx
		}
	}

	// --- 值阶段（续）：正在敲值 ---
	//    "tcp.port == 4" 这种：值与运算符之间有空格，prevIsOp 判不出来，
	//    所以这里改为反查"当前位置是否处在某个运算符的右侧"，
	//    是则仍属于填值这一步，继续给值类型提示比切到逻辑阶段更有用。
	if word != "" && insideValueFill(s, wordEnd) {
		// 值后面若还有运算符（"a == 1 >"），仍算在填值。
		// 注意 i 就是词的右边界，wordEnd..i 正是词本身，所以这里没有"尾巴"。
		stillFilling := false
		if stillFilling || !valueLooksComplete(word) {
			if sp, ok := fieldBeforeOp(s, i); ok {
				ctx.stage = stageValue
				ctx.field, ctx.spec = sp.name, sp.spec
				ctx.word = word
				return ctx
			}
		}
	}

	// --- 逻辑阶段：条件已完整 ---
	ctx.stage = stageLogic
	if !prevIsOp {
		ctx.word = word
	}
	return ctx
}

// insideValueFill 判断位置 i 是否处在"某个比较运算符的右侧、且还没遇到下一个
// 逻辑运算符"之间——也就是用户正在给这个运算符填值。
//
// 从 i 往左扫，遇到 & | ( ! 就停（那是新条件的开始）；中途若发现 == != > <
// >= <= 或 contains，就说明确实在填值。
func insideValueFill(s string, i int) bool {
	depth := 0
	for k := i; k > 0; {
		c := s[k-1]
		switch {
		case c == ')':
			depth++
			k--
		case c == '(':
			if depth == 0 {
				return false
			}
			depth--
			k--
		case c == '&' || c == '|':
			if depth == 0 {
				return false
			}
			k--
		case c == '=' || c == '>' || c == '<':
			return true
		case c == '!':
			// "!=" 是运算符；单独的 '!' 是逻辑非，停止
			if k >= 2 && s[k-2] == '=' {
				return true
			}
			if depth == 0 {
				return false
			}
			k--
		default:
			k--
		}
	}
	return false
}

// prevIsUnaryBang 判断位置前的 '!' 是不是逻辑非（前面是行首或空白）。
func prevIsUnaryBang(s string, i int) bool {
	if i == 0 {
		return false
	}
	return isFilterSpace(s[i-1])
}

// endsWithLogicalOp 判断已输入部分是否以 && / || / ( / ! 结尾。
func endsWithLogicalOp(s string) bool {
	t := strings.TrimRight(s, " \t")
	if t == "" {
		return false
	}
	switch t[len(t)-1] {
	case '&', '|', '(', '!':
		return true
	}
	return false
}

// isFilterSpace 判断是否是表达式里的空白。
func isFilterSpace(c byte) bool { return c == ' ' || c == '\t' }

// namedField 是"字段名 + 定义"的组合。
type namedField struct {
	name string
	spec fieldSpec
}

// lastCompleteField 返回紧贴位置 i 之前的字段名。
func lastCompleteField(s string, i int) (namedField, bool) {
	j := i
	for j > 0 && isFilterSpace(s[j-1]) {
		j--
	}
	end := j
	for end > 0 && isFieldWord(s[end-1]) {
		end--
	}
	name := strings.ToLower(strings.TrimSpace(s[end:j]))
	if name == "" {
		return namedField{}, false
	}
	sp, ok := fieldTable[name]
	if !ok {
		return namedField{}, false
	}
	return namedField{name, sp}, true
}

// hasTrailingOp 判断位置 i 之前紧邻的是不是运算符。
func hasTrailingOp(s string, i int) bool {
	j := i
	for j > 0 && isFilterSpace(s[j-1]) {
		j--
	}
	if j == 0 {
		return false
	}
	return isFilterOp(string(s[j-1]))
}

// valueLooksComplete 判断一个词看起来是不是"已经填完的值"。
//
// IP、端口、布尔这类值敲完就没必要再提示了；而 1.2.3 这种敲到一半的
// 仍该继续给类型提示。
func valueLooksComplete(word string) bool {
	if word == "" {
		return false
	}
	if _, err := strconv.ParseInt(word, 10, 64); err == nil {
		// 端口/IP 常常还在敲（如 "4" 可能是 443 的一部分），
		// 太短的数字先当作未完成，继续给类型提示更友好
		return len(word) >= 2
	}
	if strings.Contains(word, ".") && strings.Count(word, ".") >= 2 {
		// IPv4：段数够就是完整的（如 10.0.0.1）
		return true
	}
	if strings.Contains(word, ":") {
		return true // IPv6 敲到有冒号基本可判为完整
	}
	return false
}

// isFilterOp 判断单个字符是否是运算符字符。
func isFilterOp(s string) bool {
	switch s {
	case "=", "!", ">", "<", "&", "|":
		return true
	}
	return false
}

// isFilterOp2 判断是否是双字符运算符。
func isFilterOp2(s string) bool {
	switch s {
	case "&&", "||", "==", "!=", ">=", "<=":
		return true
	}
	return false
}

// splitFilterWords 把已完成的表达式切成词（运算符单列）。
func splitFilterWords(s string) []string {
	var out []string
	cur := strings.Builder{}
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isFieldWord(c) {
			cur.WriteByte(c)
			continue
		}
		flush()
		if i+1 < len(s) && isFilterOp2(s[i:i+2]) {
			out = append(out, s[i:i+2])
			i++
			continue
		}
		if isFilterOp(s[i : i+1]) {
			out = append(out, s[i:i+1])
		}
	}
	flush()
	return out
}

// fieldBeforeOp 返回"当前正在填值的那个比较运算符"前面的字段名。
//
// 起点 i 是有效内容的右边界（可能已经跟了值，如 "tcp.port == 4"）。
// 所以不能从 i 往前找运算符——那会先撞上值。要先回退到运算符右端，
// 再从运算符往前找字段名。
func fieldBeforeOp(s string, i int) (namedField, bool) {
	// 1) 定位运算符的右边界：跳过值（含引号字符串）与空白
	j := i
	// 跳过成对的引号字符串
	for j > 0 && isFilterSpace(s[j-1]) {
		j--
	}
	// 若运算符与值之间有空格，先吃掉这段"值"
	vs := j
	for vs > 0 && isFieldWord(s[vs-1]) {
		vs--
	}
	// 只有当 vs..j 是一段像值的东西、且再往前是空白+运算符时才跳到运算符
	if vs < j {
		k := vs
		for k > 0 && isFilterSpace(s[k-1]) {
			k--
		}
		if k > 0 && isFilterOp(string(s[k-1])) {
			j = k
		}
	} else {
		// 没有值：j 就在运算符右端（可能前面有空格）
		for j > 0 && isFilterSpace(s[j-1]) {
			j--
		}
	}

	// 2) 往前吃掉运算符本身
	k := j
	for k > 0 && isFilterOp(string(s[k-1])) {
		k--
	}
	if k == j {
		return namedField{}, false // 前面不是运算符
	}
	// 逻辑运算符（&& ||）不是比较运算符，后面不会有值
	if op := s[k:j]; op == "&&" || op == "||" || op == "&" || op == "|" {
		return namedField{}, false
	}

	// 3) 跳过运算符与字段名之间的空白，再取字段名
	m := k
	for m > 0 && isFilterSpace(s[m-1]) {
		m--
	}
	end := m
	for end > 0 && isFieldWord(s[end-1]) {
		end--
	}
	name := strings.ToLower(strings.TrimSpace(s[end:m]))
	if name == "" {
		return namedField{}, false
	}
	sp, ok := fieldTable[name]
	if !ok {
		return namedField{}, false
	}
	return namedField{name, sp}, true
}

// filterSuggest 返回当前阶段的实时提示（可直接显示的一行）。
func (t *tui) filterSuggest() string {
	ctx := analyzeFilterInput(string(t.input))
	switch ctx.stage {
	case stageNone:
		return i18n.T("net.tui.sug_none")

	case stageField:
		cands := matchFields(ctx.word, 6)
		if len(cands) == 0 {
			return i18n.Tf("net.tui.sug_no_field", ctx.word)
		}
		head := i18n.T("net.tui.sug_field")
		if ctx.word != "" {
			head = i18n.Tf("net.tui.sug_field_prefix", ctx.word)
		}
		return head + " " + strings.Join(cands, "  ") +
			i18n.T("net.tui.sug_tab")

	case stageOperator:
		return i18n.Tf("net.tui.sug_operator", ctx.field,
			strings.Join(fieldOps(ctx.spec.kind), " "))

	case stageValue:
		if ctx.field == "" {
			return i18n.T("net.tui.sug_value_generic")
		}
		return fieldValueHint(ctx.field, ctx.spec)

	case stageLogic:
		return i18n.T("net.tui.sug_logic")
	}
	return ""
}

// matchFields 按前缀匹配字段名，返回前 n 个。
func matchFields(prefix string, n int) []string {
	prefix = strings.ToLower(prefix)
	var out []string
	for _, name := range fieldNames() {
		if strings.HasPrefix(name, prefix) {
			out = append(out, name)
			if len(out) >= n {
				break
			}
		}
	}
	return out
}

// fieldOps 返回该类型字段可用的运算符。
func fieldOps(k valKind) []string {
	ops := []string{"==", "!="}
	if k == valInt || k == valFloat {
		ops = append(ops, ">", "<", ">=", "<=")
	}
	if k == valStr || k == valMAC {
		ops = append(ops, "contains")
	}
	return ops
}

// fieldValueHint 给出某字段该填什么值的提示。
func fieldValueHint(name string, spec fieldSpec) string {
	switch spec.kind {
	case valIP:
		return i18n.Tf("net.tui.sug_val_ip", name, name)
	case valInt:
		return i18n.Tf("net.tui.sug_val_int", name, name, name)
	case valStr, valMAC:
		return i18n.Tf("net.tui.sug_val_str", name, name)
	case valBool:
		return i18n.Tf("net.tui.sug_val_bool", name, name, name)
	case valFloat:
		return i18n.Tf("net.tui.sug_val_float", name, name)
	}
	return ""
}
