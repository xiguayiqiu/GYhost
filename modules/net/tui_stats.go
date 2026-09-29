// TUI 统计面板：按当前过滤结果汇总协议、端点与会话分布。
//
// 报告模式（-l / 无参数）已经把这些统计写在报告末尾；这里把它们做成可滚动
// 的面板，让用户在浏览包的同时随时对照整体分布。
//
// 统计只对"当前可见的包"生效，所以改变过滤后面板要重算——用 filterGen
// 记录过滤版本号，避免每次渲染都重扫文件。
package net

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gyhost/internal/i18n"
	"gyhost/internal/utils"
)

// statRow 是统计面板里的一行（名称 + 包数 + 字节数）。
type statRow struct {
	name    string
	packets int
	bytes   int64
}

// tuiStats 是统计面板的数据快照。
type tuiStats struct {
	protos    []statRow
	endpoints []statRow
	convs     []statRow
	packets   int
	bytes     int64
}

// ensureStats 按需计算统计（过滤变化后失效，下次渲染时重算）。
//
// 大抓包扫一遍要几百毫秒，所以只在统计面板真的可见时才做。
func (t *tui) ensureStats() {
	if !t.showStats {
		return
	}
	// stats 为 nil 说明还没算过；filterGen 变了说明过滤改过，两者都要重算。
	// （不能只比 statsFor/filterGen：两者初值都是 0，会被误判成"已算过"）
	if t.stats != nil && t.statsFor == t.filterGen {
		return
	}
	t.stats = t.computeStats()
	t.statsFor = t.filterGen
	t.statTop = 0
}

// computeStats 扫一遍当前可见的帧，汇总协议、端点与会话分布。
func (t *tui) computeStats() *tuiStats {
	s := &tuiStats{}
	protos := map[string]*counter{}
	eps := map[string]*endpoint{}
	convs := map[string]*counter{}

	// 统计只需要摘要字段，跳过 verbose 填充
	for _, idx := range t.view {
		p, err := t.frame(int(idx), false)
		if err != nil {
			continue
		}
		c, ok := protos[tuiProto(p)]
		if !ok {
			c = &counter{}
			protos[tuiProto(p)] = c
		}
		c.add(p)
		s.packets++
		s.bytes += int64(p.wireLen)

		src, dst := p.addrPair()
		for addr, sent := range map[string]bool{src: true, dst: false} {
			if addr == "" {
				continue
			}
			e, ok := eps[addr]
			if !ok {
				e = &endpoint{}
				eps[addr] = e
			}
			if sent {
				e.sent++
			} else {
				e.recv++
			}
			e.bytes += int64(p.wireLen)
		}
		if k := conversationKey(p, src, dst); k != "" {
			c, ok := convs[k]
			if !ok {
				c = &counter{}
				convs[k] = c
			}
			c.add(p)
		}
	}

	s.protos = sortedStatRows(protos)
	s.endpoints = sortedEndpointRows(eps)
	s.convs = sortedConvRows(convs)
	return s
}

// conversationKey 生成会话键：同一对端点（不分方向）归为一条会话。
func conversationKey(p *pkt, src, dst string) string {
	if src == "" || dst == "" {
		return ""
	}
	a, b := src, dst
	if a > b {
		a, b = b, a
	}
	proto := p.l4
	if proto == "" {
		proto = p.l3
	}
	if proto == "" {
		return ""
	}
	return proto + " " + a + " \u2194 " + b
}

// sortedStatRows 把协议计数按包数降序排列。
func sortedStatRows(m map[string]*counter) []statRow {
	out := make([]statRow, 0, len(m))
	for k, v := range m {
		out = append(out, statRow{name: k, packets: v.packets, bytes: v.bytes})
	}
	sortStatRows(out)
	return out
}

// sortedEndpointRows 把端点按收发总量降序排列。
func sortedEndpointRows(m map[string]*endpoint) []statRow {
	out := make([]statRow, 0, len(m))
	for k, v := range m {
		out = append(out, statRow{name: k, packets: v.sent + v.recv, bytes: v.bytes})
	}
	sortStatRows(out)
	return out
}

// sortedConvRows 把会话按包数降序排列。
func sortedConvRows(m map[string]*counter) []statRow { return sortedStatRows(m) }

// sortStatRows 就地按包数降序、名称升序排序（保证输出稳定可测）。
func sortStatRows(rows []statRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].packets != rows[j].packets {
			return rows[i].packets > rows[j].packets
		}
		return rows[i].name < rows[j].name
	})
}

// statLines 渲染统计面板的内容行。
func (t *tui) statLines(rows int) []string {
	t.ensureStats()
	if t.stats == nil {
		return append([]string{t.style.dim.Sprintf(" %s", i18n.T("net.tui.stat_calculating"))},
			blankLines(rows-1)...)
	}
	// 前导 1 空格 + 名称 + 1 空格 + 包数 + 1 空格 + 字节 + 2 空格 + 占比
	wPkt, wByte, wPct := 9, 11, 6
	wName := t.w - (wPkt + wByte + wPct + 5)
	if wName < 12 {
		wName = 12
	}
	// 表头与数据行共用同一套版式（见 statRowText），否则列头会与数字错位。
	// 右对齐必须用按可见宽度的辅助函数：fmt 的 %*s 按字符数补空格，
	// 而中文表头是双宽字符，补出来的列头仍然对不齐。
	hdr := fmt.Sprintf(" %s %s %s %s",
		utils.PadRight(i18n.T("net.tui.name"), wName-1),
		padLeftVisible(i18n.T("net.tui.packets"), wPkt),
		padLeftVisible(i18n.T("net.tui.bytes"), wByte),
		padLeftVisible(i18n.T("net.tui.percent"), wPct))
	out := []string{t.style.colKey.Sprint(utils.TruncateVisible(hdr, t.w))}

	var body []string
	body = append(body, t.statSection(i18n.T("net.tui.stat_proto"), t.stats.protos, wName, wPkt, wByte, wPct)...)
	body = append(body, t.statSection(i18n.T("net.tui.stat_endpoint"), t.stats.endpoints, wName, wPkt, wByte, wPct)...)
	body = append(body, t.statSection(i18n.T("net.tui.stat_convers"), t.stats.convs, wName, wPkt, wByte, wPct)...)
	if len(body) == 0 {
		body = append(body, t.style.dim.Sprintf(" %s", i18n.T("net.tui.stat_none")))
	}

	// 视口滚动
	if t.statTop > len(body)-1 {
		t.statTop = max(len(body)-1, 0)
	}
	if t.statTop < 0 {
		t.statTop = 0
	}
	for i := t.statTop; i < len(body) && len(out) < rows; i++ {
		out = append(out, utils.TruncateVisible(body[i], t.w))
	}
	return append(out, blankLines(rows-len(out))...)
}

// statSection 渲染一个统计小节（标题 + 数据行）。
func (t *tui) statSection(title string, rows []statRow, wName, wPkt, wByte, wPct int) []string {
	if len(rows) == 0 {
		return nil
	}
	out := []string{t.style.title.Sprint(" " + title)}
	total := t.stats.packets
	for _, r := range rows {
		out = append(out, statRowText(r, wName, wPkt, wByte, wPct, total))
	}
	return out
}

// statRowText 渲染统计面板的一行数据。
//
// 单独抽出来是为了让表头与数据行用同一套版式计算宽度——两者一旦各算各的，
// 中文表头（双宽）与数字列就会错位。
func statRowText(r statRow, wName, wPkt, wByte, wPct, total int) string {
	return fmt.Sprintf(" %s %s %s %s",
		utils.PadRight(utils.TruncateVisible(r.name, wName-1), wName-1),
		padLeftVisible(strconv.Itoa(r.packets), wPkt),
		padLeftVisible(humanBytes(r.bytes), wByte),
		padLeftVisible(pctStr(r.packets, total), wPct))
}

// padLeftVisible 按可见宽度左填充（中文等双宽字符也能对齐）。
func padLeftVisible(s string, width int) string {
	if d := width - utils.VisibleLen(s); d > 0 {
		return strings.Repeat(" ", d) + s
	}
	return s
}

// scrollStats 滚动统计面板。
func (t *tui) scrollStats(d int) {
	t.statTop += d
	if t.statTop < 0 {
		t.statTop = 0
	}
}

// statHint 返回统计面板的汇总提示（状态栏用）。
func (t *tui) statHint() string {
	if t.stats == nil {
		return ""
	}
	return i18n.Tf("net.tui.stat_summary", t.stats.packets, humanBytes(t.stats.bytes))
}
