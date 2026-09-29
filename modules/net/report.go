// 报告渲染：把统计结果按段落输出到 writer。
//
// 所有面向用户的标题、列名与句子都走 i18n；协议名、服务名等技术标识保持原样。
package net

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"gyhost/internal/i18n"
	"gyhost/internal/pcap"
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

// pctStr 渲染百分比（total 为 0 时返回 "0.0%"）。
func pctStr(part, total int) string {
	if total <= 0 {
		return "0.0%"
	}
	return fmt.Sprintf("%.1f%%", float64(part)*100/float64(total))
}

// formatDesc 渲染容器描述，如 "pcap, 小端, 微秒时间戳, v2.4, snaplen 65535"。
func formatDesc(info pcap.Info) string {
	parts := []string{info.Format.String()}
	if info.BigEndian {
		parts = append(parts, i18n.T("net.endian.be"))
	} else {
		parts = append(parts, i18n.T("net.endian.le"))
	}
	parts = append(parts, tsResolName(info.TsResol))
	if info.Version != "" {
		parts = append(parts, "v"+info.Version)
	}
	if info.Format == pcap.FormatPCAPNG {
		parts = append(parts, i18n.Tf("net.format.ifaces", info.Interfaces))
	}
	if info.SnapLen > 0 {
		parts = append(parts, fmt.Sprintf("snaplen %d", info.SnapLen))
	}
	return strings.Join(parts, ", ")
}

// tsResolName 把时间戳分母渲染成"微秒时间戳"这类描述。
func tsResolName(resol uint64) string {
	switch resol {
	case 1:
		return i18n.T("net.ts.sec")
	case 1e3:
		return i18n.T("net.ts.msec")
	case 1e6:
		return i18n.T("net.ts.usec")
	case 1e9:
		return i18n.T("net.ts.nsec")
	}
	if resol == 0 {
		resol = 1e6
	}
	return fmt.Sprintf("%d/s", resol)
}

// section 打印一个段落标题。
func section(w io.Writer, key string, a ...interface{}) {
	utils.Titlef(w, "  ==== %s ====", i18n.Tf(key, a...))
}

// field 打印概览里的一行 "标签  内容"。
func field(w io.Writer, key, value string) {
	label := utils.PadRight(i18n.T(key), 12)
	fmt.Fprintf(w, "    %s %s\n", utils.Dim("%s", label), value)
}

// padLeft 按可见宽度左填充（数字列右对齐用）。
func padLeft(s string, width int) string {
	if d := width - utils.VisibleLen(s); d > 0 {
		return strings.Repeat(" ", d) + s
	}
	return s
}

// writeTable 打印一个简单表格；right[i] 为 true 表示第 i 列右对齐。
// indent 为每行的前缀缩进（空串表示顶格）。
func writeTable(w io.Writer, headers []string, right []bool, rows [][]string, indent string) {
	if len(rows) == 0 {
		return
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = utils.VisibleLen(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(widths) {
				if n := utils.VisibleLen(c); n > widths[i] {
					widths[i] = n
				}
			}
		}
	}
	render := func(cells []string) string {
		var b strings.Builder
		for i, c := range cells {
			if i > 0 {
				b.WriteString("  ")
			}
			if i < len(right) && right[i] {
				b.WriteString(padLeft(c, widths[i]))
			} else {
				b.WriteString(utils.PadRight(c, widths[i]))
			}
		}
		return strings.TrimRight(b.String(), " ")
	}
	utils.Stylef(w, utils.StyleBold, "%s", indent+render(headers))
	for _, r := range rows {
		utils.Plainf(w, "%s", indent+render(r))
	}
}

// ---------------------------------------------------------------------------
// 排序
// ---------------------------------------------------------------------------

// nameCount 是"名字 → 计数"的排序结果。
type nameCount struct {
	name    string
	packets int
	bytes   int64
}

// sortedCounters 把协议计数按包数降序（再按字节、名字）排好。
func sortedCounters(m map[string]*counter) []nameCount {
	out := make([]nameCount, 0, len(m))
	for k, c := range m {
		out = append(out, nameCount{name: k, packets: c.packets, bytes: c.bytes})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].packets != out[j].packets {
			return out[i].packets > out[j].packets
		}
		if out[i].bytes != out[j].bytes {
			return out[i].bytes > out[j].bytes
		}
		return out[i].name < out[j].name
	})
	return out
}

// nameNum 是"名字 → 次数"的排序结果。
type nameNum struct {
	name string
	n    int
}

// sortedNums 把计数表按次数降序（再按名字）排好。
func sortedNums(m map[string]int) []nameNum {
	out := make([]nameNum, 0, len(m))
	for k, n := range m {
		out = append(out, nameNum{name: k, n: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].name < out[j].name
	})
	return out
}

// cutTop 截取前 top 条（top<=0 表示不截断）。
func cutTop(n, top int) int {
	if top > 0 && n > top {
		return top
	}
	return n
}

// sortedFlows 会话按字节降序。
func sortedFlows(m map[string]*flow) []*flow {
	out := make([]*flow, 0, len(m))
	for _, f := range m {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].bytes != out[j].bytes {
			return out[i].bytes > out[j].bytes
		}
		if out[i].packets != out[j].packets {
			return out[i].packets > out[j].packets
		}
		return out[i].a+out[i].b < out[j].a+out[j].b
	})
	return out
}

// sortedEndpoints 端点按字节降序。
func sortedEndpoints(m map[string]*endpoint) []nameCount {
	out := make([]nameCount, 0, len(m))
	for k, e := range m {
		out = append(out, nameCount{name: k, packets: e.sent + e.recv, bytes: e.bytes})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].bytes != out[j].bytes {
			return out[i].bytes > out[j].bytes
		}
		if out[i].packets != out[j].packets {
			return out[i].packets > out[j].packets
		}
		return out[i].name < out[j].name
	})
	return out
}

// sortedPorts 端口按包数降序。
func sortedPorts(m map[uint16]*portStat) []struct {
	port uint16
	st   *portStat
} {
	out := make([]struct {
		port uint16
		st   *portStat
	}, 0, len(m))
	for p, st := range m {
		out = append(out, struct {
			port uint16
			st   *portStat
		}{p, st})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].st.packets != out[j].st.packets {
			return out[i].st.packets > out[j].st.packets
		}
		if out[i].st.bytes != out[j].st.bytes {
			return out[i].st.bytes > out[j].st.bytes
		}
		return out[i].port < out[j].port
	})
	return out
}

// ---------------------------------------------------------------------------
// 报告
// ---------------------------------------------------------------------------

// writeReport 输出一个抓包的完整分析报告。
// writeReport 输出统计报告。secs 非空时只输出被选中的章节（-z）。
func writeReport(w io.Writer, res *captureResult, flt *filter, top int, secs []string) {
	a := res.a

	// ---- 概览 ----
	if len(secs) == 0 || wantSec(secs, secIO) {
		utils.Successf(w, "[+] %s", res.path)
		field(w, "net.label.format", formatDesc(res.info))
		field(w, "net.label.linktype", linkDesc(a))
		if flt != nil {
			field(w, "net.label.filter", flt.String())
		}
		packets := fmt.Sprintf("%d", a.total)
		if flt != nil && a.matched != a.total {
			packets = i18n.Tf("net.packets.filtered", a.total, a.matched)
		}
		field(w, "net.label.packets", packets)
		if a.matched > 0 {
			field(w, "net.label.time", i18n.Tf("net.time.desc",
				a.first.Format("2006-01-02 15:04:05.000"),
				a.last.Format("2006-01-02 15:04:05.000"),
				a.last.Sub(a.first).Round(time.Microsecond).String()))
			field(w, "net.label.bytes", i18n.Tf("net.bytes.desc",
				humanBytes(a.capBytes), humanBytes(a.wireBytes)))
		}
		for _, lt := range sortedWarnLinks(a) {
			utils.Warnf(w, "    [!] %s", i18n.Tf("net.warn.unsupported_link", lt, a.linkWarn[lt]))
		}
	}

	if a.matched == 0 {
		utils.Warnf(w, "    [!] %s", i18n.T("net.report.no_match"))
		return
	}

	// 各章节按 wantSec 过滤：-z 未指定时全部输出
	if len(secs) == 0 || wantSec(secs, secTimeline) {
		writeTimelineSection(w, a, top)
	}
	if a.atk != nil && (len(secs) == 0 || wantSec(secs, secAttack)) {
		writeAttackSection(w, a)
	}
	if len(secs) == 0 || wantSec(secs, secProto) {
		writeProtoSection(w, a, top)
	}
	if len(secs) == 0 || wantSec(secs, secConv) {
		writeFlowSection(w, a, top)
	}
	if len(secs) == 0 || wantSec(secs, secEndpoint) {
		writeEndpointSection(w, a, top)
	}
	if len(secs) == 0 || wantSec(secs, secPort) {
		writePortSection(w, a, top)
	}
	if len(secs) == 0 || wantSec(secs, secDNS) {
		writeDNSSection(w, a, top)
	}
	if len(secs) == 0 || wantSec(secs, secSNI) {
		writeSNISection(w, a, top)
	}
	if len(secs) == 0 || wantSec(secs, secHTTP) {
		writeHTTPSection(w, a, top)
	}
	if len(secs) == 0 || wantSec(secs, secFindings) {
		writeFindings(w, a)
	}
}

// writeAttackSection 攻击分析：启用的模型、逐模型判定与命中详情。
//
// 判定列是"命中/疑似/未命中"，关键指标列写当次抓包的原始计数与峰值速率，
// 具体迹象以 [!] 行附在表格后面（阈值见 attack.go 顶部常量）。
func writeAttackSection(w io.Writer, a *analysis) {
	s := a.atk
	if s == nil {
		return
	}
	section(w, "net.section.attack")
	field(w, "net.label.models", strings.Join(modelKeys(s.models), ", "))
	field(w, "net.label.peak", fmt.Sprintf("%d/s", s.peakPkt))

	var alarms []string
	rows := make([][]string, 0, len(modelOrder))
	for _, r := range s.evaluate() {
		rows = append(rows, []string{
			i18n.T("net.model." + r.model), verdictText(r.level), r.metrics,
		})
		alarms = append(alarms, r.alarms...)
	}
	writeTable(w,
		[]string{i18n.T("net.head.model"), i18n.T("net.head.verdict"),
			i18n.T("net.head.metrics")},
		[]bool{false, false, false},
		rows, "")
	for _, al := range alarms {
		utils.Warnf(w, "    [!] %s", al)
	}
	if s.capped {
		utils.Warnf(w, "    [!] %s", i18n.Tf("net.attack.capped", maxTrackKeys))
	}
}

// verdictText 把判定级别渲染成已国际化的文案。
func verdictText(level int) string {
	switch level {
	case levelHit:
		return i18n.T("net.verdict.hit")
	case levelSuspect:
		return i18n.T("net.verdict.suspect")
	}
	return i18n.T("net.verdict.miss")
}

// linkDesc 汇总出现过的链路层类型（含被过滤掉的帧，概览里始终可见）。
func linkDesc(a *analysis) string {
	names := make([]string, 0, len(a.linkAll))
	for n := range a.linkAll {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// sortedWarnLinks 把不支持的链路类型按编号排序。
func sortedWarnLinks(a *analysis) []uint32 {
	out := make([]uint32, 0, len(a.linkWarn))
	for lt := range a.linkWarn {
		out = append(out, lt)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// writeProtoSection 协议分布（链路/网络/传输/应用四层，一列层级）。
func writeProtoSection(w io.Writer, a *analysis, top int) {
	section(w, "net.section.protocols")
	layers := []struct {
		label string
		m     map[string]*counter
	}{
		{i18n.T("net.layer.l2"), a.links},
		{i18n.T("net.layer.l3"), a.l3s},
		{i18n.T("net.layer.l4"), a.l4s},
		{i18n.T("net.layer.l7"), a.apps},
	}
	var rows [][]string
	for _, l := range layers {
		cs := sortedCounters(l.m)
		cs = cs[:cutTop(len(cs), top)]
		for i, c := range cs {
			label := ""
			if i == 0 {
				label = l.label
			}
			rows = append(rows, []string{
				label, c.name, strconv.Itoa(c.packets),
				pctStr(c.packets, a.matched), humanBytes(c.bytes),
			})
		}
	}
	writeTable(w,
		[]string{i18n.T("net.head.layer"), i18n.T("net.head.proto"),
			i18n.T("net.head.packets"), i18n.T("net.head.percent"), i18n.T("net.head.bytes")},
		[]bool{false, false, true, true, true},
		rows, "")
}

// writeFlowSection 会话 TOP N。
func writeFlowSection(w io.Writer, a *analysis, top int) {
	if len(a.flows) == 0 {
		return
	}
	section(w, "net.section.flows", top)
	fs := sortedFlows(a.flows)
	fs = fs[:cutTop(len(fs), top)]
	rows := make([][]string, 0, len(fs))
	for i, f := range fs {
		rows = append(rows, []string{
			strconv.Itoa(i + 1), f.proto, f.a + " <-> " + f.b,
			strconv.Itoa(f.packets), humanBytes(f.bytes),
		})
	}
	writeTable(w,
		[]string{i18n.T("net.head.rank"), i18n.T("net.head.proto"),
			i18n.T("net.head.flow"), i18n.T("net.head.packets"), i18n.T("net.head.bytes")},
		[]bool{true, false, false, true, true},
		rows, "")
}

// writeEndpointSection 主机 TOP N（收发包与字节）。
func writeEndpointSection(w io.Writer, a *analysis, top int) {
	if len(a.endpoints) == 0 {
		return
	}
	section(w, "net.section.endpoints", top)
	es := sortedEndpoints(a.endpoints)
	es = es[:cutTop(len(es), top)]
	rows := make([][]string, 0, len(es))
	for i, e := range es {
		ep := a.endpoints[e.name]
		rows = append(rows, []string{
			strconv.Itoa(i + 1), e.name,
			strconv.Itoa(ep.sent), strconv.Itoa(ep.recv), humanBytes(e.bytes),
		})
	}
	writeTable(w,
		[]string{i18n.T("net.head.rank"), i18n.T("net.head.host"),
			i18n.T("net.head.sent"), i18n.T("net.head.recv"), i18n.T("net.head.bytes")},
		[]bool{true, false, true, true, true},
		rows, "")
}

// writePortSection 服务端口 TOP N。
func writePortSection(w io.Writer, a *analysis, top int) {
	if len(a.ports) == 0 {
		return
	}
	section(w, "net.section.ports", top)
	ps := sortedPorts(a.ports)
	ps = ps[:cutTop(len(ps), top)]
	rows := make([][]string, 0, len(ps))
	for i, p := range ps {
		service, ok := portService[p.port]
		if !ok {
			service = i18n.T("net.service.unknown")
		}
		rows = append(rows, []string{
			strconv.Itoa(i + 1), p.st.proto, strconv.Itoa(int(p.port)), service,
			strconv.Itoa(p.st.packets), humanBytes(p.st.bytes),
		})
	}
	writeTable(w,
		[]string{i18n.T("net.head.rank"), i18n.T("net.head.proto"),
			i18n.T("net.head.port"), i18n.T("net.head.service"),
			i18n.T("net.head.packets"), i18n.T("net.head.bytes")},
		[]bool{true, false, true, false, true, true},
		rows, "")
}

// writeDNSSection DNS 查询统计。
func writeDNSSection(w io.Writer, a *analysis, top int) {
	if a.dnsTotal == 0 && a.dnsFailed == 0 {
		return
	}
	section(w, "net.section.dns")
	utils.Plainf(w, "    %s", i18n.Tf("net.dns.summary",
		a.dnsTotal, len(a.dnsQueries), a.dnsFailed))
	qs := sortedNums(a.dnsQueries)
	qs = qs[:cutTop(len(qs), top)]
	rows := make([][]string, 0, len(qs))
	for i, q := range qs {
		rows = append(rows, []string{strconv.Itoa(i + 1), q.name, strconv.Itoa(q.n)})
	}
	writeTable(w,
		[]string{i18n.T("net.head.rank"), i18n.T("net.head.name"), i18n.T("net.head.count")},
		[]bool{true, false, true},
		rows, "")
}

// writeSNISection TLS ClientHello 里的 SNI 域名统计。
func writeSNISection(w io.Writer, a *analysis, top int) {
	if len(a.sni) == 0 {
		return
	}
	section(w, "net.section.sni")
	ss := sortedNums(a.sni)
	ss = ss[:cutTop(len(ss), top)]
	rows := make([][]string, 0, len(ss))
	for i, s := range ss {
		rows = append(rows, []string{strconv.Itoa(i + 1), s.name, strconv.Itoa(s.n)})
	}
	writeTable(w,
		[]string{i18n.T("net.head.rank"), i18n.T("net.head.name"), i18n.T("net.head.count")},
		[]bool{true, false, true},
		rows, "")
}

// writeHTTPSection 明文 HTTP 的请求量、主机与 URI 统计。
func writeHTTPSection(w io.Writer, a *analysis, top int) {
	if a.httpReq == 0 {
		return
	}
	section(w, "net.section.http")
	utils.Plainf(w, "    %s", i18n.Tf("net.http.summary", a.httpReq))

	if len(a.httpHosts) > 0 {
		utils.Plainf(w, "    %s", utils.Bold("%s", i18n.T("net.subsection.hosts")))
		hs := sortedNums(a.httpHosts)
		hs = hs[:cutTop(len(hs), top)]
		rows := make([][]string, 0, len(hs))
		for i, h := range hs {
			rows = append(rows, []string{strconv.Itoa(i + 1), h.name, strconv.Itoa(h.n)})
		}
		writeTable(w,
			[]string{i18n.T("net.head.rank"), i18n.T("net.head.host"), i18n.T("net.head.count")},
			[]bool{true, false, true},
			rows, "")
	}
	if len(a.httpURIs) > 0 {
		utils.Plainf(w, "    %s", utils.Bold("%s", i18n.T("net.subsection.uris")))
		us := sortedNums(a.httpURIs)
		us = us[:cutTop(len(us), top)]
		rows := make([][]string, 0, len(us))
		for i, u := range us {
			rows = append(rows, []string{strconv.Itoa(i + 1), u.name, strconv.Itoa(u.n)})
		}
		writeTable(w,
			[]string{i18n.T("net.head.rank"), i18n.T("net.head.uri"), i18n.T("net.head.count")},
			[]bool{true, false, true},
			rows, "")
	}
}

// writeFindings 安全发现（没有发现时也给一句明确的结论）。
//
// 凭据类发现是"一行一条"；条目较多的发现（明文端口、ARP 冲突）渲染成
// 标题 + 缩进明细表，避免几十个条目挤在一行里没法看。
func writeFindings(w io.Writer, a *analysis) {
	section(w, "net.section.findings")
	fs := a.findings()
	if len(fs) == 0 {
		utils.Plainf(w, "    %s", utils.Dim("%s", i18n.T("net.find.none")))
		return
	}
	for _, f := range fs {
		if f.table == nil {
			utils.Warnf(w, "    [!] %s", i18n.Tf("net.find."+f.kind, f.detail))
			continue
		}
		// 表格形态的发现：标题不带 %s，明细另起缩进表格
		utils.Warnf(w, "    [!] %s", i18n.T("net.find."+f.kind))
		writeTable(w, f.table.headers, f.table.right, f.table.rows, "      ")
	}
}

// ---------------------------------------------------------------------------
// 逐包列表
// ---------------------------------------------------------------------------

// 列表各列的固定宽度（端点、协议列超出时截断）。
const (
	listWidthIdx   = 6
	listWidthTime  = 12
	listWidthEP    = 46
	listWidthProto = 12
	listWidthLen   = 6
)

// writeListHeader 打印列表模式的文件信息与列头。
// verbose（-V）模式逐包输出协议树，不需要列表列头，只留文件信息。
func writeListHeader(w io.Writer, path string, info pcap.Info, flt *filter, verbose bool) {
	utils.Successf(w, "[+] %s", path)
	field(w, "net.label.format", formatDesc(info))
	if flt != nil {
		field(w, "net.label.filter", flt.String())
	}
	if verbose {
		return
	}
	h := padLeft(i18n.T("net.head.idx"), listWidthIdx) + " " +
		padLeft(i18n.T("net.head.time"), listWidthTime) + "  " +
		utils.PadRight(i18n.T("net.head.endpoints"), listWidthEP) + "  " +
		utils.PadRight(i18n.T("net.head.proto"), listWidthProto) + " " +
		padLeft(i18n.T("net.head.len"), listWidthLen) + "  " +
		i18n.T("net.head.info")
	utils.Stylef(w, utils.StyleBold, "%s", h)
}

// writePacketRow 打印列表模式的一行：序号、相对首包的时间、端点、协议、长度与摘要。
func writePacketRow(w io.Writer, p *pkt, t0 time.Time) {
	src, dst := p.addrPair()
	ep := endpointAddr(src, p.srcPort)
	if dst != "" {
		ep += " <-> " + endpointAddr(dst, p.dstPort)
	}
	proto := p.app
	if proto == "" {
		proto = p.l4
	}
	if proto == "" {
		proto = p.l3
	}
	if proto == "" {
		proto = p.link
	}
	fmt.Fprintf(w, "%6d %12.6f  %s  %s %6d  %s\n",
		p.no, p.ts.Sub(t0).Seconds(),
		utils.PadRight(utils.TruncateVisible(ep, listWidthEP), listWidthEP),
		utils.PadRight(utils.TruncateVisible(proto, listWidthProto), listWidthProto),
		p.wireLen, p.info)
}
