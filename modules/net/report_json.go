// JSON 报告（-j）：把统计结果输出成结构化数据。
//
// 这是"纯 CLI 做复杂分析"的关键一环：人读报告适合看，但没法参与计算。
// 有了 JSON，`jq` 就能任意切片、排序、聚合，也能喂给脚本或别的工具，
// 而不用去正则解析对齐的表格文本。
//
// 结构刻意保持扁平稳定：字段名用英文（技术标识），枚举值用小写，
// 便于跨版本脚本引用。
package net

import (
	"encoding/json"
	"io"
	"sort"
	"time"

	"gyhost/internal/i18n"
)

// jsonReport 是整份 JSON 报告的顶层结构。
type jsonReport struct {
	Path      string          `json:"path"`
	Format    string          `json:"format"`
	LinkType  string          `json:"link_type"`
	Filter    string          `json:"filter,omitempty"`
	Packets   int             `json:"packets_total"`
	Matched   int             `json:"packets_matched"`
	First     string          `json:"first,omitempty"`
	Last      string          `json:"last,omitempty"`
	Duration  float64         `json:"duration_seconds,omitempty"`
	CapBytes  int64           `json:"bytes_captured"`
	WireBytes int64           `json:"bytes_wire"`
	Overview  jsonOverview    `json:"overview"`
	Protocols []jsonCountRow  `json:"protocols,omitempty"`
	Convs     []jsonConvRow   `json:"conversations,omitempty"`
	Endpoints []jsonCountRow  `json:"endpoints,omitempty"`
	Ports     []jsonPortRow   `json:"ports,omitempty"`
	DNS       jsonDNS         `json:"dns"`
	TLS       []string        `json:"tls_sni,omitempty"`
	HTTP      jsonHTTP        `json:"http"`
	Findings  []jsonFinding   `json:"findings,omitempty"`
	Attack    *jsonAttack     `json:"attack,omitempty"`
	Streams   []jsonStreamRow `json:"streams,omitempty"`
	Timeline  *jsonTimeline   `json:"timeline,omitempty"`
}

// jsonTimeline 是流量时间线（-z timeline）。
type jsonTimeline struct {
	IntervalSeconds float64        `json:"interval_seconds"`
	SpanSeconds     float64        `json:"span_seconds"`
	AvgPackets      float64        `json:"avg_packets_per_second"`
	PeakSecond      float64        `json:"peak_second"`
	PeakPackets     int            `json:"peak_packets"`
	PeakBytes       int64          `json:"peak_bytes"`
	PeakPeer        string         `json:"peak_peer,omitempty"`
	Truncated       bool           `json:"truncated"`
	Buckets         []jsonTLBucket `json:"buckets"`
}

// jsonTLBucket 是一个时间桶。
type jsonTLBucket struct {
	Second  float64        `json:"second"`
	Packets int            `json:"packets"`
	Bytes   int64          `json:"bytes"`
	Protos  map[string]int `json:"protocols,omitempty"`
	TopPeer string         `json:"top_peer,omitempty"`
}

// jsonOverview 是协议层级总览。
type jsonOverview struct {
	Link  []jsonCountRow `json:"link,omitempty"`
	Net   []jsonCountRow `json:"network,omitempty"`
	Trans []jsonCountRow `json:"transport,omitempty"`
	App   []jsonCountRow `json:"application,omitempty"`
}

// jsonCountRow 是"名称 + 包数 + 字节"这一类通用行。
type jsonCountRow struct {
	Name    string  `json:"name"`
	Packets int     `json:"packets"`
	Bytes   int64   `json:"bytes"`
	Share   float64 `json:"share"` // 占总包数比例（0~1）
}

// jsonConvRow 是一条会话。
type jsonConvRow struct {
	Proto      string  `json:"proto"`
	EndpointA  string  `json:"a"`
	EndpointB  string  `json:"b"`
	Packets    int     `json:"packets"`
	Bytes      int64   `json:"bytes"`
	ServerPort int     `json:"server_port"`
	Share      float64 `json:"share"`
}

// jsonPortRow 是一个服务端口的统计。
type jsonPortRow struct {
	Proto   string `json:"proto"`
	Port    int    `json:"port"`
	Packets int    `json:"packets"`
	Bytes   int64  `json:"bytes"`
}

// jsonDNS 是 DNS 汇总。
type jsonDNS struct {
	Total   int            `json:"total"`
	Failed  int            `json:"failed"`
	Queries map[string]int `json:"queries,omitempty"`
}

// jsonHTTP 是 HTTP 汇总。
type jsonHTTP struct {
	Requests int            `json:"requests"`
	Hosts    map[string]int `json:"hosts,omitempty"`
	URIs     map[string]int `json:"uris,omitempty"`
	Creds    []jsonCred     `json:"credentials,omitempty"`
}

// jsonCred 是一条明文凭据。
type jsonCred struct {
	Service string `json:"service"`
	Kind    string `json:"kind"`
	Value   string `json:"value"`
	Flow    string `json:"flow,omitempty"`
}

// jsonFinding 是一条安全发现。
type jsonFinding struct {
	Kind   string              `json:"kind"`
	Detail string              `json:"detail,omitempty"`
	Rows   []map[string]string `json:"rows,omitempty"`
}

// jsonAttack 是攻击分析结论。
type jsonAttack struct {
	Models  []string          `json:"models"`
	PeakPkt int               `json:"peak_packets_per_second"`
	Verdict map[string]string `json:"verdict"`
	Metrics map[string]int64  `json:"metrics,omitempty"`
	Signs   map[string]string `json:"signs,omitempty"`
}

// jsonStreamRow 是一条 TCP 会话追踪。
type jsonStreamRow struct {
	Index int    `json:"index"`
	Key   string `json:"key"`
	From  string `json:"from"`
	To    string `json:"to"`
	C0    string `json:"c2s,omitempty"`
	C1    string `json:"s2c,omitempty"`
	Gaps  int    `json:"gaps"`
	Trunc bool   `json:"truncated"`
}

// writeJSONReport 输出 JSON 报告。
func writeJSONReport(w io.Writer, res *captureResult, flt *filter, top int, secs []string) error {
	rep := buildJSONReport(res, flt, top, secs)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(rep)
}

// buildJSONReport 把统计结果转成 JSON 结构。
func buildJSONReport(res *captureResult, flt *filter, top int, secs []string) *jsonReport {
	a := res.a
	rep := &jsonReport{
		Path:      res.path,
		Format:    res.info.Format.String(),
		LinkType:  linkDesc(a),
		Packets:   a.total,
		Matched:   a.matched,
		CapBytes:  a.capBytes,
		WireBytes: a.wireBytes,
	}
	if flt != nil {
		rep.Filter = flt.String()
	}
	if !a.first.IsZero() {
		rep.First = a.first.Format(time.RFC3339Nano)
		rep.Last = a.last.Format(time.RFC3339Nano)
		rep.Duration = a.last.Sub(a.first).Seconds()
	}

	all := len(secs) == 0
	if all || wantSec(secs, secProto) {
		rep.Overview = jsonOverview{
			Link:  countRows(sortedCounters(a.links), a.total),
			Net:   countRows(sortedCounters(a.l3s), a.total),
			Trans: countRows(sortedCounters(a.l4s), a.total),
			App:   countRows(sortedCounters(a.apps), a.total),
		}
		rep.Protocols = rep.Overview.App
	}
	if all || wantSec(secs, secConv) {
		rep.Convs = convRows(sortedFlows(a.flows), a.matched, top)
	}
	if all || wantSec(secs, secEndpoint) {
		rep.Endpoints = countRows(sortedEndpoints(a.endpoints), a.matched)
	}
	if all || wantSec(secs, secPort) {
		rep.Ports = portRows(sortedPorts(a.ports))
	}
	if all || wantSec(secs, secDNS) {
		rep.DNS = jsonDNS{
			Total:   a.dnsTotal,
			Failed:  a.dnsFailed,
			Queries: trimCountMap(a.dnsQueries, top),
		}
	}
	if all || wantSec(secs, secSNI) {
		rep.TLS = topNames(a.sni, top)
	}
	if all || wantSec(secs, secHTTP) {
		rep.HTTP = jsonHTTP{
			Requests: a.httpReq,
			Hosts:    trimCountMap(a.httpHosts, top),
			URIs:     trimCountMap(a.httpURIs, top),
		}
		for _, c := range a.creds {
			rep.HTTP.Creds = append(rep.HTTP.Creds, jsonCred{
				Service: c.service, Kind: c.kind, Value: c.value, Flow: c.flow,
			})
		}
	}
	if all || wantSec(secs, secFindings) {
		rep.Findings = findingsJSON(a)
	}
	if a.atk != nil && (all || wantSec(secs, secAttack)) {
		rep.Attack = attackSummary(a.atk)
	}
	if all || wantSec(secs, secTimeline) {
		rep.Timeline = timelineJSON(a.tl)
	}
	return rep
}

// timelineJSON 把时间线转成 JSON。
func timelineJSON(tl *timeline) *jsonTimeline {
	if tl == nil || len(tl.buckets) == 0 {
		return nil
	}
	out := &jsonTimeline{
		IntervalSeconds: tl.interval.Seconds(),
		SpanSeconds:     tl.last.Sub(tl.first).Seconds(),
		AvgPackets:      tl.avgPacket(),
		Truncated:       tl.capped,
	}
	if peak, ok := tl.topBucket(); ok {
		out.PeakSecond = peak.offset.Seconds()
		out.PeakPackets = peak.packets
		out.PeakBytes = peak.bytes
		out.PeakPeer = peak.topPeer
	}
	for _, b := range tl.buckets {
		if b.packets == 0 {
			continue
		}
		out.Buckets = append(out.Buckets, jsonTLBucket{
			Second:  b.offset.Seconds(),
			Packets: b.packets,
			Bytes:   b.bytes,
			Protos:  b.proto,
			TopPeer: b.topPeer,
		})
	}
	return out
}

// countRows 把 nameCount 列表转成 JSON 行，并计算占比。
func countRows(in []nameCount, total int) []jsonCountRow {
	if len(in) == 0 {
		return nil
	}
	out := make([]jsonCountRow, 0, len(in))
	for _, r := range in {
		row := jsonCountRow{Name: r.name, Packets: r.packets, Bytes: r.bytes}
		if total > 0 {
			row.Share = float64(r.packets) / float64(total)
		}
		out = append(out, row)
	}
	return out
}

// convRows 把会话列表转成 JSON 行。
func convRows(flows []*flow, total, top int) []jsonConvRow {
	if len(flows) == 0 {
		return nil
	}
	if top > 0 && len(flows) > top {
		flows = flows[:top]
	}
	out := make([]jsonConvRow, 0, len(flows))
	for _, f := range flows {
		row := jsonConvRow{
			Proto: f.proto, EndpointA: f.a, EndpointB: f.b,
			Packets: f.packets, Bytes: f.bytes, ServerPort: int(f.serverPort),
		}
		if total > 0 {
			row.Share = float64(f.packets) / float64(total)
		}
		out = append(out, row)
	}
	return out
}

// portRows 把端口统计转成 JSON 行。
func portRows(in []struct {
	port uint16
	st   *portStat
}) []jsonPortRow {
	if len(in) == 0 {
		return nil
	}
	out := make([]jsonPortRow, 0, len(in))
	for _, r := range in {
		if r.st == nil {
			continue
		}
		out = append(out, jsonPortRow{
			Proto: r.st.proto, Port: int(r.port),
			Packets: r.st.packets, Bytes: r.st.bytes,
		})
	}
	return out
}

// trimCountMap 取计数最多的前 n 项（保证输出稳定：先按计数降序，再按键名升序）。
func trimCountMap(m map[string]int, n int) map[string]int {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if n > 0 && len(keys) > n {
		keys = keys[:n]
	}
	out := make(map[string]int, len(keys))
	for _, k := range keys {
		out[k] = m[k]
	}
	return out
}

// topNames 取计数最多的前 n 个名称。
func topNames(m map[string]int, n int) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if n > 0 && len(keys) > n {
		keys = keys[:n]
	}
	return keys
}

// findingsJSON 把安全发现转成 JSON 行。
func findingsJSON(a *analysis) []jsonFinding {
	fs := a.findings()
	if len(fs) == 0 {
		return nil
	}
	out := make([]jsonFinding, 0, len(fs))
	for _, f := range fs {
		jf := jsonFinding{Kind: f.kind, Detail: f.detail}
		if f.table != nil {
			for _, row := range f.table.rows {
				m := make(map[string]string, len(row))
				for i, h := range f.table.headers {
					if i < len(row) {
						m[h] = row[i]
					}
				}
				jf.Rows = append(jf.Rows, m)
			}
		}
		out = append(out, jf)
	}
	return out
}

// attackSummary 汇总攻击分析的结论（逐模型判定 + 关键指标）。
func attackSummary(s *attackStats) *jsonAttack {
	if s == nil {
		return nil
	}
	out := &jsonAttack{
		Models:  modelKeys(s.models),
		PeakPkt: s.peakPkt,
		Verdict: map[string]string{},
		Metrics: map[string]int64{},
		Signs:   map[string]string{},
	}
	for _, m := range modelKeys(s.models) {
		out.Verdict[m] = verdictKey(m, s)
	}
	out.Metrics["tcp_packets"] = int64(s.tcpPkts)
	out.Metrics["udp_packets"] = int64(s.udpPkts)
	out.Metrics["icmp_packets"] = int64(s.icmpPkts)
	out.Metrics["peak_syn_per_sec"] = int64(s.peakSyn)
	out.Metrics["peak_udp_per_sec"] = int64(s.peakUDP)
	out.Metrics["peak_icmp_per_sec"] = int64(s.peakICMP)
	out.Metrics["retransmissions"] = int64(s.retrans)
	out.Metrics["dup_acks"] = int64(s.dupAck)
	out.Metrics["zero_windows"] = int64(s.zeroWin)
	out.Metrics["seq_gaps"] = int64(s.seqGap)
	out.Metrics["frag_overlap"] = int64(s.fragOverlap)
	out.Metrics["http_requests"] = int64(s.httpTotal)
	if s.capped {
		out.Signs["truncated"] = i18n.T("net.atk.capped")
	}
	return out
}

// verdictKey 返回某模型的判定档位（hit / suspect / none），与报告一致。
func verdictKey(model string, s *attackStats) string {
	switch model {
	case "syn":
		if s.syn > 0 {
			return "hit"
		}
		return "none"
	case "udp":
		if s.peakUDP > 0 {
			return "hit"
		}
		return "none"
	case "icmp":
		if s.peakICMP > 0 {
			return "hit"
		}
		return "none"
	case "loss":
		if s.retrans+s.dupAck+s.zeroWin+s.truncated > 0 {
			return "hit"
		}
		return "none"
	case "frag":
		if s.fragOverlap+s.fragBad > 0 {
			return "hit"
		}
		return "none"
	case "cc":
		if s.httpTotal > 0 {
			return "hit"
		}
		return "none"
	}
	return "none"
}
