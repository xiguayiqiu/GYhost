// 攻击流量分析：-m/--model 选择的分析模型。
//
// 两段式设计：
//  1. 统计阶段（observe）在扫描时单遍完成，只看包头与请求行，不保存包内容，
//     内存只与"源 IP 数 / 流数 / 抓包时长"成正比；
//  2. 判定阶段（evaluate）用"峰值速率 + 相对占比"双判据，阈值集中在常量里。
//
// 离线抓包不做在线阻断，结论一律写作"迹象"：命中表示指标明显超出正常基线，
// 疑似表示接近阈值或存在弱特征，供人工进一步确认。
package net

import (
	"errors"
	"strconv"
	"strings"

	"gyhost/internal/i18n"
)

// ---------------------------------------------------------------------------
// 模型选择
// ---------------------------------------------------------------------------

// modelSet 是 -m 选中的分析模型集合。
type modelSet struct {
	syn  bool // SYN 洪泛、源 IP 随机化/伪造
	udp  bool // UDP 洪泛
	icmp bool // ICMP 洪泛
	cc   bool // CC 攻击（HTTP 层 7）
	loss bool // 流量丢包、TCP 传输异常
	frag bool // IP 分片异常（泪滴类）
}

// any 判断是否选中了任何模型。
func (m modelSet) any() bool {
	return m.syn || m.udp || m.icmp || m.cc || m.loss || m.frag
}

// allModels 返回全部模型（-m all / -m 留空时用）。
func allModels() modelSet {
	return modelSet{syn: true, udp: true, icmp: true, cc: true, loss: true, frag: true}
}

// enable 打开一个规范名对应的模型，all/flood 是组合名。
func (m *modelSet) enable(name string) {
	switch name {
	case "all":
		*m = allModels()
	case "flood": // 通用洪泛 = 纯包速率型的三种
		m.syn, m.udp, m.icmp = true, true, true
	case "syn":
		m.syn = true
	case "udp":
		m.udp = true
	case "icmp":
		m.icmp = true
	case "cc":
		m.cc = true
	case "loss":
		m.loss = true
	case "frag":
		m.frag = true
	}
}

// modelOrder 是模型的规范输出顺序（报告按此顺序列出）。
var modelOrder = []string{"syn", "udp", "icmp", "cc", "loss", "frag"}

// modelAlias 把用户写的模型名（含别名）映射到规范名。
var modelAlias = map[string]string{
	"syn": "syn", "synflood": "syn", "syn-flood": "syn",
	"udp": "udp", "udpflood": "udp", "udp-flood": "udp",
	"icmp": "icmp", "icmpflood": "icmp", "icmp-flood": "icmp",
	"flood": "flood",
	"cc":    "cc", "ccattack": "cc", "cc-attack": "cc", "http": "cc", "layer7": "cc",
	"loss": "loss", "drop": "loss", "packetloss": "loss", "packet-loss": "loss",
	"frag": "frag", "fragment": "frag", "ipfrag": "frag", "teardrop": "frag",
	"all": "all",
}

// modelKeys 按规范顺序列出当前启用的模型名（段落标题与列表模式用）。
func modelKeys(m modelSet) []string {
	out := make([]string, 0, len(modelOrder))
	for _, name := range modelOrder {
		if m.enabled(name) {
			out = append(out, name)
		}
	}
	return out
}

// enabled 判断模型集合里是否开着某个规范名。
func (m modelSet) enabled(name string) bool {
	switch name {
	case "syn":
		return m.syn
	case "udp":
		return m.udp
	case "icmp":
		return m.icmp
	case "cc":
		return m.cc
	case "loss":
		return m.loss
	case "frag":
		return m.frag
	}
	return false
}

// parseModels 解析 -m 的取值：按逗号拆分、大小写不敏感、别名归一。
// 传了 -m 但没给出任何模型名时等价于 all（-m= 即全部分析）。
func parseModels(vals []string) (modelSet, error) {
	var ms modelSet
	var unknown []string
	for _, v := range vals {
		for _, part := range strings.Split(v, ",") {
			name := strings.ToLower(strings.TrimSpace(part))
			if name == "" {
				continue
			}
			canonical, ok := modelAlias[name]
			if !ok {
				unknown = append(unknown, strings.TrimSpace(part))
				continue
			}
			ms.enable(canonical)
		}
	}
	if len(unknown) > 0 {
		return modelSet{}, errors.New(i18n.Tf("net.err.bad_model",
			strings.Join(unknown, ", "), strings.Join(modelOrder, ", ")))
	}
	if !ms.any() && len(vals) > 0 {
		return allModels(), nil
	}
	return ms, nil
}

// ---------------------------------------------------------------------------
// 统计
// ---------------------------------------------------------------------------

// 判定级别（数值越小越严重）。
const (
	levelHit     = 0
	levelSuspect = 1
	levelMiss    = 2
)

// maxTrackKeys 是单个映射的键数上限：超大抓包（如伪造源的洪泛）里
// 停止新增键、只统计已有键，避免把内存吃光；触发时报告会给出提示。
const maxTrackKeys = 1 << 20

// fragSpanMax 是同一分片组最多记录的分片区间数（正常分片组很少超过 8 片）。
const fragSpanMax = 16

// maxSecBuckets 是速率统计的时间桶上限（约 1.5 天的逐秒数据）。
// 时间戳跨度异常的抓包不会因此把内存吃光：超出后不再新增桶，
// 后续包只累计总量、不参与峰值（结论偏保守），报告里给出"指标不完整"提示。
const maxSecBuckets = 1 << 17

// 判定阈值：速率类单位为"包或条/秒"，占比类相对本抓包。
// 基线参考——正常客户端建连 < 2 SYN/s，正常站点 < 50 RPS，正常网络很少有分片；
// 速率线刻意取高（VoIP/视频的 UDP 也能上千 pps），占比线兜住"低速但压倒性"的流量。
const (
	synPeakHit    = 100 // SYN 峰值速率
	synBacklogMin = 50  // 且满足 SYN:SYN-ACK >= synBacklogHit（半开连接）
	synBacklogHit = 3
	synShareHit   = 0.5 // SYN 占 TCP 比例，且总量 >= synShareMin
	synShareMin   = 100
	synSuspectMin = 20 // 疑似线：SYN 有量但未到命中线

	singleSrcMin   = 10  // 只出现一次的 SYN 源数量下限
	singleSrcShare = 0.5 // 且占全部 SYN 源的比例

	udpPeakHit  = 1000
	udpShareHit = 0.7
	udpMin      = 500
	udpPeakSus  = 300
	udpShareSus = 0.5
	udpMinSus   = 200

	icmpPeakHit  = 300
	icmpShareHit = 0.10
	icmpMin      = 200
	icmpPeakSus  = 100
	icmpMinSus   = 50

	ccPeakHit     = 100 // HTTP 请求峰值速率
	ccSrcHit      = 300 // 单源请求数，且占比 >= ccSrcShare
	ccSrcShare    = 0.3
	ccURISrcHit   = 20 // 同一 URI 的来源 IP 数，且请求数 >= ccURIHits
	ccURIHits     = 500
	ccPeakSuspect = 30
	ccSrcSuspect  = 100

	lossRateHit  = 0.02 // 重传占数据段比例
	lossMin      = 50   // 数据段基数，避免小样本误报
	lossCountHit = 50   // 重复 ACK / seq 间隙的绝对数
	fragSuspect  = 100  // 分片总量达到即给"疑似"
)

// secBucket 是一秒内的分类计数（速率峰值用）。
type secBucket struct {
	pkts, syn, udp, icmp, http int
}

// tcpDir 是一条 TCP 单向的状态（重传 / 重复 ACK 判定用）。
type tcpDir struct {
	have    bool
	maxSeq  uint32 // 已见数据段的最大结束序号
	haveAck bool
	ack     uint32
	dup     int // 与上一个相同 ACK 的连续个数
}

// fragSpan 是一个分片覆盖的字节区间（半开区间 [start, end)）。
type fragSpan struct{ start, end int }

// attackStats 收集攻击分析所需的原始计数。
type attackStats struct {
	models modelSet

	sec                map[int]*secBucket
	peakPkt            int
	peakSyn, peakUDP   int
	peakICMP, peakHTTP int

	pkts, tcpPkts, udpPkts, icmpPkts int

	// SYN 洪泛 / 源 IP 随机化
	syn, synack int
	srcPkts     map[string]int // 源 IP → 包数（找"只出现一次"的源）
	srcSyn      map[string]int // 源 IP → SYN 数

	// TCP 传输异常（丢包迹象）
	tcpState  map[string]*tcpDir
	dataSegs  int
	retrans   int
	seqGap    int
	dupAck    int
	zeroWin   int
	truncated int

	// CC 攻击
	httpTotal   int
	httpBySrc   map[string]int
	httpByURI   map[string]int
	uriSrcs     map[string]map[string]bool
	uriSrcEntry int
	maxSrc      string
	maxSrcN     int
	maxURI      string
	maxURIN     int

	// IP 分片异常
	fragCount, fragOverlap, fragBad int
	fragSpans                       map[string][]fragSpan

	capped bool // 有映射触到键数上限，指标不完整
}

// newAttackStats 建立空的攻击统计器。
func newAttackStats(models modelSet) *attackStats {
	return &attackStats{
		models:    models,
		sec:       map[int]*secBucket{},
		srcPkts:   map[string]int{},
		srcSyn:    map[string]int{},
		tcpState:  map[string]*tcpDir{},
		httpBySrc: map[string]int{},
		httpByURI: map[string]int{},
		uriSrcs:   map[string]map[string]bool{},
		fragSpans: map[string][]fragSpan{},
	}
}

// bucket 取（或建）某一秒的计数桶；桶数到上限后返回 nil（不再新增）。
func (s *attackStats) bucket(sec int) *secBucket {
	b := s.sec[sec]
	if b != nil {
		return b
	}
	if len(s.sec) >= maxSecBuckets {
		s.capped = true
		return nil
	}
	b = &secBucket{}
	s.sec[sec] = b
	return b
}

// count 给"键 → 次数"加一；键数到上限后只统计已有键。
func (s *attackStats) count(m map[string]int, k string) int {
	if n, ok := m[k]; ok {
		m[k] = n + 1
		return n + 1
	}
	if len(m) >= maxTrackKeys {
		s.capped = true
		return 0
	}
	m[k] = 1
	return 1
}

// observe 把一帧计入攻击统计（调用方保证已通过过滤）。
func (s *attackStats) observe(p *pkt) {
	s.pkts++
	if s.models.loss && p.capLen < p.wireLen {
		s.truncated++
	}
	b := s.bucket(int(p.ts.Unix()))
	if b != nil {
		b.pkts++
		if b.pkts > s.peakPkt {
			s.peakPkt = b.pkts
		}
	}

	switch p.l4 {
	case "TCP":
		s.tcpPkts++
		if s.models.syn {
			s.observeSYN(p, b)
		}
		if s.models.loss {
			s.observeTCP(p)
		}
	case "UDP":
		s.udpPkts++
		if s.models.udp {
			b.udp++
			if b.udp > s.peakUDP {
				s.peakUDP = b.udp
			}
		}
	case "ICMP", "ICMPv6":
		s.icmpPkts++
		if s.models.icmp {
			b.icmp++
			if b.icmp > s.peakICMP {
				s.peakICMP = b.icmp
			}
		}
	}
	if s.models.frag && p.isFrag {
		s.observeFrag(p)
	}
}

// observeSYN 统计握手方向与各源 IP 的发包量。
func (s *attackStats) observeSYN(p *pkt, b *secBucket) {
	if p.flags&0x02 != 0 && p.flags&0x10 == 0 { // SYN（不含 SYN+ACK）
		s.syn++
		b.syn++
		if b.syn > s.peakSyn {
			s.peakSyn = b.syn
		}
		if p.src != "" {
			s.count(s.srcSyn, p.src)
		}
	}
	if p.flags&0x12 == 0x12 { // SYN+ACK
		s.synack++
	}
	if p.src != "" {
		s.count(s.srcPkts, p.src)
	}
}

// observeTCP 跟踪一条方向的序号与 ACK，统计重传、间隙、重复 ACK 与零窗口。
func (s *attackStats) observeTCP(p *pkt) {
	// 零窗口只对会话中的报文有意义：RST 报文的窗口本来就是 0
	if p.win == 0 && p.flags&0x10 != 0 && p.flags&0x04 == 0 {
		s.zeroWin++
	}
	key := p.src + ":" + strconv.Itoa(int(p.srcPort)) + ">" +
		p.dst + ":" + strconv.Itoa(int(p.dstPort))
	st := s.tcpState[key]
	if st == nil {
		if len(s.tcpState) >= maxTrackKeys {
			s.capped = true
			return
		}
		st = &tcpDir{}
		s.tcpState[key] = st
	}

	n := len(p.payload)
	if n > 0 {
		s.dataSegs++
		if st.have {
			end := p.seq + uint32(n)
			switch {
			case seqDelta(end, st.maxSeq) <= 0:
				s.retrans++ // 整段都已见过：重传
			case seqDelta(p.seq, st.maxSeq) > 0:
				s.seqGap++ // 与上一段之间有空洞：丢包或乱序
			}
			if seqDelta(end, st.maxSeq) > 0 {
				st.maxSeq = end
				st.have = true
			}
		} else {
			st.maxSeq, st.have = p.seq+uint32(n), true
		}
		st.ack, st.dup, st.haveAck = p.ack, 1, true
		return
	}
	if p.flags&0x10 == 0 || p.flags&0x02 != 0 {
		return // 不是纯 ACK（SYN/FIN/RST 不参与重复 ACK 判定）
	}
	if st.haveAck && p.ack == st.ack {
		st.dup++
		if st.dup == 3 { // 经典判据：连续 3 个重复 ACK 视作一次丢包事件
			s.dupAck++
		}
		return
	}
	st.ack, st.dup, st.haveAck = p.ack, 1, true
}

// observeFrag 统计分片总量、重叠与畸形（非首片长度 < 8 字节）。
func (s *attackStats) observeFrag(p *pkt) {
	s.fragCount++
	if p.fragOff > 0 && p.fragSize > 0 && p.fragSize < 8 {
		s.fragBad++
	}
	if p.fragSize <= 0 {
		return // 长度未知（截断），无法判断重叠
	}
	start := int(p.fragOff) * 8
	end := start + p.fragSize
	key := p.l3 + "|" + p.src + "|" + p.dst + "|" + strconv.FormatUint(uint64(p.fragID), 10)

	spans := s.fragSpans[key]
	for _, sp := range spans {
		if sp.start < end && start < sp.end {
			s.fragOverlap++
			break
		}
	}
	if len(spans) >= fragSpanMax {
		return
	}
	if _, ok := s.fragSpans[key]; !ok && len(s.fragSpans) >= maxTrackKeys {
		s.capped = true
		return
	}
	s.fragSpans[key] = append(spans, fragSpan{start, end})
}

// observeHTTP 记录一条 HTTP 请求（URI 由 analyze.go 解析好后传入）。
func (s *attackStats) observeHTTP(p *pkt, uri string, b *secBucket) {
	s.httpTotal++
	b.http++
	if b.http > s.peakHTTP {
		s.peakHTTP = b.http
	}
	if p.src != "" {
		if n := s.count(s.httpBySrc, p.src); n > s.maxSrcN {
			s.maxSrcN, s.maxSrc = n, p.src
		}
	}
	if n := s.count(s.httpByURI, uri); n > s.maxURIN {
		s.maxURIN, s.maxURI = n, uri
	}
	s.addURISrc(uri, p.src)
}

// addURISrc 记录"URI → 来源 IP 集合"，用于识别分布式 CC（很多源打同一个 URI）。
func (s *attackStats) addURISrc(uri, src string) {
	if src == "" {
		return
	}
	set := s.uriSrcs[uri]
	if set == nil {
		if len(s.uriSrcs) >= maxTrackKeys {
			s.capped = true
			return
		}
		set = map[string]bool{}
		s.uriSrcs[uri] = set
	}
	if set[src] {
		return
	}
	if s.uriSrcEntry >= maxTrackKeys {
		s.capped = true
		return
	}
	set[src] = true
	s.uriSrcEntry++
}

// seqDelta 返回 a-b 的有符号差，处理 32 位序号回绕。
func seqDelta(a, b uint32) int32 { return int32(a - b) }

// ---------------------------------------------------------------------------
// 判定
// ---------------------------------------------------------------------------

// attackResult 是一个模型的判定结果（文本已走 i18n）。
type attackResult struct {
	model   string
	level   int
	metrics string
	alarms  []string
}

// evaluate 按规范顺序给出每个启用模型的判定与命中详情。
func (s *attackStats) evaluate() []attackResult {
	out := make([]attackResult, 0, len(modelOrder))
	for _, name := range modelKeys(s.models) {
		switch name {
		case "syn":
			out = append(out, s.verdictSYN())
		case "udp":
			out = append(out, s.verdictUDP())
		case "icmp":
			out = append(out, s.verdictICMP())
		case "cc":
			out = append(out, s.verdictCC())
		case "loss":
			out = append(out, s.verdictLoss())
		case "frag":
			out = append(out, s.verdictFrag())
		}
	}
	return out
}

// verdictSYN 判定 SYN 洪泛与源 IP 随机化/伪造。
func (s *attackStats) verdictSYN() attackResult {
	share := pctStr(s.syn, s.tcpPkts)
	r := attackResult{
		model:   "syn",
		level:   levelMiss,
		metrics: i18n.Tf("net.metric.syn", s.syn, s.peakSyn, s.synack, len(s.srcSyn), share),
	}
	switch {
	case s.peakSyn >= synPeakHit,
		s.syn >= synBacklogMin && s.synack*synBacklogHit <= s.syn,
		s.syn >= synShareMin && float64(s.syn) >= synShareHit*float64(s.tcpPkts):
		r.level = levelHit
	case s.syn >= synSuspectMin && (s.synack*2 <= s.syn ||
		float64(s.syn) >= synShareHit*float64(s.tcpPkts)):
		r.level = levelSuspect
	}

	// 源 IP 随机化/伪造：大量源只出现 1 次且只发 SYN
	single := 0
	for ip, n := range s.srcPkts {
		if n == 1 && s.srcSyn[ip] > 0 {
			single++
		}
	}
	synSrcs := len(s.srcSyn)
	if synSrcs >= singleSrcMin && float64(single) >= singleSrcShare*float64(synSrcs) {
		r.level = levelHit
		r.alarms = append(r.alarms, i18n.Tf("net.attack.random_src",
			single, synSrcs, pctStr(single, synSrcs)))
	}
	if r.level != levelMiss {
		r.alarms = append(append([]string{}, i18n.Tf("net.attack.syn",
			s.syn, s.synack, s.peakSyn, share)), r.alarms...)
	}
	return r
}

// verdictUDP 判定 UDP 洪泛。
func (s *attackStats) verdictUDP() attackResult {
	share := pctStr(s.udpPkts, s.pkts)
	r := attackResult{
		model:   "udp",
		level:   levelMiss,
		metrics: i18n.Tf("net.metric.udp", s.udpPkts, s.peakUDP, share),
	}
	switch {
	case s.peakUDP >= udpPeakHit,
		s.udpPkts >= udpMin && float64(s.udpPkts) >= udpShareHit*float64(s.pkts):
		r.level = levelHit
	case s.peakUDP >= udpPeakSus,
		s.udpPkts >= udpMinSus && float64(s.udpPkts) >= udpShareSus*float64(s.pkts):
		r.level = levelSuspect
	}
	if r.level != levelMiss {
		r.alarms = append(r.alarms, i18n.Tf("net.attack.udp", s.peakUDP, share))
	}
	return r
}

// verdictICMP 判定 ICMP 洪泛。
func (s *attackStats) verdictICMP() attackResult {
	share := pctStr(s.icmpPkts, s.pkts)
	r := attackResult{
		model:   "icmp",
		level:   levelMiss,
		metrics: i18n.Tf("net.metric.icmp", s.icmpPkts, s.peakICMP, share),
	}
	switch {
	case s.peakICMP >= icmpPeakHit,
		s.icmpPkts >= icmpMin && float64(s.icmpPkts) >= icmpShareHit*float64(s.pkts):
		r.level = levelHit
	case s.peakICMP >= icmpPeakSus,
		s.icmpPkts >= icmpMinSus && float64(s.icmpPkts) >= icmpShareHit*float64(s.pkts):
		r.level = levelSuspect
	}
	if r.level != levelMiss {
		r.alarms = append(r.alarms, i18n.Tf("net.attack.icmp", s.peakICMP, share))
	}
	return r
}

// verdictCC 判定 CC 攻击：请求速率、单源高频、分布式打同一 URI。
func (s *attackStats) verdictCC() attackResult {
	r := attackResult{
		model: "cc",
		level: levelMiss,
		metrics: i18n.Tf("net.metric.cc", s.httpTotal, s.peakHTTP,
			orDash(s.maxSrc), s.maxSrcN, orDash(s.maxURI), s.maxURIN),
	}
	base := s.httpTotal
	if base < 1 {
		base = 1
	}
	srcShare := float64(s.maxSrcN) / float64(base)
	switch {
	case s.peakHTTP >= ccPeakHit,
		s.maxSrcN >= ccSrcHit && srcShare >= ccSrcShare,
		len(s.uriSrcs[s.maxURI]) >= ccURISrcHit && s.maxURIN >= ccURIHits:
		r.level = levelHit
	case s.peakHTTP >= ccPeakSuspect, s.maxSrcN >= ccSrcSuspect:
		r.level = levelSuspect
	}
	if r.level == levelMiss {
		return r
	}
	r.alarms = append(r.alarms, i18n.Tf("net.attack.cc",
		s.httpTotal, s.peakHTTP, orDash(s.maxSrc), s.maxSrcN, orDash(s.maxURI), s.maxURIN))
	if n := len(s.uriSrcs[s.maxURI]); n >= ccURISrcHit && s.maxURIN >= ccURIHits {
		r.alarms = append(r.alarms, i18n.Tf("net.attack.cc_dist",
			orDash(s.maxURI), n, s.maxURIN))
	}
	if s.maxSrcN >= ccSrcSuspect && srcShare >= ccSrcShare {
		r.alarms = append(r.alarms, i18n.Tf("net.attack.cc_single",
			orDash(s.maxSrc), s.maxSrcN, pctStr(s.maxSrcN, s.httpTotal)))
	}
	return r
}

// verdictLoss 判定流量丢包与 TCP 传输异常。
func (s *attackStats) verdictLoss() attackResult {
	rate := pctStr(s.retrans, s.dataSegs)
	r := attackResult{
		model: "loss",
		level: levelMiss,
		metrics: i18n.Tf("net.metric.loss", s.retrans, rate,
			s.dupAck, s.seqGap, s.zeroWin, s.truncated),
	}
	switch {
	case s.dataSegs >= lossMin && float64(s.retrans) >= lossRateHit*float64(s.dataSegs),
		s.dupAck >= lossCountHit, s.seqGap >= lossCountHit:
		r.level = levelHit
	case s.retrans > 0, s.dupAck > 0, s.seqGap > 0, s.zeroWin > 0, s.truncated > 0:
		r.level = levelSuspect
	}
	if r.level != levelMiss {
		r.alarms = append(r.alarms, i18n.Tf("net.attack.loss",
			s.retrans, rate, s.dupAck, s.seqGap, s.zeroWin))
	}
	if s.truncated > 0 {
		r.alarms = append(r.alarms, i18n.Tf("net.attack.trunc", s.truncated))
	}
	return r
}

// verdictFrag 判定 IP 分片异常（重叠 / 畸形即为泪滴类攻击特征）。
func (s *attackStats) verdictFrag() attackResult {
	r := attackResult{
		model:   "frag",
		level:   levelMiss,
		metrics: i18n.Tf("net.metric.frag", s.fragCount, s.fragOverlap, s.fragBad),
	}
	switch {
	case s.fragOverlap > 0, s.fragBad > 0:
		r.level = levelHit
		r.alarms = append(r.alarms, i18n.Tf("net.attack.frag", s.fragOverlap, s.fragBad))
	case s.fragCount >= fragSuspect:
		r.level = levelSuspect
	}
	return r
}

// orDash 空值渲染成 "-"，保证表格列可读。
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
