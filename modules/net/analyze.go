// 流量统计与安全发现。
//
// 一帧解码完就喂给 analysis：四层协议计数、端点/会话/端口、
// DNS/TLS/HTTP 摘要，以及明文凭据、ARP 冲突这类安全发现的原始素材。
package net

import (
	"errors"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gyhost/internal/i18n"
	"gyhost/internal/pcap"
)

// counter 是一组"包数 + 字节数"计数。
type counter struct {
	packets int
	bytes   int64
}

func (c *counter) add(p *pkt) {
	c.packets++
	c.bytes += int64(p.wireLen)
}

// endpoint 是一个 IP 的收发统计。
type endpoint struct {
	sent, recv int
	bytes      int64
}

// flow 是一条会话：同一对地址（端口）之间的双向流量。
type flow struct {
	proto      string // TCP / UDP / ICMP / ARP ...
	a, b       string // 两端（IP 或 IP:端口），a <= b
	packets    int
	bytes      int64
	serverPort uint16 // 服务端口（首包目的端口；TCP 以 SYN 为准）
}

// portStat 是某个服务端口的流量统计。
type portStat struct {
	proto   string
	packets int
	bytes   int64
}

// credRec 是一条待报告的明文凭据。
type credRec struct {
	service string // HTTP / FTP / POP3 / IMAP / SMTP
	kind    string // USER / PASS / LOGIN / Authorization / password
	value   string // 明文内容
	flow    string // 所在会话
	context string // 附加信息（如 HTTP 请求行）
}

// finding 是一条安全发现：kind 决定 i18n 句式，detail 是填充内容。
//
// 同一类发现条目较多时（如几十个明文端口、多个 ARP 冲突），用 table 承载
// "标题 + 明细表"，避免把所有条目挤在一行里导致无法阅读。
type finding struct {
	kind   string
	detail string
	table  *findingTable
}

// findingTable 是"标题 + 明细表"形态的发现内容。
type findingTable struct {
	headers []string
	right   []bool
	rows    [][]string
}

// flowMemo 记住"上一帧命中的会话"，用原始字段（未渲染的地址与端口）
// 做比较，避免每帧都重新拼 map 键。
type flowMemo struct {
	proto            string
	src, dst         string
	srcPort, dstPort uint16
	flow             *flow
}

// analysis 是单个抓包的统计结果。
type analysis struct {
	total     int // 文件总包数
	matched   int // 通过过滤的包数
	first     time.Time
	last      time.Time
	capBytes  int64
	wireBytes int64

	links   map[string]*counter
	linkAll map[string]bool // 出现过的全部链路层名（含被过滤掉的，概览用）
	l3s     map[string]*counter
	l4s     map[string]*counter
	apps    map[string]*counter

	endpoints map[string]*endpoint
	flows     map[string]*flow
	ports     map[uint16]*portStat

	lastFlow flowMemo // 上一帧所属会话的记忆（见 flowOf）
	segBuf   []byte   // flowOf 渲染端点与拼键的复用缓冲
	seg2Buf  []byte
	keyBuf   []byte

	dnsQueries map[string]int
	dnsTotal   int
	dnsFailed  int
	sni        map[string]int
	httpHosts  map[string]int
	httpURIs   map[string]int
	httpReq    int

	creds    []credRec
	credSeen map[string]bool
	lastUser map[string]string // 会话里最近一次 USER（用于给 PASS 补用户名）

	arpIPs    map[string]map[string]bool // IP → 出现过的 MAC
	clearText map[uint16]int             // 明文服务端口 → 包数

	linkWarn map[uint32]int // 解不出网络层的链路类型 → 帧数

	// tl 是流量时间线（-z timeline），默认不采集
	tl *timeline

	// TCP 会话重组（-z follow）。默认不收集，只有显式要求时才占用内存。
	streams   map[string]*streamConv
	streamLim streamLimits
	// streamKey 当前帧所属会话的重组键（复用 flowMemo 的记忆优化）
	streamMemo flowMemo

	atk *attackStats // -m 启用的攻击分析统计（未启用时为 nil）
}

// newAnalysis 创建空的统计器；models 非空时顺带开启攻击分析。
func newAnalysis(models modelSet) *analysis {
	a := &analysis{
		links:      map[string]*counter{},
		linkAll:    map[string]bool{},
		l3s:        map[string]*counter{},
		l4s:        map[string]*counter{},
		apps:       map[string]*counter{},
		endpoints:  map[string]*endpoint{},
		flows:      map[string]*flow{},
		ports:      map[uint16]*portStat{},
		dnsQueries: map[string]int{},
		sni:        map[string]int{},
		httpHosts:  map[string]int{},
		httpURIs:   map[string]int{},
		credSeen:   map[string]bool{},
		lastUser:   map[string]string{},
		arpIPs:     map[string]map[string]bool{},
		clearText:  map[uint16]int{},
		linkWarn:   map[uint32]int{},
	}
	if models.any() {
		a.atk = newAttackStats(models)
	}
	return a
}

// observe 把一帧计入统计（调用方保证已通过过滤）。
func (a *analysis) observe(p *pkt) {
	a.matched++
	if a.matched == 1 {
		a.first, a.last = p.ts, p.ts
	} else {
		if p.ts.Before(a.first) {
			a.first = p.ts
		}
		if p.ts.After(a.last) {
			a.last = p.ts
		}
	}
	a.capBytes += int64(p.capLen)
	a.wireBytes += int64(p.wireLen)

	// ---- 四层协议计数 ----
	addCount(a.links, p.link, p)
	if p.l3 != "" {
		addCount(a.l3s, p.l3, p)
	}
	if p.l4 != "" {
		addCount(a.l4s, p.l4, p)
	}
	if p.l4 == "TCP" || p.l4 == "UDP" {
		name := p.app
		if name == "" {
			name = i18n.T("net.proto.unidentified")
		}
		addCount(a.apps, name, p)
	}

	// ---- 端点 ----
	src, dst := p.addrPair()
	if src != "" {
		ep := a.endpoint(src)
		ep.sent++
		ep.bytes += int64(p.wireLen)
	}
	if dst != "" && dst != src {
		ep := a.endpoint(dst)
		ep.recv++
		ep.bytes += int64(p.wireLen)
	}

	// ---- 会话与端口 ----
	f := a.flowOf(p)
	if f != nil {
		f.packets++
		f.bytes += int64(p.wireLen)
		f.note(p)
		if f.serverPort != 0 && (p.l4 == "TCP" || p.l4 == "UDP") {
			st := a.ports[f.serverPort]
			if st == nil {
				st = &portStat{proto: p.l4}
				a.ports[f.serverPort] = st
			}
			st.packets++
			st.bytes += int64(p.wireLen)
			if _, ok := clearTextPorts[f.serverPort]; ok {
				a.clearText[f.serverPort]++
			}
		}
	}

	a.observeApp(p, f)
	a.observeSecurity(p, f)
	if a.atk != nil {
		a.atk.observe(p)
	}
}

// addCount 给某个协议计数器加一。
func addCount(m map[string]*counter, name string, p *pkt) {
	if name == "" {
		return
	}
	c := m[name]
	if c == nil {
		c = &counter{}
		m[name] = c
	}
	c.add(p)
}

// endpoint 取（或建）一个端点统计。
func (a *analysis) endpoint(ip string) *endpoint {
	e := a.endpoints[ip]
	if e == nil {
		e = &endpoint{}
		a.endpoints[ip] = e
	}
	return e
}

// flowOf 取（或建）当前帧所属的会话；没有地址信息时返回 nil。
//
// 两级优化，都不改变统计结果：
//  1. 记住"上一帧所属会话"（抓包里同一会话的包通常是连续的），命中时只做
//     字符串比较，完全不用拼 map 键；
//  2. 未命中时在复用缓冲区里拼键。对 map 来说 string(buf) 形式的查找
//     不会分配，只有真正新建会话才生成键字符串。
func (a *analysis) flowOf(p *pkt) *flow {
	src, dst := p.addrPair()
	if src == "" || dst == "" {
		a.lastFlow = flowMemo{}
		return nil
	}
	proto := p.l4
	if proto == "" {
		proto = p.l3
	}
	if proto == "" {
		proto = p.link
	}
	if proto == "" {
		a.lastFlow = flowMemo{}
		return nil
	}
	// 记忆命中：同一会话的连续帧直接复用
	if c := &a.lastFlow; c.flow != nil &&
		c.proto == proto && c.src == src && c.dst == dst &&
		c.srcPort == p.srcPort && c.dstPort == p.dstPort {
		return c.flow
	}

	// 两端渲染进复用缓冲，按字典序定序后拼成 map 键。
	// 键也用复用缓冲：a.flows[string(key)] 这种形式的 map 查找不会分配，
	// 只有真正新建会话时才把键转成字符串存下来。
	seg1 := appendEndpoint(a.segBuf[:0], src, p.srcPort)
	a.segBuf = seg1
	seg2 := appendEndpoint(a.seg2Buf[:0], dst, p.dstPort)
	a.seg2Buf = seg2
	lo, hi := seg1, seg2
	if string(lo) > string(hi) {
		lo, hi = hi, lo
	}
	key := append(a.keyBuf[:0], proto...)
	key = append(key, '|')
	key = append(key, lo...)
	key = append(key, '|')
	key = append(key, hi...)
	a.keyBuf = key

	f, ok := a.flows[string(key)] // 查找不分配
	if !ok {
		f = &flow{proto: proto, a: string(lo), b: string(hi)}
		a.flows[string(key)] = f
	}
	a.lastFlow = flowMemo{proto: proto, src: src, dst: dst,
		srcPort: p.srcPort, dstPort: p.dstPort, flow: f}
	return f
}

// appendEndpoint 把端点（有端口时带端口，IPv6 自动加方括号）追加到 dst。
// 与 endpointAddr 等价，但支持写入调用方提供的缓冲区。
func appendEndpoint(dst []byte, ip string, port uint16) []byte {
	if port == 0 {
		return append(dst, ip...)
	}
	if strings.IndexByte(ip, ':') >= 0 { // IPv6 加方括号
		dst = append(dst, '[')
		dst = append(dst, ip...)
		dst = append(dst, ']')
	} else {
		dst = append(dst, ip...)
	}
	dst = append(dst, ':')
	return strconv.AppendUint(dst, uint64(port), 10)
}

// note 记录本帧对"服务端口"的推断：TCP 以 SYN 为准，其余用首包目的端口。
func (f *flow) note(p *pkt) {
	if p.srcPort == 0 && p.dstPort == 0 {
		return
	}
	syn := p.l4 == "TCP" && p.flags&0x02 != 0 && p.flags&0x10 == 0
	if f.serverPort == 0 || syn {
		f.serverPort = p.dstPort
	}
}

// addrPair 返回本帧用于统计的端点地址：优先网络层 IP；
// 没有网络层时退回 MAC（802.11 管理/控制帧这类不携带 IP 的帧）。
func (p *pkt) addrPair() (src, dst string) {
	if p.src != "" {
		return p.src, p.dst
	}
	return p.srcMAC(), p.dstMAC()
}

// endpointAddr 渲染端点（有端口时带端口，IPv6 自动加方括号）。
func endpointAddr(ip string, port uint16) string {
	if port == 0 {
		return ip
	}
	if strings.IndexByte(ip, ':') >= 0 { // IPv6 加方括号
		return "[" + ip + "]:" + strconv.Itoa(int(port))
	}
	return ip + ":" + strconv.Itoa(int(port))
}

// observeApp 记录应用层要素：DNS 查询、TLS SNI、HTTP 主机与 URI。
func (a *analysis) observeApp(p *pkt, f *flow) {
	switch p.app {
	case "DNS", "mDNS", "LLMNR":
		if len(p.payload) == 0 {
			return
		}
		m, ok := parseDNS(p.payload, p.l4 == "TCP")
		if !ok {
			return
		}
		if m.qr {
			if m.rcode != 0 {
				a.dnsFailed++
			}
			return
		}
		a.dnsTotal++
		if m.qname != "" {
			a.dnsQueries[m.qname]++
		}

	case "TLS":
		if len(p.payload) >= 6 && p.payload[0] == 22 && p.payload[5] == 1 {
			if sni := clientHelloSNI(p.payload); sni != "" {
				a.sni[sni]++
			}
		}

	case "HTTP":
		a.observeHTTP(p, f)
	}
}

// observeHTTP 记录请求行、Host、凭据与明文口令字段。
func (a *analysis) observeHTTP(p *pkt, f *flow) {
	if len(p.payload) == 0 {
		return
	}
	if !isHTTPRequest(p.payload) {
		return // 响应或续传片段不计请求
	}
	a.httpReq++
	if uri, ok := httpRequestURI(p.payload); ok {
		if len(uri) > 96 {
			uri = uri[:96] + "..."
		}
		a.httpURIs[uri]++
		if a.atk != nil && a.atk.models.cc {
			a.atk.observeHTTP(p, uri, a.atk.bucket(int(p.ts.Unix())))
		}
	}
	// 只有真正发现凭据时才需要渲染会话串（flowStr 只在下面用到）
	host, creds := httpReqInfo(p.payload)
	if host != "" {
		a.httpHosts[host]++
	}
	fields := scanPassFields(p.payload)
	if len(creds) == 0 && len(fields) == 0 {
		return
	}
	line, _ := firstLine(p.payload)
	flowStr := flowString(f, p)
	for _, c := range creds {
		a.addCred(p, c, flowStr, line)
	}
	for _, hf := range fields {
		a.addCred(p, rawCred{kind: hf.key, value: hf.value}, flowStr, line)
	}
}

// observeSecurity 记录明文凭据、ARP 冲突与明文服务的原始素材。
func (a *analysis) observeSecurity(p *pkt, f *flow) {
	if p.app == "FTP" || p.app == "POP3" || p.app == "IMAP" || p.app == "SMTP" {
		if len(p.payload) > 0 {
			flowStr := flowString(f, p)
			for _, c := range scanCreds(p.app, p.payload) {
				a.addCred(p, c, flowStr, "")
			}
		}
	}
	if p.l3 == "ARP" && p.arpSenderIP != "" && p.arpSenderIP != "0.0.0.0" && p.hasSrcMAC {
		set := a.arpIPs[p.arpSenderIP]
		if set == nil {
			set = map[string]bool{}
			a.arpIPs[p.arpSenderIP] = set
		}
		set[p.srcMAC()] = true
	}
}

// addCred 记录一条明文凭据（按 会话+类型+内容 去重，重传不会刷屏）。
//
// FTP/POP3 的 PASS 会补上同一会话里最近一次 USER 的用户名。
func (a *analysis) addCred(p *pkt, c rawCred, flowStr, context string) {
	value := c.value
	if c.kind == "USER" {
		a.lastUser[flowStr] = c.value
	}
	if c.kind == "PASS" {
		if u := a.lastUser[flowStr]; u != "" {
			value = u + ":" + c.value
		}
	}
	key := p.app + "\x00" + c.kind + "\x00" + value + "\x00" + flowStr + "\x00" + context
	if a.credSeen[key] {
		return
	}
	a.credSeen[key] = true
	a.creds = append(a.creds, credRec{
		service: p.app, kind: c.kind, value: value,
		flow: flowStr, context: context,
	})
}

// flowString 渲染会话的可读形式（用于凭据定位，按数据包真实方向）。
func flowString(f *flow, p *pkt) string {
	if p != nil && p.src != "" && p.dst != "" {
		return endpointAddr(p.src, p.srcPort) + " -> " + endpointAddr(p.dst, p.dstPort)
	}
	if f != nil {
		return f.a + " <-> " + f.b
	}
	return ""
}

// ---------------------------------------------------------------------------
// 安全发现
// ---------------------------------------------------------------------------

// clearTextPorts 默认不加密、值得提醒的服务端口。
var clearTextPorts = map[uint16]string{
	21: "FTP", 20: "FTP-data", 23: "Telnet", 25: "SMTP", 587: "SMTP",
	110: "POP3", 143: "IMAP", 389: "LDAP", 161: "SNMP", 69: "TFTP",
	514: "Syslog", 111: "portmap", 137: "NBNS", 138: "NBDS", 139: "NBSS",
	445: "SMB", 2049: "NFS", 1900: "SSDP", 5060: "SIP", 6667: "IRC",
	3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 1521: "Oracle",
	5900: "VNC", 6379: "Redis", 11211: "Memcached", 27017: "MongoDB",
	1883: "MQTT", 3128: "HTTP-proxy",
}

// findings 汇总安全发现（按严重程度排序）。
func (a *analysis) findings() []finding {
	var out []finding

	for _, c := range a.creds {
		detail := c.service + " " + c.kind + " " + c.value
		if c.context != "" {
			detail += " (" + c.context + ")"
		}
		if c.flow != "" {
			detail += " [" + c.flow + "]"
		}
		kind := "cred"
		if !isStandardCred(c.kind) {
			kind = "field"
		}
		out = append(out, finding{kind: kind, detail: detail})
	}

	// ARP 冲突：每个 IP 一行，便于看清是哪几个 IP 有问题
	var conflicted [][]string
	for ip, macs := range a.arpIPs {
		if len(macs) < 2 {
			continue
		}
		list := make([]string, 0, len(macs))
		for m := range macs {
			list = append(list, m)
		}
		sort.Strings(list)
		conflicted = append(conflicted, []string{ip, strings.Join(list, ", ")})
	}
	if len(conflicted) > 0 {
		sort.Slice(conflicted, func(i, j int) bool {
			return conflicted[i][0] < conflicted[j][0]
		})
		out = append(out, finding{kind: "arp", table: &findingTable{
			headers: []string{i18n.T("net.head.ip"), i18n.T("net.head.mac")},
			right:   []bool{false, false},
			rows:    conflicted,
		}})
	}

	// 明文服务：按服务名 + 端口排成表格，包数列右对齐
	if len(a.clearText) > 0 {
		ports := make([]uint16, 0, len(a.clearText))
		for port := range a.clearText {
			ports = append(ports, port)
		}
		sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
		rows := make([][]string, 0, len(ports))
		for _, p := range ports {
			rows = append(rows, []string{
				clearTextPorts[p], strconv.Itoa(int(p)),
				strconv.Itoa(a.clearText[p]),
			})
		}
		out = append(out, finding{kind: "cleartext", table: &findingTable{
			headers: []string{i18n.T("net.head.service"), i18n.T("net.head.port"),
				i18n.T("net.head.packets")},
			right: []bool{false, true, true},
			rows:  rows,
		}})
	}
	return out
}

// isStandardCred 判断凭据类型是否是"整对账号口令"，
// 不是的话按"字段里发现口令"归类。
func isStandardCred(kind string) bool {
	switch kind {
	case "USER", "PASS", "LOGIN", "Authorization", "AUTH PLAIN":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// 扫描驱动
// ---------------------------------------------------------------------------

// captureResult 是一个抓包的完整解析结果。
type captureResult struct {
	path string
	info pcap.Info
	a    *analysis
}

// scanOpts 控制一次抓包解析：过滤条件、攻击分析模型与回调。
type scanOpts struct {
	flt     *filter
	models  modelSet
	verbose bool // 详细模式：填充协议树字段
	// streams 非 nil 时启用 TCP 会话重组（-z follow）
	streams *streamLimits
	// timeRange 非 nil 时按时间窗口过滤（-t）
	timeRange *timeRange
	// timeline 非 nil 时按时间桶统计流量（-z timeline）
	timeline *timelineLimits
	onOpen   func(pcap.Info)
	onPkt    func(*pkt) error
}

// scanCapture 打开并解析一个抓包：逐帧解码 -> 过滤 -> 统计。
// onOpen 在容器头解析完成后回调（列表模式先打印文件信息）；
// onPkt 非 nil 时对每个通过过滤的包回调（列表模式逐行输出用）。
func scanCapture(path string, o scanOpts) (*captureResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New(i18n.Tf("net.err.open", path, err))
	}
	defer f.Close()

	size := int64(0)
	if st, err := f.Stat(); err == nil {
		size = st.Size()
	}

	r, err := pcap.Open(f, size)
	if err != nil {
		if errors.Is(err, pcap.ErrNotCapture) {
			return nil, errors.New(i18n.Tf("net.err.unrecognized", path))
		}
		return nil, errors.New(i18n.Tf("net.err.bad_capture", err))
	}
	if o.onOpen != nil {
		o.onOpen(r.Info())
	}

	a := newAnalysis(o.models)
	if o.timeline != nil {
		a.enableTimeline(o.timeline.interval, o.timeline.maxBucket)
	}
	if o.streams != nil {
		a.enableStreams(*o.streams)
	}
	// 复用同一个 pkt：统计过程只把字符串/计数存进 map，不持有帧本身，
	// 因此逐帧复用是安全的（每帧一次堆分配在大抓包上是明显的 GC 压力）。
	var dp pkt
	// 过滤表达式引用了 ip.ttl / tcp.hdr_len 这类只在详细模式下填充的字段时，
	// 必须打开 verbose，否则这些字段恒为 0，过滤会静默给出错误结果。
	verbose := o.verbose || o.flt.needsVerbose()
	for {
		rec, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New(i18n.Tf("net.err.bad_capture", err))
		}
		a.total++
		// 时间窗口过滤（-t）：与 -f 独立，先于它判定。
		// 相对秒数要拿首帧做基准，所以首次遇到时先记住 a.first。
		if o.timeRange != nil {
			if a.first.IsZero() {
				a.first = rec.Time
			}
			if !o.timeRange.match(rec.Time, a.first) {
				continue
			}
		}
		p := decodeInto(&dp, rec, o.onPkt != nil, verbose)
		if p.link == "" {
			// 链路类型不认识：仍参与统计，但给出明确提示
			a.linkWarn[rec.LinkType]++
			p.link = i18n.Tf("net.link.unknown", rec.LinkType)
		}
		a.linkAll[p.link] = true
		if o.flt != nil && !o.flt.match(p) {
			continue
		}
		a.observe(p)
		a.collectTimeline(p)
		a.collectStream(p)
		if o.onPkt != nil {
			if err := o.onPkt(p); err != nil {
				return nil, err
			}
		}
	}
	return &captureResult{path: path, info: r.Info(), a: a}, nil
}

// hasData 判断统计里是否还有可展示的会话（供报告裁剪空段落）。
func (a *analysis) hasData() bool { return a.matched > 0 && len(a.flows) > 0 }
