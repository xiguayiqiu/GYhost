// 显示过滤器的字段表：把 "tcp.port"、"ip.addr"、"frame.len" 这样的名字
// 映射到解码结果上的取值。
//
// 字段经 registerField 注册，并声明是否依赖详细解码（-V 才填充的那些字段）。
// 带这类字段的表达式会自动打开详细解码——否则 ip.ttl 之类字段恒为 0，
// 过滤会静默给出错误结果（见 filter.needsVerbose）。
package net

import (
	"net"
	"strconv"
	"strings"
)

// valKind 是字段值的类型，决定了哪些运算符可用、比较怎么做。
type valKind byte

const (
	valNone  valKind = iota
	valInt           // 整数（端口、长度、TTL …）
	valFloat         // 浮点（时间戳 …）
	valIP            // IP 地址
	valStr           // 字符串（协议名、HTTP Host、DNS 名 …）
	valMAC           // MAC 地址
	valBool          // 布尔标志位
)

// val 是一个字段值。
//
// 多值字段（如 tcp.port 同时有源/目的两个取值）用 vals 保存全部取值，
// 运算符对任一取值成立即算成立——这与 Wireshark 的行为一致。
type val struct {
	kind valKind
	i    int64
	f    float64
	s    string
	ip   net.IP
	b    bool
	vals []val
}

// num 返回数值型字段的数值；非数值返回 0。
func (v val) num() float64 {
	switch v.kind {
	case valInt:
		return float64(v.i)
	case valFloat:
		return v.f
	}
	return 0
}

// text 返回字段的文本形式（用于字符串比较与错误提示）。
func (v val) text() string {
	switch v.kind {
	case valInt:
		return strconv.FormatInt(v.i, 10)
	case valFloat:
		return strconv.FormatFloat(v.f, 'g', -1, 64)
	case valStr, valMAC:
		return v.s
	case valIP:
		if v.ip != nil {
			return v.ip.String()
		}
	case valBool:
		if v.b {
			return "1"
		}
		return "0"
	}
	return ""
}

// each 遍历该值的全部取值（多值字段），fn 返回 true 表示"命中"。
//
// 返回值是"是否有任一取值命中"。这里必须遍历完所有取值而不能短路：
// 多值字段（如 tcp.port = {源端口, 目的端口}）的语义是"任一命中即算命中"，
// 若第一个取值不匹配就提前返回，后面那个真正匹配的取值会被漏掉。
func (v val) each(fn func(val) bool) bool {
	if len(v.vals) == 0 {
		return fn(v)
	}
	hit := false
	for _, x := range v.vals {
		if fn(x) {
			hit = true
		}
	}
	return hit
}

// fieldSpec 描述一个可过滤字段。
type fieldSpec struct {
	kind valKind
	// get 取出该字段在一帧里的取值；多值时用 vals 填充。
	get func(p *pkt) val
	// verbose 表示该字段依赖详细解码。
	verbose bool
	// doc 是给用户看的说明（/ ? 帮助）。
	doc string
}

// fieldTable 是全部可过滤字段，键为小写字段名。
var fieldTable = map[string]fieldSpec{}

// registerField 注册一个字段。
func registerField(name string, spec fieldSpec) {
	fieldTable[strings.ToLower(name)] = spec
}

// fieldExists 判断字段名是否已注册。
func fieldExists(name string) bool {
	_, ok := fieldTable[strings.ToLower(name)]
	return ok
}

// fieldNames 返回排序后的字段名列表（补全与帮助用）。
func fieldNames() []string {
	out := make([]string, 0, len(fieldTable))
	for k := range fieldTable {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// intVal 构造整数值。
func intVal(i int64) val { return val{kind: valInt, i: i} }

// strVal 构造字符串值。
func strVal(s string) val { return val{kind: valStr, s: s} }

// ipVal 构造 IP 值。
func ipVal(ip net.IP) val { return val{kind: valIP, ip: ip} }

// macVal 构造 MAC 值。
func macVal(s string) val { return val{kind: valMAC, s: s} }

// multi 构造多值字段：src/dst 两向都放进 vals，任一命中即算命中。
func multi(a, b val) val { return val{kind: a.kind, vals: []val{a, b}} }

// init 注册全部可过滤字段。
func init() {
	registerFrameFields()
	registerNetFields()
	registerTransportFields()
	registerAppFields()
}

// registerFrameFields 注册帧层与链路层字段。
func registerFrameFields() {
	registerField("frame.number", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.no))
	}, false, "帧序号"})
	registerField("frame.len", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.wireLen))
	}, false, "线上帧长度（字节）"})
	registerField("frame.cap_len", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.capLen))
	}, false, "已捕获长度（字节）"})
	registerField("frame.time", fieldSpec{valFloat, func(p *pkt) val {
		return val{kind: valFloat, f: float64(p.ts.UnixNano()) / 1e9}
	}, false, "到达时间（Unix 秒）"})
	registerField("frame.protocols", fieldSpec{valStr, func(p *pkt) val {
		return strVal(strings.Join(protocolStack(p), ":"))
	}, false, "协议栈，如 ethertype:ip:tcp:http"})

	// eth.src / eth.dst 都返回双向 MAC：Wireshark 里这两个字段等价
	macPair := func(p *pkt) val { return multi(macVal(p.srcMAC()), macVal(p.dstMAC())) }
	registerField("eth.src", fieldSpec{valMAC, macPair, false, "以太网 MAC（源或目的）"})
	registerField("eth.dst", fieldSpec{valMAC, macPair, false, "以太网 MAC（源或目的）"})
	registerField("eth.addr", fieldSpec{valMAC, macPair, false, "同 eth.src"})
	registerField("eth.type", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.etype))
	}, false, "EtherType"})
}

// registerNetFields 注册网络层字段。
func registerNetFields() {
	registerField("ip.src", fieldSpec{valIP, func(p *pkt) val { return ipVal(p.srcIP) }, false, "源 IP"})
	registerField("ip.dst", fieldSpec{valIP, func(p *pkt) val { return ipVal(p.dstIP) }, false, "目的 IP"})
	registerField("ip.addr", fieldSpec{valIP, func(p *pkt) val {
		return multi(ipVal(p.srcIP), ipVal(p.dstIP))
	}, false, "源或目的 IP"})
	registerField("ipv6.src", fieldSpec{valIP, func(p *pkt) val { return ipVal(p.srcIP) }, false, "源 IPv6"})
	registerField("ipv6.dst", fieldSpec{valIP, func(p *pkt) val { return ipVal(p.dstIP) }, false, "目的 IPv6"})
	registerField("ipv6.addr", fieldSpec{valIP, func(p *pkt) val {
		return multi(ipVal(p.srcIP), ipVal(p.dstIP))
	}, false, "源或目的 IPv6"})

	// 以下字段仅在详细解码时填充
	registerField("ip.proto", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.ipProto))
	}, true, "IP 协议号"})
	registerField("ip.ttl", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.ipTTL))
	}, true, "TTL / Hop Limit"})
	registerField("ip.len", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.ipLen))
	}, true, "IP 总长度"})
	registerField("ip.id", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.ipID))
	}, true, "IP 标识"})
	registerField("ip.tos", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.ipTOS))
	}, true, "DSCP / ECN"})
	registerField("ip.dsfield", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.ipTOS))
	}, true, "同 ip.tos"})
	registerField("ip.version", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.ipVer))
	}, true, "IP 版本号"})
	registerField("ip.hdr_len", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.ipIHL))
	}, true, "IP 头长度（字节）"})
	registerField("ip.checksum", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.ipCksum))
	}, true, "IP 头校验和"})
	registerField("ip.flags.df", fieldSpec{valBool, func(p *pkt) val {
		return val{kind: valBool, b: p.fragDF}
	}, true, "不分片标志"})
	registerField("ip.flags.mf", fieldSpec{valBool, func(p *pkt) val {
		return val{kind: valBool, b: p.fragMore}
	}, true, "更多分片标志"})
	registerField("ip.frag_offset", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.fragOff) * 8)
	}, true, "分片偏移（字节）"})
}

// registerTransportFields 注册传输层字段。
func registerTransportFields() {
	// 端口字段：按协议名注册，值取该帧实际的 src/dst 端口
	portField := func(name, doc string) {
		registerField(name, fieldSpec{valInt, func(p *pkt) val {
			return multi(intVal(int64(p.srcPort)), intVal(int64(p.dstPort)))
		}, false, doc})
	}
	portField("tcp.port", "TCP 源或目的端口")
	portField("udp.port", "UDP 源或目的端口")
	registerField("tcp.srcport", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.srcPort))
	}, false, "TCP 源端口"})
	registerField("tcp.dstport", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.dstPort))
	}, false, "TCP 目的端口"})
	registerField("udp.srcport", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.srcPort))
	}, false, "UDP 源端口"})
	registerField("udp.dstport", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.dstPort))
	}, false, "UDP 目的端口"})

	// 以下字段仅在详细解码时填充
	registerField("tcp.seq", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.seq))
	}, true, "TCP 序号"})
	registerField("tcp.ack", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.ack))
	}, true, "TCP 确认号"})
	registerField("tcp.window_size_value", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.win))
	}, true, "TCP 窗口大小"})
	registerField("tcp.hdr_len", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.tcpHdrLen))
	}, true, "TCP 头长度（字节）"})
	registerField("tcp.urgent_pointer", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.tcpUrgent))
	}, true, "TCP 紧急指针"})
	registerField("tcp.checksum", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.tcpCksum))
	}, true, "TCP 校验和"})
	registerField("tcp.payload_len", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(len(p.payload)))
	}, false, "TCP 载荷长度（字节）"})
	registerField("udp.length", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.udpLen))
	}, true, "UDP 长度"})
	registerField("udp.checksum", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.udpCksum))
	}, true, "UDP 校验和"})
	registerField("icmp.type", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.icmpType))
	}, true, "ICMP 类型"})
	registerField("icmp.code", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.icmpCode))
	}, true, "ICMP 代码"})
	registerField("icmp.seq", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.icmpSeq))
	}, true, "ICMP 序列号"})
	registerField("icmp.ident", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.icmpID))
	}, true, "ICMP 标识符"})

	// TCP 标志位：整体掩码 + 逐位布尔
	registerField("tcp.flags", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.flags))
	}, false, "TCP 标志位（8 位掩码）"})
	registerField("tcp.flags.num", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.flags))
	}, false, "同 tcp.flags"})
	for _, fb := range []struct {
		name string
		mask uint8
	}{
		{"fin", 0x01}, {"syn", 0x02}, {"rst", 0x04}, {"psh", 0x08},
		{"ack", 0x10}, {"urg", 0x20}, {"ece", 0x40}, {"cwr", 0x80},
	} {
		mask := fb.mask
		registerField("tcp.flags."+fb.name, fieldSpec{valBool, func(p *pkt) val {
			return val{kind: valBool, b: p.flags&mask != 0}
		}, false, "TCP " + strings.ToUpper(fb.name) + " 标志"})
	}

	// ARP
	registerField("arp.src.proto_ipv4", fieldSpec{valIP, func(p *pkt) val {
		return ipVal(net.ParseIP(p.arpSenderIP))
	}, true, "ARP 发送方 IP"})
	registerField("arp.dst.proto_ipv4", fieldSpec{valIP, func(p *pkt) val {
		return ipVal(net.ParseIP(p.arpTgtIP))
	}, true, "ARP 目标 IP"})
	registerField("arp.opcode", fieldSpec{valInt, func(p *pkt) val {
		return intVal(int64(p.arpOp))
	}, true, "ARP 操作码（1 请求 / 2 应答）"})
}

// registerAppFields 注册应用层字段，以及协议名的存在性过滤。
func registerAppFields() {
	registerField("http.host", fieldSpec{valStr, func(p *pkt) val {
		if p.app != "HTTP" {
			return strVal("")
		}
		h, _ := httpReqInfo(p.payload)
		return strVal(h)
	}, false, "HTTP Host 头"})
	registerField("http.request.method", fieldSpec{valStr, func(p *pkt) val {
		if p.app != "HTTP" || !isHTTPRequest(p.payload) {
			return strVal("")
		}
		if i := strings.IndexByte(p.info, ' '); i > 0 {
			return strVal(p.info[:i])
		}
		return strVal("")
	}, false, "HTTP 请求方法"})
	registerField("http.request.uri", fieldSpec{valStr, func(p *pkt) val {
		if p.app != "HTTP" {
			return strVal("")
		}
		return strVal(httpPath(p.info))
	}, false, "HTTP 请求路径"})
	registerField("http.request.full_uri", fieldSpec{valStr, func(p *pkt) val {
		if p.app != "HTTP" {
			return strVal("")
		}
		return strVal(httpPath(p.info))
	}, false, "同 http.request.uri"})
	registerField("http.user_agent", fieldSpec{valStr, func(p *pkt) val {
		if p.app != "HTTP" {
			return strVal("")
		}
		return strVal(headerValue(p.payload, "User-Agent"))
	}, false, "HTTP User-Agent"})
	registerField("http.response.code", fieldSpec{valInt, func(p *pkt) val {
		if p.app != "HTTP" || isHTTPRequest(p.payload) {
			return intVal(0)
		}
		return intVal(int64(httpStatusCode(p.info)))
	}, false, "HTTP 响应状态码"})
	registerField("tls.handshake.extensions_server_name", fieldSpec{valStr, func(p *pkt) val {
		if p.app != "TLS" {
			return strVal("")
		}
		return strVal(clientHelloSNI(p.payload))
	}, false, "TLS SNI（Server Name Indication）"})
	registerField("tls.sni", fieldSpec{valStr, func(p *pkt) val {
		if p.app != "TLS" {
			return strVal("")
		}
		return strVal(clientHelloSNI(p.payload))
	}, false, "同 tls.handshake.extensions_server_name"})
	registerField("dns.qry.name", fieldSpec{valStr, func(p *pkt) val {
		m, ok := parseDNS(p.payload, p.l4 == "TCP")
		if !ok {
			return strVal("")
		}
		return strVal(m.qname)
	}, false, "DNS 查询名"})
	registerField("dns.resp.name", fieldSpec{valStr, func(p *pkt) val {
		m, ok := parseDNS(p.payload, p.l4 == "TCP")
		if !ok || m.qr {
			return strVal("")
		}
		return strVal(m.qname)
	}, false, "DNS 应答里的查询名"})
	registerField("dns.flags.response", fieldSpec{valBool, func(p *pkt) val {
		m, ok := parseDNS(p.payload, p.l4 == "TCP")
		return val{kind: valBool, b: ok && m.qr}
	}, false, "DNS 是否为应答"})
	registerField("data.data", fieldSpec{valStr, func(p *pkt) val {
		return strVal(string(p.payload))
	}, false, "载荷原始内容（配合 contains 使用）"})

	// 协议名注册为"存在性"字段：tcp、udp、dns、http … 裸写即等价于 == 1
	registerProtoFields()
	registerLegacyAliases()
}

// registerLegacyAliases 注册旧语法里的简写字段。
//
// "port 80" 在旧语法里是独立关键字；新语法要能写 "port == 80"，
// 否则从旧写法迁移过来会直接报"未知字段"。
func registerLegacyAliases() {
	portAny := func(p *pkt) val {
		return multi(intVal(int64(p.srcPort)), intVal(int64(p.dstPort)))
	}
	registerField("port", fieldSpec{valInt, portAny, false, "源或目的端口（旧语法简写）"})
	registerField("host", fieldSpec{valIP, func(p *pkt) val {
		return multi(ipVal(p.srcIP), ipVal(p.dstIP))
	}, false, "源或目的 IP（旧语法简写）"})
}

// registerProtoFields 把已知协议名注册为存在性字段。
func registerProtoFields() {
	for name := range protoSet() {
		pn := name
		registerField(pn, fieldSpec{valInt, func(p *pkt) val {
			if matchProto(pn, p) {
				return intVal(1)
			}
			return intVal(0)
		}, false, "协议存在性（等价于 " + pn + "）"})
	}
	for _, an := range appFieldNames() {
		an := an
		registerField(an, fieldSpec{valInt, func(p *pkt) val {
			if strings.EqualFold(p.app, an) {
				return intVal(1)
			}
			return intVal(0)
		}, false, "应用层协议存在性（等价于 " + an + "）"})
	}
}

// appFieldNames 返回可作为字段的应用层协议名（已排序）。
func appFieldNames() []string {
	set := map[string]bool{}
	for _, n := range appByPort {
		set[strings.ToLower(n)] = true
	}
	for _, n := range []string{
		"HTTP", "DNS", "TLS", "HTTP2", "QUIC", "SSH",
		"SMTP", "FTP", "POP3", "IMAP", "NTP", "DHCP", "MDNS", "LLMNR",
	} {
		set[strings.ToLower(n)] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

// httpPath 从 "GET /index.html HTTP/1.1" 里取出请求路径。
func httpPath(info string) string {
	i := strings.IndexByte(info, ' ')
	if i <= 0 {
		return ""
	}
	rest := info[i+1:]
	if j := strings.IndexByte(rest, ' '); j > 0 {
		return rest[:j]
	}
	return rest
}

// headerValue 从 HTTP 载荷里取指定头字段的值。
func headerValue(payload []byte, name string) string {
	lower := strings.ToLower(name)
	for _, line := range strings.Split(string(payload), "\r\n") {
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(line[:i]), lower) {
			return strings.TrimSpace(line[i+1:])
		}
	}
	return ""
}

// httpStatusCode 从 "HTTP/1.1 200 OK" 里取出状态码。
func httpStatusCode(info string) int {
	if !strings.HasPrefix(info, "HTTP/") {
		return 0
	}
	parts := strings.SplitN(info, " ", 3)
	if len(parts) < 2 {
		return 0
	}
	n := 0
	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// fieldHelp 列出全部字段与说明，供 TUI 的过滤帮助使用。
func fieldHelp() string {
	var b strings.Builder
	for _, n := range fieldNames() {
		b.WriteString("  ")
		b.WriteString(n)
		for i := len(n); i < 34; i++ {
			b.WriteByte(' ')
		}
		b.WriteString(fieldTable[n].doc)
		b.WriteByte('\n')
	}
	return b.String()
}
