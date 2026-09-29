// 应用层识别与载荷解析。
//
// 识别顺序：先看载荷特征（HTTP/TLS/SSH 这类有魔数或语法的），
// 再退回端口映射；解析结果供列表摘要与统计两处使用。
package net

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"gyhost/internal/utils"
)

// appByPort 端口 → 应用层协议名（协议统计口径）。
// 443/993 这类端口按其承载的协议算 TLS，避免同一条流被拆成两个名字。
var appByPort = map[uint16]string{
	20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet",
	25: "SMTP", 587: "SMTP", 465: "TLS",
	53: "DNS", 5353: "mDNS", 5355: "LLMNR",
	67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP",
	110: "POP3", 143: "IMAP", 993: "TLS", 995: "TLS",
	137: "NBNS", 138: "NBDS", 139: "NBSS", 445: "SMB",
	161: "SNMP", 162: "SNMP", 389: "LDAP", 636: "TLS", 88: "Kerberos",
	80: "HTTP", 8080: "HTTP", 8000: "HTTP", 8888: "HTTP",
	443: "TLS", 8443: "TLS", 853: "TLS",
	111: "portmap", 2049: "NFS", 3128: "HTTP",
	514: "Syslog", 520: "RIP", 623: "IPMI", 1900: "SSDP",
	5060: "SIP", 5061: "TLS", 1723: "PPTP", 1701: "L2TP",
	1883: "MQTT", 8883: "TLS", 5672: "AMQP", 61613: "MQTT",
	3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 1521: "Oracle",
	27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached",
	5900: "VNC", 3389: "RDP", 6667: "IRC", 1935: "RTMP", 554: "RTSP",
	179: "BGP", 500: "IKE", 4500: "IKE", 1194: "OpenVPN", 51820: "WireGuard",
	6666: "IRC", 6697: "IRC",
}

// portService 端口 → 服务名（端口表的展示口径，比协议名更贴近 /etc/services）。
var portService = map[uint16]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
	25: "smtp", 587: "submission", 465: "smtps",
	53: "dns", 5353: "mdns", 5355: "llmnr", 67: "dhcp", 68: "dhcp",
	69: "tftp", 123: "ntp", 110: "pop3", 143: "imap", 993: "imaps", 995: "pop3s",
	137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 445: "microsoft-ds",
	161: "snmp", 162: "snmptrap", 389: "ldap", 636: "ldaps", 88: "kerberos",
	80: "http", 8080: "http-alt", 8000: "http-alt", 8888: "http-alt",
	443: "https", 8443: "https-alt", 853: "domain-s",
	111: "rpcbind", 2049: "nfs", 3128: "squid", 514: "syslog", 520: "rip",
	1900: "ssdp", 5060: "sip", 5061: "sips", 1701: "l2tp", 1723: "pptp",
	1883: "mqtt", 8883: "mqtts", 5672: "amqp",
	3306: "mysql", 5432: "postgres", 1433: "ms-sql-s", 1521: "oracle",
	27017: "mongodb", 6379: "redis", 9200: "elasticsearch", 11211: "memcache",
	5900: "vnc", 3389: "ms-wbt", 6667: "irc", 1935: "rtmp", 554: "rtsp",
	179: "bgp", 500: "isakmp", 4500: "ike-nat", 1194: "openvpn", 51820: "wireguard",
	623: "ipmi", 6666: "irc", 6697: "irc",
}

// httpMethods 支持识别的 HTTP 方法（避免把 SSH 横幅之类误判成请求行）。
var httpMethods = map[string]bool{
	"GET": true, "POST": true, "HEAD": true, "PUT": true, "DELETE": true,
	"OPTIONS": true, "PATCH": true, "TRACE": true, "CONNECT": true,
	"PROPFIND": true, "PROPPATCH": true, "MKCOL": true, "COPY": true,
	"MOVE": true, "LOCK": true, "UNLOCK": true, "SEARCH": true,
	"REPORT": true, "NOTIFY": true, "SUBSCRIBE": true, "UNSUBSCRIBE": true,
	"PURGE": true, "LINK": true, "UNLINK": true,
}

// ---------------------------------------------------------------------------
// 识别
// ---------------------------------------------------------------------------

// classifyApp 给传输层帧标注应用层协议与摘要。
func classifyApp(p *pkt) {
	if p.l4 != "TCP" && p.l4 != "UDP" {
		return
	}
	// 报告模式不需要摘要：只做协议判定，省掉每帧的字符串构造
	if len(p.payload) > 0 {
		name, info := sniffPayload(p.payload, p.l4 == "TCP", p.wantInfo)
		if name != "" {
			p.app = name
			p.info = info
			return
		}
	}
	if name := appByPort[p.dstPort]; name != "" {
		p.app = name
	} else {
		p.app = appByPort[p.srcPort]
	}
	// 按端口识别出来的协议没有载荷嗅探摘要，这里补一个（列表摘要）
	if p.app != "" && p.info == "" && p.wantInfo {
		p.info = appInfo(p)
	}
}

// appInfo 为按端口识别的应用层生成列表摘要（语言中性，形如 tshark 的 Info 列）。
//
// 载荷嗅探（HTTP/TLS/DTLS/SSH）已经自带摘要，这里只补文本类与结构化类协议。
func appInfo(p *pkt) string {
	if len(p.payload) == 0 {
		return ""
	}
	switch p.app {
	case "DNS", "mDNS", "LLMNR":
		return dnsInfo(p)
	case "DHCP", "DHCPv6":
		return dhcpInfo(p.payload)
	case "FTP", "FTP-data", "POP3", "IMAP", "SMTP", "IRC", "Telnet", "NNTP", "SIP", "LDAP":
		return textLineInfo(p.payload)
	}
	return ""
}

// dnsInfo 生成 DNS 摘要：
//
//	"A example.com"（查询）、"A example.com -> 93.184.216.34"（应答）、
//	"NXDOMAIN nope.invalid"（失败应答）。
func dnsInfo(p *pkt) string {
	m, ok := parseDNS(p.payload, p.l4 == "TCP")
	if !ok || m.qname == "" {
		return ""
	}
	if !m.qr {
		return dnsTypeName(m.qtype) + " " + m.qname
	}
	if m.rcode != 0 {
		return dnsRcodeName(m.rcode) + " " + m.qname
	}
	if len(m.answers) > 0 {
		return m.qname + " -> " + strings.Join(m.answers, ", ")
	}
	return dnsTypeName(m.qtype) + " " + m.qname
}

// textLineInfo 取文本协议的首行作为摘要；非可打印内容返回空串（退回长度摘要）。
func textLineInfo(b []byte) string {
	line, _ := firstLine(b)
	line = strings.TrimRight(line, "\r")
	if !printableASCII(line) {
		return ""
	}
	return utils.TruncateVisible(line, 72)
}

// printableASCII 判断整串是否为可打印 ASCII（制表符也算）。
func printableASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '\t' {
			continue
		}
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// sniffPayload 按载荷特征识别协议，命中时同时返回列表摘要。
//
// wantInfo 为 false 时只判定协议名，不构造摘要字符串（大流量下的主要开销）。
func sniffPayload(b []byte, isTCP, wantInfo bool) (string, string) {
	if !isTCP {
		if s, ok := sniffDTLS(b); ok {
			return "DTLS", s
		}
		return "", ""
	}
	if ok := isHTTPRequest(b); ok {
		if !wantInfo {
			return "HTTP", ""
		}
		s, _ := httpRequest(b)
		return "HTTP", s
	}
	if ok := isHTTPResponse(b); ok {
		if !wantInfo {
			return "HTTP", ""
		}
		s, _ := httpResponse(b)
		return "HTTP", s
	}
	if ok := isTLSRecord(b); ok {
		if !wantInfo {
			return "TLS", ""
		}
		s, _ := tlsRecord(b)
		return "TLS", s
	}
	if len(b) >= 4 && string(b[:4]) == "SSH-" {
		if !wantInfo {
			return "SSH", ""
		}
		line := b
		if i := bytes.IndexAny(line, "\r\n"); i >= 0 {
			line = line[:i]
		}
		return "SSH", string(line)
	}
	return "", ""
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

// isHTTPRequest 判断是否为 HTTP 请求行（不构造摘要字符串）。
func isHTTPRequest(b []byte) bool {
	i := bytes.IndexByte(b, ' ')
	if i <= 0 {
		return false
	}
	return httpMethods[string(b[:i])]
}

// isHTTPResponse 判断是否为 HTTP 响应行（不构造摘要字符串）。
func isHTTPResponse(b []byte) bool {
	return bytes.HasPrefix(b, httpPrefix)
}

// httpPrefix 是 HTTP 响应行的固定前缀。
var httpPrefix = []byte("HTTP/")

// isTLSRecord 判断是否为 TLS 记录（不构造摘要字符串）。
func isTLSRecord(b []byte) bool {
	if len(b) < 5 || b[1] != 0x03 || b[2] > 0x04 {
		return false
	}
	switch b[0] {
	case 20, 21, 22, 23, 24:
	default:
		return false
	}
	// 记录长度上限：2^14 + 开销，防止把随机数据当 TLS
	return int(binary.BigEndian.Uint16(b[3:5])) <= 18436
}

// httpRequestURI 从请求行里取出 URI（第二段），不构造整行的字符串。
func httpRequestURI(b []byte) (string, bool) {
	limit := len(b)
	if limit > 4096 {
		limit = 4096
	}
	head := b[:limit]
	sp := bytes.IndexByte(head, ' ')
	if sp <= 0 {
		return "", false
	}
	rest := head[sp+1:]
	// 跳过 URI 后的分隔符
	for len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
		rest = rest[1:]
	}
	end := 0
	for end < len(rest) && rest[end] != ' ' && rest[end] != '\t' &&
		rest[end] != '\r' && rest[end] != '\n' {
		end++
	}
	if end == 0 {
		return "", false
	}
	return string(rest[:end]), true
}

// httpRequest 判断是否为 HTTP 请求并生成摘要 "GET /index.html HTTP/1.1"。
func httpRequest(b []byte) (string, bool) {
	line, _ := firstLine(b)
	fields := strings.Fields(line)
	if len(fields) < 2 || !httpMethods[fields[0]] {
		return "", false
	}
	return line, true
}

// httpResponse 判断是否为 HTTP 响应并生成摘要 "HTTP/1.1 200 OK"。
func httpResponse(b []byte) (string, bool) {
	line, _ := firstLine(b)
	if !strings.HasPrefix(line, "HTTP/") {
		return "", false
	}
	return line, true
}

// firstLine 取载荷的第一行（按前 4 KiB 查找换行）。
func firstLine(b []byte) (string, []byte) {
	limit := len(b)
	if limit > 4096 {
		limit = 4096
	}
	head := b[:limit]
	i := bytes.IndexByte(head, '\n')
	if i < 0 {
		return strings.TrimRight(string(head), "\r"), b
	}
	return strings.TrimRight(string(head[:i]), "\r"), b[i+1:]
}

// httpHeadEnd 返回 HTTP 头部（不含结尾空行）的字节切片，最多取前 64 KiB。
// 抓包被截断或头部跨包时，只返回当前帧里能看到的部分。
func httpHeadEnd(b []byte) []byte {
	if len(b) > 64<<10 {
		b = b[:64<<10]
	}
	if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
		return b[:i]
	}
	if i := bytes.Index(b, []byte("\n\n")); i >= 0 {
		return b[:i]
	}
	return b
}

// splitHTTPHead 返回头部文本（请求行 + 全部头），最多取前 64 KiB。
// 抓包被截断或头部跨包时，只解析当前帧里能看到的部分。
func splitHTTPHead(b []byte) string {
	return string(httpHeadEnd(b))
}

// httpReqInfo 解析 HTTP 请求的关键头（Host、Authorization）。
// 返回主机名与 Basic/Digest 解出的凭据（若有）。
//
// 逐行扫描字节切片，不复制整段头部、也不构造行切片。
func httpReqInfo(b []byte) (host string, creds []rawCred) {
	head := httpHeadEnd(b)
	first := true
	for len(head) > 0 {
		line := head
		if i := bytes.IndexByte(head, '\n'); i >= 0 {
			line, head = head[:i], head[i+1:]
		} else {
			head = nil
		}
		line = bytes.TrimRight(line, "\r")
		if first { // 跳过请求行
			first = false
			continue
		}
		j := bytes.IndexByte(line, ':')
		if j < 0 {
			continue
		}
		name := asciiLowerTrim(line[:j])
		val := string(bytes.TrimSpace(line[j+1:]))
		switch string(name) {
		case "host":
			if host == "" {
				host = val
			}
		case "authorization", "proxy-authorization":
			if c, ok := authCred(val); ok {
				creds = append(creds, c)
			}
		}
	}
	return host, creds
}

// asciiLowerTrim 把字节切片转成小写字符串并去掉首尾空白（头名不分配中间切片）。
func asciiLowerTrim(b []byte) string {
	b = bytes.TrimSpace(b)
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

// authCred 解析 Authorization 头的值。
//
// Basic:  base64(user:pass)  → 直接解出明文
// Digest: 只暴露 username 等公开字段，取 username
func authCred(v string) (rawCred, bool) {
	switch {
	case strings.HasPrefix(strings.ToLower(v), "basic "):
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[6:]))
		if err != nil {
			raw, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(v[6:]))
		}
		if err != nil {
			return rawCred{}, false
		}
		return rawCred{kind: "Authorization", value: string(raw)}, true
	case strings.HasPrefix(strings.ToLower(v), "digest "):
		if u := digestField(v, "username"); u != "" {
			return rawCred{kind: "Authorization", value: "username=" + u}, true
		}
	}
	return rawCred{}, false
}

// digestField 从 Digest 头里取某个字段的值（引号内的内容）。
func digestField(v, key string) string {
	k := key + "="
	i := strings.Index(strings.ToLower(v), strings.ToLower(k))
	if i < 0 {
		return ""
	}
	s := v[i+len(k):]
	if strings.HasPrefix(s, `"`) {
		if j := strings.IndexByte(s[1:], '"'); j >= 0 {
			return s[1 : 1+j]
		}
		return ""
	}
	if j := strings.IndexByte(s, ','); j >= 0 {
		s = s[:j]
	}
	return strings.TrimSpace(s)
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

// tlsRecord 判断是否为 TLS 记录并生成摘要（如 "ClientHello SNI=a.com"）。
func tlsRecord(b []byte) (string, bool) {
	if len(b) < 5 || b[1] != 0x03 || b[2] > 0x04 {
		return "", false
	}
	switch b[0] {
	case 20, 21, 22, 23, 24:
	default:
		return "", false
	}
	// 记录长度上限：2^14 + 开销，防止把随机数据当 TLS
	if n := int(binary.BigEndian.Uint16(b[3:5])); n > 18436 {
		return "", false
	}
	return tlsInfo(b), true
}

// sniffDTLS 识别 DTLS 记录（版本 0xfe 系列）。
func sniffDTLS(b []byte) (string, bool) {
	if len(b) < 5 || b[1] != 0xfe {
		return "", false
	}
	switch b[0] {
	case 20, 21, 22, 23, 24:
	default:
		return "", false
	}
	if n := int(binary.BigEndian.Uint16(b[3:5])); n > 16384+2048 {
		return "", false
	}
	return tlsInfo(b), true
}

// tlsInfo 渲染 TLS 记录类型；握手记录进一步区分 ClientHello/ServerHello。
func tlsInfo(b []byte) string {
	names := map[byte]string{20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "Application Data", 24: "Heartbeat"}
	name := names[b[0]]
	if b[0] != 22 || len(b) < 6 {
		return name
	}
	hs := map[byte]string{
		1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket",
		11: "Certificate", 12: "ServerKeyExchange", 13: "CertificateRequest",
		14: "ServerHelloDone", 15: "CertificateVerify", 16: "ClientKeyExchange",
		20: "Finished", 8: "EncryptedExtensions",
	}
	h := hs[b[5]]
	if h == "" {
		return name
	}
	if b[5] == 1 {
		if sni := clientHelloSNI(b); sni != "" {
			return h + " SNI=" + sni
		}
	}
	return h
}

// clientHelloSNI 从 TLS ClientHello 记录里解析 server_name 扩展。
//
// 走完整个握手结构，任何一步越界都返回空串（宁可不显示也不猜）。
func clientHelloSNI(b []byte) string {
	// 记录层: type(1) ver(2) len(2)
	if len(b) < 5+4 {
		return ""
	}
	rec := 5 + int(binary.BigEndian.Uint16(b[3:5]))
	if rec > len(b) {
		rec = len(b) // 抓包截断
	}
	body := b[5:rec]
	if len(body) < 4 || body[0] != 1 { // handshake type = ClientHello
		return ""
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if 4+hsLen > len(body) {
		hsLen = len(body) - 4
	}
	p := body[4 : 4+hsLen]
	need := func(n int) bool { return len(p) >= n }

	if !need(34) { // client_version(2) + random(32)
		return ""
	}
	p = p[34:]
	if !need(1) {
		return ""
	}
	n := int(p[0])
	if !need(1 + n) {
		return ""
	}
	p = p[1+n:] // session_id
	if !need(2) {
		return ""
	}
	n = int(binary.BigEndian.Uint16(p[:2]))
	if !need(2 + n) {
		return ""
	}
	p = p[2+n:] // cipher_suites
	if !need(1) {
		return ""
	}
	n = int(p[0])
	if !need(1 + n) {
		return ""
	}
	p = p[1+n:] // compression_methods
	if !need(2) {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if extLen > len(p) {
		extLen = len(p)
	}
	exts := p[:extLen]
	for len(exts) >= 4 {
		typ := binary.BigEndian.Uint16(exts[0:2])
		n := int(binary.BigEndian.Uint16(exts[2:4]))
		if 4+n > len(exts) {
			return ""
		}
		val := exts[4 : 4+n]
		if typ == 0 { // server_name
			return serverName(val)
		}
		exts = exts[4+n:]
	}
	return ""
}

// serverName 解析 server_name 扩展体：list_len(2) + [type(1) len(2) name..]
func serverName(v []byte) string {
	if len(v) < 5 {
		return ""
	}
	if v[2] != 0 { // name_type = host_name
		return ""
	}
	n := int(binary.BigEndian.Uint16(v[3:5]))
	if 5+n > len(v) {
		return ""
	}
	return string(v[5 : 5+n])
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

// dnsMsg 是一条 DNS 报文的解析结果。
type dnsMsg struct {
	qr      bool
	opcode  byte
	rcode   byte
	qname   string
	qtype   uint16
	answers []string // 应答里的 A/AAAA 地址（最多 6 条）
	ancount int
}

// parseDNS 解析 DNS 报文（UDP 直接读，TCP 多 2 字节长度前缀）。
// 只有报头可信时也会返回 ok=true，便于统计失败响应。
func parseDNS(b []byte, isTCP bool) (dnsMsg, bool) {
	off := 0
	if isTCP {
		if len(b) < 12+2 {
			return dnsMsg{}, false
		}
		off = 2
	}
	if len(b) < off+12 {
		return dnsMsg{}, false
	}
	flags := binary.BigEndian.Uint16(b[off+2 : off+4])
	opcode := byte((flags >> 11) & 0xf)
	if opcode > 5 { // 不是 DNS
		return dnsMsg{}, false
	}
	m := dnsMsg{
		qr:      flags&0x8000 != 0,
		opcode:  opcode,
		rcode:   byte(flags & 0xf),
		ancount: int(binary.BigEndian.Uint16(b[off+6 : off+8])),
	}
	pos := off + 12
	qd := int(binary.BigEndian.Uint16(b[off+4 : off+6]))
	if qd > 0 {
		name, npos, ok := readDNSName(b, pos)
		if !ok || npos+4 > len(b) {
			return m, true
		}
		m.qname = name
		m.qtype = binary.BigEndian.Uint16(b[npos : npos+2])
		pos = npos + 4
	}
	for i := 0; i < m.ancount && i < 64; i++ {
		_, npos, ok := readDNSName(b, pos)
		if !ok || npos+10 > len(b) {
			break
		}
		typ := binary.BigEndian.Uint16(b[npos : npos+2])
		rdlen := int(binary.BigEndian.Uint16(b[npos+8 : npos+10]))
		if npos+10+rdlen > len(b) {
			break
		}
		rdata := b[npos+10 : npos+10+rdlen]
		if typ == 1 && rdlen == 4 && len(m.answers) < 6 {
			m.answers = append(m.answers, net4(rdata))
		} else if typ == 28 && rdlen == 16 && len(m.answers) < 6 {
			m.answers = append(m.answers, net16(rdata))
		}
		pos = npos + 10 + rdlen
	}
	return m, true
}

// readDNSName 读域名（支持压缩指针），返回名字与下一字段偏移。
func readDNSName(b []byte, off int) (string, int, bool) {
	var (
		parts   []string
		pos     = off
		steps   int
		nextOff = -1
	)
	for {
		steps++
		if pos >= len(b) || steps > 128 {
			return "", 0, false
		}
		n := int(b[pos])
		switch {
		case n == 0:
			pos++
			if nextOff < 0 {
				nextOff = pos
			}
			if len(parts) == 0 {
				return ".", nextOff, true
			}
			return strings.Join(parts, "."), nextOff, true
		case n&0xc0 == 0xc0: // 压缩指针
			if pos+1 >= len(b) {
				return "", 0, false
			}
			if nextOff < 0 {
				nextOff = pos + 2
			}
			pos = (n&0x3f)<<8 | int(b[pos+1])
		case n&0xc0 != 0:
			return "", 0, false
		default:
			if pos+1+n > len(b) {
				return "", 0, false
			}
			parts = append(parts, string(b[pos+1:pos+1+n]))
			pos += 1 + n
		}
	}
}

// net4 / net16 把网络字节序地址渲染成可读 IP。
func net4(b []byte) string { return net.IP(b).String() }

func net16(b []byte) string { return net.IP(b).String() }

// dnsTypeName 把 DNS 查询类型编号渲染成可读名。
func dnsTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 35:
		return "NAPTR"
	case 41:
		return "OPT"
	case 43:
		return "DS"
	case 46:
		return "RRSIG"
	case 47:
		return "NSEC"
	case 48:
		return "DNSKEY"
	case 52:
		return "TLSA"
	case 65:
		return "HTTPS"
	case 64:
		return "SVCB"
	case 99:
		return "SPF"
	case 255:
		return "ANY"
	case 257:
		return "CAA"
	}
	return fmt.Sprintf("TYPE%d", t)
}

// dnsRcodeName 渲染响应码。
func dnsRcodeName(r byte) string {
	switch r {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	}
	return fmt.Sprintf("RCODE%d", r)
}

// ---------------------------------------------------------------------------
// DHCP
// ---------------------------------------------------------------------------

// dhcpMsgTypes DHCP 选项 53 的消息类型名。
var dhcpMsgTypes = map[byte]string{
	1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
	5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM",
}

// dhcpInfo 解析 DHCP 报文的消息类型；不是 DHCP 时返回空串。
//
// BOOTP 定长部分 236 字节，其后是 4 字节 magic cookie，再往后是选项。
func dhcpInfo(b []byte) string {
	if len(b) < 241 {
		return ""
	}
	// magic cookie: 0x63825363
	if binary.BigEndian.Uint32(b[236:240]) != 0x63825363 {
		return ""
	}
	for i := 240; i+1 < len(b); {
		code := b[i]
		if code == 0xff { // End
			break
		}
		if code == 0x00 { // Pad
			i++
			continue
		}
		n := int(b[i+1])
		if i+2+n > len(b) {
			break
		}
		if code == 53 && n >= 1 {
			if name := dhcpMsgTypes[b[i+2]]; name != "" {
				return name
			}
			return fmt.Sprintf("MSG%d", b[i+2])
		}
		i += 2 + n
	}
	return ""
}

// ---------------------------------------------------------------------------
// 凭据抽取
// ---------------------------------------------------------------------------

// rawCred 是从载荷里直接读出的一条明文凭据。
type rawCred struct {
	kind  string // USER / PASS / LOGIN / Authorization / AUTH PLAIN
	value string // 明文内容
}

// httpField 是 HTTP 请求里的一个键值字段（查询串或表单体）。
type httpField struct {
	key   string
	value string
}

// scanCreds 按协议从载荷里抽取明文凭据。
//
// 只做单帧解析，不做 TCP 流重组：跨包的 AUTH LOGIN 之类拿不到，会明确不认。
func scanCreds(app string, b []byte) []rawCred {
	var out []rawCred
	switch app {
	case "FTP", "POP3":
		eachLine(b, func(line string) {
			upper := strings.ToUpper(line)
			for _, kw := range []string{"USER ", "PASS "} {
				if strings.HasPrefix(upper, kw) && len(line) > len(kw) {
					out = append(out, rawCred{kind: kw[:4], value: strings.TrimSpace(line[len(kw):])})
				}
			}
		})
	case "IMAP":
		eachLine(b, func(line string) {
			f := strings.Fields(line)
			if len(f) >= 4 && strings.EqualFold(f[1], "LOGIN") {
				out = append(out, rawCred{kind: "LOGIN", value: f[2] + ":" + f[3]})
			}
		})
	case "SMTP":
		eachLine(b, func(line string) {
			if !strings.HasPrefix(strings.ToUpper(line), "AUTH PLAIN") {
				return
			}
			v := strings.TrimSpace(line[len("AUTH PLAIN"):])
			raw, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				raw, err = base64.RawStdEncoding.DecodeString(v)
			}
			if err != nil {
				return
			}
			// AUTH PLAIN: \0username\0password
			parts := strings.Split(string(raw), "\x00")
			if len(parts) >= 3 {
				out = append(out, rawCred{kind: "AUTH PLAIN", value: parts[1] + ":" + parts[2]})
			}
		})
	case "HTTP":
		_, out = httpReqInfo(b)
	}
	return out
}

// scanPassFields 找出 HTTP 载荷里形如 password=xxx 的明文口令字段。
//
// 这里保留"先转小写副本再 bytes.Index"的写法：bytes.Index 走的是 SIMD
// 加速路径，实测比逐字节大小写无关匹配快得多（每个请求只多一次拷贝）。
func scanPassFields(b []byte) []httpField {
	if len(b) > 64<<10 {
		b = b[:64<<10]
	}
	lower := asciiLower(b)
	var out []httpField
	for _, key := range passKeys {
		k := []byte(key + "=")
		for start := 0; start < len(lower); {
			i := bytes.Index(lower[start:], k)
			if i < 0 {
				break
			}
			i += start
			// 前缀必须是分隔符，避免命中 "cpasswd=" 这类子串
			if i > 0 {
				c := lower[i-1]
				if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
					start = i + len(k)
					continue
				}
			}
			vstart := i + len(k)
			vend := vstart
			for vend < len(lower) && !strings.ContainsRune(sepStop, rune(lower[vend])) {
				vend++
			}
			if vend > vstart && vend-vstart <= 128 {
				out = append(out, httpField{key: key, value: string(b[vstart:vend])})
			}
			start = vend + 1
			if start <= i {
				start = i + len(k)
			}
		}
	}
	return out
}

// passKeys 参与明文口令扫描的字段名。
var passKeys = []string{
	"password", "passwd", "pwd", "pass", "passw", "user_password",
	"login_password", "secret", "token", "api_key", "apikey",
}

// sepStop 口令字段值的终止字符。
const sepStop = "& \t\r\n\"'<>;,#"

// asciiLower 只把 'A'-'Z' 转小写，长度严格不变（保持偏移可用）。
func asciiLower(b []byte) []byte {
	out := append([]byte(nil), b...)
	for i, c := range out {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + 32
		}
	}
	return out
}

// eachLine 按行回调载荷内容（最多取前 16 KiB）。
func eachLine(b []byte, fn func(string)) {
	if len(b) > 16<<10 {
		b = b[:16<<10]
	}
	for len(b) > 0 {
		var line string
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = string(b[:i]), b[i+1:]
		} else {
			line, b = string(b), nil
		}
		if line = strings.TrimRight(line, "\r"); line != "" {
			fn(line)
		}
	}
}
