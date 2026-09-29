// 旧过滤语法的兼容层。
//
// 原实现用 strings.Fields 切词，只能表达"协议名 / host IP / port N"三类原子，
// 已被 filter_parse.go 的显示过滤器取代。但两种写法都要继续可用：
//   - "-f" 命令行与 TUI 启动参数沿用历史行为，脚本里可能已写死
//   - 已有测试与文档都以旧写法描述
//
// 策略：先按显示过滤器解析；失败时回退到旧解析器。新语法能表达的旧表达式
// 会被新引擎接管（结果一致），无法表达的（如 "host 10.0.0.1 extra"）仍由
// 旧解析器报错，保持原有的错误提示。
package net

import (
	"net"
	"strconv"
	"strings"
)

// legacyTerm 是旧语法的原子条件。
type legacyTerm struct {
	neg   bool
	kind  legacyKind
	dir   dir
	proto string
	ip    net.IP
	port  uint16
}

type legacyKind byte

const (
	legacyProto legacyKind = iota
	legacyHost
	legacyPort
)

// legacyFilter 是旧语法的过滤表达式：组内"与"，组间"或"。
type legacyFilter struct {
	groups [][]legacyTerm
}

// parseLegacy 解析旧语法。
func parseLegacy(s string) (*legacyFilter, error) {
	toks := strings.Fields(s)
	f := &legacyFilter{}
	var cur []legacyTerm
	flush := func() {
		if len(cur) > 0 {
			f.groups = append(f.groups, cur)
			cur = nil
		}
	}
	i := 0
	for i < len(toks) {
		switch strings.ToLower(toks[i]) {
		case "and":
			i++
		case "or":
			flush()
			i++
		case "not":
			t, n, err := parseLegacyTerm(toks, i+1)
			if err != nil {
				return nil, err
			}
			t.neg = true
			cur = append(cur, t)
			i = n
		default:
			t, n, err := parseLegacyTerm(toks, i)
			if err != nil {
				return nil, err
			}
			cur = append(cur, t)
			i = n
		}
	}
	flush()
	if len(f.groups) == 0 {
		return nil, nil
	}
	return f, nil
}

// parseLegacyTerm 从 toks[i] 起解析一个旧式原子，返回下一个待处理下标。
func parseLegacyTerm(toks []string, i int) (legacyTerm, int, error) {
	if i >= len(toks) {
		return legacyTerm{}, 0, errFilterMissing("not")
	}
	d := dirAny
	dirTok := toks[i]
	switch strings.ToLower(toks[i]) {
	case "src", "source":
		d, i = dirSrc, i+1
	case "dst", "destination", "dest":
		d, i = dirDst, i+1
	}
	if i >= len(toks) {
		return legacyTerm{}, 0, errFilterMissing(dirTok)
	}
	low := strings.ToLower(toks[i])

	// 裸数字等价于 port："udp 53" ≡ "udp and port 53"
	if n, err := strconv.Atoi(low); err == nil && n >= 0 && n <= 65535 {
		return legacyTerm{kind: legacyPort, dir: d, port: uint16(n)}, i + 1, nil
	}

	switch low {
	case "host":
		if i+1 >= len(toks) {
			return legacyTerm{}, 0, errFilterMissing("host")
		}
		ip := net.ParseIP(toks[i+1])
		if ip == nil {
			return legacyTerm{}, 0, errFilterIP(toks[i+1])
		}
		return legacyTerm{kind: legacyHost, dir: d, ip: ip}, i + 2, nil
	case "port":
		if i+1 >= len(toks) {
			return legacyTerm{}, 0, errFilterMissing("port")
		}
		n, err := strconv.Atoi(toks[i+1])
		if err != nil || n < 0 || n > 65535 {
			return legacyTerm{}, 0, errFilterPort(toks[i+1])
		}
		return legacyTerm{kind: legacyPort, dir: d, port: uint16(n)}, i + 2, nil
	}

	if d != dirAny {
		return legacyTerm{}, 0, errFilterDir(dirTok)
	}
	if !knownProto(low) {
		return legacyTerm{}, 0, errFilterToken(toks[i])
	}
	return legacyTerm{kind: legacyProto, proto: low}, i + 1, nil
}

// match 判断一帧是否通过旧式过滤。
func (f *legacyFilter) match(p *pkt) bool {
	if f == nil || len(f.groups) == 0 {
		return true
	}
	for _, g := range f.groups {
		ok := true
		for i := range g {
			res := g[i].match(p)
			if g[i].neg {
				res = !res
			}
			if !res {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// match 判断单个旧式原子条件。
func (t *legacyTerm) match(p *pkt) bool {
	switch t.kind {
	case legacyProto:
		return matchProto(t.proto, p)
	case legacyHost:
		switch t.dir {
		case dirSrc:
			return t.ip.Equal(p.srcIP)
		case dirDst:
			return t.ip.Equal(p.dstIP)
		default:
			return t.ip.Equal(p.srcIP) || t.ip.Equal(p.dstIP)
		}
	case legacyPort:
		switch t.dir {
		case dirSrc:
			return p.srcPort != 0 && p.srcPort == t.port
		case dirDst:
			return p.dstPort != 0 && p.dstPort == t.port
		default:
			return (p.srcPort != 0 && p.srcPort == t.port) ||
				(p.dstPort != 0 && p.dstPort == t.port)
		}
	}
	return false
}

// String 回显旧式表达式的规范化形式。
func (f *legacyFilter) String() string {
	if f == nil {
		return ""
	}
	gs := make([]string, 0, len(f.groups))
	for _, g := range f.groups {
		ts := make([]string, 0, len(g))
		for i := range g {
			ts = append(ts, g[i].String())
		}
		gs = append(gs, strings.Join(ts, " and "))
	}
	return strings.Join(gs, " or ")
}

// String 回显单个旧式原子。
func (t *legacyTerm) String() string {
	s := ""
	switch t.kind {
	case legacyProto:
		s = t.proto
	case legacyHost:
		s = "host " + t.ip.String()
	case legacyPort:
		s = "port " + strconv.Itoa(int(t.port))
	}
	switch t.dir {
	case dirSrc:
		s = "src " + s
	case dirDst:
		s = "dst " + s
	}
	if t.neg {
		s = "not " + s
	}
	return s
}

// matchProto 按协议名匹配：网络/传输层特指优先，再看应用层。
//
// 显示过滤器与旧语法共用这套判定，保证 "tcp" 在两种写法下含义一致。
func matchProto(name string, p *pkt) bool {
	switch name {
	case "ip", "ipv4":
		return p.l3 == "IPv4"
	case "ip6", "ipv6":
		return p.l3 == "IPv6"
	case "icmp6":
		return p.l4 == "ICMPv6"
	case "arp":
		return p.l3 == "ARP" || p.l3 == "RARP"
	}
	if p.l4 != "" && strings.EqualFold(p.l4, name) {
		return true
	}
	if p.l3 != "" && strings.EqualFold(p.l3, name) {
		return true
	}
	return p.app != "" && strings.EqualFold(p.app, name)
}
