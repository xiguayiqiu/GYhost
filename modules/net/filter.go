// 抓包过滤：把过滤表达式变成可对解码结果求值的条件。
//
// 支持两套语法：
//
//  1. 显示过滤器（Wireshark 风格，主要写法）
//
//     ip.addr == 10.0.0.1 && tcp.port == 443
//     frame.len > 1000 || http.host contains "example"
//     !(arp || icmp) && tcp.flags.syn == 1
//
//     词法/语法/求值分别在 filter_parse.go、filter_fields.go。
//
//  2. 旧语法（兼容保留）
//
//     tcp and port 443
//     src host 192.168.1.1 or dst port 53
//     not host 10.0.0.1
//
//     由 filter_legacy.go 实现，命令行与文档里的历史写法继续有效。
//
// 解析顺序：先试显示过滤器，失败再回退旧语法。新引擎能表达的旧表达式会被
// 直接接管（语义等价），只有新引擎不认的才交给旧解析器。
package net

import (
	"errors"
	"strings"

	"gyhost/internal/i18n"
)

// dir 是地址/端口的方向限定（旧语法用）。
type dir byte

const (
	dirAny dir = iota
	dirSrc
	dirDst
)

// filter 是一棵可求值的过滤表达式树。
//
// root 为 nil 表示不过滤（全部通过）。
type filter struct {
	root node
	// legacy 是旧语法解析的结果；非 nil 时走旧求值路径。
	legacy *legacyFilter
	// verbose 表示表达式引用了需要详细解码的字段。
	verbose bool
	// src 是用户输入的原始表达式（状态栏回显用）。
	src string
}

// protoCache 缓存 protoSet 的结果。
var protoCache map[string]bool

// knownProto 判断协议名是否可识别（大小写不敏感）。
func knownProto(name string) bool {
	_, ok := protoSet()[name]
	return ok
}

// protoSet 汇总可用于过滤的协议名。
func protoSet() map[string]bool {
	if protoCache != nil {
		return protoCache
	}
	set := map[string]bool{}
	for _, n := range []string{
		"tcp", "udp", "icmp", "icmpv6", "icmp6", "gre", "esp", "ah", "sctp",
		"igmp", "ospf", "eigrp", "pim", "vrrp",
		"ip", "ipv4", "ip6", "ipv6", "arp", "rarp", "eapol", "lldp",
		"mpls", "pppoe", "lacp", "cdp", "macsec", "fcoe",
		"dtls",
	} {
		set[n] = true
	}
	for _, n := range appByPort {
		set[strings.ToLower(n)] = true
	}
	protoCache = set
	return set
}

// parseFilter 解析过滤表达式；空串返回 nil（不过滤）。
//
// 顺序很关键：先试旧语法，再试显示过滤器。
//
// 旧语法把 "port"/"host" 当关键字（"port 443" 是"端口等于 443"），
// 而显示过滤器里它们是字段（"port == 443"）。两者对同一串文本的理解不同，
// 若让新引擎先接管，"port 443" 会被理解成"存在名为 port 的字段且等于 443"，
// 结果与历史行为不符。旧解析器对无法表达的写法（如含 "&&"、括号、
// 点号字段名）会报错，正好用来区分。
func parseFilter(s string) (*filter, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if lf, err := parseLegacy(s); err == nil && lf != nil {
		return &filter{legacy: lf, src: s}, nil
	}
	f, derr := parseDisplay(s)
	if derr != nil {
		// 两者都失败：优先报旧语法的错误，它对 "port abc" 这类更有指向性
		if _, lerr := parseLegacy(s); lerr != nil && !isDisplayOnly(s) {
			return nil, lerr
		}
		return nil, derr
	}
	return f, nil
}

// isDisplayOnly 判断表达式是否明显是新语法（避免旧错误信息误导新写法）。
func isDisplayOnly(s string) bool {
	return strings.ContainsAny(s, "()&|!<>=.") ||
		strings.Contains(s, "==") || strings.Contains(s, "!=")
}

// parseDisplay 按显示过滤器语法解析。
func parseDisplay(s string) (*filter, error) {
	toks, err := lex(s)
	if err != nil {
		return nil, err
	}
	// 纯空白/无有效 token 交给旧解析器处理
	if len(toks) == 0 || (len(toks) == 1 && toks[0].kind == tkEOF) {
		return nil, errors.New(i18n.T("net.err.filter_empty"))
	}
	p := &parser{toks: toks}
	root, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tkEOF {
		return nil, errors.New(i18n.Tf("net.err.filter_token", p.peek().text))
	}
	return &filter{root: root, verbose: root.needsVerbose(), src: s}, nil
}

// match 判断一帧是否通过过滤；f 为 nil 时全部通过。
func (f *filter) match(p *pkt) bool {
	if f == nil {
		return true
	}
	if f.legacy != nil {
		return f.legacy.match(p)
	}
	if f.root == nil {
		return true
	}
	return f.root.eval(p)
}

// needsVerbose 报告该过滤器是否需要详细解码才能求值。
func (f *filter) needsVerbose() bool { return f != nil && f.verbose }

// String 回显规范化形式。
func (f *filter) String() string {
	if f == nil {
		return ""
	}
	if f.legacy != nil {
		return f.legacy.String()
	}
	if f.root == nil {
		return ""
	}
	return f.root.String()
}

// Src 返回用户输入的原始表达式。
func (f *filter) Src() string {
	if f == nil {
		return ""
	}
	return f.src
}

// ---------------------------------------------------------------------------
// 错误构造（集中在此，便于统一走 i18n）
// ---------------------------------------------------------------------------

func errFilterMissing(what string) error {
	return errors.New(i18n.Tf("net.err.filter_missing", what))
}

func errFilterIP(s string) error { return errors.New(i18n.Tf("net.err.filter_ip", s)) }

func errFilterPort(s string) error { return errors.New(i18n.Tf("net.err.filter_port", s)) }

func errFilterToken(s string) error { return errors.New(i18n.Tf("net.err.filter_token", s)) }

func errFilterDir(s string) error { return errors.New(i18n.Tf("net.err.filter_dir", s)) }
