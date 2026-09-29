// 显示过滤器的词法分析与语法分析：把表达式文本变成可求值的 AST。
//
// 采用递归下降，优先级与 Wireshark 一致：
//
//	||          最低
//	&&
//	== != > < >= <=  contains
//	!  ( )
//
// 词法分析单独成一步，是为了让 "a > 1 > 2" 这类错误在解析期就报出来，
// 而不是留到逐帧求值时才发现。
package net

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"unicode"

	"gyhost/internal/i18n"
)

// tokKind 是 token 类别。
type tokKind byte

const (
	tkEOF    tokKind = iota
	tkIdent          // 字段名 / 协议名
	tkNumber         // 数字
	tkString         // "引号字符串"
	tkIP             // IP 字面量
	tkOp             // 运算符
	tkLParen
	tkRParen
	tkAnd
	tkOr
	tkNot
)

// token 是一个词法单元。
type token struct {
	kind tokKind
	text string // 原文（标识符/运算符）
	num  float64
	ival int64
	str  string
	ip   net.IP
	pos  int // 在原表达式中的起始位置，用于报错
}

// lexer 是词法分析器。
type lexer struct {
	src  string
	pos  int
	toks []token
}

// lex 把表达式切成 token 序列。
func lex(src string) ([]token, error) {
	l := &lexer{src: src}
	for {
		l.skipSpace()
		if l.pos >= len(l.src) {
			break
		}
		start := l.pos
		c := l.src[l.pos]
		switch {
		case c == '(':
			l.pos++
			l.toks = append(l.toks, token{kind: tkLParen, text: "(", pos: start})
		case c == ')':
			l.pos++
			l.toks = append(l.toks, token{kind: tkRParen, text: ")", pos: start})
		case c == '"' || c == '\'':
			s, err := l.lexString(c)
			if err != nil {
				return nil, err
			}
			l.toks = append(l.toks, token{kind: tkString, str: s, text: s, pos: start})
		case c == '&' && l.peekAt(1) == '&':
			l.pos += 2
			l.toks = append(l.toks, token{kind: tkAnd, text: "&&", pos: start})
		case c == '|' && l.peekAt(1) == '|':
			l.pos += 2
			l.toks = append(l.toks, token{kind: tkOr, text: "||", pos: start})
		case c == '!':
			// "!=" 是比较运算符，单独的 "!" 是逻辑非
			if l.peekAt(1) == '=' {
				l.pos += 2
				l.toks = append(l.toks, token{kind: tkOp, text: "!=", pos: start})
			} else {
				l.pos++
				l.toks = append(l.toks, token{kind: tkNot, text: "!", pos: start})
			}
		case c == '=' && l.peekAt(1) == '=':
			l.pos += 2
			l.toks = append(l.toks, token{kind: tkOp, text: "==", pos: start})
		case c == '>' || c == '<':
			l.pos++
			op := string(c)
			if l.peekAt(0) == '=' {
				l.pos++
				op += "="
			}
			l.toks = append(l.toks, token{kind: tkOp, text: op, pos: start})
		case isIdentStart(c):
			l.lexIdent()
		case c >= '0' && c <= '9':
			// 可能是 "80"，也可能是 "10.0.0.7"：先试 IP
			if !l.lexIPLiteral() {
				l.lexNumber()
			}
		default:
			return nil, errors.New(i18n.Tf("net.err.filter_char", string(c)))
		}
	}
	l.toks = append(l.toks, token{kind: tkEOF, pos: l.pos})
	return l.toks, nil
}

func (l *lexer) skipSpace() {
	for l.pos < len(l.src) && unicode.IsSpace(rune(l.src[l.pos])) {
		l.pos++
	}
}

func (l *lexer) peekAt(off int) byte {
	if l.pos+off < len(l.src) {
		return l.src[l.pos+off]
	}
	return 0
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '.' || c == '-' || c == '$' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

// lexString 读一个引号字符串，支持 \" 转义。
func (l *lexer) lexString(quote byte) (string, error) {
	l.pos++ // 跳过起始引号
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if c == '\\' && l.pos+1 < len(l.src) {
			b.WriteByte(l.src[l.pos+1])
			l.pos += 2
			continue
		}
		if c == quote {
			l.pos++
			return b.String(), nil
		}
		b.WriteByte(c)
		l.pos++
	}
	return "", errors.New(i18n.T("net.err.filter_unterminated"))
}

// lexIdent 读标识符，并识别 and / or / not / contains 等单词运算符。
func (l *lexer) lexIdent() {
	start := l.pos
	for l.pos < len(l.src) && isIdentPart(l.src[l.pos]) {
		l.pos++
	}
	word := l.src[start:l.pos]
	switch strings.ToLower(word) {
	case "and", "&&":
		l.toks = append(l.toks, token{kind: tkAnd, text: word, pos: start})
	case "or", "||":
		l.toks = append(l.toks, token{kind: tkOr, text: word, pos: start})
	case "not":
		l.toks = append(l.toks, token{kind: tkNot, text: word, pos: start})
	default:
		// IPv6 地址里含冒号，单独处理
		if ip := l.tryIPAt(start); ip != nil {
			l.toks = append(l.toks, token{kind: tkIP, ip: ip, text: l.src[start:l.pos], pos: start})
			return
		}
		l.toks = append(l.toks, token{kind: tkIdent, text: word, pos: start})
	}
}

// lexIPLiteral 尝试把当前位置起的字面量读成 IP 地址。
//
// 必须先于 lexNumber 尝试："10.0.0.7" 以数字开头，只按数字读会得到 "10.0"
// 再跟一个 ".0.7"，表达式就废了。
func (l *lexer) lexIPLiteral() bool {
	start := l.pos
	ip := l.tryIPAt(start)
	if ip == nil {
		return false
	}
	// tryIPAt 会把 l.pos 推进到字面量末尾，所以 text 要用进入时的起点
	l.toks = append(l.toks, token{
		kind: tkIP, ip: ip, text: l.src[start:l.pos], pos: start,
	})
	return true
}

// lexNumber 读数字（整数或小数）。
func (l *lexer) lexNumber() {
	start := l.pos
	isFloat := false
	for l.pos < len(l.src) && l.src[l.pos] >= '0' && l.src[l.pos] <= '9' {
		l.pos++
	}
	if l.pos < len(l.src) && l.src[l.pos] == '.' &&
		l.pos+1 < len(l.src) && l.src[l.pos+1] >= '0' && l.src[l.pos+1] <= '9' {
		isFloat = true
		l.pos++
		for l.pos < len(l.src) && l.src[l.pos] >= '0' && l.src[l.pos] <= '9' {
			l.pos++
		}
	}
	text := l.src[start:l.pos]
	if isFloat {
		f, _ := strconv.ParseFloat(text, 64)
		l.toks = append(l.toks, token{kind: tkNumber, num: f, text: text, pos: start})
		return
	}
	n, _ := strconv.ParseInt(text, 10, 64)
	l.toks = append(l.toks, token{kind: tkNumber, ival: n, num: float64(n), text: text, pos: start})
}

// tryIPAt 尝试把 src[start:] 起的标识符读成 IPv4/IPv6 地址。
func (l *lexer) tryIPAt(start int) net.IP {
	end := start
	for end < len(l.src) && (isIdentPart(l.src[end]) || l.src[end] == ':' || l.src[end] == '%') {
		// 遇到运算符/空白就停
		if l.src[end] == '&' || l.src[end] == '|' || l.src[end] == '>' ||
			l.src[end] == '<' || l.src[end] == '=' {
			break
		}
		end++
	}
	cand := l.src[start:end]
	if !strings.Contains(cand, ".") && !strings.Contains(cand, ":") {
		return nil
	}
	ip := net.ParseIP(cand)
	if ip == nil {
		return nil
	}
	l.pos = end
	return ip
}

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

// node 是过滤表达式的语法树节点。
type node interface {
	eval(p *pkt) bool
	// needsVerbose 报告该子树是否引用了需要详细解码的字段。
	needsVerbose() bool
	// String 回显规范化形式。
	String() string
}

// nodeAnd 是逻辑与（多值字段对任一取值成立即算成立）。
type nodeAnd struct{ kids []node }

func (n *nodeAnd) eval(p *pkt) bool {
	for _, k := range n.kids {
		if !k.eval(p) {
			return false
		}
	}
	return true
}

func (n *nodeAnd) needsVerbose() bool {
	for _, k := range n.kids {
		if k.needsVerbose() {
			return true
		}
	}
	return false
}

func (n *nodeAnd) String() string {
	parts := make([]string, 0, len(n.kids))
	for _, k := range n.kids {
		// 子节点里含 || 时必须加括号，否则回显后再解析语义就变了
		parts = append(parts, parenIfOr(k))
	}
	return strings.Join(parts, " and ")
}

// nodeOr 是逻辑或。
type nodeOr struct{ kids []node }

func (n *nodeOr) eval(p *pkt) bool {
	for _, k := range n.kids {
		if k.eval(p) {
			return true
		}
	}
	return false
}

func (n *nodeOr) needsVerbose() bool {
	for _, k := range n.kids {
		if k.needsVerbose() {
			return true
		}
	}
	return false
}

func (n *nodeOr) String() string {
	parts := make([]string, 0, len(n.kids))
	for _, k := range n.kids {
		parts = append(parts, k.String())
	}
	return strings.Join(parts, " or ")
}

// nodeNot 是逻辑非。
type nodeNot struct{ kid node }

func (n *nodeNot) eval(p *pkt) bool   { return !n.kid.eval(p) }
func (n *nodeNot) needsVerbose() bool { return n.kid.needsVerbose() }
func (n *nodeNot) String() string     { return "not " + parenIfOr(n.kid) }

// nodeExists 是"字段存在且非零"，即裸写协议名（tcp ≡ tcp == 1）。
type nodeExists struct {
	field string
	spec  fieldSpec
}

func (n *nodeExists) eval(p *pkt) bool {
	v := n.spec.get(p)
	return v.each(func(x val) bool {
		switch x.kind {
		case valBool:
			return x.b
		case valInt:
			return x.i != 0
		case valFloat:
			return x.f != 0
		case valStr:
			return x.s != ""
		case valIP:
			return x.ip != nil
		case valMAC:
			return x.s != ""
		}
		return false
	})
}
func (n *nodeExists) needsVerbose() bool { return n.spec.verbose }
func (n *nodeExists) String() string     { return n.field }

// nodeCmp 是"字段 运算符 值"比较。
type nodeCmp struct {
	field string
	spec  fieldSpec
	op    string
	lit   val
}

func (n *nodeCmp) eval(p *pkt) bool {
	got := n.spec.get(p)
	// "!=" 的语义是"没有任何取值等于该值"，而不是"存在某个取值不等于"。
	// 对多值字段（tcp.port = {源端口, 目的端口}），后者会让
	// "tcp.port != 443" 在目的端口恰为 443 时错误地成立。
	// 其余运算符都是"任一取值满足即成立"。
	if n.op == "!=" {
		return !got.each(func(x val) bool { return compare(x, "==", n.lit) })
	}
	return got.each(func(x val) bool { return compare(x, n.op, n.lit) })
}

func (n *nodeCmp) needsVerbose() bool { return n.spec.verbose }

func (n *nodeCmp) String() string {
	return n.field + " " + n.op + " " + n.lit.text()
}

// parenIfOr 给逻辑或节点加括号，保证回显后语义不变。
func parenIfOr(n node) string {
	s := n.String()
	if _, ok := n.(*nodeOr); ok {
		return "(" + s + ")"
	}
	return s
}

// compare 对单个字段取值做比较。
func compare(x val, op string, lit val) bool {
	switch op {
	case "==":
		return valEqual(x, lit)
	case "!=":
		return !valEqual(x, lit)
	case "contains":
		return strings.Contains(strings.ToLower(x.text()), strings.ToLower(lit.text()))
	case ">":
		return valNum(x, lit, func(a, b float64) bool { return a > b })
	case "<":
		return valNum(x, lit, func(a, b float64) bool { return a < b })
	case ">=":
		return valNum(x, lit, func(a, b float64) bool { return a >= b })
	case "<=":
		return valNum(x, lit, func(a, b float64) bool { return a <= b })
	}
	return false
}

// valEqual 按类型做相等判断，跨类型时退化为文本比较。
func valEqual(x, lit val) bool {
	if x.kind == valIP || lit.kind == valIP {
		// IP 相等交给 net.IP 处理（它知道 IPv4-mapped IPv6 的等价关系）
		a, b := x.ip, lit.ip
		if x.kind != valIP {
			a = net.ParseIP(x.text())
		}
		if lit.kind != valIP {
			b = net.ParseIP(lit.text())
		}
		if a == nil || b == nil {
			return false
		}
		return a.Equal(b)
	}
	if x.kind == valMAC || lit.kind == valMAC {
		return strings.EqualFold(x.text(), lit.text())
	}
	if isNumeric(x.kind) && isNumeric(lit.kind) {
		return x.num() == lit.num()
	}
	if x.kind == valBool || lit.kind == valBool {
		return truthy(x) == truthy(lit)
	}
	return strings.EqualFold(x.text(), lit.text())
}

// valNum 做数值比较；任一侧不是数值则返回 false。
func valNum(x, lit val, f func(a, b float64) bool) bool {
	if !isNumeric(x.kind) || !isNumeric(lit.kind) {
		return false
	}
	return f(x.num(), lit.num())
}

func isNumeric(k valKind) bool { return k == valInt || k == valFloat }

func truthy(v val) bool {
	switch v.kind {
	case valBool:
		return v.b
	case valInt:
		return v.i != 0
	case valFloat:
		return v.f != 0
	case valStr, valMAC:
		return v.s != ""
	case valIP:
		return v.ip != nil
	}
	return false
}

// ---------------------------------------------------------------------------
// 语法分析（递归下降）
// ---------------------------------------------------------------------------

// parser 是递归下降语法分析器。
type parser struct {
	toks []token
	pos  int
}

// parseExpr 是 parseDisplayFilter 的语法分析部分。
func (p *parser) parseExpr() (node, error) { return p.parseOr() }

// parseOr 处理最低优先级的 ||。
func (p *parser) parseOr() (node, error) {
	kid, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tkOr {
		return kid, nil
	}
	or := &nodeOr{kids: []node{kid}}
	for p.peek().kind == tkOr {
		p.pos++
		k, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		or.kids = append(or.kids, k)
	}
	return or, nil
}

// parseAnd 处理 &&。裸写的多个条件（空格分隔）也视为"与"，
// 这样 "tcp port 80" 与 "tcp && port 80" 等价，与旧语法一致。
func (p *parser) parseAnd() (node, error) {
	kid, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	and := &nodeAnd{kids: []node{kid}}
	for {
		switch p.peek().kind {
		case tkAnd:
			p.pos++
		case tkEOF, tkRParen, tkOr:
			return and, nil
		default:
			// 隐式与：后��还有东西就继续
		}
		k, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		and.kids = append(and.kids, k)
	}
}

// parseUnary 处理 ! 与括号。
func (p *parser) parseUnary() (node, error) {
	switch p.peek().kind {
	case tkNot:
		p.pos++
		kid, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &nodeNot{kid: kid}, nil
	case tkLParen:
		p.pos++
		kid, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tkRParen {
			return nil, errors.New(i18n.T("net.err.filter_unclosed_paren"))
		}
		p.pos++
		return kid, nil
	}
	return p.parseComparison()
}

// parseComparison 处理 "字段 [运算符 值]"，省略运算符即存在性判断。
func (p *parser) parseComparison() (node, error) {
	t := p.peek()
	if t.kind != tkIdent {
		return nil, errors.New(i18n.Tf("net.err.filter_token", t.text))
	}
	p.pos++
	name := t.text
	spec, ok := fieldTable[strings.ToLower(name)]
	if !ok {
		return nil, errors.New(i18n.Tf("net.err.filter_unknown_field", name))
	}

	// 运算符、单词运算符，或"省略运算符的相等比较"（port 80 / host 1.2.3.4）
	op := ""
	hasOp := true // 是否真的读掉了一个运算符
	nxt := p.peek()
	switch {
	case nxt.kind == tkOp:
		op = nxt.text
	case nxt.kind == tkIdent && (strings.EqualFold(nxt.text, "contains") ||
		strings.EqualFold(nxt.text, "matches")):
		op = strings.ToLower(nxt.text)
	case nxt.kind == tkNumber || nxt.kind == tkString || nxt.kind == tkIP:
		// "port 80" / "host 10.0.0.1"：旧语法里 host/port 是关键字，
		// 新语法把它们做成了字段，这里补上等价写法。
		// 注意此处不能前进指针——值就在当前位置，交给 parseLiteral 读。
		op = "=="
		hasOp = false
	default:
		// 后面没有运算符也没有值：按"字段存在性"处理（裸写 tcp）
		return &nodeExists{field: name, spec: spec}, nil
	}
	if hasOp {
		p.pos++
	}

	lit, err := p.parseLiteral(spec, name)
	if err != nil {
		return nil, err
	}
	return &nodeCmp{field: name, spec: spec, op: op, lit: lit}, nil
}

// parseLiteral 读比较运算符右边的值，并按字段类型做转换与校验。
func (p *parser) parseLiteral(spec fieldSpec, field string) (val, error) {
	t := p.peek()
	switch t.kind {
	case tkNumber:
		p.pos++
		return coerceNum(spec, t, field)
	case tkString:
		p.pos++
		return coerceStr(spec, t.str, field)
	case tkIP:
		p.pos++
		return coerceIP(spec, t.ip, field)
	case tkIdent:
		// 允许 "ip.addr == 10.0.0.1" 之外的写法：tcp.port == http
		p.pos++
		return coerceStr(spec, t.text, field)
	case tkEOF:
		return val{}, errors.New(i18n.Tf("net.err.filter_missing", field+" "+opText(t)))
	}
	return val{}, errors.New(i18n.Tf("net.err.filter_missing", field))
}

func opText(t token) string { return t.text }

// portLikeFields 是取值必须是合法端口号的字段。
//
// 不校验的话 "tcp.port == 999999" 会被静默接受并恒不匹配，
// 用户看不出是写错了端口还是抓包里真没有。
var portLikeFields = map[string]bool{
	"tcp.port": true, "tcp.srcport": true, "tcp.dstport": true,
	"udp.port": true, "udp.srcport": true, "udp.dstport": true,
	"port": true,
}

// coerceNum 把数字字面量转成字段期望的类型。
func coerceNum(spec fieldSpec, t token, field string) (val, error) {
	switch spec.kind {
	case valInt:
		if portLikeFields[strings.ToLower(field)] &&
			(t.ival < 0 || t.ival > 65535) {
			return val{}, errors.New(i18n.Tf("net.err.filter_port", t.text))
		}
		return intVal(t.ival), nil
	case valFloat:
		return val{kind: valFloat, f: t.num}, nil
	case valBool:
		return val{kind: valBool, b: t.ival != 0}, nil
	case valIP:
		return val{}, errors.New(i18n.Tf("net.err.filter_ip", t.text))
	}
	// 字符串字段与数字比较：转成文本（大小写不敏感）
	return strVal(t.text), nil
}

// coerceStr 把字符串字面量转成字段期望的类型。
func coerceStr(spec fieldSpec, s, field string) (val, error) {
	switch spec.kind {
	case valIP:
		ip := net.ParseIP(s)
		if ip == nil {
			return val{}, errors.New(i18n.Tf("net.err.filter_ip", s))
		}
		return ipVal(ip), nil
	case valInt:
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return val{}, errors.New(i18n.Tf("net.err.filter_number", s))
		}
		return intVal(n), nil
	case valFloat:
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return val{}, errors.New(i18n.Tf("net.err.filter_number", s))
		}
		return val{kind: valFloat, f: f}, nil
	case valBool:
		switch strings.ToLower(s) {
		case "1", "true", "set", "yes":
			return val{kind: valBool, b: true}, nil
		case "0", "false", "unset", "no":
			return val{kind: valBool, b: false}, nil
		}
		return val{}, errors.New(i18n.Tf("net.err.filter_number", s))
	case valMAC:
		return macVal(s), nil
	}
	return strVal(s), nil
}

// coerceIP 把 IP 字面量转成字段期望的类型。
func coerceIP(spec fieldSpec, ip net.IP, field string) (val, error) {
	if spec.kind == valIP {
		return ipVal(ip), nil
	}
	if spec.kind == valStr || spec.kind == valMAC {
		return strVal(ip.String()), nil
	}
	return val{}, errors.New(i18n.Tf("net.err.filter_ip", ip.String()))
}

// peek 返回当前 token（不前进）。
func (p *parser) peek() token {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return token{kind: tkEOF}
}
