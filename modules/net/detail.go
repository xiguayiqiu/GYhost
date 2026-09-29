// 逐包详细视图（-V）：按 tshark -V 的协议树形态输出每个字段的明细，
// 便于定位单包的具体问题（TCP 选项、IP 分片、DNS 记录 …）。
//
// 协议名、字段名等技术标识保持原样（与报告里的约定一致）；
// 面向用户的句子与提示走 i18n。
package net

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"gyhost/internal/i18n"
)

// detIndent 是协议树每层的缩进宽度。
const detIndent = 4

// dnode 是协议树的一个节点：要么是一个协议层标题（section），
// 要么是该层下的一个字段（"名称: 值"）。
//
// 字段的 depth 记录它在扁平输出里的缩进层级；depth>=2 的字段会挂到
// 同层最近一个 depth-1 字段之下（形如 tshark 里 "标志位" 之下的
// DF / MF），于是扁平视图与可折叠树是同一棵树的两种渲染。
type dnode struct {
	label     string   // 显示文本：section 是标题，字段是 "名称: 值"
	name      string   // 字段名（section 为空）
	value     string   // 字段值（section 为空）
	key       string   // 稳定标识：字段用字段名，协议层用协议标识（见 Key）
	isSection bool     // 是否是可折叠的协议层标题
	depth     int      // 扁平渲染的缩进层级（section 恒为 0）
	children  []*dnode // 子字段（折叠时整棵收起）
}

// dTree 是一棵构建好的协议树。
//
// roots 是顶层协议层（Frame / 以太网 II / IPv4 / TCP / HTTP …）；
// hexLines 是与树分离的整帧 hexdump 行，不参与折叠 —— TUI 拿它渲染
// 独立的 bytes 面板，扁平渲染器再把它们接在树后面输出。
type dTree struct {
	roots    []*dnode
	hexLines []string
}

// detailWriter 把各协议层的明细汇成一棵协议树（自己不写文本）。
//
// 各 det* 函数只管按层级塞字段，输出形态由 dTree 的渲染器决定。
type detailWriter struct {
	tree  *dTree
	cur   *dnode   // 当前 section（还没出现 section 时为 nil）
	level []*dnode // level[k] = 最近一个扁平层级为 k 的节点
}

// newDetailWriter 创建一个空的协议树构建器。
func newDetailWriter() *detailWriter {
	return &detailWriter{tree: &dTree{}}
}

// field 在指定层级追加一条 "名称: 值"。
func (d *detailWriter) field(depth int, name, value string) {
	if depth < 1 {
		depth = 1
	}
	n := &dnode{label: name + ": " + value, name: name, value: value,
		key: name, depth: depth}
	if parent := d.parentAt(depth); parent != nil {
		parent.children = append(parent.children, n)
	} else {
		d.tree.roots = append(d.tree.roots, n)
	}
	d.remember(n)
}

// parentAt 返回 depth 层级字段的父节点：优先挂到上一层最近的那个节点之下
// （没有才退回当前 section），这样 depth=2 的标志位天然成为"标志位"的子节点。
func (d *detailWriter) parentAt(depth int) *dnode {
	if depth >= 2 && depth-1 < len(d.level) {
		if p := d.level[depth-1]; p != nil {
			return p
		}
	}
	return d.cur
}

// remember 记下 n 是该层级最近追加的节点，并丢弃更深的记录
// （之后的 depth=2 字段不该挂到一个隔了老远的旧节点下）。
func (d *detailWriter) remember(n *dnode) {
	for len(d.level) < n.depth {
		d.level = append(d.level, nil)
	}
	d.level = append(d.level[:n.depth], n)
}

// flag 追加一条布尔位字段（Set / Not set）。
func (d *detailWriter) flag(depth int, name string, set bool) {
	v := i18n.T("net.det.notset")
	if set {
		v = i18n.T("net.det.set")
	}
	d.field(depth, name, v)
}

// section 开一层协议标题（顶格，可折叠的父节点）。
//
// proto 是稳定的协议标识（如 "tcp"、"ipv4"），只用于折叠状态记忆；
// title 是给人看的标题，往往含地址、端口等逐包变化的内容，不能当标识用。
func (d *detailWriter) section(proto, title string) {
	n := &dnode{label: title, key: proto, isSection: true}
	d.tree.roots = append(d.tree.roots, n)
	d.cur = n
	d.level = []*dnode{n}
}

// hexLine 收一行 hexdump：与协议树分开存放，供 TUI 的 bytes 面板独立取用。
func (d *detailWriter) hexLine(line string) {
	d.tree.hexLines = append(d.tree.hexLines, line)
}

// writePacketDetail 输出单个包的完整协议树（tshark -V 风格）。
func writePacketDetail(w io.Writer, p *pkt, t0 time.Time) {
	buildPacketDetail(p, t0).WriteFlat(w)
}

// buildPacketDetail 构建单个包的协议树。
func buildPacketDetail(p *pkt, t0 time.Time) *dTree {
	d := newDetailWriter()

	// ---- Frame ----
	d.section("frame", i18n.Tf("net.det.frame_hdr", p.no,
		p.wireLen, p.wireLen*8, p.capLen, p.capLen*8))
	d.field(1, i18n.T("net.det.encap"), linkTypeName(p.linkType))
	d.field(1, i18n.T("net.det.arrival"), p.ts.Format("2006-01-02 15:04:05.000000"))
	d.field(1, i18n.T("net.det.epoch"),
		strconv.FormatInt(p.ts.Unix(), 10)+"."+fmt.Sprintf("%09d", p.ts.Nanosecond()))
	d.field(1, i18n.T("net.det.since_ref"),
		strconv.FormatFloat(p.ts.Sub(t0).Seconds(), 'f', 9, 64)+" "+i18n.T("net.det.seconds"))
	d.field(1, i18n.T("net.det.frame_no"), strconv.Itoa(p.no))
	d.field(1, i18n.T("net.det.frame_len"), i18n.Tf("net.det.bytes_bits", p.wireLen, p.wireLen*8))
	d.field(1, i18n.T("net.det.cap_len"), i18n.Tf("net.det.bytes_bits", p.capLen, p.capLen*8))
	if p.capLen < p.wireLen {
		d.field(1, i18n.T("net.det.truncated"), i18n.T("net.det.yes"))
	}
	d.field(1, i18n.T("net.det.protocols"), strings.Join(protocolStack(p), ":"))

	// ---- 链路层 ----
	switch p.linkType {
	case dltEthernet:
		detEthernet(d, p)
	case dltLinuxSLL, dltLinuxSLL2:
		detLinkSimple(d, p)
	}

	// ---- 网络层 ----
	switch p.l3 {
	case "IPv4":
		detIPv4(d, p)
	case "IPv6":
		detIPv6(d, p)
	case "ARP":
		detARP(d, p)
	}

	// ---- 传输层 ----
	switch p.l4 {
	case "TCP":
		detTCP(d, p)
	case "UDP":
		detUDP(d, p)
	case "ICMP", "ICMPv6":
		detICMP(d, p)
	}

	// ---- 应用层载荷 ----
	detPayload(d, p)
	detHexDump(d, p)
	return d.tree
}

// ---------------------------------------------------------------------------
// 渲染器：同一棵树的两种视图
// ---------------------------------------------------------------------------

// WriteFlat 按 tshark -V 的扁平形态输出协议树：协议层标题顶格，字段按
// depth 每层缩进 detIndent 个空格，最后接上整帧的 hexdump 行。
//
// 这里用 fmt.Fprintf 而不是 utils.Plainf：后者会自动补一个换行，
// 而调用点自带 "\n"，否则会出现空行。
func (t *dTree) WriteFlat(w io.Writer) {
	for _, n := range t.roots {
		writeNodeFlat(w, n)
	}
	for _, line := range t.hexLines {
		fmt.Fprintf(w, "%s\n", line)
	}
}

// writeNodeFlat 先序输出一个节点及其子节点。
func writeNodeFlat(w io.Writer, n *dnode) {
	if n.depth > 0 {
		fmt.Fprintf(w, "%s%s\n", strings.Repeat(" ", n.depth*detIndent), n.label)
	} else {
		fmt.Fprintf(w, "%s\n", n.label)
	}
	for _, c := range n.children {
		writeNodeFlat(w, c)
	}
}

// FlatString 把协议树渲染成扁平文本（含 hexdump 行）。
func (t *dTree) FlatString() string {
	var b strings.Builder
	t.WriteFlat(&b)
	return b.String()
}

// Walk 以先序遍历协议树（TUI 的可折叠树视图按它渲染）。
//
// depth 是节点距根的层数（顶层协议层为 0），与 dnode.depth（扁平缩进层级）
// 通常一致，但不是一回事：扁平输出里并列的字段在树里可能父子相接。
// fn 返回 false 时不再下探该节点的子树，其余遍历照旧；hexdump 行不在
// 遍历范围内，要用 hexLines 单独取。
func (t *dTree) Walk(fn func(n *dnode, depth int) bool) {
	for _, n := range t.roots {
		walkNode(n, 0, fn)
	}
}

// walkNode 先序遍历一棵子树。
func walkNode(n *dnode, depth int, fn func(n *dnode, depth int) bool) {
	if !fn(n, depth) {
		return
	}
	for _, c := range n.children {
		walkNode(c, depth+1, fn)
	}
}

// Section 返回协议标识对应的顶层协议层节点（找不到返回 nil）。
func (t *dTree) Section(proto string) *dnode {
	for _, n := range t.roots {
		if n.isSection && n.key == proto {
			return n
		}
	}
	return nil
}

// Child 按字段名返回直接子字段（找不到返回 nil）。
func (n *dnode) Child(name string) *dnode {
	if n == nil {
		return nil
	}
	for _, c := range n.children {
		if c.name == name {
			return c
		}
	}
	return nil
}

// Key 返回节点的稳定标识：字段是字段名，协议层是协议标识。
//
// 之所以不用 label 做标识：协议层标题里含地址、端口、序号等逐包变化的内容，
// 拿它当键会导致"折叠状态无法在换包后保持"。
func (n *dnode) Key() string { return n.key }

// protocolStack 返回该包经过的协议层级链（形如 eth:ethertype:ip:tcp:http）。
func protocolStack(p *pkt) []string {
	var out []string
	if p.link != "" {
		out = append(out, strings.ToLower(strings.Fields(p.link)[0]))
	}
	if len(p.vlanIDs) > 0 {
		out = append(out, "vlan")
	}
	if p.etype != 0 {
		out = append(out, "ethertype")
	}
	switch p.l3 {
	case "IPv4":
		out = append(out, "ip")
	case "IPv6":
		out = append(out, "ipv6")
	case "ARP":
		out = append(out, "arp")
	}
	switch p.l4 {
	case "TCP":
		out = append(out, "tcp")
	case "UDP":
		out = append(out, "udp")
	case "ICMP":
		out = append(out, "icmp")
	case "ICMPv6":
		out = append(out, "icmpv6")
	}
	if p.app != "" {
		out = append(out, strings.ToLower(p.app))
	}
	return out
}

// detEthernet 输出以太网层字段。
func detEthernet(d *detailWriter, p *pkt) {
	dst, src := p.dstMAC(), p.srcMAC()
	d.section("eth", i18n.Tf("net.det.eth_hdr", src, dst))
	d.field(1, i18n.T("net.det.dst"), dst)
	d.field(1, i18n.T("net.det.src"), src)
	for i, vlan := range p.vlanIDs {
		d.field(1, i18n.Tf("net.det.vlan_idx", i+1), strconv.Itoa(int(vlan)))
	}
	if p.etype != 0 {
		d.field(1, i18n.T("net.det.type"), i18n.Tf("net.det.etype", ethTypeName(p.etype), p.etype))
	}
}

// detLinkSimple 输出 SLL / SLL2 这类无 MAC 字段的链路层。
func detLinkSimple(d *detailWriter, p *pkt) {
	d.section("link", p.link)
	if p.etype != 0 {
		d.field(1, i18n.T("net.det.type"), i18n.Tf("net.det.etype", ethTypeName(p.etype), p.etype))
	}
}

// detIPv4 输出 IPv4 头字段。
func detIPv4(d *detailWriter, p *pkt) {
	src, dst := p.src, p.dst
	flags := byte(0)
	if p.fragDF {
		flags |= 0x40
	}
	if p.fragMore {
		flags |= 0x20
	}
	d.section("ipv4", i18n.Tf("net.det.ipv4_hdr", src, dst))
	d.field(1, i18n.T("net.det.version"), "4")
	d.field(1, i18n.T("net.det.hdr_len"), i18n.Tf("net.det.bytes", p.ipIHL, p.ipIHL/4))
	d.field(1, i18n.T("net.det.dsfield"),
		fmt.Sprintf("0x%02x (DSCP: 0x%02x, ECN: 0x%x)", p.ipTOS, p.ipTOS>>2, p.ipTOS&0x03))
	d.field(1, i18n.T("net.det.total_len"), strconv.Itoa(p.ipLen))
	d.field(1, i18n.T("net.det.ident"), fmt.Sprintf("0x%04x (%d)", p.ipID, p.ipID))
	d.field(1, i18n.T("net.det.flags"), fmt.Sprintf("0x%x", flags))
	d.flag(2, i18n.T("net.det.df"), p.fragDF)
	d.flag(2, i18n.T("net.det.mf"), p.fragMore)
	if p.fragOff != 0 {
		d.field(1, i18n.T("net.det.frag_off"), i18n.Tf("net.det.frag_off_val", p.fragOff, p.fragOff*8))
	}
	d.field(1, i18n.T("net.det.ttl"), strconv.Itoa(int(p.ipTTL)))
	d.field(1, i18n.T("net.det.protocol"), ipProtoName(p.ipProto))
	d.field(1, i18n.T("net.det.hdr_cksum"), fmt.Sprintf("0x%04x", p.ipCksum))
	d.field(1, i18n.T("net.det.src_addr"), src)
	d.field(1, i18n.T("net.det.dst_addr"), dst)
}

// detIPv6 输出 IPv6 头字段。
func detIPv6(d *detailWriter, p *pkt) {
	src, dst := p.src, p.dst
	d.section("ipv6", i18n.Tf("net.det.ipv6_hdr", src, dst))
	d.field(1, i18n.T("net.det.version"), "6")
	d.field(1, i18n.T("net.det.tclass"),
		fmt.Sprintf("0x%02x (DSCP: 0x%02x, ECN: 0x%x)", p.ipTOS, p.ipTOS>>2, p.ipTOS&0x03))
	d.field(1, i18n.T("net.det.flow_label"), fmt.Sprintf("0x%05x", p.ipFlow))
	d.field(1, i18n.T("net.det.payload_len"), strconv.Itoa(p.ipLen))
	d.field(1, i18n.T("net.det.next_hdr"), ipProtoName(p.ipProto))
	d.field(1, i18n.T("net.det.hop_limit"), strconv.Itoa(int(p.ipTTL)))
	d.field(1, i18n.T("net.det.src_addr"), src)
	d.field(1, i18n.T("net.det.dst_addr"), dst)
	if p.isFrag {
		d.field(1, i18n.T("net.det.frag_off"), i18n.Tf("net.det.frag_off_val", p.fragOff, p.fragOff*8))
	}
}

// tcpFlagBit 是 TCP 的一个标志位（用于逐位展示）。
type tcpFlagBit struct {
	name string
	set  bool
}

// tcpFlagBits 逐位返回 TCP 标志（位序与 tcpFlagsStr 一致：高位在前）。
func tcpFlagBits(f uint8) []tcpFlagBit {
	names := []string{"CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN"}
	masks := []uint8{0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01}
	out := make([]tcpFlagBit, 0, len(names))
	for i, n := range names {
		out = append(out, tcpFlagBit{i18n.T("net.det.flag." + strings.ToLower(n)), f&masks[i] != 0})
	}
	return out
}

// detTCP 输出 TCP 头字段（含标志位与选项）。
func detTCP(d *detailWriter, p *pkt) {
	d.section("tcp", i18n.Tf("net.det.tcp_hdr", p.srcPort, p.dstPort, p.seq, p.ack, len(p.payload)))
	d.field(1, i18n.T("net.det.src_port"), strconv.Itoa(int(p.srcPort)))
	d.field(1, i18n.T("net.det.dst_port"), strconv.Itoa(int(p.dstPort)))
	d.field(1, i18n.T("net.det.seq"), strconv.FormatUint(uint64(p.seq), 10))
	d.field(1, i18n.T("net.det.ack"), strconv.FormatUint(uint64(p.ack), 10))
	d.field(1, i18n.T("net.det.hdr_len"), i18n.Tf("net.det.bytes", p.tcpHdrLen, p.tcpHdrLen/4))
	d.field(1, i18n.T("net.det.tcp_flags"), tcpFlagsStr(p.flags))
	for _, t := range tcpFlagBits(p.flags) {
		d.flag(2, t.name, t.set)
	}
	d.field(1, i18n.T("net.det.window"), strconv.Itoa(int(p.win)))
	d.field(1, i18n.T("net.det.checksum"), fmt.Sprintf("0x%04x", p.tcpCksum))
	d.field(1, i18n.T("net.det.urgent_ptr"), strconv.Itoa(int(p.tcpUrgent)))
	detTCPOptions(d, p.tcpOpts)
}

// detTCPOptions 逐条解析 TCP 选项（kind/length + 关键取值）。
func detTCPOptions(d *detailWriter, b []byte) {
	if len(b) == 0 {
		d.field(1, i18n.T("net.det.options"), i18n.T("net.det.none"))
		return
	}
	for off := 0; off < len(b); {
		kind := b[off]
		if kind == 0 { // EOL
			d.field(1, i18n.Tf("net.det.opt_kind", "EOL"), "")
			return
		}
		if kind == 1 { // NOP
			d.field(1, i18n.Tf("net.det.opt_kind", "NOP"), "")
			off++
			continue
		}
		if off+2 > len(b) {
			break
		}
		l := int(b[off+1])
		if l < 2 || off+l > len(b) {
			break
		}
		d.field(1, i18n.Tf("net.det.opt_kind", tcpOptName(kind)),
			tcpOptValue(kind, b[off+2:off+l]))
		off += l
	}
}

// tcpOptName 返回 TCP 选项种类的可读名（未识别时给十六进制）。
func tcpOptName(kind byte) string {
	switch kind {
	case 2:
		return "MSS"
	case 3:
		return "Window Scale"
	case 4:
		return "SACK Permitted"
	case 5:
		return "SACK"
	case 8:
		return "Timestamps"
	}
	return "0x" + strconv.FormatUint(uint64(kind), 16)
}

// tcpOptValue 渲染常见 TCP 选项的取值。
func tcpOptValue(kind byte, v []byte) string {
	switch kind {
	case 2:
		if len(v) == 2 {
			return strconv.Itoa(int(v[0])<<8 | int(v[1]))
		}
	case 3:
		if len(v) == 1 {
			return strconv.Itoa(int(v[0]))
		}
	case 8:
		if len(v) == 8 {
			tsval := int(v[0])<<24 | int(v[1])<<16 | int(v[2])<<8 | int(v[3])
			tsecr := int(v[4])<<24 | int(v[5])<<16 | int(v[6])<<8 | int(v[7])
			return "TSval " + strconv.Itoa(tsval) + ", TSecr " + strconv.Itoa(tsecr)
		}
	}
	if len(v) == 0 {
		return ""
	}
	return "0x" + fmt.Sprintf("%x", v)
}

// detUDP 输出 UDP 头字段。
func detUDP(d *detailWriter, p *pkt) {
	d.section("udp", i18n.Tf("net.det.udp_hdr", p.srcPort, p.dstPort, len(p.payload)))
	d.field(1, i18n.T("net.det.src_port"), strconv.Itoa(int(p.srcPort)))
	d.field(1, i18n.T("net.det.dst_port"), strconv.Itoa(int(p.dstPort)))
	d.field(1, i18n.T("net.det.length"), strconv.Itoa(p.udpLen))
	d.field(1, i18n.T("net.det.checksum"), fmt.Sprintf("0x%04x", p.udpCksum))
	if svc := portService[p.dstPort]; svc != "" {
		d.field(1, i18n.T("net.det.service"), svc)
	}
}

// detICMP 输出 ICMP / ICMPv6 头字段。
func detICMP(d *detailWriter, p *pkt) {
	name := icmpTypeName(p.l4 == "ICMPv6", p.icmpType)
	d.section("icmp", i18n.Tf("net.det.icmp_hdr", name, p.icmpType, p.icmpCode))
	d.field(1, i18n.T("net.det.type"), i18n.Tf("net.det.icmp_type", name, p.icmpType))
	d.field(1, i18n.T("net.det.code"), strconv.Itoa(int(p.icmpCode)))
	d.field(1, i18n.T("net.det.checksum"), fmt.Sprintf("0x%04x", p.icmpCksum))
	if len(p.payload) >= 8 {
		d.field(1, i18n.T("net.det.icmp_id"), strconv.Itoa(int(p.icmpID)))
		d.field(1, i18n.T("net.det.icmp_seq"), strconv.Itoa(int(p.icmpSeq)))
	}
}

// detARP 输出 ARP 字段。
func detARP(d *detailWriter, p *pkt) {
	op := i18n.T("net.det.arp_other")
	switch p.arpOp {
	case 1:
		op = i18n.T("net.det.arp_request")
	case 2:
		op = i18n.T("net.det.arp_reply")
	}
	d.section("arp", i18n.Tf("net.det.arp_hdr", op))
	d.field(1, i18n.T("net.det.hw_type"), fmt.Sprintf("0x%04x", p.arpHwType))
	d.field(1, i18n.T("net.det.proto_type"), fmt.Sprintf("0x%04x", p.arpProtoType))
	d.field(1, i18n.T("net.det.hw_size"), strconv.Itoa(int(p.arpHwSize)))
	d.field(1, i18n.T("net.det.proto_size"), strconv.Itoa(int(p.arpProtoSize)))
	d.field(1, i18n.T("net.det.arp_op"), op)
	d.field(1, i18n.T("net.det.arp_sender_mac"), p.srcMAC())
	d.field(1, i18n.T("net.det.arp_sender_ip"), p.arpSenderIP)
	d.field(1, i18n.T("net.det.arp_target_mac"), macStr(p.arpTgtMACRaw[:]))
	d.field(1, i18n.T("net.det.arp_target_ip"), p.arpTgtIP)
}

// detPayload 输出应用层载荷的可读明细。
func detPayload(d *detailWriter, p *pkt) {
	if p.app == "" {
		// 没有识别出应用层协议（如 ARP/ICMP）时直接给摘要，不额外起一个空标题
		if p.info != "" {
			d.field(1, i18n.T("net.det.info"), p.info)
		}
		return
	}
	d.section("app", p.app)
	if p.info != "" {
		d.field(1, i18n.T("net.det.info"), p.info)
	}
	switch p.app {
	case "HTTP":
		host, creds := httpReqInfo(p.payload)
		if host != "" {
			d.field(1, i18n.T("net.det.http_host"), host)
		}
		for _, c := range creds {
			d.field(1, i18n.T("net.det.http_cred"), c.kind+" "+c.value)
		}
		for _, hf := range scanPassFields(p.payload) {
			d.field(1, i18n.T("net.det.http_pass"), hf.key+"="+hf.value)
		}
	case "DNS", "mDNS", "LLMNR":
		if m, ok := parseDNS(p.payload, p.l4 == "TCP"); ok && m.qname != "" {
			d.field(1, i18n.T("net.det.dns_name"), m.qname)
			if len(m.answers) > 0 {
				d.field(1, i18n.T("net.det.dns_ans"), strings.Join(m.answers, ", "))
			}
		}
	case "TLS":
		if sni := clientHelloSNI(p.payload); sni != "" {
			d.field(1, i18n.T("net.det.tls_sni"), sni)
		}
	}
}

// detHexDump 以 16 字节一行的经典 hexdump 输出整帧原始字节。
func detHexDump(d *detailWriter, p *pkt) {
	if len(p.raw) == 0 {
		return
	}
	d.section("hex", i18n.T("net.det.frame_data"))
	for off := 0; off < len(p.raw); off += 16 {
		end := off + 16
		if end > len(p.raw) {
			end = len(p.raw)
		}
		chunk := p.raw[off:end]
		var hex, ascii strings.Builder
		for i, b := range chunk {
			if i == 8 {
				hex.WriteByte(' ')
			}
			fmt.Fprintf(&hex, "%02x ", b)
			if b >= 0x20 && b < 0x7f {
				ascii.WriteByte(b)
			} else {
				ascii.WriteByte('.')
			}
		}
		d.hexLine(fmt.Sprintf("%s%04x  %-39s  %s", strings.Repeat(" ", detIndent),
			off, hex.String(), ascii.String()))
	}
}

// linkTypeName 把链路层类型编号渲染成名称。
func linkTypeName(lt uint32) string {
	switch lt {
	case dltEthernet:
		return "Ethernet (1)"
	case dltLinuxSLL:
		return "Linux cooked capture (113)"
	case dltLinuxSLL2:
		return "Linux cooked capture v2 (276)"
	case dltNull, dltLoop:
		return "Loopback"
	case dltRaw, dltRawAlt:
		return "Raw IP"
	case dltPPP, dltPppSerial, dltPppHdlc:
		return "PPP"
	case dltIEEE80211:
		return "IEEE 802.11 (105)"
	case dltRadiotap:
		return "IEEE 802.11 radiotap (127)"
	}
	return strconv.FormatUint(uint64(lt), 10)
}

// ethTypeName 把 EtherType 渲染成名称（未知时只给十六进制）。
func ethTypeName(et uint16) string {
	switch et {
	case etIPv4:
		return "IPv4"
	case etIPv6:
		return "IPv6"
	case etARP:
		return "ARP"
	case etRARP:
		return "RARP"
	case etVLAN:
		return "802.1Q"
	case etVLANQinQ:
		return "802.1ad"
	case etMPLS:
		return "MPLS"
	case etPPPoESess:
		return "PPPoE Session"
	case etEAPOL:
		return "EAPOL"
	case etLLDP:
		return "LLDP"
	}
	return "0x" + fmt.Sprintf("%04x", et)
}

// ipProtoName 把 IP 协议号渲染成名称。
func ipProtoName(n uint8) string {
	switch n {
	case 1:
		return "ICMP (1)"
	case 2:
		return "IGMP (2)"
	case 6:
		return "TCP (6)"
	case 17:
		return "UDP (17)"
	case 47:
		return "GRE (47)"
	case 50:
		return "ESP (50)"
	case 51:
		return "AH (51)"
	case 58:
		return "ICMPv6 (58)"
	case 89:
		return "OSPF (89)"
	case 103:
		return "PIM (103)"
	case 112:
		return "VRRP (112)"
	case 132:
		return "SCTP (132)"
	}
	return "0x" + strconv.FormatUint(uint64(n), 16)
}

// icmpTypeName 把 ICMP / ICMPv6 的类型码渲染成名称。
func icmpTypeName(v6 bool, t byte) string {
	if v6 {
		switch t {
		case 128:
			return "Echo (ping) request"
		case 129:
			return "Echo (ping) reply"
		case 133:
			return "Router Solicitation"
		case 134:
			return "Router Advertisement"
		case 135:
			return "Neighbor Solicitation"
		case 136:
			return "Neighbor Advertisement"
		}
		return "Unknown"
	}
	switch t {
	case 0:
		return "Echo (ping) reply"
	case 3:
		return "Destination Unreachable"
	case 8:
		return "Echo (ping) request"
	case 11:
		return "Time-to-live exceeded"
	}
	return "Unknown"
}
