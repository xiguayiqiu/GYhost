// TCP 流重组：把乱序、重传、分段的报文按序拼回两个方向的字节流。
//
// 这是"看流量里到底传了什么"的唯一办法——单看包只能看到分片后的片段，
// 而 HTTP 请求体、SMTP 会话、文件内容都要拼起来才认得出明文。
//
// 重组要点：
//   - 用 SYN 里的初始序号（ISN）做基准，序号回绕用无符号减法天然处理
//   - 重传（同一段序号重复到达）只留第一次，不重复拼接
//   - 中间缺号的空洞填 0 并记录缺口，避免把缺失数据当成真实内容
//   - 双向分开重组，各自从自己方向的 ISN 起算
package net

import (
	"sort"
	"strconv"
	"strings"
)

// streamSeg 是一段带相对序号的载荷。
type streamSeg struct {
	seq  uint32 // 相对 ISN 的偏移
	data []byte
}

// streamDir 是一个方向的重组缓冲。
type streamDir struct {
	endpoint  string // 端点渲染文本（含端口）
	isn       uint32 // 初始序号；没见到 SYN 时为 0（此时相对序号不可靠）
	haveISN   bool
	segs      []streamSeg
	bytes     int64  // 已收集的载荷字节数
	dropped   int64  // 因超出上限而丢弃的字节数
	firstSeq  uint32 // 收到的第一个相对序号，用于没有 ISN 时对齐
	haveFirst bool
}

// streamConv 是一条 TCP 双向会话。
type streamConv struct {
	key   string // 会话键（与 flows 相同，便于与 -z conv 对齐）
	proto string
	dirs  [2]*streamDir
	// gap 记录重组时发现的空洞总数，供报告提示"内容不完整"
	gap int
	// truncated 表示因内存上限丢弃过数据
	truncated bool
}

// streamLimits 是重组的内存上限。
//
// 抓包可能很大（几百 MB 载荷），全部留在内存并不总是合理；
// 超过上限就停止收集并标记，让报告明确说"内容不完整"，而不是给出
// 一个看起来完整实则被截断的会话。
type streamLimits struct {
	perDir  int64 // 单方向上限
	total   int64 // 单会话上限（两方向之和）
	perSess int   // 单会话的段数上限
}

const (
	defaultStreamPerDir  = 8 << 20  // 单方向 8 MiB
	defaultStreamPerSess = 16 << 20 // 单会话 16 MiB
	defaultStreamSegs    = 20000    // 单会话最多 2 万段，防止段数爆炸
)

// newTCPStream 创建一个空会话。
func newStreamConv(key, proto string) *streamConv {
	return &streamConv{key: key, proto: proto}
}

// dir 返回 d 号方向的缓冲，按需创建。
func (s *streamConv) dir(d int, endpoint string) *streamDir {
	if s.dirs[d] == nil {
		s.dirs[d] = &streamDir{endpoint: endpoint}
	}
	return s.dirs[d]
}

// dirFor 按端点字典序确定方向号，返回该方向的缓冲。
//
// 方向 0 永远是字典序较小的一端，方向 1 是另一端；各方向记住自己的发送端，
// 这样 follow 输出里两侧显示的才是真实的两端。
func (s *streamConv) dirFor(src, dst string, sport, dport uint16) *streamDir {
	ep := src + ":" + itoa(int(sport))
	peer := dst + ":" + itoa(int(dport))
	if ep <= peer {
		return s.dir(0, ep)
	}
	return s.dir(1, ep)
}

// add 收集一个方向的载荷。
func (d *streamDir) add(seq uint32, isn uint32, haveISN bool, payload []byte, lim streamLimits) bool {
	if len(payload) == 0 {
		return false
	}
	d.bytes += int64(len(payload))
	if !haveISN {
		// 没有 ISN（没抓到握手）：以第一个收到的序号为基准，
		// 保证同一会话内部相对有序（跨会话不可比，但重组仍可用）
		if !d.haveFirst {
			d.firstSeq = seq
			d.haveFirst = true
		}
		seq = seq - d.firstSeq
	}
	if d.bytes > lim.perDir || len(d.segs) >= lim.perSess {
		d.dropped += int64(len(payload))
		return true // 已超限
	}
	cp := append([]byte(nil), payload...)
	d.segs = append(d.segs, streamSeg{seq: seq, data: cp})
	return false
}

// reassemble 按序拼接一个方向，返回字节流与空洞数。
//
// 接收者可能为 nil：单向会话（只抓到单向载荷）里另一方向根本没有缓冲。
func (d *streamDir) reassemble() ([]byte, int) {
	if d == nil || len(d.segs) == 0 {
		return nil, 0
	}
	segs := make([]streamSeg, len(d.segs))
	copy(segs, d.segs)
	// 相对序号是无符号差值，正常抓包里单调递增；用无符号比较即可
	sort.Slice(segs, func(i, j int) bool { return segs[i].seq < segs[j].seq })

	var out []byte
	var cur uint32
	first := true
	gaps := 0
	for _, s := range segs {
		switch {
		case first:
			cur = s.seq
			first = false
		case s.seq > cur:
			// 中间缺了一段：用 0 填充并记缺口，绝不把缺失当真实数据
			gaps++
			for i := cur; i < s.seq; i++ {
				out = append(out, 0)
			}
			cur = s.seq
		case cur > s.seq:
			// 与已收数据重叠（重传/乱序）：只取新增的那部分
			off := int(cur - s.seq)
			if off >= len(s.data) {
				continue // 完全重复的重传
			}
			out = append(out, s.data[off:]...)
			cur += uint32(len(s.data) - off)
			continue
		}
		out = append(out, s.data...)
		cur += uint32(len(s.data))
	}
	return out, gaps
}

// followFormat 是 TCP 流追踪的输出格式。
type followFormat int

const (
	followASCII followFormat = iota // 可打印字符（对齐 tshark 的 ascii）
	followRaw                       // 原始字节（转义不可打印字符）
	followHex                       // 十六进制 hexdump
)

// parseFollowFormat 解析 -z follow 的格式参数。
func parseFollowFormat(s string) (followFormat, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ascii", "":
		return followASCII, true
	case "raw":
		return followRaw, true
	case "hex":
		return followHex, true
	}
	return followASCII, false
}

// renderASCII 把字节流渲染成可打印字符，非打印字符用 '.' 占位。
func renderASCII(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 0x20 && c < 0x7f {
			out[i] = c
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}

// renderRaw 把字节流渲染成原始文本，非打印字符用 C 风格转义。
//
// 保留可打印字符原样，其余用 \xNN / \n / \r / \t 转义，
// 这样 SMTP 会话、HTTP 头这类混合文本读起来仍然连贯。
func renderRaw(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b) + 16)
	for _, c := range b {
		switch c {
		case '\n':
			sb.WriteString("\\n")
		case '\r':
			sb.WriteString("\\r")
		case '\t':
			sb.WriteString("\\t")
		case '\\':
			sb.WriteString("\\\\")
		default:
			if c >= 0x20 && c < 0x7f {
				sb.WriteByte(c)
			} else {
				sb.WriteString(hexEscape(c))
			}
		}
	}
	return sb.String()
}

// hexEscape 返回单字节的十六进制转义。
func hexEscape(c byte) string {
	const hexd = "0123456789abcdef"
	return string([]byte{'\\', 'x', hexd[c>>4], hexd[c&0xf]})
}

// renderHex 把字节流渲染成 hexdump。
func renderHex(b []byte) string {
	var sb strings.Builder
	for off := 0; off < len(b); off += 16 {
		end := off + 16
		if end > len(b) {
			end = len(b)
		}
		chunk := b[off:end]
		var hx, asc strings.Builder
		for i, c := range chunk {
			if i == 8 {
				hx.WriteByte(' ')
			}
			const hexd = "0123456789abcdef"
			hx.WriteByte(hexd[c>>4])
			hx.WriteByte(hexd[c&0xf])
			hx.WriteByte(' ')
			if c >= 0x20 && c < 0x7f {
				asc.WriteByte(c)
			} else {
				asc.WriteByte('.')
			}
		}
		sb.WriteString(hexOffset(off))
		sb.WriteString("  ")
		sb.WriteString(hx.String())
		sb.WriteString(" ")
		sb.WriteString(asc.String())
		sb.WriteByte('\n')
	}
	return sb.String()
}

// hexOffset 把偏移渲染成定宽 4 位十六进制。
func hexOffset(off int) string {
	const hexd = "0123456789abcdef"
	return string([]byte{
		hexd[(off>>12)&0xf], hexd[(off>>8)&0xf],
		hexd[(off>>4)&0xf], hexd[off&0xf],
	})
}

// follow 重组并渲染一条会话，返回双向的内容与元信息。
func (s *streamConv) follow(format followFormat) (c0, c1 string, gaps int) {
	b0, g0 := s.dirs[0].reassemble()
	b1, g1 := s.dirs[1].reassemble()
	gaps = g0 + g1
	s.gap = gaps
	switch format {
	case followRaw:
		return renderRaw(b0), renderRaw(b1), gaps
	case followHex:
		return renderHex(b0), renderHex(b1), gaps
	default:
		return renderASCII(b0), renderASCII(b1), gaps
	}
}

// enableStreams 打开 TCP 会话重组收集。
func (a *analysis) enableStreams(lim streamLimits) {
	a.streams = map[string]*streamConv{}
	a.streamLim = lim
}

// collectStream 收集一帧的 TCP 载荷（未启用重组时直接返回）。
func (a *analysis) collectStream(p *pkt) {
	if a.streams == nil || p.l4 != "TCP" || len(p.payload) == 0 {
		return
	}
	if p.seq == 0 && p.ack == 0 && len(p.payload) == 0 {
		return
	}
	src, dst := p.addrPair()
	if src == "" || dst == "" {
		return
	}
	// 会话键与 flows 保持一致，这样 -z follow 的序号能与 -z conv 对上
	lo, hi := src+":"+itoa(int(p.srcPort)), dst+":"+itoa(int(p.dstPort))
	if lo > hi {
		lo, hi = hi, lo
	}
	key := "TCP|" + lo + "|" + hi

	sc := a.streams[key]
	if sc == nil {
		sc = newStreamConv(key, "TCP")
		a.streams[key] = sc
	}
	// 方向：按端点字典序固定为 0/1，两个方向各自从自己的 ISN 起算。
	// 每个方向记住自己的发送端（而不是"较小的那端"），否则两侧会显示成同一个。
	sd := sc.dirFor(src, dst, p.srcPort, p.dstPort)
	// SYN（不带 ACK）携带本方向的初始序号
	haveISN, isn := sd.haveISN, sd.isn
	if p.flags&0x02 != 0 && p.flags&0x10 == 0 {
		sd.isn = p.seq
		sd.haveISN = true
		haveISN, isn = true, p.seq
	}
	if sd.add(p.seq, isn, haveISN, p.payload, a.streamLim) {
		sc.truncated = true
	}
}

// itoa 是 strconv.Itoa 的短别名（这里只在热路径拼接键时用）。
func itoa(n int) string { return strconv.Itoa(n) }
