package pcap

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// iface 是 pcapng 的一个接口（IDB）：链路类型与时间戳基准。
// pcap 没有接口概念，等价信息存放在 Reader 上。
type iface struct {
	linkType uint32
	snapLen  uint32
	tsResol  uint64 // 时间戳分母（每秒 tick 数），默认 1e6 微秒
	tsOffset int64  // 时间戳偏移（秒）
}

// Reader 顺序读取一个抓包容器。
//
// 用法：
//
//	r, err := pcap.Open(f, size)
//	for { rec, err := r.Next(); if err == io.EOF { break } ... }
type Reader struct {
	br   *bufio.Reader
	cnt  *countingReader // 底层字节计数，pos() 据此算当前偏移
	info Info
	kind Format

	// pcap
	order    binary.ByteOrder
	linkType uint32

	// pcapng
	ngOrder binary.ByteOrder
	ngBuf   []byte
	ifaces  []*iface

	// pktBuf 是 pcap 格式的帧缓冲，逐帧复用（见 nextPCAP）。
	pktBuf []byte

	index int // 已产出的帧数
}

// countingReader 记录已从底层读取的字节数。
//
// 偏移不靠各解析分支手工累加：偏移只要算错一个字节，FrameData 就会静默读出
// 错位的帧——那种错误在界面上表现为"详情对不上"，极难察觉。
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// pos 返回下一个待解析字节的文件偏移。
//
// bufio 会预读，所以 countingReader 的计数总是超前；减去缓冲区里还没被解析
// 消费的部分即得当前位置。
func (r *Reader) pos() int64 {
	return r.cnt.n - int64(r.br.Buffered())
}

// Open 识别并打开抓包容器。
//
// 输入不是 pcap/pcapng 时返回 ErrNotCapture；结构损坏返回具体错误。
// 文件头截断（有魔数但读不全）按结构损坏处理。
func Open(f io.ReaderAt, size int64) (*Reader, error) {
	if size < 4 {
		return nil, ErrNotCapture
	}
	// 魔数用 ReadAt 判断，不消耗 bufio 的读取位置
	head := make([]byte, 4)
	if n, _ := f.ReadAt(head, 0); n < 4 {
		return nil, ErrNotCapture
	}

	r := &Reader{cnt: &countingReader{r: io.NewSectionReader(f, 0, size)}}
	r.br = bufio.NewReaderSize(r.cnt, 1<<16)
	switch {
	case IsPCAPNG(head):
		r.kind = FormatPCAPNG
		if err := r.openPCAPNG(); err != nil {
			return nil, err
		}
	case IsPCAP(head):
		r.kind = FormatPCAP
		if err := r.openPCAP(); err != nil {
			return nil, err
		}
	default:
		return nil, ErrNotCapture
	}
	return r, nil
}

// Info 返回容器元信息（pcapng 的接口数随扫描递增）。
func (r *Reader) Info() Info { return r.info }

// Next 返回下一帧；文件结束返回 io.EOF。
//
// 返回的 Record.Data 指向内部复用缓冲区，只在下一次 Next 之前有效。
func (r *Reader) Next() (Record, error) {
	if r.kind == FormatPCAPNG {
		return r.nextPCAPNG()
	}
	return r.nextPCAP()
}

// ---------------------------------------------------------------------------
// pcap
// ---------------------------------------------------------------------------

// openPCAP 解析 24 字节全局头。
func (r *Reader) openPCAP() error {
	var gh [24]byte
	if _, err := io.ReadFull(r.br, gh[:]); err != nil {
		if isTruncated(err) {
			return fmt.Errorf("pcap global header truncated")
		}
		return err
	}
	order := pcapByteOrder(gh[:4])
	if order == nil {
		return fmt.Errorf("pcap magic not recognized")
	}
	v := binary.LittleEndian.Uint32(gh[:4])
	nano := v == pcapMagicNano || v == bswap32(pcapMagicNano)

	r.order = order
	r.linkType = order.Uint32(gh[20:24])
	r.info = Info{
		Format:    FormatPCAP,
		BigEndian: order == binary.BigEndian,
		Version:   fmt.Sprintf("%d.%d", order.Uint16(gh[4:6]), order.Uint16(gh[6:8])),
		SnapLen:   order.Uint32(gh[16:20]),
		Nano:      nano,
		TsResol:   1e6,
	}
	if nano {
		r.info.TsResol = 1e9
	}
	return nil
}

// nextPCAP 读取一条记录：16 字节记录头 + 数据。
//
// 尾部截断（抓包在写入过程中被中断）按 EOF 处理，已解析的帧仍然有效。
func (r *Reader) nextPCAP() (Record, error) {
	for {
		p0 := r.pos() // 本条记录在文件中的偏移
		var rh [16]byte
		if _, err := io.ReadFull(r.br, rh[:]); err != nil {
			return Record{}, eofOrErr(err)
		}
		order := r.order
		sec, frac := order.Uint32(rh[0:4]), order.Uint32(rh[4:8])
		incl := int64(order.Uint32(rh[8:12]))
		orig := order.Uint32(rh[12:16])

		if incl == 0 {
			// 全零填充记录：跳过（与 hashdump 的处理保持一致）
			continue
		}
		if incl > MaxPacket {
			return Record{}, fmt.Errorf("packet length %d exceeds limit", incl)
		}
		// 复用帧缓冲：Record.Data 的约定本来就是"只在下次 Next 之前有效"，
		// 每帧一次 make 在大抓包上是可观的分配与 GC 开销。
		if int64(cap(r.pktBuf)) < incl {
			r.pktBuf = make([]byte, incl)
		}
		data := r.pktBuf[:incl]
		if _, err := io.ReadFull(r.br, data); err != nil {
			return Record{}, eofOrErr(err)
		}

		ts := time.Unix(int64(sec), int64(frac))
		if !r.info.Nano {
			ts = time.Unix(int64(sec), int64(frac)*1000)
		}
		r.index++
		if orig < uint32(incl) {
			orig = uint32(incl)
		}
		return Record{Index: r.index, Time: ts, LinkType: r.linkType,
			Data: data, OrigLen: orig,
			Ref: r.frameRef(p0, r.linkType, orig)}, nil
	}
}

// frameRef 组装一帧的定位信息。
func (r *Reader) frameRef(off int64, linkType, origLen uint32) FrameRef {
	be := r.info.BigEndian
	if r.kind == FormatPCAP {
		be = r.order == binary.BigEndian
	}
	return FrameRef{
		Offset:    off,
		Format:    r.kind,
		BigEndian: be,
		LinkType:  linkType,
		OrigLen:   origLen,
	}
}

// eofOrErr 把"读到文件末尾"的各种错误统一成 io.EOF，其余原样返回。
func eofOrErr(err error) error {
	if isTruncated(err) {
		return io.EOF
	}
	return err
}

// pcapByteOrder 由魔数判定文件字节序；无法识别返回 nil。
func pcapByteOrder(m []byte) binary.ByteOrder {
	if len(m) < 4 {
		return nil
	}
	switch {
	case m[0] == 0xd4 && m[1] == 0xc3, m[0] == 0x4d && m[1] == 0x3c:
		return binary.LittleEndian // d4 c3 b2 a1 / 4d 3c b2 a1
	case m[0] == 0xa1 && m[1] == 0xb2:
		return binary.BigEndian // a1 b2 c3 d4 / a1 b2 3c 4d
	}
	return nil
}

// ---------------------------------------------------------------------------
// pcapng
// ---------------------------------------------------------------------------

// openPCAPNG 解析首块（必须是 Section Header Block）。
func (r *Reader) openPCAPNG() error {
	var head [12]byte
	if _, err := io.ReadFull(r.br, head[:]); err != nil {
		if isTruncated(err) {
			return fmt.Errorf("pcapng section header block truncated")
		}
		return err
	}
	if binary.LittleEndian.Uint32(head[0:4]) != blockSHB {
		return fmt.Errorf("pcapng section header block missing")
	}
	order, err := shbByteOrder(head)
	if err != nil {
		return err
	}
	blen := int64(order.Uint32(head[4:8]))
	if blen < 12 || blen > MaxBlock {
		return fmt.Errorf("pcapng bad block length %d", blen)
	}
	body, err := r.readBlockBody(head, blen)
	if err != nil {
		if err == io.EOF {
			return fmt.Errorf("pcapng section header block truncated")
		}
		return err
	}
	r.ngOrder = order
	r.info = Info{
		Format:    FormatPCAPNG,
		BigEndian: order == binary.BigEndian,
		Version:   shbVersion(order, body),
		TsResol:   1e6,
	}
	return nil
}

// shbByteOrder 从 SHB 头部的字节序标识判定字节序。
func shbByteOrder(head [12]byte) (binary.ByteOrder, error) {
	switch binary.LittleEndian.Uint32(head[8:12]) {
	case byteOrderMagic:
		return binary.LittleEndian, nil
	case bswap32(byteOrderMagic):
		return binary.BigEndian, nil
	}
	return nil, fmt.Errorf("pcapng bad byte-order magic")
}

// shbVersion 取 SHB 的主次版本号。
func shbVersion(order binary.ByteOrder, body []byte) string {
	if len(body) < 8 {
		return "1.0"
	}
	return fmt.Sprintf("%d.%d", order.Uint16(body[4:6]), order.Uint16(body[6:8]))
}

// readBlockBody 把 12 字节头与剩余块体读进复用缓冲区，返回块体（不含块头与尾长）。
func (r *Reader) readBlockBody(head [12]byte, blen int64) ([]byte, error) {
	if int64(cap(r.ngBuf)) < blen {
		r.ngBuf = make([]byte, blen)
	}
	blk := r.ngBuf[:blen]
	copy(blk[:12], head[:])
	if _, err := io.ReadFull(r.br, blk[12:]); err != nil {
		if isTruncated(err) {
			return nil, io.EOF
		}
		return nil, err
	}
	// 去掉 8 字节块头与尾部 4 字节重复长度，得到块体。
	return blk[8 : blen-4], nil
}

// nextPCAPNG 逐块读取，产出 EPB / SPB 承载的帧；其余块直接跳过。
func (r *Reader) nextPCAPNG() (Record, error) {
	for {
		b0 := r.pos() // 当前块在文件中的偏移
		var head [12]byte
		if _, err := io.ReadFull(r.br, head[:]); err != nil {
			return Record{}, eofOrErr(err)
		}

		// 新 section：SHB 的块类型是字节回文，先识别再按新字节序读块长。
		if binary.LittleEndian.Uint32(head[0:4]) == blockSHB {
			order, err := shbByteOrder(head)
			if err != nil {
				return Record{}, err
			}
			blen := int64(order.Uint32(head[4:8]))
			if blen < 12 || blen > MaxBlock {
				return Record{}, fmt.Errorf("pcapng bad block length %d", blen)
			}
			if _, err := r.readBlockBody(head, blen); err != nil {
				if err == io.EOF {
					return Record{}, io.EOF
				}
				return Record{}, err
			}
			// 新 section 的接口表失效
			r.ngOrder = order
			r.info.BigEndian = order == binary.BigEndian
			r.ifaces = nil
			r.info.Interfaces = 0
			r.info.SnapLen = 0
			r.info.TsResol = 1e6
			r.info.TsOffset = 0
			continue
		}

		order := r.ngOrder
		if order == nil {
			return Record{}, fmt.Errorf("pcapng section header block missing")
		}
		bt := order.Uint32(head[0:4])
		blen := int64(order.Uint32(head[4:8]))
		if blen < 12 || blen > MaxBlock {
			return Record{}, fmt.Errorf("pcapng bad block length %d", blen)
		}
		body, err := r.readBlockBody(head, blen)
		if err != nil {
			if err == io.EOF {
				return Record{}, io.EOF
			}
			return Record{}, err
		}

		switch bt {
		case blockIDB:
			r.addIface(order, body)

		case blockEPB:
			// 块体: iface(4) ts_high(4) ts_low(4) cap_len(4) orig_len(4) data..
			if len(body) < 20 {
				continue
			}
			ifc := r.ifaceAt(order.Uint32(body[0:4]))
			ts := uint64(order.Uint32(body[4:8]))<<32 | uint64(order.Uint32(body[8:12]))
			capLen := int64(order.Uint32(body[12:16]))
			orig := order.Uint32(body[16:20])
			if capLen < 0 || capLen > int64(len(body)-20) {
				capLen = int64(len(body) - 20)
			}
			r.index++
			return Record{
				Index:    r.index,
				Time:     ifc.time(ts),
				LinkType: ifc.linkType,
				Data:     body[20 : 20+capLen],
				OrigLen:  orig,
				Ref:      r.frameRef(b0, ifc.linkType, orig),
			}, nil

		case blockSPB:
			// 块体: orig_len(4) data..（无时间戳，走接口 0）
			if len(body) < 4 {
				continue
			}
			orig := order.Uint32(body[0:4])
			data := body[4:]
			if n := int64(orig); n < int64(len(data)) {
				data = data[:n]
			}
			r.index++
			lt := r.ifaceAt(0).linkType
			return Record{
				Index:    r.index,
				LinkType: lt,
				Data:     data,
				OrigLen:  orig,
				Ref:      r.frameRef(b0, lt, orig),
			}, nil
		}
	}
}

// addIface 登记一个 Interface Description Block。
func (r *Reader) addIface(order binary.ByteOrder, body []byte) {
	if len(body) < 8 {
		return
	}
	ifc := &iface{
		linkType: uint32(order.Uint16(body[0:2])),
		snapLen:  order.Uint32(body[4:8]),
		tsResol:  1e6,
	}
	// 选项: code(2) len(2) value(按 4 字节对齐)
	for opt := body[8:]; len(opt) >= 4; {
		code := order.Uint16(opt[0:2])
		n := int(order.Uint16(opt[2:4]))
		if 4+n > len(opt) {
			break
		}
		val := opt[4 : 4+n]
		switch code {
		case optIfTsResol:
			if len(val) == 1 {
				ifc.tsResol = tsResolDenom(val[0])
			}
		case optIfTsOffst:
			if len(val) == 8 {
				ifc.tsOffset = int64(order.Uint64(val))
			}
		}
		opt = opt[4+n:]
		if pad := (4 - n%4) % 4; pad > 0 {
			if pad > len(opt) {
				break
			}
			opt = opt[pad:]
		}
	}
	r.ifaces = append(r.ifaces, ifc)
	r.info.Interfaces++
	if ifc.snapLen != 0 {
		r.info.SnapLen = ifc.snapLen
	}
	// Info 里记首接口的时间戳基准，供报告展示
	if len(r.ifaces) == 1 {
		r.info.TsResol = ifc.tsResol
		r.info.TsOffset = ifc.tsOffset
	}
}

// tsResolDenom 把 if_tsresol 选项换算成分母（每秒 tick 数）。
//
// 最高位为 0 表示 10^n，为 1 表示 2^n；超出可表示范围时退回默认微秒。
func tsResolDenom(v byte) uint64 {
	if v&0x80 != 0 {
		n := v & 0x7f
		if n >= 63 {
			return 1e6
		}
		return 1 << n
	}
	if v > 18 {
		return 1e6
	}
	d := uint64(1)
	for i := byte(0); i < v; i++ {
		d *= 10
	}
	return d
}

// ifaceAt 按接口号取接口；越界或还没登记过时返回一个默认接口。
func (r *Reader) ifaceAt(id uint32) *iface {
	if id < uint32(len(r.ifaces)) {
		return r.ifaces[id]
	}
	return &iface{tsResol: 1e6}
}

// time 把 64 位 tick 数换算成时间。
func (ifc *iface) time(ts uint64) time.Time {
	resol := ifc.tsResol
	if resol == 0 {
		resol = 1e6
	}
	sec := int64(ts/resol) + ifc.tsOffset
	var nsec int64
	if resol <= 1e9 {
		nsec = int64(ts%resol) * 1e9 / int64(resol)
	}
	return time.Unix(sec, nsec)
}
