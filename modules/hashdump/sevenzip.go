package hashdump

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"

	"github.com/ulikunitz/xz/lzma"

	"gyhost/internal/i18n"
)

// 7z 编码 ID（DOC/Methods.txt、7zHeader.h）。
var (
	z7Copy    = []byte{0x00}
	z7LZMA2   = []byte{0x21}
	z7Delta   = []byte{0x03}
	z7LZMA1   = []byte{0x03, 0x01, 0x01}
	z7PPMD    = []byte{0x03, 0x04, 0x01}
	z7Deflate = []byte{0x04, 0x01, 0x08}
	z7Bzip2   = []byte{0x04, 0x02, 0x02}
	z7AES     = []byte{0x06, 0xf1, 0x07, 0x01}
	z7BCJ     = []byte{0x03, 0x03, 0x01, 0x03}
	z7BCJ2    = []byte{0x03, 0x03, 0x01, 0x1b}
	z7PPC     = []byte{0x03, 0x03, 0x02, 0x05}
	z7Alpha   = []byte{0x03, 0x03, 0x03, 0x01}
	z7IA64    = []byte{0x03, 0x03, 0x04, 0x01}
	z7ARM     = []byte{0x03, 0x03, 0x05, 0x01}
	z7ARMT    = []byte{0x03, 0x03, 0x07, 0x01}
	z7SPARC   = []byte{0x03, 0x03, 0x08, 0x05}
)

// 7z 头部节点 ID。
const (
	z7NidEnd           = 0x00
	z7NidHeader        = 0x01
	z7NidArchiveProps  = 0x02
	z7NidMainStreams   = 0x04
	z7NidFilesInfo     = 0x05
	z7NidPackInfo      = 0x06
	z7NidUnpackInfo    = 0x07
	z7NidSubStreams    = 0x08
	z7NidSize          = 0x09
	z7NidCRC           = 0x0a
	z7NidFolder        = 0x0b
	z7NidCodersUnpSize = 0x0c
	z7NidNumUnpack     = 0x0d
	z7NidEmptyStream   = 0x0e
	z7NidName          = 0x11
	z7NidEncodedHeader = 0x17
)

// z7Coder 是 folder 中的一个编解码器。
type z7Coder struct {
	id     []byte
	numIn  int
	numOut int
	props  []byte
}

// z7Folder 是 7z 的数据文件夹（一组编解码器 + 打包流）。
type z7Folder struct {
	coders   []z7Coder
	numPack  int
	numOut   int
	unpSizes []int64 // 每个输出流的解包大小
	crc      *uint32 // 文件夹级 CRC（可能未定义）

	subNums  int       // 子流数量（默认 1）
	subSizes []int64   // 每条子流的解包大小
	subCRCs  []*uint32 // 每条子流的 CRC
}

// folderUnpackSize 返回文件夹的最终解包大小（最后一个输出流）。
func (f *z7Folder) folderUnpackSize() int64 {
	if len(f.unpSizes) == 0 {
		return 0
	}
	return f.unpSizes[len(f.unpSizes)-1]
}

// z7Streams 是 7z 的 StreamsInfo。
type z7Streams struct {
	packPos   int64
	packSizes []int64
	folders   []z7Folder
}

// z7Header 是解析后的 Header。
type z7Header struct {
	streams *z7Streams
	names   []string
	empty   []bool
}

// extract7z 从 7z 压缩包中提取哈希，对应 hashcat -m 11600。
func extract7z(f io.ReaderAt, size int64, path string) (*Result, error) {
	res := &Result{Path: path, Kind: "7z"}
	if size < 32 {
		return nil, errBroken("7z signature header truncated")
	}
	sig, err := readAt(f, size, 0, 32)
	if err != nil {
		return nil, err
	}
	nextOff := int64(binary.LittleEndian.Uint64(sig[12:20]))
	nextSize := int64(binary.LittleEndian.Uint64(sig[20:28]))
	if nextSize == 0 {
		return res, nil // 未写入头信息的空压缩包
	}
	if nextOff < 0 || nextSize < 1 || 32+nextOff+nextSize > size {
		return nil, errBroken("7z header offset %d+%d beyond %d", nextOff, nextSize, size)
	}
	blob, err := readAt(f, size, 32+nextOff, nextSize)
	if err != nil {
		return nil, err
	}

	switch blob[0] {
	case z7NidHeader:
		h, err := parseZ7Header(blob)
		if err != nil {
			return nil, err
		}
		emitZ7(res, f, size, h.streams, z7DataNames(h), "")
		return res, nil

	case z7NidEncodedHeader:
		r := newReader(blob[1:])
		st, err := parseZ7Streams(r)
		if err != nil {
			return nil, err
		}
		if len(st.folders) == 0 || len(st.folders[0].coders) == 0 {
			return nil, errBroken("empty encoded header")
		}
		// 第一个编码器就是 AES => 文件名（头部）本身被加密，
		// 哈希取自这段头流，无法解析出文件名。
		if bytes.Equal(st.folders[0].coders[0].id, z7AES) {
			emitZ7(res, f, size, st, nil, i18n.T("hashdump.info.header"))
			return res, nil
		}
		plain, err := decodeZ7HeaderStream(f, size, st)
		if err != nil {
			return nil, err
		}
		h, err := parseZ7Header(plain)
		if err != nil {
			return nil, err
		}
		emitZ7(res, f, size, h.streams, z7DataNames(h), "")
		return res, nil

	default:
		return nil, errBroken("unexpected 7z header id 0x%02x", blob[0])
	}
}

// decodeZ7HeaderStream 解码 kEncodedHeader 的打包流（仅支持单编码器链）。
func decodeZ7HeaderStream(f io.ReaderAt, size int64, st *z7Streams) ([]byte, error) {
	fold := &st.folders[0]
	if len(fold.coders) != 1 || fold.numPack != 1 || len(st.packSizes) == 0 {
		return nil, errBroken("unsupported encoded header coder chain")
	}
	data, err := readAt(f, size, 32+st.packPos, st.packSizes[0])
	if err != nil {
		return nil, err
	}
	outSize := fold.folderUnpackSize()
	c := fold.coders[0]

	switch {
	case bytes.Equal(c.id, z7Copy):
		if int64(len(data)) < outSize {
			return nil, errBroken("encoded header short copy")
		}
		return data[:outSize], nil

	case bytes.Equal(c.id, z7LZMA1):
		return z7LZMA1Decode(c.props, outSize, data)

	case bytes.Equal(c.id, z7Deflate):
		return z7DeflateDecode(outSize, data)

	default:
		return nil, errBroken("unsupported encoded header codec %s", codecName(c.id))
	}
}

// z7LZMA1Decode 按 "LZMA alone" 格式解码（7z 的打包头就是这样存的）。
func z7LZMA1Decode(props []byte, outSize int64, data []byte) ([]byte, error) {
	if len(props) != 5 {
		return nil, errBroken("bad LZMA1 properties (%d bytes)", len(props))
	}
	hdr := make([]byte, 13, 13+len(data))
	copy(hdr, props)
	binary.LittleEndian.PutUint64(hdr[5:], uint64(outSize))
	buf := append(hdr, data...)

	zr, err := lzma.NewReader(bytes.NewReader(buf))
	if err != nil {
		return nil, errBroken("lzma header: %v", err)
	}
	out, err := io.ReadAll(io.LimitReader(zr, outSize+1))
	if err != nil {
		return nil, errBroken("lzma decode: %v", err)
	}
	if int64(len(out)) < outSize {
		return nil, errBroken("lzma output %d < %d", len(out), outSize)
	}
	return out[:outSize], nil
}

// z7DeflateDecode 解码裸 deflate 流（7z 的 Deflate 编码器不带 zlib 头）。
func z7DeflateDecode(outSize int64, data []byte) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(data)), outSize+1))
	if err == nil && int64(len(out)) >= outSize {
		return out[:outSize], nil
	}
	return nil, errBroken("deflate decode: %v", err)
}

// ---------------------------------------------------------------------------
// 头解析
// ---------------------------------------------------------------------------

// z7Uint64 解析 7z 的变长整数编码。
func (r *reader) z7Uint64() int64 {
	first := r.u8()
	if r.err != nil {
		return 0
	}
	var value int64
	for i := 0; i < 8; i++ {
		if first&(0x80>>uint(i)) == 0 {
			value |= int64(first&(0x7f>>uint(i))) << uint(8*i)
			return value
		}
		b := r.u8()
		if r.err != nil {
			return 0
		}
		value |= int64(b) << uint(8*i)
	}
	return value
}

// readZ7BitVec 解析位向量（kEmptyStream 等）。
func readZ7BitVec(r *reader, n int) []bool {
	out := make([]bool, n)
	data := r.take((n + 7) / 8)
	if data == nil {
		return out
	}
	for i := 0; i < n; i++ {
		out[i] = data[i/8]&(1<<uint(i%8)) != 0
	}
	return out
}

// readZ7BoolVec 解析 "AllAreDefined + 位向量" 结构。
func readZ7BoolVec(r *reader, n int) []bool {
	if r.u8() != 0 {
		out := make([]bool, n)
		for i := range out {
			out[i] = true
		}
		return out
	}
	return readZ7BitVec(r, n)
}

// readZ7Digests 解析 "AllAreDefined + CRC32[]" 结构。
func readZ7Digests(r *reader, n int) []*uint32 {
	defined := readZ7BoolVec(r, n)
	out := make([]*uint32, n)
	for i := 0; i < n; i++ {
		if !defined[i] {
			continue
		}
		v := r.u32()
		if r.err != nil {
			return out
		}
		u := v
		out[i] = &u
	}
	return out
}

// parseZ7Folder 解析一个 folder。
func parseZ7Folder(r *reader) z7Folder {
	var f z7Folder
	numCoders := int(r.z7Uint64())
	totalIn, totalOut := 0, 0
	for i := 0; i < numCoders && r.err == nil; i++ {
		flags := r.u8()
		if r.err != nil {
			break
		}
		idSize := int(flags & 0x0f)
		complex := flags&0x10 != 0
		hasProps := flags&0x20 != 0
		if flags&0x80 != 0 { // external
			r.fail()
			break
		}
		id := r.take(idSize)
		numIn, numOut := 1, 1
		if complex {
			numIn = int(r.z7Uint64())
			numOut = int(r.z7Uint64())
		}
		var props []byte
		if hasProps {
			ps := r.z7Uint64()
			props = r.take(int(ps))
		}
		if r.err != nil {
			break
		}
		f.coders = append(f.coders, z7Coder{
			id:     append([]byte(nil), id...),
			numIn:  numIn,
			numOut: numOut,
			props:  append([]byte(nil), props...),
		})
		totalIn += numIn
		totalOut += numOut
	}
	// 绑定关系与打包流序号对本模块无用，只跳过。
	numBind := totalOut - 1
	for i := 0; i < numBind && r.err == nil; i++ {
		r.z7Uint64()
		r.z7Uint64()
	}
	numPack := totalIn - numBind
	f.numPack = numPack
	if numPack > 1 {
		for i := 0; i < numPack && r.err == nil; i++ {
			r.z7Uint64()
		}
	}
	f.numOut = totalOut
	return f
}

// parseZ7Streams 解析 StreamsInfo（kPackInfo / kUnpackInfo / kSubStreamsInfo）。
func parseZ7Streams(r *reader) (*z7Streams, error) {
	s := &z7Streams{}

	nid := r.u8()
	if r.err != nil {
		return nil, errBroken("streams info truncated")
	}

	if nid == z7NidPackInfo {
		s.packPos = r.z7Uint64()
		numPack := int(r.z7Uint64())
		if r.err != nil || numPack < 0 {
			return nil, errBroken("bad PackInfo")
		}
		nid = r.u8()
		if nid == z7NidSize {
			for i := 0; i < numPack && r.err == nil; i++ {
				s.packSizes = append(s.packSizes, r.z7Uint64())
			}
			nid = r.u8()
		}
		if nid == z7NidCRC {
			readZ7Digests(r, numPack)
			nid = r.u8()
		}
		if r.err != nil || nid != z7NidEnd {
			return nil, errBroken("PackInfo not terminated (0x%02x)", nid)
		}
		nid = r.u8()
	}

	if nid != z7NidUnpackInfo {
		return nil, errBroken("kUnpackInfo expected (0x%02x)", nid)
	}
	if r.u8() != z7NidFolder {
		return nil, errBroken("kFolder expected")
	}
	numFolders := int(r.z7Uint64())
	if r.err != nil || numFolders < 0 {
		return nil, errBroken("bad folder count")
	}
	if r.u8() != 0 {
		return nil, errBroken("external folders not supported")
	}
	for i := 0; i < numFolders && r.err == nil; i++ {
		s.folders = append(s.folders, parseZ7Folder(r))
	}
	if r.u8() != z7NidCodersUnpSize {
		return nil, errBroken("kCodersUnPackSize expected")
	}
	for i := range s.folders {
		for j := 0; j < s.folders[i].numOut && r.err == nil; j++ {
			s.folders[i].unpSizes = append(s.folders[i].unpSizes, r.z7Uint64())
		}
	}
	crcs := []*uint32(nil)
	nid = r.u8()
	if nid == z7NidCRC {
		crcs = readZ7Digests(r, numFolders)
		nid = r.u8()
	}
	if r.err != nil || nid != z7NidEnd {
		return nil, errBroken("UnpackInfo not terminated (0x%02x)", nid)
	}
	for i := range s.folders {
		if i < len(crcs) {
			s.folders[i].crc = crcs[i]
		}
	}
	nid = r.u8()

	if nid == z7NidSubStreams {
		if err := parseZ7SubStreams(r, s); err != nil {
			return nil, err
		}
		nid = r.u8()
	} else {
		defaultSubStreams(s)
	}
	if r.err != nil || nid != z7NidEnd {
		return nil, errBroken("StreamsInfo not terminated (0x%02x)", nid)
	}
	return s, nil
}

// defaultSubStreams 在缺少 SubStreamsInfo 时补全默认值：
// 每个 folder 恰好一条子流，大小取文件夹解包大小，CRC 取文件夹 CRC。
func defaultSubStreams(s *z7Streams) {
	for i := range s.folders {
		f := &s.folders[i]
		f.subNums = 1
		f.subSizes = []int64{f.folderUnpackSize()}
		f.subCRCs = []*uint32{f.crc}
	}
}

// parseZ7SubStreams 解析 SubStreamsInfo。
func parseZ7SubStreams(r *reader, s *z7Streams) error {
	for i := range s.folders {
		s.folders[i].subNums = 1
	}

	nid := r.u8()
	if r.err != nil {
		return errBroken("SubStreamsInfo truncated")
	}
	if nid == z7NidNumUnpack {
		for i := range s.folders {
			s.folders[i].subNums = int(r.z7Uint64())
		}
		nid = r.u8()
	}
	if r.err != nil {
		return errBroken("SubStreamsInfo truncated")
	}

	if nid == z7NidSize {
		for i := range s.folders {
			f := &s.folders[i]
			if f.subNums == 0 {
				continue
			}
			var sum int64
			for j := 0; j < f.subNums-1 && r.err == nil; j++ {
				v := r.z7Uint64()
				f.subSizes = append(f.subSizes, v)
				sum += v
			}
			if r.err != nil {
				return errBroken("SubStreamsInfo sizes truncated")
			}
			f.subSizes = append(f.subSizes, f.folderUnpackSize()-sum)
		}
		nid = r.u8()
	} else {
		for i := range s.folders {
			f := &s.folders[i]
			if f.subNums > 1 {
				return errBroken("substream count > 1 without sizes")
			}
			if f.subNums == 1 {
				f.subSizes = []int64{f.folderUnpackSize()}
			}
		}
	}
	if r.err != nil {
		return errBroken("SubStreamsInfo truncated")
	}

	// CRC：folder 只有一条子流且自带 CRC 时直接复用，否则逐条读取。
	folderOK := func(f *z7Folder) bool { return f.subNums == 1 && f.crc != nil }

	if nid == z7NidCRC {
		numDigests := 0
		for i := range s.folders {
			if !folderOK(&s.folders[i]) {
				numDigests += s.folders[i].subNums
			}
		}
		defined := readZ7BoolVec(r, numDigests)
		if r.err != nil {
			return errBroken("SubStreamsInfo crc truncated")
		}
		k := 0
		for i := range s.folders {
			f := &s.folders[i]
			f.subCRCs = make([]*uint32, f.subNums)
			if folderOK(f) {
				f.subCRCs[0] = f.crc
				continue
			}
			for j := 0; j < f.subNums; j++ {
				if k < len(defined) && defined[k] {
					v := r.u32()
					if r.err != nil {
						return errBroken("SubStreamsInfo crc truncated")
					}
					u := v
					f.subCRCs[j] = &u
				}
				k++
			}
		}
		nid = r.u8()
	} else {
		for i := range s.folders {
			f := &s.folders[i]
			f.subCRCs = make([]*uint32, f.subNums)
			if folderOK(f) {
				f.subCRCs[0] = f.crc
			}
		}
	}
	if r.err != nil || nid != z7NidEnd {
		return errBroken("SubStreamsInfo not terminated (0x%02x)", nid)
	}
	return nil
}

// parseZ7Header 解析 7z 的 kHeader。
func parseZ7Header(b []byte) (*z7Header, error) {
	r := newReader(b)
	if r.u8() != z7NidHeader {
		return nil, errBroken("not a 7z header")
	}
	h := &z7Header{}

	nid := r.u8()
	if r.err != nil {
		return nil, errBroken("header truncated")
	}

	if nid == z7NidArchiveProps {
		for {
			t := r.u8()
			if r.err != nil {
				return nil, errBroken("archive properties truncated")
			}
			if t == z7NidEnd {
				break
			}
			sz := r.z7Uint64()
			r.skip(int(sz))
		}
		nid = r.u8()
	}

	if nid == z7NidMainStreams {
		st, err := parseZ7Streams(r)
		if err != nil {
			return nil, err
		}
		h.streams = st
		nid = r.u8()
	}

	if nid == z7NidFilesInfo {
		numFiles := int(r.z7Uint64())
		if r.err != nil || numFiles < 0 {
			return nil, errBroken("bad file count")
		}
		for {
			ptype := r.u8()
			if r.err != nil {
				return nil, errBroken("FilesInfo truncated")
			}
			if ptype == z7NidEnd {
				break
			}
			psize := r.z7Uint64()
			data := r.take(int(psize))
			if r.err != nil {
				return nil, errBroken("FilesInfo property truncated")
			}
			switch ptype {
			case z7NidName:
				h.names = parseZ7Names(data)
			case z7NidEmptyStream:
				h.empty = readZ7BitVec(newReader(data), numFiles)
			}
		}
		nid = r.u8()
	}

	if r.err != nil || nid != z7NidEnd {
		return nil, errBroken("header not terminated (0x%02x)", nid)
	}
	return h, nil
}

// parseZ7Names 解析 kName 属性（UTF-16LE、以 U+0000 结尾的字符串序列）。
func parseZ7Names(data []byte) []string {
	r := newReader(data)
	if r.u8() != 0 { // external
		return nil
	}
	var out []string
	for r.remaining() >= 2 {
		var units []uint16
		terminated := false
		for r.remaining() >= 2 {
			u := r.u16()
			if u == 0 {
				terminated = true
				break
			}
			units = append(units, u)
		}
		out = append(out, string(utf16.Decode(units)))
		if !terminated {
			break
		}
	}
	return out
}

// z7DataNames 把 FilesInfo 的文件名映射到子流（跳过空流文件）。
func z7DataNames(h *z7Header) []string {
	if h == nil || len(h.names) == 0 {
		return nil
	}
	if len(h.empty) != len(h.names) {
		return h.names
	}
	out := make([]string, 0, len(h.names))
	for i, n := range h.names {
		if !h.empty[i] {
			out = append(out, n)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// 哈希构造
// ---------------------------------------------------------------------------

// emitZ7 遍历所有 folder，为含 AES 编码器的 folder 生成哈希。
//
// dataNames 是按子流顺序排列的文件名；取不到时退回 anonName
// （文件名被加密时传入"（加密的头部/文件名）"这样的占位说明）。
func emitZ7(res *Result, f io.ReaderAt, size int64, st *z7Streams, dataNames []string, anonName string) {
	if st == nil {
		return
	}
	packOff := int64(32) + st.packPos
	packIdx := 0
	streamIdx := 0

	for i := range st.folders {
		fold := &st.folders[i]
		name := ""
		if streamIdx < len(dataNames) {
			name = dataNames[streamIdx]
		}
		if name == "" {
			name = anonName
		}

		aesIdx := -1
		for ci, c := range fold.coders {
			if bytes.Equal(c.id, z7AES) {
				aesIdx = ci
				break
			}
		}
		if aesIdx >= 0 {
			emitZ7Entry(res, f, size, st, fold, packIdx, packOff, aesIdx, name)
		}

		for k := 0; k < fold.numPack; k++ {
			idx := packIdx + k
			if idx < len(st.packSizes) {
				packOff += st.packSizes[idx]
			}
		}
		packIdx += fold.numPack
		streamIdx += fold.subNums
	}
}

// emitZ7Entry 为单个 folder 构造 $7z$ 哈希。
func emitZ7Entry(
	res *Result,
	f io.ReaderAt,
	size int64,
	st *z7Streams,
	fold *z7Folder,
	packIdx int,
	packOff int64,
	aesIdx int,
	name string,
) {
	if fold.numPack != 1 || packIdx >= len(st.packSizes) || aesIdx >= len(fold.unpSizes) {
		res.addSkip(name, i18n.T("hashdump.skip.broken"))
		return
	}
	dataLen := st.packSizes[packIdx]
	unpackSize := fold.unpSizes[aesIdx]
	if dataLen < 16 {
		res.addSkip(name, i18n.T("hashdump.skip.short"))
		return
	}
	if dataLen > maxInlineByte {
		res.addSkip(name, i18n.Tf("hashdump.skip.large", dataLen))
		return
	}
	if unpackSize > dataLen {
		res.addSkip(name, i18n.T("hashdump.skip.broken"))
		return
	}

	// CRC：优先取该 folder 的第一条子流。
	var crc *uint32
	var crcLen int64
	if fold.subNums >= 1 && len(fold.subCRCs) > 0 && fold.subCRCs[0] != nil && len(fold.subSizes) > 0 {
		crc = fold.subCRCs[0]
		crcLen = fold.subSizes[0]
	} else if fold.crc != nil {
		crc = fold.crc
		crcLen = fold.folderUnpackSize()
	}
	if crc == nil {
		res.addSkip(name, i18n.T("hashdump.skip.no_crc"))
		return
	}

	// 压缩方式与 coder 属性
	dataType, attrs, badID := z7Attrs(fold.coders, aesIdx)
	if badID != nil {
		res.addSkip(name, i18n.Tf("hashdump.skip.codec", codecName(badID)))
		return
	}
	if dataType != 0 && crcLen <= 0 {
		res.addSkip(name, i18n.T("hashdump.skip.broken"))
		return
	}

	// AES coder 属性：KDF 迭代次数、salt、IV
	power, saltLen, ivLen, iv, ok := z7AESProps(fold.coders[aesIdx].props)
	if !ok {
		res.addSkip(name, i18n.T("hashdump.skip.broken"))
		return
	}
	if power > 31 {
		res.addSkip(name, i18n.Tf("hashdump.skip.method", fmt.Sprintf("KDF power=%d", power)))
		return
	}
	if saltLen != 0 {
		res.addSkip(name, i18n.Tf("hashdump.skip.method", fmt.Sprintf("salt_len=%d", saltLen)))
		return
	}

	data, err := readAt(f, size, packOff, dataLen)
	if err != nil {
		res.addSkip(name, i18n.T("hashdump.skip.broken"))
		return
	}

	var b strings.Builder
	fmt.Fprintf(&b, "$7z$%d$%d$0$$%d$%s$%d$%d$%d$%s",
		dataType, power, ivLen, hexLower(iv), *crc, dataLen, unpackSize, hexLower(data))
	if dataType != 0 {
		fmt.Fprintf(&b, "$%d$%s", crcLen, attrs)
	}
	res.addEntry(name, 11600, b.String())
}

// z7Attrs 计算 AES 之后各编码器的压缩类型与属性。
//
// 返回的 badID 非空表示 hashcat 无法处理（返回 0 与空属性即可丢弃）。
func z7Attrs(coders []z7Coder, aesIdx int) (int, string, []byte) {
	dataType := 0
	attrs := ""
	compressors := 0

	for i := aesIdx + 1; i < len(coders); i++ {
		c := coders[i]
		var t int
		switch {
		case bytes.Equal(c.id, z7Copy):
			continue // 空操作
		case bytes.Equal(c.id, z7LZMA1):
			t = 1
		case bytes.Equal(c.id, z7LZMA2):
			t = 2
		case bytes.Equal(c.id, z7Deflate):
			t = 7
		case bytes.Equal(c.id, z7PPMD):
			t = 3
		case bytes.Equal(c.id, z7Bzip2):
			t = 6
		default:
			return 0, "", c.id // 预处理器或未知算法
		}
		compressors++
		if compressors > 1 {
			return 0, "", c.id // hashcat 不支持级联压缩
		}
		if t != 0 && t != 1 && t != 2 && t != 7 {
			return 0, "", c.id // hashcat 只支持 0/1/2/7
		}
		if t == 1 && len(c.props) != 5 {
			return 0, "", c.id
		}
		if t == 2 && len(c.props) != 1 {
			return 0, "", c.id
		}
		dataType = t
		attrs = hexLower(c.props)
	}
	return dataType, attrs, nil
}

// z7AESProps 解码 AES coder 的属性（john 7z2john 的 get_decoder_properties）。
//
//	props[0]: bit0-5 = KDF 迭代次数的二进制对数，bit6/7 = IV/salt 长度高位
//	props[1]: bit4-7 = salt 长度低位，bit0-3 = IV 长度低位
//	其后依次为 salt、IV（IV 不足 16 字节补零）
func z7AESProps(props []byte) (power int, saltLen int, ivLen int, iv []byte, ok bool) {
	if len(props) == 0 {
		return 0, 0, 0, nil, false
	}
	iv = make([]byte, 16)
	b0 := props[0]
	power = int(b0 & 0x3f)
	if b0&0xc0 == 0 {
		return power, 0, 16, iv, true
	}
	if len(props) < 2 {
		return 0, 0, 0, nil, false
	}
	b1 := props[1]
	saltLen = int(b0>>7&1) + int(b1>>4)
	ivLen = int(b0>>6&1) + int(b1&0x0f)
	off := 2
	if off+saltLen > len(props) {
		return 0, 0, 0, nil, false
	}
	off += saltLen
	n := ivLen
	if off+n > len(props) {
		n = len(props) - off
	}
	if n > 16 {
		n = 16
	}
	copy(iv, props[off:off+n])
	return power, saltLen, ivLen, iv, true
}

// codecName 返回编码器 ID 的可读名字。
func codecName(id []byte) string {
	type pair struct {
		id   []byte
		name string
	}
	table := []pair{
		{z7Copy, "Copy"},
		{z7LZMA1, "LZMA1"},
		{z7LZMA2, "LZMA2"},
		{z7Deflate, "Deflate"},
		{z7PPMD, "PPMd"},
		{z7Bzip2, "BZip2"},
		{z7AES, "AES256+SHA256"},
		{z7BCJ, "BCJ"},
		{z7BCJ2, "BCJ2"},
		{z7PPC, "PPC"},
		{z7Alpha, "Alpha"},
		{z7IA64, "IA64"},
		{z7ARM, "ARM"},
		{z7ARMT, "ARMT"},
		{z7SPARC, "SPARC"},
		{z7Delta, "Delta"},
	}
	for _, p := range table {
		if bytes.Equal(p.id, id) {
			return p.name
		}
	}
	return "0x" + hexLower(id)
}
