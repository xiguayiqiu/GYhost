package mem

import "math"

// histogram 是字节值直方图，用于流式累计香农熵。
//
// 内存可能有几百 MB，保留全部字节再算熵会浪费内存；
// 直方图只有 256 个计数器，一次遍历即可得到精确熵。
type histogram [256]uint64

// add 累计一段数据的字节分布。
func (h *histogram) add(data []byte) {
	for _, b := range data {
		h[b]++
	}
}

// total 返回累计的字节数。
func (h histogram) total() uint64 {
	var n uint64
	for _, c := range h {
		n += c
	}
	return n
}

// entropy 按当前直方图计算香农熵（bit/字节）。
func (h histogram) entropy() float64 {
	n := float64(h.total())
	if n == 0 {
		return 0
	}
	e := 0.0
	for _, c := range h {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}
