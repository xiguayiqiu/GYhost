package mem

import "math"

// Entropy 返回 data 的香农熵（0 ~ 8，单位 bit/字节）。
//
// 用途：判断一段内存是明文/结构化数据（< 6）、压缩数据（7 ~ 7.9）还是
// 加密数据或已擦除的随机数据（> 7.9）。空输入返回 0。
func Entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	h := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// EntropyClass 是熵值的归一化分类，供报告展示。
type EntropyClass int

const (
	// EntropyEmpty 空区域。
	EntropyEmpty EntropyClass = iota
	// EntropyLow 低熵：稀疏数据、零填充、长重复串。
	EntropyLow
	// EntropyMedium 中熵：明文、结构化数据、可执行代码。
	EntropyMedium
	// EntropyHigh 高熵：压缩数据（png/zip/gzip 载荷等）。
	EntropyHigh
	// EntropyMax 极高熵：加密数据、密钥材料、随机数。
	EntropyMax
)

// String 返回分类标识。
func (c EntropyClass) String() string {
	switch c {
	case EntropyEmpty:
		return "empty"
	case EntropyLow:
		return "low"
	case EntropyMedium:
		return "medium"
	case EntropyHigh:
		return "high"
	case EntropyMax:
		return "max"
	default:
		return "unknown"
	}
}

// ClassifyEntropy 按熵值给出分类，阈值参照常见内存取证实践。
func ClassifyEntropy(h float64) EntropyClass {
	switch {
	case h <= 0.01:
		return EntropyEmpty
	case h < 4:
		return EntropyLow
	case h < 7:
		return EntropyMedium
	case h < 7.9:
		return EntropyHigh
	default:
		return EntropyMax
	}
}
