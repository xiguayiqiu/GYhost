// Package mask 实现 hashcat 风格的掩码解析与实时枚举。
//
// 掩码用字符集占位符描述候选密码的每一位，例如 ?l?l?d?d 表示
// 「两位小写字母 + 两位数字」。支持的标准字符集与 hashcat 一致：
//
//	?l  小写字母            ?u  大写字母
//	?d  数字                ?h  十六进制（小写）
//	?H  十六进制（大写）     ?s  可见特殊字符（含空格）
//	?a  ?l?u?d?s            ?b  0x00-0xff
//	??  字面量 '?'
//
// 其余字符按字面量处理。枚举顺序同样与 hashcat 一致：最右位变化最快。
//
// 用法: gyhost hashac -i hashes.txt --mask '?d?d?d?d'
package mask

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
)

// 标准字符集。
const (
	lower   = "abcdefghijklmnopqrstuvwxyz"
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits  = "0123456789"
	hexLow  = "0123456789abcdef"
	hexUp   = "0123456789ABCDEF"
	special = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
)

// 解析错误。
var (
	// ErrEmpty 掩码为空。
	ErrEmpty = errors.New("mask: empty expression")
	// ErrSyntax 掩码语法非法（如结尾多出 '?'、未知的字符集占位符）。
	ErrSyntax = errors.New("mask: invalid expression")
)

// Mask 是一个已解析的掩码表达式。
type Mask struct {
	expr string
	sets [][]byte // 每个位置的候选字符
	size uint64   // 候选总数（溢出时饱和到 MaxUint64）
}

// Parse 解析掩码表达式。
func Parse(expr string) (*Mask, error) {
	if expr == "" {
		return nil, ErrEmpty
	}

	var sets [][]byte
	b := []byte(expr)
	for i := 0; i < len(b); i++ {
		if b[i] != '?' {
			sets = append(sets, []byte{b[i]})
			continue
		}
		i++
		if i >= len(b) {
			return nil, fmt.Errorf("%w: trailing '?'", ErrSyntax)
		}
		switch b[i] {
		case 'l':
			sets = append(sets, []byte(lower))
		case 'u':
			sets = append(sets, []byte(upper))
		case 'd':
			sets = append(sets, []byte(digits))
		case 'h':
			sets = append(sets, []byte(hexLow))
		case 'H':
			sets = append(sets, []byte(hexUp))
		case 's':
			sets = append(sets, []byte(special))
		case 'a':
			sets = append(sets, []byte(lower+upper+digits+special))
		case 'b':
			sets = append(sets, allBytes())
		case '?':
			sets = append(sets, []byte{'?'})
		default:
			return nil, fmt.Errorf("%w: unknown charset ?%c", ErrSyntax, b[i])
		}
	}
	if len(sets) == 0 {
		return nil, ErrEmpty
	}

	m := &Mask{expr: expr, sets: sets, size: 1}
	for _, s := range sets {
		if m.size > math.MaxUint64/uint64(len(s)) {
			m.size = math.MaxUint64 // 饱和，避免回绕成小数字误导用户
			break
		}
		m.size *= uint64(len(s))
	}
	return m, nil
}

// String 返回原始表达式。
func (m *Mask) String() string { return m.expr }

// Keyspace 返回候选总数（可能饱和到 MaxUint64）。
func (m *Mask) Keyspace() uint64 { return m.size }

// Saturated 判断候选总数是否已溢出饱和（此时 Keyspace 不是精确值）。
func (m *Mask) Saturated() bool { return m.size == math.MaxUint64 }

// Each 按 hashcat 顺序（最右位变化最快）枚举全部候选；fn 返回 false 时立即停止。
func (m *Mask) Each(fn func(string) bool) {
	n := len(m.sets)
	idx := make([]int, n)
	buf := make([]byte, n)

	for {
		for i := 0; i < n; i++ {
			buf[i] = m.sets[i][idx[i]]
		}
		if !fn(string(buf)) {
			return
		}

		// 里程表式递增：从最右位开始进位
		p := n - 1
		for p >= 0 {
			idx[p]++
			if idx[p] < len(m.sets[p]) {
				break
			}
			idx[p] = 0
			p--
		}
		if p < 0 {
			return // 已枚举完
		}
	}
}

// allBytes 返回 0x00-0xff 的全字节集。
func allBytes() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// ---------------------------------------------------------------------------
// 候选来源
// ---------------------------------------------------------------------------

// Source 是候选密码来源：字典文件或掩码枚举。
type Source interface {
	// Each 逐个产出候选；fn 返回 false 时停止。
	Each(fn func(string) bool)
	// Close 释放底层资源（掩码枚举无需释放）。
	Close() error
}

// FileSource 从字典文件逐行读取候选。
type FileSource struct{ f *os.File }

// NewFileSource 包装一个已打开的字典文件。
func NewFileSource(f *os.File) *FileSource { return &FileSource{f: f} }

// Each 逐行产出候选。
func (s *FileSource) Each(fn func(string) bool) {
	scanner := bufio.NewScanner(s.f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		if !fn(scanner.Text()) {
			return
		}
	}
}

// Close 关闭文件。
func (s *FileSource) Close() error {
	if s.f == nil {
		return nil
	}
	return s.f.Close()
}

// Enumerator 按掩码实时枚举候选。
type Enumerator struct{ m *Mask }

// NewEnumerator 用已解析的掩码构造枚举源。
func NewEnumerator(m *Mask) *Enumerator { return &Enumerator{m: m} }

// Each 枚举全部候选。
func (e *Enumerator) Each(fn func(string) bool) { e.m.Each(fn) }

// Close 无资源可释放。
func (e *Enumerator) Close() error { return nil }

// 确保 Enumerator 不会误用为 io.Closer 之外的东西。
var _ Source = (*FileSource)(nil)
var _ Source = (*Enumerator)(nil)
var _ io.Closer = (*FileSource)(nil)
