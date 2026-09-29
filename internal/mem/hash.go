package mem

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
)

// HashSet 是一次计算得到的多种摘要，便于在报告里同时给出。
type HashSet struct {
	MD5    string
	SHA1   string
	SHA256 string
	SHA512 string
}

// Empty 判断是否没有任何摘要。
func (h HashSet) Empty() bool {
	return h.MD5 == "" && h.SHA1 == "" && h.SHA256 == "" && h.SHA512 == ""
}

// Hasher 增量计算多种摘要，用于流式读取大块内存时避免全部驻留内存。
type Hasher struct {
	md5    hash.Hash
	sha1   hash.Hash
	sha256 hash.Hash
	sha512 hash.Hash
}

// NewHasher 创建多算法增量计算器。
func NewHasher() *Hasher {
	return &Hasher{
		md5:    md5.New(),
		sha1:   sha1.New(),
		sha256: sha256.New(),
		sha512: sha512.New(),
	}
}

// Write 累加一段数据。
func (h *Hasher) Write(p []byte) (int, error) {
	n, err := h.md5.Write(p)
	if err != nil {
		return n, err
	}
	if _, err := h.sha1.Write(p); err != nil {
		return n, err
	}
	if _, err := h.sha256.Write(p); err != nil {
		return n, err
	}
	if _, err := h.sha512.Write(p); err != nil {
		return n, err
	}
	return n, nil
}

// Sum 返回当前累计数据的全部摘要。
func (h *Hasher) Sum() HashSet {
	return HashSet{
		MD5:    hex.EncodeToString(h.md5.Sum(nil)),
		SHA1:   hex.EncodeToString(h.sha1.Sum(nil)),
		SHA256: hex.EncodeToString(h.sha256.Sum(nil)),
		SHA512: hex.EncodeToString(h.sha512.Sum(nil)),
	}
}

// HashBytes 一次性计算 data 的全部摘要。
func HashBytes(data []byte) HashSet {
	h := NewHasher()
	h.Write(data)
	return h.Sum()
}

// HashStrings 返回给定摘要集中的非空项，形如 "md5=… sha256=…"。
func (h HashSet) HashStrings() []string {
	var out []string
	if h.MD5 != "" {
		out = append(out, "md5="+h.MD5)
	}
	if h.SHA1 != "" {
		out = append(out, "sha1="+h.SHA1)
	}
	if h.SHA256 != "" {
		out = append(out, "sha256="+h.SHA256)
	}
	if h.SHA512 != "" {
		out = append(out, "sha512="+h.SHA512)
	}
	return out
}
