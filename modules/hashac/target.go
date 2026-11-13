// Package hashac 实现 GYhost 的通用哈希碰撞（离线爆破）模块。
//
// 覆盖网络安全中常见的可枚举哈希：MD5/SHA-1/SHA-256/SHA-512 裸摘要、
// WPA2（PMKID / EAPOL 四次握手）、RAR5、ZIP（ZipCrypto / WinZip AES）、7z AES、
// 加密 PDF（RC4-40/128、AES-128/256）、Office 文档密码（$office$ 2007/2010/2013，
// hashcat 9400/9500/9600）以及 $y$ yescrypt（hashcat 36100）。其中一部分算法可交给
// internal/cuda 用 GPU 加速（--gpu），其余自动回退 CPU。
//
// 用法: gyhost hashac -i [哈希文件] -p [密码字典]
package hashac

import (
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"hash"
	"strings"

	"gyhost/internal/cuda"
	"gyhost/internal/i18n"
	"gyhost/internal/pwdhash"
)

// Kind 目标哈希类型（同时用于 GPU 分派与 i18n 标签）。
type Kind string

// 支持的目标类型。
const (
	KindMD5         Kind = "md5"
	KindSHA1        Kind = "sha1"
	KindSHA256      Kind = "sha256"
	KindSHA512      Kind = "sha512"
	KindWPA2PMKID   Kind = "wpa2-pmkid"
	KindWPA2EAPOL   Kind = "wpa2-eapol"
	KindRAR5        Kind = "rar5"
	KindZIPAES      Kind = "zip-aes"
	KindZipCrypto   Kind = "zipcrypto"
	Kind7z          Kind = "7z"
	KindPDFRC440    Kind = "pdf-rc4-40"
	KindPDFRC4128   Kind = "pdf-rc4-128"
	KindPDFAES128   Kind = "pdf-aes-128"
	KindPDFAES256   Kind = "pdf-aes-256"
	KindPDFAES256R6 Kind = "pdf-aes-256-r6"
	KindOffice2007  Kind = "office-2007"
	KindOffice2010  Kind = "office-2010"
	KindOffice2013  Kind = "office-2013"
	KindYescrypt    Kind = "yescrypt"
)

// Checker 校验一个已知哈希（实现必须并发安全：只读）。
type Checker interface {
	// Check 判断明文密码是否匹配该哈希。
	Check(password string) bool
}

// Target 一个待爆破的目标。
type Target struct {
	Raw   string           // 原始哈希行
	Kind  Kind             // 目标类型
	Mode  int              // 对应的 hashcat 模式号
	Check Checker          // CPU 校验器
	GPU   *cuda.HashTarget // 非 nil 表示可交给通用 GPU 内核；nil 表示不走该路径
	// YGPU 非 nil 表示可交给 yescrypt GPU 内核。yescrypt 每个候选要独占
	// 16·N·r 字节显存，批量与流水线都和通用内核完全不同，所以单独一条路径。
	YGPU *cuda.YescryptTarget
}

// Label 返回该类型的可读名称（已国际化）。
func (t *Target) Label() string { return i18n.T("hashac.algo." + string(t.Kind)) }

// ---------------------------------------------------------------------------
// 解析与识别
// ---------------------------------------------------------------------------

// Parse 解析一行哈希。
//
// modeOverride 非 0 时强制按该 hashcat 模式解析（用于同形歧义，如 32 字节
// 十六进制串默认按 MD5）；否则按前缀/形态自动识别。
func Parse(line string, modeOverride int) (*Target, error) {
	h := strings.TrimSpace(line)
	if h == "" {
		return nil, errors.New(i18n.T("hashac.err.empty_hash"))
	}

	if modeOverride != 0 {
		return parseMode(h, modeOverride)
	}

	switch {
	case strings.HasPrefix(h, "WPA*01*"):
		return parseWPA2(h, true)
	case strings.HasPrefix(h, "WPA*02*"):
		return parseWPA2(h, false)
	case strings.HasPrefix(h, "$rar5$"):
		return parseRAR5(h)
	case strings.HasPrefix(h, "$zip2$"):
		return parseZIPAES(h)
	case strings.HasPrefix(h, "$pkzip2$"):
		return parseZipCrypto(h)
	case strings.HasPrefix(h, "$7z$"):
		return parse7z(h)
	case strings.HasPrefix(h, "$pdf$"):
		return parsePDF(h, modeOverride)
	case strings.HasPrefix(h, "$office$"), strings.HasPrefix(h, "$oldoffice$"):
		return parseOffice(h, modeOverride)
	case strings.HasPrefix(h, "$y$"):
		return parseYescrypt(h)
	}

	if isHex(h) {
		switch len(h) {
		case 32:
			return newDigestTarget(h, KindMD5, 0)
		case 40:
			return newDigestTarget(h, KindSHA1, 100)
		case 64:
			return newDigestTarget(h, KindSHA256, 1400)
		case 128:
			return newDigestTarget(h, KindSHA512, 1700)
		}
	}
	return nil, errors.New(i18n.Tf("hashac.err.unknown", clip(h)))
}

// parseMode 按显式的 hashcat 模式号解析。
func parseMode(h string, mode int) (*Target, error) {
	switch mode {
	case 0, 100, 1400, 1700:
		kind := KindMD5
		switch mode {
		case 100:
			kind = KindSHA1
		case 1400:
			kind = KindSHA256
		case 1700:
			kind = KindSHA512
		}
		if !isHex(h) {
			return nil, errors.New(i18n.Tf("hashac.err.bad_syntax", clip(h)))
		}
		return newDigestTarget(h, kind, mode)
	case 22000:
		if strings.HasPrefix(h, "WPA*02*") {
			return parseWPA2(h, false)
		}
		return parseWPA2(h, true)
	case 13000:
		return parseRAR5(h)
	case 13600:
		return parseZIPAES(h)
	case 17200, 17210:
		return parseZipCrypto(h)
	case 11600:
		return parse7z(h)
	case 10400, 10500, 10600, 10700:
		return parsePDF(h, mode)
	case 9400, 9500, 9600:
		return parseOffice(h, mode)
	case 36100:
		return parseYescrypt(h)
	}
	return nil, errors.New(i18n.Tf("hashac.err.mode", mode))
}

// parseYescrypt 解析 $y$ yescrypt 哈希（hashcat -m 36100）。
//
// CPU 校验直接复用 internal/pwdhash（与 shadow 模块同一套实现）；
// GPU 参数用 pwdhash.ParseYescrypt 解码出原始盐与 32 字节目标密钥。
// 两者口径一致，GPU 命中后仍由 CPU 复核，避免内核与库的实现差异造成误报。
func parseYescrypt(h string) (*Target, error) {
	checker, err := pwdhash.NewChecker(h)
	if err != nil {
		return nil, errSyntax(h)
	}
	t := &Target{Raw: h, Kind: KindYescrypt, Mode: 36100, Check: checker}
	// 参数超出 GPU 支持范围（例如 N 过大）时不影响 CPU 爆破，只是留在 CPU。
	if p, ok := pwdhash.ParseYescrypt(h); ok {
		y := &cuda.YescryptTarget{NLog2: p.NLog2, R: p.R, Salt: p.Salt, Key: p.Key}
		if err := y.Validate(); err == nil {
			t.YGPU = y
		}
	}
	return t, nil
}

// clip 截断过长哈希，避免提示信息刷屏。
func clip(s string) string {
	const max = 48
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// isHex 判断是否全为十六进制字符。
func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// unhex 解析十六进制串（大小写不敏感）。
func unhex(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.ToLower(s))
	if err != nil {
		return nil, errors.New(i18n.Tf("hashac.err.bad_syntax", clip(s)))
	}
	return b, nil
}

// ---------------------------------------------------------------------------
// 公共辅助
// ---------------------------------------------------------------------------

// pbkdf2Key 是 RFC 2898 的 PBKDF2 实现（仅用标准库，避免新增依赖）。
func pbkdf2Key(newHash func() hash.Hash, password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(newHash, password)
	hashLen := prf.Size()
	blocks := (keyLen + hashLen - 1) / hashLen

	dk := make([]byte, 0, blocks*hashLen)
	var buf [4]byte
	u := make([]byte, hashLen)
	t := make([]byte, hashLen)
	for block := 1; block <= blocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:])
		copy(t, prf.Sum(nil))

		copy(u, t)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for i := range t {
				t[i] ^= u[i]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// hmacSum 计算 HMAC，返回完整摘要。
func hmacSum(newHash func() hash.Hash, key, data []byte) []byte {
	m := hmac.New(newHash, key)
	m.Write(data)
	return m.Sum(nil)
}
