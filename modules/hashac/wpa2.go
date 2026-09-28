package hashac

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"strings"

	"gyhost/internal/cuda"
)

// WPA2 相关常量。
const (
	// wpa2Iter 是 PMK 派生的 PBKDF2 迭代次数（IEEE 802.11i）。
	wpa2Iter = 4096
	// pmkLen PMK 长度。
	pmkLen = 32
	// pmkidDataLen "PMK Name" || AP || STA 的长度。
	pmkidDataLen = 8 + 6 + 6
	// eapolMICOffset MIC 在 802.1X 帧中的偏移（RSN/WPA 均为 81）。
	eapolMICOffset = 81
	// eapolMICLen MIC 长度。
	eapolMICLen = 16
)

// ---------------------------------------------------------------------------
// WPA2 PMKID（hashcat -m 22000，WPA*01*）
// ---------------------------------------------------------------------------

type pmkidChecker struct {
	ssid  []byte
	data  []byte // "PMK Name" || AP || STA
	pmkid []byte
}

// Check PMK = PBKDF2-SHA1(pw, SSID, 4096, 32)，PMKID = HMAC-SHA1(PMK, data)[:16]。
func (c *pmkidChecker) Check(pw string) bool {
	pmk := pbkdf2Key(sha1.New, []byte(pw), c.ssid, wpa2Iter, pmkLen)
	mac := hmacSum(sha1.New, pmk, c.data)
	return hmac.Equal(mac[:16], c.pmkid)
}

// ---------------------------------------------------------------------------
// WPA2 EAPOL 四次握手（hashcat -m 22000，WPA*02*）
// ---------------------------------------------------------------------------

type eapolChecker struct {
	keyver int
	mic    []byte // 16 字节 MIC
	ap     []byte
	sta    []byte
	ssid   []byte
	anonce []byte
	snonce []byte
	eapol  []byte // MIC 字段已置零的 802.1X 帧
}

// Check 由 PMK 推导 PTK，再按 keyver 选择 MIC 算法比对。
func (c *eapolChecker) Check(pw string) bool {
	pmk := pbkdf2Key(sha1.New, []byte(pw), c.ssid, wpa2Iter, pmkLen)
	ptk := wpa2PTK(c.keyver, pmk, c.sta, c.ap, c.snonce, c.anonce)

	var mic []byte
	switch c.keyver {
	case 1: // WPA1 → HMAC-MD5
		mic = hmacSum(md5.New, ptk, c.eapol)
	case 2: // WPA2 → HMAC-SHA1
		mic = hmacSum(sha1.New, ptk, c.eapol)
	case 3: // WPA2-SHA256 → AES-CMAC
		mic = aesCMAC(ptk, c.eapol)
	default:
		return false
	}
	if len(mic) < eapolMICLen {
		return false
	}
	return hmac.Equal(mic[:eapolMICLen], c.mic)
}

// wpa2PTK 推导 PTK 的前 16 字节（= KCK）。
//
// keyver 1/2 用 HMAC-SHA1，keyver 3 用 HMAC-SHA256（802.11w / AKM-SHA256）。
func wpa2PTK(keyver int, pmk, sta, ap, snonce, anonce []byte) []byte {
	var b bytes.Buffer
	b.WriteString("Pairwise key expansion")

	legacy := keyver == 1 || keyver == 2
	if legacy {
		b.WriteByte(0)
	}
	// Min(AA, SPA) || Max(AA, SPA)
	if bytes.Compare(sta, ap) < 0 {
		b.Write(sta)
		b.Write(ap)
	} else {
		b.Write(ap)
		b.Write(sta)
	}
	// Min(ANonce, SNonce) || Max(ANonce, SNonce)
	if bytes.Compare(snonce, anonce) < 0 {
		b.Write(snonce)
		b.Write(anonce)
	} else {
		b.Write(anonce)
		b.Write(snonce)
	}

	// 末尾这个 0x00 是 PRF 的块计数器 i（i=0）：hashcat 的 module_22000 先拼出 99 字节的
	// pke（"Pairwise key expansion\x00" + MAC + nonce），再由 hmac_sha1_generic 追加计数器，
	// 等价于 HMAC-SHA1(PMK, pke || 0x00) 的前 20 字节。keyver 3 走 802.11w 的 0x80 0x01 结束标记。
	var prf []byte
	if legacy {
		b.WriteByte(0)
		prf = hmacSum(sha1.New, pmk, b.Bytes())
	} else {
		data := make([]byte, 0, b.Len()+4)
		data = append(data, 0x01, 0x00)
		data = append(data, b.Bytes()...)
		data = append(data, 0x80, 0x01)
		prf = hmacSum(sha256.New, pmk, data)
	}
	return prf[:16]
}

// aesCMAC 计算 AES-128-CMAC（RFC 4493），key 取前 16 字节。
func aesCMAC(key, msg []byte) []byte {
	if len(key) < 16 {
		return nil
	}
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil
	}

	// 子密钥 K1 / K2
	l := make([]byte, 16)
	block.Encrypt(l, make([]byte, 16))
	k1 := cmacSubkey(l)
	k2 := cmacSubkey(k1)

	n := (len(msg) + 15) / 16
	if n == 0 {
		n = 1
	}
	complete := len(msg) > 0 && len(msg)%16 == 0

	last := make([]byte, 16)
	if complete {
		copy(last, msg[(n-1)*16:])
		xorInto(last, k1)
	} else {
		rem := msg[(n-1)*16:]
		copy(last, rem)
		last[len(rem)] = 0x80
		xorInto(last, k2)
	}

	x := make([]byte, 16)
	tmp := make([]byte, 16)
	for i := 0; i < n-1; i++ {
		xorInto(x, msg[i*16:(i+1)*16])
		block.Encrypt(tmp, x)
		copy(x, tmp)
	}
	xorInto(x, last)
	block.Encrypt(tmp, x)
	return tmp
}

// cmacSubkey 计算 CMAC 子密钥：整体左移一位，溢出则异或 Rb(0x87)。
func cmacSubkey(in []byte) []byte {
	out := make([]byte, 16)
	var carry byte
	for i := 15; i >= 0; i-- {
		out[i] = in[i]<<1 | carry
		carry = in[i] >> 7
	}
	if carry != 0 {
		out[15] ^= 0x87
	}
	return out
}

// xorInto 就地把 src 异或进 dst（长度取小者）。
func xorInto(dst, src []byte) {
	for i := 0; i < len(dst) && i < len(src); i++ {
		dst[i] ^= src[i]
	}
}

// ---------------------------------------------------------------------------
// 解析
// ---------------------------------------------------------------------------

// parseWPA2 解析 hcxtools 22000 格式：
//
//	WPA*01*pmkid*AP*STA*ESSID***                      （PMKID）
//	WPA*02*mic*AP*STA*ESSID*ANonce*EAPOL*MessagePair  （EAPOL）
func parseWPA2(h string, pmkid bool) (*Target, error) {
	f := strings.Split(h, "*")
	if len(f) < 6 || f[0] != "WPA" {
		return nil, errSyntax(h)
	}
	ap, err1 := unhex(f[3])
	sta, err2 := unhex(f[4])
	ssid, err3 := unhex(f[5])
	if err1 != nil || err2 != nil || err3 != nil || len(ap) != 6 || len(sta) != 6 {
		return nil, errSyntax(h)
	}

	if pmkid {
		tag, err := unhex(f[2])
		if err != nil || len(tag) != 16 {
			return nil, errSyntax(h)
		}
		data := make([]byte, 0, pmkidDataLen)
		data = append(data, []byte("PMK Name")...)
		data = append(data, ap...)
		data = append(data, sta...)

		return &Target{
			Raw: h, Kind: KindWPA2PMKID, Mode: 22000,
			Check: &pmkidChecker{ssid: ssid, data: data, pmkid: tag},
			GPU:   &cuda.HashTarget{Algo: cuda.HashWPA2PMKID, Salt: ssid, Data: data, Check: tag},
		}, nil
	}

	if len(f) < 8 {
		return nil, errSyntax(h)
	}
	mic, err4 := unhex(f[2])
	anonce, err5 := unhex(f[6])
	eapol, err6 := unhex(f[7])
	if err4 != nil || err5 != nil || err6 != nil {
		return nil, errSyntax(h)
	}
	if len(mic) < eapolMICLen || len(anonce) != 32 || len(eapol) < eapolMICOffset+eapolMICLen {
		return nil, errSyntax(h)
	}

	keyver := int(binary.BigEndian.Uint16(eapol[5:7])) & 3
	frame := append([]byte(nil), eapol...)
	for i := eapolMICOffset; i < eapolMICOffset+eapolMICLen; i++ {
		frame[i] = 0
	}

	c := &eapolChecker{
		keyver: keyver,
		mic:    mic[:eapolMICLen],
		ap:     ap,
		sta:    sta,
		ssid:   ssid,
		anonce: anonce,
		snonce: frame[17:49],
		eapol:  frame,
	}
	return &Target{
		Raw: h, Kind: KindWPA2EAPOL, Mode: 22000, Check: c,
		GPU: eapolGPU(keyver, ssid, sta, ap, anonce, mic[:eapolMICLen], frame),
	}, nil
}

// eapolGPU 组装四次握手的 GPU 目标；超出 GPU 约束（如 EAPOL 帧过长）时返回 nil。
//
// Data 布局: Min(AP,STA) || Max(AP,STA) || ANonce(32) || EAPOL 帧，
// Iter 传 keyver（1=HMAC-MD5 / 2=HMAC-SHA1 / 3=AES-CMAC）。
func eapolGPU(keyver int, ssid, sta, ap, anonce, mic, frame []byte) *cuda.HashTarget {
	data := make([]byte, 0, 44+len(frame))
	if bytes.Compare(sta, ap) < 0 {
		data = append(data, sta...)
		data = append(data, ap...)
	} else {
		data = append(data, ap...)
		data = append(data, sta...)
	}
	data = append(data, anonce...)
	data = append(data, frame...)

	gt := &cuda.HashTarget{
		Algo:  cuda.HashWPA2EAPOL,
		Salt:  ssid,
		Data:  data,
		Check: mic,
		Iter:  keyver,
	}
	if err := gt.Validate(); err != nil {
		return nil
	}
	return gt
}
