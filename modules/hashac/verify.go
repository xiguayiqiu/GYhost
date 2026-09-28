package hashac

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/ulikunitz/xz/lzma"

	"gyhost/internal/cuda"
	"gyhost/internal/i18n"
)

// errSyntax 统一生成"格式非法"错误。
func errSyntax(h string) error {
	return errors.New(i18n.Tf("hashac.err.bad_syntax", clip(h)))
}

// ---------------------------------------------------------------------------
// 裸摘要：MD5 / SHA-1 / SHA-256 / SHA-512
// ---------------------------------------------------------------------------

type digestChecker struct {
	kind Kind
	want []byte
}

// Check 计算明文摘要并与目标比较。
func (c *digestChecker) Check(pw string) bool {
	var sum []byte
	switch c.kind {
	case KindMD5:
		s := md5.Sum([]byte(pw))
		sum = s[:]
	case KindSHA1:
		s := sha1.Sum([]byte(pw))
		sum = s[:]
	case KindSHA256:
		s := sha256.Sum256([]byte(pw))
		sum = s[:]
	case KindSHA512:
		s := sha512.Sum512([]byte(pw))
		sum = s[:]
	default:
		return false
	}
	return hmac.Equal(sum, c.want)
}

// newDigestTarget 构造裸摘要目标（GPU 可加速）。
func newDigestTarget(h string, kind Kind, mode int) (*Target, error) {
	want, err := unhex(h)
	if err != nil {
		return nil, err
	}
	algo := 0
	switch kind {
	case KindMD5:
		algo = cuda.HashRawMD5
	case KindSHA1:
		algo = cuda.HashRawSHA1
	case KindSHA256:
		algo = cuda.HashRawSHA256
	case KindSHA512:
		algo = cuda.HashRawSHA512
	}
	t := &Target{Raw: h, Kind: kind, Mode: mode, Check: &digestChecker{kind: kind, want: want}}
	if algo != 0 {
		t.GPU = &cuda.HashTarget{Algo: algo, Check: want}
	}
	return t, nil
}

// ---------------------------------------------------------------------------
// RAR5：PBKDF2-HMAC-SHA256 + 8 字节异或折叠校验（hashcat -m 13000）
// ---------------------------------------------------------------------------

// rar5Checker implements hashcat -m 13000（PBKDF2-HMAC-SHA256 + 异或折叠）。
type rar5Checker struct {
	salt  []byte
	check []byte
	power int
}

// Check 派生 32 字节密钥，按 8 字节分组逐字节异或折叠后与 pswcheck 比较。
//
// 迭代次数是 RAR5 独有的 (1<<power)+32（不是单纯的 2^power），
// 这一点由 hashcat 官方测试向量与真实压缩包共同确认。
func (c *rar5Checker) Check(pw string) bool {
	key := pbkdf2Key(sha256.New, []byte(pw), c.salt, rar5Iter(c.power), 32)
	var fold [8]byte
	for i := 0; i < 8; i++ {
		fold[i] = key[i] ^ key[i+8] ^ key[i+16] ^ key[i+24]
	}
	return hmac.Equal(fold[:], c.check)
}

// rar5Iter 由 KDF power 得到实际迭代次数。
func rar5Iter(power int) int { return (1 << power) + 32 }

// parseRAR5 解析 $rar5$saltLen$salt$kdfCount$iv$checkLen$check。
func parseRAR5(h string) (*Target, error) {
	f := strings.Split(h, "$")
	// ["", "rar5", saltLen, salt, kdfCount, iv, checkLen, check]
	if len(f) < 8 {
		return nil, errSyntax(h)
	}
	saltLen, err1 := strconv.Atoi(f[2])
	power, err2 := strconv.Atoi(f[4])
	checkLen, err3 := strconv.Atoi(f[6])
	salt, err4 := unhex(f[3])
	check, err5 := unhex(f[7])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
		return nil, errSyntax(h)
	}
	if saltLen >= 0 && saltLen <= len(salt) {
		salt = salt[:saltLen]
	}
	if checkLen >= 0 && checkLen <= len(check) {
		check = check[:checkLen]
	}
	if power < 0 || power > 24 || len(check) == 0 {
		return nil, errSyntax(h)
	}
	return &Target{
		Raw: h, Kind: KindRAR5, Mode: 13000,
		Check: &rar5Checker{salt: salt, check: check, power: power},
		GPU:   &cuda.HashTarget{Algo: cuda.HashRAR5, Salt: salt, Check: check, Iter: power},
	}, nil
}

// ---------------------------------------------------------------------------
// WinZip AES：PBKDF2-HMAC-SHA1(1000) + HMAC-SHA1 认证码（hashcat -m 13600）
// ---------------------------------------------------------------------------

type zipAESChecker struct {
	keyLen int
	salt   []byte
	verify []byte
	cipher []byte
	auth   []byte
}

// Check 先比 2 字节密码校验值，再用认证密钥校验 10 字节认证码。
func (c *zipAESChecker) Check(pw string) bool {
	derived := pbkdf2Key(sha1.New, []byte(pw), c.salt, zipAESIter, 2*c.keyLen+2)
	if !hmac.Equal(derived[2*c.keyLen:], c.verify) {
		return false
	}
	mac := hmacSum(sha1.New, derived[c.keyLen:2*c.keyLen], c.cipher)
	return hmac.Equal(mac[:authCodeLen], c.auth)
}

// zipAESIter 是 WinZip AES 的 PBKDF2 迭代次数。
const zipAESIter = 1000

// authCodeLen 是 WinZip AES 认证码长度。
const authCodeLen = 10

// parseZIPAES 解析 $zip2$*type*strength*magic*salt*verify*len*cipher*auth*$/zip2$。
//
// 字段顺序与 hashcat 的 13600 文档一致（也正是 hashdump 产出的形态）。注意
// TrimPrefix 去掉 "$zip2$" 之后 body 仍以 '*' 开头，所以下标整体后移一位：
//
//	$zip2$*0*3*0*b022a3b1ff45551f97971ba9ca9efe23*1d03*10*8a87…*5a8fb140c28cee8ab062*$/zip2$
//	    f[1]   f[2]  f[3]  f[4]                   f[5]   f[6] f[7] f[8]
//	     │      │     │     │                      │      │    │    └ 10 字节认证码
//	     │      │     │     │                      │      │    └────── 密文（可为空）
//	     │      │     │     │                      │      └─────────── 密文字节数
//	     │      │     │     │                      └────────────────── 2 字节口令校验值
//	     │      │     │     └──────────────────────────────────────────── 16 字节盐
//	     │      │     └────────────────────────────────────────────────── magic（0=文件内容 1=注释）
//	     │      └──────────────────────────────────────────────────────── 密钥强度（1/2/3 → AES-128/192/256）
//	     └─────────────────────────────────────────────────────────────── type（0 = WinZip AES）
func parseZIPAES(h string) (*Target, error) {
	if !strings.HasPrefix(h, "$zip2$") || !strings.HasSuffix(h, "$/zip2$") {
		return nil, errSyntax(h)
	}
	body := strings.TrimSuffix(strings.TrimPrefix(h, "$zip2$"), "$/zip2$")
	f := strings.Split(body, "*")
	// f[0] 是前导 '*' 切出的空串，f[len-1] 是末尾 '*' 切出的空串
	if len(f) < 9 {
		return nil, errSyntax(h)
	}
	strength, err := strconv.Atoi(f[2])
	if err != nil {
		return nil, errSyntax(h)
	}
	keyLen := 0
	switch strength {
	case 1:
		keyLen = 16
	case 2:
		keyLen = 24
	case 3:
		keyLen = 32
	default:
		return nil, errSyntax(h)
	}
	salt, err1 := unhex(f[4])
	verify, err2 := unhex(f[5])
	cipher, err3 := unhex(f[7])
	auth, err4 := unhex(f[8])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return nil, errSyntax(h)
	}
	if len(verify) < 2 || len(auth) < authCodeLen || len(salt) == 0 {
		return nil, errSyntax(h)
	}
	// 认证码覆盖整段密文：CPU 侧拿完整密文算，GPU 侧有 MaxCipherDataLen 的上限。
	// 两种边界都不挂 GPU 目标：密文为空（加密的空文件，只剩 2 字节口令校验值，
	// 内核判不出来）或超长（截断后认证码必然不符），都交给 CPU。
	var gpuCipher []byte
	if len(cipher) > 0 && len(cipher) <= cuda.MaxCipherDataLen {
		gpuCipher = cipher
	}

	check := make([]byte, 0, 2+authCodeLen)
	check = append(check, verify[:2]...)
	check = append(check, auth[:authCodeLen]...)

	t := &Target{
		Raw: h, Kind: KindZIPAES, Mode: 13600,
		Check: &zipAESChecker{keyLen: keyLen, salt: salt, verify: verify[:2], cipher: cipher, auth: auth[:authCodeLen]},
	}
	if gpuCipher != nil {
		t.GPU = &cuda.HashTarget{Algo: cuda.HashZIPAES, Salt: salt, Data: gpuCipher, Check: check, KeyLen: keyLen}
	}
	return t, nil
}

// ---------------------------------------------------------------------------
// ZipCrypto（传统 PKWARE 流密码，hashcat -m 17200/17210）
// ---------------------------------------------------------------------------

// PKZIP 流密码的初始密钥。
const (
	zipCryptoKey0 = 0x12345678
	zipCryptoKey1 = 0x23456789
	zipCryptoKey2 = 0x34567890

	methodStored  = 0
	methodDeflate = 8
)

// zipCrypto 是 PKZIP 流密码的三个 32 位状态。
type zipCrypto struct{ k0, k1, k2 uint32 }

// update 吸收一个明文字节更新密钥（crc32.IEEETable 与 PKZIP 的多项式一致）。
func (z *zipCrypto) update(c byte) {
	z.k0 = z.k0>>8 ^ crc32.IEEETable[byte(z.k0)^c]
	z.k1 = (z.k1+(z.k0&0xff))*134775813 + 1
	z.k2 = z.k2>>8 ^ crc32.IEEETable[byte(z.k2)^byte(z.k1>>24)]
}

// keystreamByte 生成当前密钥流字节。
func (z *zipCrypto) keystreamByte() byte {
	temp := (z.k2 | 2) & 0xffff
	return byte(((temp * (temp ^ 1)) >> 8) & 0xff)
}

// initZipCrypto 用口令初始化密钥流。
func initZipCrypto(pw string) *zipCrypto {
	z := &zipCrypto{k0: zipCryptoKey0, k1: zipCryptoKey1, k2: zipCryptoKey2}
	for i := 0; i < len(pw); i++ {
		z.update(pw[i])
	}
	return z
}

// decryptZipCrypto 就地解密整段数据（含 12 字节加密头）。
func decryptZipCrypto(z *zipCrypto, data []byte) []byte {
	out := make([]byte, len(data))
	for i, c := range data {
		p := c ^ z.keystreamByte()
		z.update(p)
		out[i] = p
	}
	return out
}

type zipCryptoChecker struct {
	method  int
	crc     uint32
	check   uint16
	dosTime uint16
	oneByte bool
	data    []byte
}

// Check 先校验 12 字节加密头，再解密全部数据并核对 CRC32。
//
// 头部校验按 APPNOTE 6.1：第 11（版本 >= 2.0）或第 10/11 字节应为 CRC 高位，
// 若置了数据描述符标志则改用 DOS 时间高位；再用 CRC32 做精确确认，
// 避免 1 字节校验带来的误报。
func (c *zipCryptoChecker) Check(pw string) bool {
	plain := decryptZipCrypto(initZipCrypto(pw), c.data)
	if len(plain) < 12 {
		return false
	}
	if c.oneByte {
		b := plain[11]
		if b != byte(c.crc>>24) && b != byte(c.dosTime>>8) {
			return false
		}
	} else {
		v := uint16(plain[10]) | uint16(plain[11])<<8
		if v != c.check && v != c.dosTime {
			return false
		}
	}

	payload := plain[12:]
	switch c.method {
	case methodStored:
		return crc32.ChecksumIEEE(payload) == c.crc
	case methodDeflate:
		out, err := io.ReadAll(flate.NewReader(bytes.NewReader(payload)))
		if err != nil {
			return false
		}
		return crc32.ChecksumIEEE(out) == c.crc
	}
	return false
}

// parseZipCrypto 解析 $pkzip2$count*B*DT*MT*CL*UL*CR*OF*OX*CT*DL*CS*TC*DATA*$/pkzip2$。
func parseZipCrypto(h string) (*Target, error) {
	if !strings.HasPrefix(h, "$pkzip2$") || !strings.HasSuffix(h, "*$/pkzip2$") {
		return nil, errSyntax(h)
	}
	body := strings.TrimSuffix(strings.TrimPrefix(h, "$pkzip2$"), "*$/pkzip2$")
	f := strings.Split(body, "*")
	if len(f) < 14 {
		return nil, errSyntax(h)
	}

	oneByte := f[1] == "1"
	if !oneByte && f[1] != "2" {
		return nil, errSyntax(h)
	}
	crcVal, err1 := strconv.ParseUint(f[6], 16, 32)
	ct, err2 := strconv.Atoi(f[9])
	cs, err3 := strconv.ParseUint(f[11], 16, 16)
	tc, err4 := strconv.ParseUint(f[12], 16, 16)
	data, err5 := unhex(f[13])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
		return nil, errSyntax(h)
	}
	if ct != methodStored && ct != methodDeflate {
		return nil, errSyntax(h)
	}
	// 12 字节就是加密头本身（空文件），合法
	if len(data) < 12 {
		return nil, errSyntax(h)
	}

	mode := 17200
	if ct == methodStored {
		mode = 17210
	}
	c := &zipCryptoChecker{
		method:  ct,
		crc:     uint32(crcVal),
		check:   uint16(cs),
		dosTime: uint16(tc),
		oneByte: oneByte,
		data:    data,
	}
	// GPU 侧只能比对头部 1~2 字节（弱校验），命中后由 crack.go 用 CPU 完整复核。
	// 内核解密的就是这 12 个字节，所以只把它们下发：条目再大也不会撞上
	// HashTarget 对 Data 的长度上限，Validate 也就不会把 GPU 目标否掉。
	b := 2
	if oneByte {
		b = 1
	}
	gpuCheck := make([]byte, 4)
	binary.LittleEndian.PutUint16(gpuCheck[0:2], uint16(cs))
	binary.LittleEndian.PutUint16(gpuCheck[2:4], uint16(tc))
	gpu := &cuda.HashTarget{Algo: cuda.HashZipCrypto, Data: data[:12], Check: gpuCheck, Iter: b}
	if err := gpu.Validate(); err != nil {
		gpu = nil
	}
	return &Target{Raw: h, Kind: KindZipCrypto, Mode: mode, Check: c, GPU: gpu}, nil
}

// ---------------------------------------------------------------------------
// 7z AES-256：SHA-256 迭代 KDF + AES-256-CBC + 解压后 CRC32（hashcat -m 11600）
// ---------------------------------------------------------------------------

// 7z 的数据编码器类型（$7z$ 的首字段）。
const (
	z7Copy    = 0
	z7LZMA1   = 1
	z7LZMA2   = 2
	z7Deflate = 7
)

// errBadArchive 表示解密后的数据无法按声明的编码器解压。
var errBadArchive = errors.New("hashac: bad archive data")

type sevenZipChecker struct {
	datatype int
	power    int
	salt     []byte // 7z AES salt（hashdump 输出中通常为空）
	iv       []byte // 16 字节 IV
	crc      uint32
	unpack   int64 // AES 解密后打包流长度
	crcLen   int64 // 解压后数据长度（datatype != 0 时有效）
	data     []byte
	attrs    []byte
}

// Check 用 7z KDF 派生密钥，AES-CBC 解密后解压并核对 CRC32。
func (c *sevenZipChecker) Check(pw string) bool {
	if len(c.data) == 0 || len(c.data)%aes.BlockSize != 0 {
		return false
	}
	block, err := aes.NewCipher(sevenZipKDF(pw, c.salt, c.power))
	if err != nil {
		return false
	}
	dec := make([]byte, len(c.data))
	cipher.NewCBCDecrypter(block, c.iv).CryptBlocks(dec, c.data)

	plain, err := c.decompress(dec)
	if err != nil {
		return false
	}
	return crc32.ChecksumIEEE(plain) == c.crc
}

// decompress 按编码器类型解压打包流（datatype 0 表示未压缩，直接取前 unpack 字节）。
func (c *sevenZipChecker) decompress(dec []byte) ([]byte, error) {
	if c.unpack <= 0 || int64(len(dec)) < c.unpack {
		return nil, errBadArchive
	}
	packed := dec[:c.unpack]
	if c.datatype == z7Copy {
		return packed, nil
	}
	if c.crcLen <= 0 {
		return nil, errBadArchive
	}

	switch c.datatype {
	case z7Deflate:
		return readExact(flate.NewReader(bytes.NewReader(packed)), c.crcLen)
	case z7LZMA1:
		if len(c.attrs) != 5 {
			return nil, errBadArchive
		}
		// 7z 的 LZMA1 是裸流，按 "lzma alone" 头补齐后再解码。
		hdr := make([]byte, 13, 13+len(packed))
		copy(hdr, c.attrs)
		binary.LittleEndian.PutUint64(hdr[5:], uint64(c.crcLen))
		r, err := lzma.NewReader(bytes.NewReader(append(hdr, packed...)))
		if err != nil {
			return nil, err
		}
		return readExact(r, c.crcLen)
	case z7LZMA2:
		r, err := lzma.NewReader2(bytes.NewReader(packed))
		if err != nil {
			return nil, err
		}
		return readExact(r, c.crcLen)
	}
	return nil, errBadArchive
}

// readExact 读取恰好 n 字节（不足视为失败，超出部分截断）。
func readExact(r io.Reader, n int64) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(r, n))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) < n {
		return nil, io.ErrUnexpectedEOF
	}
	return out, nil
}

// sevenZipKDF 实现 7-Zip 的 AES 密钥派生（7zAes.cpp CKeyInfo::CalcKey）：
//
//	key = SHA256( concat_{i=0}^{2^power-1} ( salt || pw_utf16le || LE32(i) || 00 00 00 00 ) )
func sevenZipKDF(pw string, salt []byte, power int) []byte {
	units := utf16.Encode([]rune(pw))
	pwb := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(pwb[2*i:], u)
	}

	rounds := 1 << power
	h := sha256.New()
	var ctr [8]byte
	buf := make([]byte, 0, len(salt)+len(pwb)+8)
	for i := 0; i < rounds; i++ {
		buf = buf[:0]
		buf = append(buf, salt...)
		buf = append(buf, pwb...)
		binary.LittleEndian.PutUint32(ctr[:4], uint32(i))
		buf = append(buf, ctr[:]...)
		h.Write(buf)
	}
	return h.Sum(nil)
}

// parse7z 解析：
//
//	$7z$datatype$power$saltLen$salt$ivLen$iv$crc$dataLen$unpackSize$data[$crcLen$attrs]
func parse7z(h string) (*Target, error) {
	f := strings.Split(h, "$")
	if len(f) < 12 {
		return nil, errSyntax(h)
	}
	datatype, err1 := strconv.Atoi(f[2])
	power, err2 := strconv.Atoi(f[3])
	salt, err3 := unhex(f[5])
	ivRaw, err4 := unhex(f[7])
	crcVal, err5 := strconv.ParseUint(f[8], 10, 32)
	unpack, err6 := strconv.ParseInt(f[10], 10, 64)
	data, err7 := unhex(f[11])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil ||
		err5 != nil || err6 != nil || err7 != nil {
		return nil, errSyntax(h)
	}
	switch datatype {
	case z7Copy, z7LZMA1, z7LZMA2, z7Deflate:
	default:
		return nil, errSyntax(h)
	}
	if power < 0 || power > 24 || unpack <= 0 {
		return nil, errSyntax(h)
	}

	iv := make([]byte, aes.BlockSize)
	copy(iv, ivRaw)

	var crcLen int64
	var attrs []byte
	if len(f) >= 14 {
		if v, err := strconv.ParseInt(f[12], 10, 64); err == nil {
			crcLen = v
		}
		if b, err := unhex(f[13]); err == nil {
			attrs = b
		}
	}

	c := &sevenZipChecker{
		datatype: datatype,
		power:    power,
		salt:     salt,
		iv:       iv,
		crc:      uint32(crcVal),
		unpack:   unpack,
		crcLen:   crcLen,
		data:     data,
		attrs:    attrs,
	}
	// 仅 Copy 编码器（无需解压）可交给 GPU；LZMA/Deflate 必须解压，回退 CPU。
	var gpu *cuda.HashTarget
	if datatype == z7Copy {
		// 内核按 AES-128-CBC 逐块解密，要求密文长度是 16 的倍数；真实条目的
		// 压缩流长度通常不是，补零到整块即可——校验只看前 unpack 字节的 CRC32，
		// 补出来的尾巴落在数据之后，不影响结果。
		gpuData := data
		if pad := len(gpuData) % 16; pad != 0 {
			gpuData = append(append([]byte{}, gpuData...), make([]byte, 16-pad)...)
		}
		gt := &cuda.HashTarget{
			Algo:   cuda.Hash7z,
			Salt:   salt,
			Data:   gpuData,
			Check:  []byte{byte(crcVal), byte(crcVal >> 8), byte(crcVal >> 16), byte(crcVal >> 24)},
			IV:     iv,
			Iter:   power,
			KeyLen: int(unpack),
		}
		// 密文可能很大（内核要整段解密），超长才放弃 GPU；历史上按 384 字节的
		// 通用上限卡，导致几乎所有真实 7z 条目都静默退回 CPU。
		if err := gt.Validate(); err == nil {
			gpu = gt
		}
	}
	return &Target{Raw: h, Kind: Kind7z, Mode: 11600, Check: c, GPU: gpu}, nil
}
