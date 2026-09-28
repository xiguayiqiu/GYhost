// 加密 Office 文档的口令校验（hashcat -m 9400/9500/9600）。
//
// 哈希行由 hashdump 从 OOXML 的 EncryptionInfo 流提取，格式与 john 的
// office2john 一致：
//
//	$office$*<年份>*<第二字段>*<密钥位数>*<盐长>*<盐>*<加密校验值>*<加密校验哈希>
//
// 第二字段的含义随年份变化：2007 是 verifierHashSize（KDF 轮数固定 50000，
// 见 [MS-OFFCRYPTO] 2.3.4），2010/2013 是 spinCount（KDF 轮数）。
//
// 两代算法都只重建口令校验值，不需要解密正文：
//   - 2007 标准加密（-m 9400）：SHA-1 KDF 50000 轮 + 一个 SHA1(H ‖ LE32(0)) 收尾块，
//     再按 2.3.4.7 用 0x36/0x5C 两个填充块各做一次 SHA-1 拼出 AES 密钥
//     （verifierHashSize 不小于密钥字节数时只要第一段），AES-ECB 解出 16 字节
//     校验值，比对 SHA-1(校验值) 的前 16 字节；
//   - 2010/2013 agile 加密（-m 9500/9600）：SHA-1 / SHA-512 KDF spinCount 轮，
//     用两个 block key 分别派生「校验值密钥」与「哈希密钥」，
//     AES-CBC（IV = 盐）解出 16 字节校验值与 32 字节校验哈希，
//     比对 SHA-1 / SHA-512(校验值) 的前 20 字节。
//
// 口令一律按 UTF-16LE 编码参与 KDF（与 7z、RAR3-hp 相同）。三种年份都有
// CUDA 内核（internal/cuda 的 HashOffice），--gpu 时交给 GPU 批量校验。
//
// 参考：john 的 office_fmt_plug.c（本文件的测试向量全部取自其测试表）、
// hashcat 的 -m 9400/9500/9600，二者与本实现逐字节一致。
package hashac

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"strconv"
	"strings"
	"unicode/utf16"

	"gyhost/internal/cuda"
	"gyhost/internal/i18n"
)

// Office 相关常量。
const (
	// office2007Spin 是标准加密（2007）固定的 KDF 轮数。
	office2007Spin = 50000
	// officeCompareLen 是 agile 加密比对校验哈希的字节数（john/hashcat 都比 20 字节，
	// 即便 2013 的 SHA-512 摘要有 64 字节）。
	officeCompareLen = 20
	// officeEncHashLen 是 agile 加密要下发的校验哈希密文字节数（两个 AES 分组）。
	officeEncHashLen = 32
)

// agile 加密派生两把密钥用的 block key（[MS-OFFCRYPTO] 2.3.4.4）。
var (
	officeBlockInputKey = [8]byte{0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79}
	officeBlockValueKey = [8]byte{0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e}
)

// ---------------------------------------------------------------------------
// 解析
// ---------------------------------------------------------------------------

// parseOffice 解析 $office$ 哈希行（hashcat -m 9400/9500/9600）。
//
// modeOverride 非 0 时要求与年份推出的模式号一致，否则报错，避免"强制模式"
// 静默改变校验算法（与 parsePDF 的处理一致）。
func parseOffice(h string, modeOverride int) (*Target, error) {
	const tag = "$office$*"
	if strings.HasPrefix(h, "$oldoffice$") {
		// RC4 时代的 Word 97-2003 / Excel 口令校验（-m 9700/9800）算法完全不同
		return nil, errors.New(i18n.T("hashac.err.oldoffice"))
	}
	if !strings.HasPrefix(h, tag) {
		return nil, errSyntax(h)
	}
	// [年份 第二字段 密钥位数 盐长 盐 加密校验值 加密校验哈希]
	f := strings.Split(strings.TrimPrefix(h, tag), "*")
	if len(f) != 7 {
		return nil, errSyntax(h)
	}
	year, err1 := strconv.Atoi(f[0])
	field2, err2 := strconv.Atoi(f[1])
	keyBits, err3 := strconv.Atoi(f[2])
	saltLen, err4 := strconv.Atoi(f[3])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return nil, errSyntax(h)
	}

	var kind Kind
	var mode int
	switch year {
	case 2007:
		kind, mode = KindOffice2007, 9400
	case 2010:
		kind, mode = KindOffice2010, 9500
	case 2013:
		kind, mode = KindOffice2013, 9600
	default:
		return nil, errors.New(i18n.Tf("hashac.err.office_year", year))
	}
	if modeOverride != 0 && modeOverride != mode {
		return nil, errors.New(i18n.Tf("hashac.err.office_mode", mode, modeOverride))
	}

	keyLen := keyBits / 8
	if keyBits%8 != 0 || (keyLen != 16 && keyLen != 24 && keyLen != 32) {
		return nil, errSyntax(h)
	}
	salt, err1 := unhex(f[4])
	verifier, err2 := unhex(f[5])
	encHash, err3 := unhex(f[6])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errSyntax(h)
	}
	if len(salt) == 0 || len(salt) != saltLen || len(verifier) != aes.BlockSize {
		return nil, errSyntax(h)
	}

	t := &Target{Raw: h, Kind: kind, Mode: mode}
	var gpu *cuda.HashTarget
	if year == 2007 {
		// field2 = verifierHashSize，决定 DeriveKey 要不要第二段（见 office2007Key）
		if field2 <= 0 || field2 > 64 || len(encHash) < aes.BlockSize {
			return nil, errSyntax(h)
		}
		c := &office2007Checker{
			spin:     office2007Spin,
			hashLen:  field2,
			keyLen:   keyLen,
			salt:     salt,
			verifier: verifier,
			encHash:  encHash,
		}
		t.Check = c
		gpu = officeGPU(year, salt, verifier, field2, office2007Spin, keyLen, encHash)
	} else {
		// agile：field2 = spinCount；校验哈希要两个 AES 分组才能解出比对的 20 字节
		if field2 < 0 || field2 > cuda.MaxHashIter {
			return nil, errSyntax(h)
		}
		if len(salt) != aes.BlockSize || len(encHash) < officeEncHashLen {
			return nil, errSyntax(h)
		}
		c := &officeAgileChecker{
			year:     year,
			spin:     field2,
			keyLen:   keyLen,
			salt:     salt,
			verifier: verifier,
			encHash:  encHash,
		}
		t.Check = c
		gpu = officeGPU(year, salt, verifier, 0, field2, keyLen, encHash)
	}
	t.GPU = gpu
	return t, nil
}

// officeGPU 组装 Office 目标的 GPU 目标（字段布局见 cuda.HashOffice）。
//
// Data = LE32(年份) || LE32(verifierHashSize) || encryptedVerifier(16)，
// Check = 加密校验哈希，Salt = 盐（agile 时兼作 CBC 的 IV），
// Iter = KDF 轮数，KeyLen = AES 密钥字节数。字段不满足内核约束时返回 nil，
// 由 crack.go 回退 CPU。
func officeGPU(year int, salt, verifier []byte, hashLen, spin, keyLen int, encHash []byte) *cuda.HashTarget {
	data := make([]byte, 8+len(verifier))
	binary.LittleEndian.PutUint32(data[0:], uint32(year))
	binary.LittleEndian.PutUint32(data[4:], uint32(hashLen))
	copy(data[8:], verifier)

	gt := &cuda.HashTarget{
		Algo:   cuda.HashOffice,
		Salt:   salt,
		Data:   data,
		Check:  encHash,
		Iter:   spin,
		KeyLen: keyLen,
	}
	if err := gt.Validate(); err != nil {
		return nil
	}
	return gt
}

// ---------------------------------------------------------------------------
// 2007：SHA-1 KDF + AES-ECB（hashcat -m 9400）
// ---------------------------------------------------------------------------

type office2007Checker struct {
	spin     int    // KDF 轮数，固定 50000
	hashLen  int    // verifierHashSize，来自哈希第二字段
	keyLen   int    // AES 密钥字节数（16/24/32）
	salt     []byte // 盐
	verifier []byte // 16 字节加密校验值
	encHash  []byte // 加密校验哈希（至少 16 字节）
}

// Check 派生 AES 密钥后解出校验值，比对 SHA-1(校验值) 的前 16 字节。
func (c *office2007Checker) Check(pw string) bool {
	if len(c.verifier) != aes.BlockSize || len(c.encHash) < aes.BlockSize {
		return false
	}
	digest := officeKDF(sha1.New(), sha1.Size, c.salt, utf16LE(pw), c.spin)

	// 收尾块：H = SHA1(H ‖ LE32(0))（[MS-OFFCRYPTO] 2.3.4，john 的
	// GeneratePasswordHashUsingSHA1 末尾 "append block (0) to H(n)" 同此）
	var tail [sha1.Size + 4]byte
	copy(tail[:sha1.Size], digest)
	final := sha1.Sum(tail[:])

	key := office2007Key(final[:], c.keyLen, c.hashLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	// 两段都是 ECB 单块：block.Decrypt 即一次 AES 解密
	var plain, dec [aes.BlockSize]byte
	block.Decrypt(plain[:], c.verifier)
	block.Decrypt(dec[:], c.encHash[:aes.BlockSize])
	sum := sha1.Sum(plain[:])
	return hmac.Equal(sum[:16], dec[:])
}

// office2007Key 实现 [MS-OFFCRYPTO] 2.3.4.7 的 DeriveKey：
// X = SHA1(0x36 填充 ‖ H)，verifierHashSize < 密钥字节数时再补一段
// SHA1(0x5C 填充 ‖ H)，取前 keyLen 字节。参数不可能凑出密钥时返回 nil。
func office2007Key(digest []byte, keyLen, hashLen int) []byte {
	key := officePadSHA1(digest, 0x36)
	if hashLen < keyLen {
		key = append(key, officePadSHA1(digest, 0x5c)...)
	}
	if keyLen > len(key) {
		return nil
	}
	return key[:keyLen]
}

// officePadSHA1 计算 SHA1(填充 ‖ H)：H 的每个字节异或 pad，其余字节为 pad。
func officePadSHA1(digest []byte, pad byte) []byte {
	var block [64]byte
	for i := range block {
		block[i] = pad
	}
	for i := 0; i < len(digest) && i < len(block); i++ {
		block[i] = pad ^ digest[i]
	}
	s := sha1.Sum(block[:])
	return s[:]
}

// ---------------------------------------------------------------------------
// 2010 / 2013：SHA-1 / SHA-512 KDF + AES-CBC（hashcat -m 9500/9600）
// ---------------------------------------------------------------------------

type officeAgileChecker struct {
	year     int    // 2010（SHA-1）或 2013（SHA-512）
	spin     int    // KDF 轮数（spinCount）
	keyLen   int    // AES 密钥字节数（16/24/32）
	salt     []byte // 16 字节盐，同时是 CBC 的初始向量
	verifier []byte // 16 字节加密校验值
	encHash  []byte // 加密校验哈希（至少 32 字节）
}

// Check 派生两把 AES 密钥，CBC 解出校验值与校验哈希后比对摘要前 20 字节。
func (c *officeAgileChecker) Check(pw string) bool {
	if len(c.salt) != aes.BlockSize || len(c.verifier) != aes.BlockSize ||
		len(c.encHash) < officeEncHashLen {
		return false
	}
	newHash, digestLen := c.newHash, sha1.Size
	if c.year == 2013 {
		digestLen = sha512.Size
	}

	digest := officeKDF(newHash(), digestLen, c.salt, utf16LE(pw), c.spin)
	k1 := officeBlockKey(newHash(), digest, &officeBlockInputKey, c.keyLen)
	k2 := officeBlockKey(newHash(), digest, &officeBlockValueKey, c.keyLen)
	plain := c.cbcDecrypt(k1, c.verifier)
	value := c.cbcDecrypt(k2, c.encHash[:officeEncHashLen])
	if plain == nil || value == nil {
		return false
	}

	h := newHash()
	h.Write(plain)
	sum := h.Sum(nil)
	return hmac.Equal(sum[:officeCompareLen], value[:officeCompareLen])
}

// newHash 给出该年份的摘要构造函数。
func (c *officeAgileChecker) newHash() hash.Hash {
	if c.year == 2013 {
		return sha512.New()
	}
	return sha1.New()
}

// officeBlockKey 实现 [MS-OFFCRYPTO] 2.3.4.4：block key 拼在 KDF 结果之后再摘要一次，
// 取前 keyLen 字节；摘要短于密钥时按规范补 0x36（SHA-1 配 192/256 位密钥）。
func officeBlockKey(h hash.Hash, digest []byte, blockKey *[8]byte, keyLen int) []byte {
	h.Reset()
	h.Write(digest)
	h.Write(blockKey[:])
	k := h.Sum(nil)
	if keyLen <= len(k) {
		return k[:keyLen]
	}
	out := make([]byte, keyLen)
	copy(out, k)
	for i := len(k); i < keyLen; i++ {
		out[i] = 0x36
	}
	return out
}

// cbcDecrypt 用该目标的盐做 IV 解密整段密文；密文不整除分组或密钥非法时返回 nil。
func (c *officeAgileChecker) cbcDecrypt(key, data []byte) []byte {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	iv := make([]byte, aes.BlockSize)
	copy(iv, c.salt)
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	return out
}

// ---------------------------------------------------------------------------
// 公共辅助
// ---------------------------------------------------------------------------

// officeKDF 实现 [MS-OFFCRYPTO] 1.3.6 的口令哈希迭代：
//
//	H(0) = SHAx(盐 ‖ UTF-16LE(口令))
//	H(n) = SHAx(LE32(n-1) ‖ H(n-1))   共 spin 轮
//
// digestLen 是摘要字节数（SHA-1 为 20、SHA-512 为 64）；全程复用两块摘要缓冲，
// 不在循环里分配内存——50000/100000 轮的分配会把 GC 吃满。
func officeKDF(h hash.Hash, digestLen int, salt, pw16 []byte, spin int) []byte {
	var prev, next [64]byte
	var scratch [4 + 64]byte

	h.Reset()
	h.Write(salt)
	h.Write(pw16)
	h.Sum(prev[:0])

	for i := 0; i < spin; i++ {
		binary.LittleEndian.PutUint32(scratch[:4], uint32(i))
		copy(scratch[4:], prev[:digestLen])
		h.Reset()
		h.Write(scratch[:4+digestLen])
		h.Sum(next[:0])
		prev, next = next, prev
	}
	return prev[:digestLen]
}

// utf16LE 把口令编码为 UTF-16LE（Office、7z、RAR3-hp 的口令编码方式）。
func utf16LE(pw string) []byte {
	units := utf16.Encode([]rune(pw))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[2*i:], u)
	}
	return out
}
