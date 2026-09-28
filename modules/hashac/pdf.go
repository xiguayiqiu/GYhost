// 加密 PDF 的口令校验（hashcat -m 10400/10500/10600/10700）。
//
// 哈希行由 hashdump 从 PDF 的 /Encrypt 字典与 trailer /ID 提取，格式与 john 的
// pdf2john 一致：
//
//	V<=4: $pdf$V*R*Length*P*EncryptMetadata*id0len*id0*ulen*U*olen*O
//	V=5 : $pdf$5*R*Length*P*EncryptMetadata*id0len*id0*ulen*U*olen*O*uelen*UE*oelen*OE
//
// 两代算法都只重建口令校验值，不需要解密正文：
//   - V<=4（PDF 32000-1 §7.6.3 标准安全处理器）：MD5 + RC4，Algorithm 2 派生
//     加密密钥，再按 Algorithm 4（R=2）或 Algorithm 5（R>=3）重建 /U 并比对；
//   - V=5（PDF 2.0 / ISO 32000-2，AES-256）：Algorithm 2.A（R=5）或
//     Algorithm 2.B（R=6，AES 迭代 64 轮 + SHA-256/384/512 变体）重建 /U 前 32 字节。
//
// 重建 /U 时加密/摘要的对象是 32 字节的固定填充串本身，而不是"填充后的口令"，
// 这是标准安全处理器最容易踩的坑：口令只参与密钥派生（Algorithm 2/3）。
//
// 与 hashcat 不同，这里用户口令与所有者口令都会尝试——命中任意一个都能打开
// 该 PDF（hashcat 的 10400/10500/10600/10700 只校验用户口令）。
// 两代算法都已有 CUDA 内核（internal/cuda 的 HashPDF），--gpu 时交给 GPU 批量校验；
// 字段不全（ID 非 16 字节、/U /O 不足 48 字节等）时 GPU 目标为 nil，自动回退 CPU。
package hashac

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"os"
	"strconv"
	"strings"

	"gyhost/internal/cuda"
	"gyhost/internal/i18n"
)

// pdfPadding 是标准安全处理器的 32 字节口令填充串（PDF 32000-1 §7.6.3.3）。
var pdfPadding = [32]byte{
	0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41,
	0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
	0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
	0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a,
}

// ---------------------------------------------------------------------------
// 解析
// ---------------------------------------------------------------------------

// parsePDF 解析 hashcat 的 $pdf$ 哈希行。
//
// modeOverride 非 0 时要求与 /V /R 推出的模式号一致，否则报错，避免"强制模式"
// 静默改变校验算法。
func parsePDF(h string, modeOverride int) (*Target, error) {
	const prefix = "$pdf$"
	if !strings.HasPrefix(h, prefix) {
		return nil, errSyntax(h)
	}
	f := strings.Split(strings.TrimPrefix(h, prefix), "*")
	// [V R Length P encMD id0len id0 ulen U olen O (uelen UE oelen OE)]
	if len(f) < 11 {
		return nil, errSyntax(h)
	}
	v, err1 := strconv.Atoi(f[0])
	r, err2 := strconv.Atoi(f[1])
	length, err3 := strconv.Atoi(f[2])
	// /P 允许写成无符号（4294967292 即 -4），按 64 位收再折回 32 位，与 hashdump 一致
	p, err4 := strconv.ParseInt(f[3], 10, 64)
	encMD, err5 := strconv.Atoi(f[4])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
		return nil, errSyntax(h)
	}

	kind, mode := pdfKindMode(v, r)
	if mode == 0 {
		return nil, errors.New(i18n.Tf("hashac.err.pdf_version", v, r))
	}
	if modeOverride != 0 && modeOverride != mode {
		return nil, errors.New(i18n.Tf("hashac.err.pdf_mode", mode, modeOverride))
	}

	id0, ok1 := pdfField(f[5], f[6])
	u, ok2 := pdfField(f[7], f[8])
	o, ok3 := pdfField(f[9], f[10])
	if !ok1 || !ok2 || !ok3 || len(id0) == 0 || len(u) == 0 || len(o) == 0 {
		return nil, errSyntax(h)
	}

	t := &Target{Raw: h, Kind: kind, Mode: mode}
	if v == 5 {
		// 用户校验要 /U 前 40 字节，所有者校验还要 /U 的第 40..48 字节
		if len(u) < 40 || len(o) < 40 {
			return nil, errSyntax(h)
		}
		c := &pdfAES256Checker{r: r, u: u, o: o}
		t.Check, t.GPU = c, c.gpu()
		return t, nil
	}

	// V<=4 的 /O /U 恒为 32 字节：不足补零，超出截断（与 hashcat 的定长缓冲一致）
	c := &pdfLegacyChecker{
		r:           r,
		keyLen:      pdfKeyLen(v, length),
		p:           uint32(int32(p)),
		encryptMeta: encMD != 0,
		id0:         id0,
		o:           fitPDFBytes(o, 32),
		u:           fitPDFBytes(u, 32),
	}
	t.Check, t.GPU = c, c.gpu()
	return t, nil
}

// pdfKindMode 由 /V /R 给出算法标签与 hashcat 模式号（与 hashdump 的 pdfMode 一致）。
func pdfKindMode(v, r int) (Kind, int) {
	if r < 2 || r > 6 {
		return "", 0
	}
	switch {
	case v == 1:
		return KindPDFRC440, 10400
	case v == 5 && r == 6:
		return KindPDFAES256R6, 10700
	case v == 5:
		return KindPDFAES256, 10600
	case v == 4:
		return KindPDFAES128, 10500
	case v == 2, v == 3:
		return KindPDFRC4128, 10500
	}
	return "", 0
}

// pdfKeyLen 由 /V 与 /Length 得出加密密钥字节数（PDF 32000-1 Algorithm 2）：
// V=1 固定 40 位、V=4 固定 128 位，其余按 /Length 折算，缺失或非法时按 128 位。
func pdfKeyLen(v, length int) int {
	switch {
	case v <= 1:
		return 5
	case v == 4:
		return 16
	case length >= 40 && length <= 128 && length%8 == 0:
		return length / 8
	}
	return 16
}

// pdfField 解析 "<字节长度>*<十六进制>" 字段：解码后按声明长度截断。
//
// 长度声明大于实际字节数时（个别工具按十六进制字符数计）原样保留，只认小不认大。
func pdfField(n, hx string) ([]byte, bool) {
	b, err := hex.DecodeString(strings.TrimSpace(hx))
	if err != nil {
		return nil, false
	}
	if k, err := strconv.Atoi(n); err == nil && k >= 0 && k <= len(b) {
		b = b[:k]
	}
	return b, true
}

// fitPDFBytes 把字段定长化：不足补零，超出截断。
func fitPDFBytes(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

// ---------------------------------------------------------------------------
// V<=4：MD5 + RC4（PDF 32000-1 标准安全处理器）
// ---------------------------------------------------------------------------

// pdfLegacyChecker 实现 -m 10400 / -m 10500 的 CPU 校验。
type pdfLegacyChecker struct {
	r           int    // 修订号 2..4
	keyLen      int    // 加密密钥字节数（5 或 16）
	p           uint32 // 权限标志，按 32 位小端参与密钥派生
	encryptMeta bool   // /EncryptMetadata 是否为 true
	id0         []byte // trailer /ID 的第一个元素
	o, u        []byte // 定长 32 字节的 /O 与 /U
}

// Check 先按用户口令比对 /U，不中再按所有者口令反解 /O。
func (c *pdfLegacyChecker) Check(pw string) bool {
	return c.checkUser(pw) || c.checkOwner(pw)
}

// checkUser 实现 Algorithm 4（R=2）与 Algorithm 5（R>=3）：派生密钥后重建 /U 比对。
//
// 重建的对象是 32 字节固定填充串本身（不是"填充后的口令"）：
//   - R=2：U = RC4(key, 填充串)，32 字节全比对；
//   - R>=3：U[0:16] = RC4^i(MD5(填充串 ‖ /ID[0]))，i = 0..19，第 i 轮用 key^i；
//     U[16:32] 由生成方任意填充，不参与比对（与 hashcat 一致）。
//
// pw 可以是用户口令原文，也可以是 checkOwner 反解出的 32 字节填充口令；
// 后者已是 32 字节，pdfPad 会原样返回。
func (c *pdfLegacyChecker) checkUser(pw string) bool {
	key := c.deriveKey(pw)
	if c.r >= 3 {
		h := md5.New()
		h.Write(pdfPadding[:])
		h.Write(c.id0)
		buf := h.Sum(nil)
		// 先用原密钥加密一次，再用密钥^i 各加密一次（i = 1..19）
		for i := 0; i < 20; i++ {
			buf = pdfRC4(pdfXOR(key, i), buf)
		}
		return hmac.Equal(buf, c.u[:16])
	}
	return hmac.Equal(pdfRC4(key, pdfPadding[:]), c.u)
}

// checkOwner 实现 Algorithm 3 的逆运算：/O 是用所有者口令派生的密钥把"填充后的
// 用户口令"RC4 迭代加密得到的（R>=3 共 20 轮，需按 key^19..key^0 逆序解），
// 先还原出该 32 字节填充口令，再走用户口令校验。
func (c *pdfLegacyChecker) checkOwner(pw string) bool {
	// R>=3 时所有者密钥同样要做 50 轮 MD5 强化（Algorithm 3 步骤 c）
	key := pdfMD5Rounds(md5Sum(pdfPad(pw)), c.keyLen, c.r)

	iterations := 1
	if c.r >= 3 {
		iterations = 20
	}
	user := make([]byte, len(c.o))
	copy(user, c.o)
	for x := iterations - 1; x >= 0; x-- {
		user = pdfRC4(pdfXOR(key, x), user)
	}
	return c.checkUser(string(user))
}

// deriveKey 实现 Algorithm 2：MD5(填充口令 ‖ /O ‖ P 小端 ‖ /ID[0] ‖ FFFFFFFF?)，
// R>=3 时再对密钥字节迭代 50 轮 MD5。
func (c *pdfLegacyChecker) deriveKey(pw string) []byte {
	h := md5.New()
	h.Write(pdfPad(pw))
	h.Write(c.o)
	var pbuf [4]byte
	binary.LittleEndian.PutUint32(pbuf[:], c.p)
	h.Write(pbuf[:])
	h.Write(c.id0)
	// R>=4 且 /EncryptMetadata 为 false 时额外吸收 FFFFFFFF
	if c.r >= 4 && !c.encryptMeta {
		h.Write([]byte{0xff, 0xff, 0xff, 0xff})
	}
	return pdfMD5Rounds(h.Sum(nil), c.keyLen, c.r)
}

// pdfMD5Rounds 实现 Algorithm 2/3 的 50 轮 MD5 强化：R>=3 时反复取上一轮摘要的
// 前 keyLen 字节做 MD5，最后仍返回前 keyLen 字节（与 qpdf 的 iterate_md5_digest 一致）。
func pdfMD5Rounds(digest []byte, keyLen, r int) []byte {
	n := keyLen
	if n > len(digest) {
		n = len(digest)
	}
	d := digest
	if r >= 3 {
		for i := 0; i < 50; i++ {
			d = md5Sum(d[:n])
		}
	}
	return d[:n]
}

// md5Sum 返回 data 的 MD5 摘要。
func md5Sum(data []byte) []byte {
	s := md5.Sum(data)
	return s[:]
}

// gpu 给出该校验器对应的 GPU 目标（字段布局见 cuda.HashPDF）；
// 参数不满足内核要求时返回 nil，由 crack.go 回退 CPU。
func (c *pdfLegacyChecker) gpu() *cuda.HashTarget {
	if len(c.id0) != 16 {
		return nil
	}
	iv := make([]byte, 8) // P(4 字节小端) || flags(bit0=EncryptMetadata) || 保留 3 字节
	binary.LittleEndian.PutUint32(iv, c.p)
	if c.encryptMeta {
		iv[4] = 1
	}
	return &cuda.HashTarget{
		Algo:   cuda.HashPDF,
		Salt:   c.id0,
		Data:   c.o,
		Check:  c.u,
		Iter:   c.r,
		KeyLen: c.keyLen,
		IV:     iv,
	}
}

// ---------------------------------------------------------------------------
// V=5：AES-256（ISO 32000-2）
// ---------------------------------------------------------------------------

// pdfAES256Checker 实现 -m 10600（R=5）与 -m 10700（R=6）的 CPU 校验。
type pdfAES256Checker struct {
	r int    // 修订号 5 或 6
	u []byte // /U：前 32 字节校验值，32..40 校验盐，40..48 密钥盐
	o []byte // /O：结构同 /U，udata 段取 /U 的前 48 字节
}

// Check 依次尝试用户口令与所有者口令（口令按规范截断到 127 字节）。
func (c *pdfAES256Checker) Check(pw string) bool {
	if len(pw) > 127 {
		pw = pw[:127]
	}
	p := []byte(pw)
	if hmac.Equal(pdfHashV5(p, c.u[32:40], nil, c.r), c.u[:32]) {
		return true
	}
	if len(c.u) < 48 {
		return false
	}
	return hmac.Equal(pdfHashV5(p, c.o[32:40], c.u[:48], c.r), c.o[:32])
}

// pdfR6ForceGPU 读环境变量 GYHOST_PDF_R6_GPU：设成 1/true/yes/on 时，
// 即使 R=6 的 GPU 内核比 CPU 慢也照样交给 GPU（例如换了更强的显卡）。
func pdfR6ForceGPU() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GYHOST_PDF_R6_GPU"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// gpu 给出该校验器对应的 GPU 目标（字段布局见 cuda.HashPDF）；
// /U /O 不足 48 字节时（所有者口令路径要 /U 前 48 字节）返回 nil 回退 CPU。
//
// R=6（-m 10700）默认返回 nil：内核本身是好的（internal/cuda 里有向量测试直接跑它），
// 但每个候选要做 64~288 轮 AES-128-CBC，实测在本机 RTX 3050 上约 1.0 kH/s，
// 而 16 线程 CPU 约 10.7 kH/s——GPU 反而慢一个数量级，所以默认仍走 CPU。
// 差距的来源：内核用的 AES 是按字节实现的（与 hashac 的 CPU 版逐字节对应），
// 且比 hashcat 多算一遍所有者口令路径。设 GYHOST_PDF_R6_GPU=1 可强制交给 GPU；
// 内核换成 T-table 版 AES 之后，把下面的开关删掉即可。
func (c *pdfAES256Checker) gpu() *cuda.HashTarget {
	if c.r != 5 && !pdfR6ForceGPU() {
		return nil
	}
	if len(c.u) < 48 || len(c.o) < 48 {
		return nil
	}
	salt := make([]byte, 16) // 用户校验盐 || 所有者校验盐
	copy(salt, c.u[32:40])
	copy(salt[8:], c.o[32:40])
	return &cuda.HashTarget{
		Algo:  cuda.HashPDF,
		Salt:  salt,
		Data:  c.u[:48],
		Check: c.o[:48],
		Iter:  c.r,
	}
}

// pdfHashV5 实现 Algorithm 2.A（R=5）与 Algorithm 2.B（R=6）：
// 先 SHA-256(口令 ‖ 盐 ‖ udata)；R=6 再做"轮数不定"的强化——每轮把
// (口令 ‖ K ‖ udata) 整串重复 64 次喂给 AES-128-CBC（key = K[0:16]，IV = K[16:32]），
// 按密文前 16 字节之和对 3 取模选 SHA-256/384/512 摘出新的 K；至少 64 轮，
// 之后由密文末字节是否大于「轮次-32」决定是否继续（最多 288 轮）；最后取前 32 字节。
//
// udata 为空表示校验用户口令；校验所有者口令时传 /U 的前 48 字节。
// 数据非法（无法 AES 分块）时返回 nil。
//
// 性能：R=6 每轮要加密 64 份 unit（典型口令 2.5KB，最长 15KB），一个候选往往上百轮。
// 早期版本每轮新建两份大缓冲"拼完再加密"，单候选产出 657KB 垃圾，16 线程反而比
// 单线程还慢（分配器与 GC 把系统时间吃满）。现在缓冲全放在 pdfKDFState 里跨轮复用，
// 按 pdfChunk 分块批量 CBC 再整块喂摘要，每轮只留 3 次小分配。
func pdfHashV5(pw, salt, udata []byte, r int) []byte {
	h := sha256.New()
	h.Write(pw)
	h.Write(salt)
	h.Write(udata)
	var buf [64]byte // 新一轮 K 的落点（SHA-512 最长 64 字节）
	k := h.Sum(buf[:0])
	if r < 6 {
		return k
	}

	var st pdfKDFState
	for round := 1; ; round++ {
		if !st.round(pw, k, udata) {
			return nil
		}
		k = st.h.Sum(buf[:0])

		// 前 64 轮必须跑满；之后末字节 <= 轮次-32 即收敛（最多 288 轮必然结束）
		if round >= 64 && int(st.last) <= round-32 {
			return k[:32]
		}
	}
}

// pdfChunk 是一轮强化里批量做 AES-128-CBC 的分块大小（须为分组倍数）。
const pdfChunk = 1024

// pdfKDFState 承载一轮 Algorithm 2.B 的全部中间缓冲，跨轮复用：
// unit = (口令 ‖ K ‖ udata) 先摆好，再分块填进明文缓冲做 CBC，密文整块喂给摘要。
// 64 份 unit 的总长恒为 16 的倍数，因此末块不会跨分组。
type pdfKDFState struct {
	h    hash.Hash      // 本轮选定的摘要（首块密文产出后才知道用哪种）
	unit [256]byte      // 口令 ‖ K ‖ udata（口令≤127、K≤64、udata≤48）
	pt   [pdfChunk]byte // 明文缓冲
	ct   [pdfChunk]byte // 密文缓冲
	last byte           // 末块末字节，供终止判定
}

// round 把 (pw ‖ K ‖ udata) 重复 64 次做 AES-128-CBC，密文流按首块 mod 3 摘要进 s.h。
// 参数非法（密钥或 unit 过长等）时返回 false。
func (s *pdfKDFState) round(pw, k, udata []byte) bool {
	if len(k) < 32 || len(pw)+len(k)+len(udata) > len(s.unit) {
		return false
	}
	n := copy(s.unit[:], pw)
	n += copy(s.unit[n:], k)
	n += copy(s.unit[n:], udata)
	block, err := aes.NewCipher(k[:16])
	if err != nil {
		return false
	}
	// NewCBCEncrypter 把 IV 拷进内部状态，之后连续 CryptBlocks 即可保持链式
	cbc := cipher.NewCBCEncrypter(block, k[16:32])

	total := 64 * n // 恒为分组倍数
	s.h = nil
	pos := 0 // 下一块要从 unit 的哪个位置接着取（分块边界不会正好对齐 unit）
	for off := 0; off < total; {
		want := pdfChunk
		if total-off < want {
			want = total - off
		}
		for filled := 0; filled < want; { // 按 unit 循环往复地填满本块
			c := copy(s.pt[filled:want], s.unit[pos:n])
			filled += c
			if pos += c; pos == n {
				pos = 0
			}
		}
		cbc.CryptBlocks(s.ct[:want], s.pt[:want])
		if s.h == nil {
			// 首块 16 字节之和即 E 的前 16 字节之和；256 ≡ 1 (mod 3)，
			// 故等价于把前 16 字节当大端 128 位整数取模。
			sum := 0
			for _, b := range s.ct[:16] {
				sum += int(b)
			}
			switch sum % 3 {
			case 0:
				s.h = sha256.New()
			case 1:
				s.h = sha512.New384()
			default:
				s.h = sha512.New()
			}
		}
		s.h.Write(s.ct[:want])
		s.last = s.ct[want-1]
		off += want
	}
	return true
}

// ---------------------------------------------------------------------------
// 公共辅助
// ---------------------------------------------------------------------------

// pdfPad 把口令填充/截断到 32 字节（PDF 32000-1 §7.6.3.3 步骤 a）：
// 超过 32 字节只取前 32 字节；不足则在口令之后追加固定填充串。
func pdfPad(pw string) []byte {
	out := make([]byte, 32)
	n := copy(out, pw)
	copy(out[n:], pdfPadding[:])
	return out
}

// pdfXOR 返回每个字节都异或 x 的密钥副本（RC4 迭代加密用）。
func pdfXOR(key []byte, x int) []byte {
	out := make([]byte, len(key))
	for i, b := range key {
		out[i] = b ^ byte(x)
	}
	return out
}

// pdfRC4 用 RC4 加密/解密 data（同一运算），不改动入参。
func pdfRC4(key, data []byte) []byte {
	if len(key) == 0 {
		return nil
	}
	var s [256]byte
	for i := range s {
		s[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(key[i%len(key)])) & 0xff
		s[i], s[j] = s[j], s[i]
	}
	out := make([]byte, len(data))
	copy(out, data)
	x, y := 0, 0
	for n := range out {
		x = (x + 1) & 0xff
		y = (y + int(s[x])) & 0xff
		s[x], s[y] = s[y], s[x]
		out[n] ^= s[(int(s[x])+int(s[y]))&0xff]
	}
	return out
}
