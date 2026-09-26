// Package cuda 提供 GYhost 的公共 NVIDIA CUDA 加速能力。
//
// 这是 shadow 模块以及后续所有需要 GPU 加速的模块的统一入口：
// 业务代码只依赖本包的 Target / Verify / Devices 等抽象，
// 不直接触碰 cgo 与 CUDA 运行时；CUDA 相关的 C/CUDA 源码见同目录
// cuda.h / cuda.cu（算法核心为 __host__ __device__，主机与 GPU 共用一份实现）。
//
// 构建：
//
//	make -C internal/cuda      # 生成 libgyhost_cuda.a（需要 nvcc）
//	go build -tags cuda        # 编译启用 CUDA 的二进制
//
// 不带 -tags cuda 的普通构建同样可编译，此时 Compiled() 返回 false、
// Verify 返回 ErrNotCompiled，调用方据此回退 CPU 实现。
package cuda

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf16"
)

const (
	// AlgoMD5Crypt md5crypt，shadow 中的 $1$。
	AlgoMD5Crypt = 1
	// AlgoSHA256Crypt sha256crypt，shadow 中的 $5$。
	AlgoSHA256Crypt = 5
	// AlgoSHA512Crypt sha512crypt，shadow 中的 $6$。
	AlgoSHA512Crypt = 6
)

// 通用哈希算法编号（hashac 使用），与 cuda.h 中的 GYHOST_HASH_* 对应。
const (
	// HashRawMD5 裸 MD5：md5(pw) == Check（16 字节）。
	HashRawMD5 = 100
	// HashRawSHA1 裸 SHA-1：sha1(pw) == Check（20 字节）。
	HashRawSHA1 = 101
	// HashRawSHA256 裸 SHA-256：sha256(pw) == Check（32 字节）。
	HashRawSHA256 = 102
	// HashRawSHA512 裸 SHA-512：sha512(pw) == Check（64 字节）。
	HashRawSHA512 = 103
	// HashZIPAES WinZip AES：PBKDF2-HMAC-SHA1(pw, Salt, 1000, 2*KeyLen+2)，
	// 校验 derived[2*KeyLen:] == Check[0:2] 且 HMAC-SHA1(derived[KeyLen:2*KeyLen], Data)[0:10] == Check[2:12]。
	HashZIPAES = 110
	// HashZipCrypto ZipCrypto 传统加密（hashcat -m 17200/17210）：
	// 由密码初始化 PKZIP 三密钥流，解密 Data 前 12 字节得到加密头，
	// 按 Iter=B（1 或 2）比对已知明文字节。Check 前 2 字节为 CS（小端）、
	// 后 2 字节为 TC（小端）。**这是弱校验**，命中后必须由 CPU 完整复核。
	HashZipCrypto = 111
	// HashWPA2PMKID WPA2 PMKID：PBKDF2-HMAC-SHA1(pw, Salt, 4096, 32)，
	// 再 HMAC-SHA1(PMK, Data)[0:16] == Check（Data = "PMK Name" || AP || STA）。
	HashWPA2PMKID = 120
	// HashWPA2EAPOL WPA/WPA2 四次握手（hashcat -m 22000 的 WPA*02*）：
	// PBKDF2-HMAC-SHA1(pw, Salt=ESSID, 4096, 32) 得 PMK，PRF 前 16 字节为 KCK，
	// 再按 Iter=keyver 计算 MIC 并与 Check 比对（1=HMAC-MD5、2=HMAC-SHA1、
	// 3=AES-CMAC）。Data = Min(AP,STA) || Max(AP,STA) || ANonce(32) || EAPOL 帧，
	// 其中 EAPOL 帧的 MIC 字段已置零、SNonce 位于帧内偏移 17。
	HashWPA2EAPOL = 121
	// HashRAR5 RAR5：PBKDF2-HMAC-SHA256(pw, Salt, (1<<Iter)+32, 32)，
	// 派生密钥按 8 字节分组逐字节异或折叠后等于 Check（8 字节）。
	HashRAR5 = 130
	// HashRAR3HP RAR3 头加密（-hp，hashcat -m 12500）：候选密码按 UTF-16LE
	// 编码后走交织 SHA-1 KDF（262144 轮）+ AES-128-CBC 解密 Data（16 字节密文头），
	// 明文前 7 字节等于 Check（固定常量 c4 3d 7b 00 40 07 00）。
	// 密码最多 64 个 UTF-16 码元（与 hashcat 上限一致），超出由 CPU 校验。
	HashRAR3HP = 131
	// Hash7z 7z AES-256（hashcat -m 11600 的 Copy 编码器子集）：候选密码按
	// UTF-16LE 编码做 SHA-256 迭代 KDF（2^Iter 轮），AES-256-CBC 解密 Data，
	// 前 KeyLen 字节的 CRC32 等于 Check（4 字节小端）。IV 为 16 字节初始向量。
	// LZMA/Deflate 等需要解压校验的类型不适用，由 CPU 校验。
	Hash7z = 140
)

const (
	// MaxPasswordLen GPU 单个候选密码允许的最大字节数；
	// 超长候选由调用方自行回退 CPU 校验。
	MaxPasswordLen = 255
	// MaxSaltLen GPU 允许的最大盐长度（字节）。
	MaxSaltLen = 64
	// MaxBatch 单次 Verify 允许的候选密码数量上限。
	MaxBatch = 1 << 20
	// MaxRounds 允许的最大迭代轮数；更大的目标回退 CPU 校验。
	MaxRounds = math.MaxInt32
)

// 与 cuda.h 中 GYHOST_CUDA_* 对应的返回码。
const (
	codeOK        = 0
	codeParam     = -1
	codeNoDevice  = -2
	codeAlloc     = -3
	codeKernel    = -4
	codeAlgorithm = -5
)

// 公共错误，调用方用 errors.Is 判别并给出国际化提示。
var (
	// ErrNotCompiled 当前二进制未启用 CUDA 构建（缺少 -tags cuda）。
	ErrNotCompiled = errors.New("cuda: built without CUDA support")
	// ErrNoDevice 没有可用的 CUDA 设备。
	ErrNoDevice = errors.New("cuda: no CUDA device available")
	// ErrUnsupported 目标哈希算法不支持 GPU 校验。
	ErrUnsupported = errors.New("cuda: hash algorithm not supported on GPU")
	// ErrParam 参数非法（盐过长、密文为空、轮数越界等）。
	ErrParam = errors.New("cuda: invalid parameter")
	// ErrPasswordTooLong 候选密码长度超过 MaxPasswordLen。
	ErrPasswordTooLong = errors.New("cuda: password exceeds MaxPasswordLen")
	// ErrRuntime CUDA 运行期错误（显存分配、内核发射失败）。
	ErrRuntime = errors.New("cuda: runtime error")
)

// Device 描述一块可用的 CUDA 设备。
type Device struct {
	Index    int    // 设备编号（用于 Verify 的 device 参数）
	Name     string // 设备名称，如 "NVIDIA GeForce RTX 3050 Laptop GPU"
	MemoryMB int64  // 显存总量（MB）
}

// String 返回可直接展示的设备描述。
func (d Device) String() string {
	return fmt.Sprintf("%s (%d MB)", d.Name, d.MemoryMB)
}

// Target 是一个可在 GPU 上校验的目标哈希（盐 + 轮数 + 密文）。
//
// 由调用方从编码哈希（如 $6$rounds=5000$salt$hash）解析得到，
// 解析与格式无关的通用参数见 internal/pwdhash.ParseCrypt。
type Target struct {
	Algo   int    // AlgoMD5Crypt / AlgoSHA256Crypt / AlgoSHA512Crypt
	Salt   string // 盐
	Rounds int    // 仅 sha-crypt 有意义；md5crypt 固定 1000 轮
	Key    string // 目标密文（crypt base64）
}

// Validate 校验该目标能否交给 GPU 处理。
func (t Target) Validate() error {
	switch t.Algo {
	case AlgoMD5Crypt, AlgoSHA256Crypt, AlgoSHA512Crypt:
	default:
		return ErrUnsupported
	}
	if len(t.Salt) > MaxSaltLen {
		return ErrParam
	}
	if t.Key == "" || strings.IndexByte(t.Key, 0) >= 0 {
		return ErrParam
	}
	if t.Rounds < 0 || t.Rounds > MaxRounds {
		return ErrParam
	}
	return nil
}

// AlgoID 把 pwdhash 的算法标识（"1"/"5"/"6"）映射为 GPU 算法编号。
func AlgoID(algo string) (int, bool) {
	switch algo {
	case "1":
		return AlgoMD5Crypt, true
	case "5":
		return AlgoSHA256Crypt, true
	case "6":
		return AlgoSHA512Crypt, true
	}
	return 0, false
}

// Supported 判断该算法标识是否支持 GPU 校验。
func Supported(algo string) bool {
	_, ok := AlgoID(algo)
	return ok
}

// ---------------------------------------------------------------------------
// 通用哈希目标（hashac 模块使用）
// ---------------------------------------------------------------------------

// 通用哈希的单字段长度上限（与 cuda.h 中的 GYHOST_HASH_* 常量一致）。
const (
	// MaxHashSaltLen 盐/IV 的最大字节数。
	MaxHashSaltLen = 64
	// MaxHashDataLen 额外数据（如 HMAC 输入、EAPOL 帧）的最大字节数。
	MaxHashDataLen = 384
	// MaxHashCheckLen 目标校验值的最大字节数。
	MaxHashCheckLen = 64
	// MaxHashIter 允许的最大 KDF 迭代轮数（power 形式的上限见各算法）。
	MaxHashIter = 1 << 24
)

// HashTarget 描述一个可在 GPU 上校验的通用哈希（hashac 模块使用）。
//
// 与 Target 一样，业务代码只依赖本结构，不感知底层是 CPU 还是 GPU。
// 各算法的字段含义见 HashXxx 常量说明。
type HashTarget struct {
	Algo   int    // HashRawMD5 / HashZIPAES / HashZipCrypto / HashWPA2PMKID / HashWPA2EAPOL / ...
	Salt   []byte // 盐（ZIP AES 为 salt，WPA2 为 SSID/ESSID，RAR5/RAR3 为 salt，7z 为 AES salt）
	Data   []byte // 额外数据（ZIP AES 为密文，WPA2 见对应常量说明，RAR3 为 16 字节密文头，7z 为加密数据）
	Check  []byte // 目标校验值
	Iter   int    // RAR5/7z = KDF power（迭代次数为 1<<Iter）；RAR3 固定 2^18 轮；ZipCrypto = B；WPA2-EAPOL = keyver
	KeyLen int    // ZIP AES 的密钥长度（16/24/32）；7z 的解压后字节数
	IV     []byte // 初始向量（仅 7z 使用，16 字节）
}

// Validate 校验该目标能否交给 GPU 处理。
func (t HashTarget) Validate() error {
	switch t.Algo {
	case HashRawMD5:
		if len(t.Check) != 16 {
			return ErrParam
		}
	case HashRawSHA1:
		if len(t.Check) != 20 {
			return ErrParam
		}
	case HashRawSHA256:
		if len(t.Check) != 32 {
			return ErrParam
		}
	case HashRawSHA512:
		if len(t.Check) != 64 {
			return ErrParam
		}
	case HashZIPAES:
		if t.KeyLen != 16 && t.KeyLen != 24 && t.KeyLen != 32 {
			return ErrParam
		}
		if len(t.Check) != 12 || len(t.Data) == 0 {
			return ErrParam
		}
	case HashWPA2PMKID:
		if len(t.Check) != 16 || len(t.Data) != 20 {
			return ErrParam
		}
	case HashZipCrypto:
		if len(t.Check) != 4 || len(t.Data) <= 12 {
			return ErrParam
		}
		if t.Iter != 1 && t.Iter != 2 {
			return ErrParam
		}
	case HashWPA2EAPOL:
		// Data = MAC块(12) + ANonce(32) + EAPOL 帧，帧长至少到 MIC 结束（97）。
		if len(t.Check) != 16 || len(t.Data) < 44+97 {
			return ErrParam
		}
		if t.Iter < 1 || t.Iter > 3 {
			return ErrParam
		}
	case HashRAR5:
		if len(t.Check) != 8 || t.Iter < 0 || t.Iter > 24 {
			return ErrParam
		}
	case HashRAR3HP:
		if len(t.Check) != 7 || len(t.Salt) != 8 || len(t.Data) != 16 {
			return ErrParam
		}
	case Hash7z:
		if len(t.Check) != 4 || len(t.IV) != 16 || t.Iter < 0 || t.Iter > 24 {
			return ErrParam
		}
		if len(t.Data) == 0 || len(t.Data) > MaxHashDataLen || len(t.Data)%16 != 0 {
			return ErrParam
		}
		if t.KeyLen <= 0 || t.KeyLen > len(t.Data) {
			return ErrParam
		}
	default:
		return ErrUnsupported
	}
	if len(t.Salt) > MaxHashSaltLen || len(t.Data) > MaxHashDataLen || len(t.Check) > MaxHashCheckLen {
		return ErrParam
	}
	return nil
}

// SupportedHash 判断该通用哈希算法编号是否支持 GPU 校验。
func SupportedHash(algo int) bool {
	switch algo {
	case HashRawMD5, HashRawSHA1, HashRawSHA256, HashRawSHA512,
		HashZIPAES, HashZipCrypto, HashWPA2PMKID, HashWPA2EAPOL,
		HashRAR5, HashRAR3HP, Hash7z:
		return true
	}
	return false
}

// utf16Units 计算字符串的 UTF-16 码元数（不产生分配）。
func utf16Units(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xffff {
			n += 2 // 代理对
		} else {
			n++
		}
	}
	return n
}

// utf16le 把密码按 UTF-16LE 编码（与 Go 端 utf16.Encode([]rune(pw)) 一致）。
func utf16le(pw string) []byte {
	units := make([]uint16, 0, len(pw))
	for _, r := range pw {
		if r > 0xffff {
			r, lo := utf16.EncodeRune(r)
			units = append(units, uint16(r), uint16(lo))
		} else {
			units = append(units, uint16(r))
		}
	}
	out := make([]byte, 2*len(units))
	for i, u := range units {
		out[2*i] = byte(u)
		out[2*i+1] = byte(u >> 8)
	}
	return out
}

// HashPasswordFits 判断候选密码能否交给 GPU 按该算法校验。
//
// 通用上限是 len(pw) <= MaxPasswordLen；RAR3-hp 额外要求不超过 64 个
// UTF-16 码元、7z 不超过 127 个（native 侧缓冲区大小约束）。
// 不满足的候选由调用方回退 CPU 校验。
func HashPasswordFits(algo int, pw string) bool {
	if len(pw) > MaxPasswordLen {
		return false
	}
	switch algo {
	case HashRAR3HP:
		return utf16Units(pw) <= 64
	case Hash7z:
		return utf16Units(pw) <= 127
	}
	return true
}

// Compiled 返回当前二进制是否编译了 CUDA 支持（-tags cuda）。
func Compiled() bool { return compiled() }

// Privileged 报告当前进程是否具备启用 GPU 所需的权限。
//
// 这是一道策略门禁：类 Unix 系统要求以 root（euid 0）运行，
// Windows 没有 root 概念、恒为 true。调用方在请求了 --gpu 但本函数返回
// false 时，应提示需要 root 并回退 CPU 爆破。
func Privileged() bool { return privileged() }

// Available 返回是否存在可用的 CUDA 设备。
func Available() bool {
	_, err := Devices()
	return err == nil
}

// Devices 枚举可用的 CUDA 设备。
func Devices() ([]Device, error) {
	if !compiled() {
		return nil, ErrNotCompiled
	}
	n := deviceCount()
	if n <= 0 {
		return nil, ErrNoDevice
	}
	out := make([]Device, 0, n)
	for i := 0; i < n; i++ {
		name, mem, err := deviceAt(i)
		if err != nil {
			continue
		}
		out = append(out, Device{Index: i, Name: name, MemoryMB: mem})
	}
	if len(out) == 0 {
		return nil, ErrNoDevice
	}
	return out, nil
}

// DefaultDevice 返回首个可用设备。
func DefaultDevice() (Device, error) {
	devs, err := Devices()
	if err != nil {
		return Device{}, err
	}
	return devs[0], nil
}

// Verify 在指定设备上批量校验候选密码，返回首个命中的候选下标（无命中为 -1）。
//
// 一批候选共享同一个目标哈希；候选必须满足 len(pw) <= MaxPasswordLen，
// 超长候选请由调用方回退 CPU 校验。并发安全：每次调用独立申请显存。
func Verify(t Target, passwords []string, device int) (int, error) {
	if !compiled() {
		return -1, ErrNotCompiled
	}
	if err := t.Validate(); err != nil {
		return -1, err
	}
	if len(passwords) == 0 {
		return -1, nil
	}
	if len(passwords) > MaxBatch {
		return -1, ErrParam
	}
	if device < 0 {
		return -1, ErrParam
	}

	// 拍平成 [数据区][偏移][长度] 三段，一次上传显存
	data, offs, lens, err := flatten(passwords)
	if err != nil {
		return -1, err
	}
	return verifyNative(t.Algo, data, offs, lens, t.Salt, t.Rounds, t.Key, device)
}

// flatten 把候选密码列表拍平成 [数据区][偏移][长度] 三段，
// 供 GPU 一次上传；候选长度超过 MaxPasswordLen 时返回 ErrPasswordTooLong。
func flatten(passwords []string) (data []byte, offs, lens []int32, err error) {
	var total int
	for _, p := range passwords {
		if len(p) > MaxPasswordLen {
			return nil, nil, nil, ErrPasswordTooLong
		}
		total += len(p)
	}
	data = make([]byte, 0, total+1)
	offs = make([]int32, len(passwords))
	lens = make([]int32, len(passwords))
	for i, p := range passwords {
		offs[i] = int32(len(data))
		data = append(data, p...)
		lens[i] = int32(len(p))
	}
	if len(data) == 0 {
		data = make([]byte, 1) // 全空候选时也要给 C 侧一个合法指针
	}
	return data, offs, lens, nil
}

// Check 使用主机端（CPU）参考实现校验单个密码。
//
// 它与 GPU 内核共用 cuda.cu 中的同一套算法代码，用于一致性自检与调试，
// 不会访问 GPU。
func Check(t Target, password string) (bool, error) {
	if !compiled() {
		return false, ErrNotCompiled
	}
	if err := t.Validate(); err != nil {
		return false, err
	}
	if len(password) > MaxPasswordLen {
		return false, ErrPasswordTooLong
	}
	rc, err := checkNative(t.Algo, password, t.Salt, t.Rounds, t.Key)
	if err != nil {
		return false, err
	}
	return rc == 1, nil
}

// VerifyHash 在指定设备上批量校验通用哈希目标，返回首个命中的候选下标（无命中为 -1）。
//
// 与 Verify 相同，一批候选共享同一个目标；并发安全，每次调用独立申请显存。
// RAR3-hp / 7z 的候选密码会先按 UTF-16LE 编码再下发，返回的下标仍对应
// 原始 passwords 切片。
func VerifyHash(t HashTarget, passwords []string, device int) (int, error) {
	if !compiled() {
		return -1, ErrNotCompiled
	}
	if err := t.Validate(); err != nil {
		return -1, err
	}
	if len(passwords) == 0 {
		return -1, nil
	}
	if len(passwords) > MaxBatch {
		return -1, ErrParam
	}
	if device < 0 {
		return -1, ErrParam
	}

	if t.Algo == HashRAR3HP || t.Algo == Hash7z {
		cvt := make([]string, len(passwords))
		for i, pw := range passwords {
			if !HashPasswordFits(t.Algo, pw) {
				return -1, ErrPasswordTooLong
			}
			cvt[i] = string(utf16le(pw))
		}
		passwords = cvt
	}

	data, offs, lens, err := flatten(passwords)
	if err != nil {
		return -1, err
	}
	return verifyHashNative(t.Algo, data, offs, lens, t.Salt, t.Data, t.Check, t.IV, t.Iter, t.KeyLen, device)
}

// CheckHash 使用主机端（CPU）参考实现校验单个密码。
//
// 它与 GPU 内核共用 cuda.cu 中的同一套算法代码，用于一致性自检与调试，
// 不会访问 GPU。RAR3-hp / 7z 的密码按 UTF-16LE 编码后传入。
func CheckHash(t HashTarget, password string) (bool, error) {
	if !compiled() {
		return false, ErrNotCompiled
	}
	if err := t.Validate(); err != nil {
		return false, err
	}
	if !HashPasswordFits(t.Algo, password) {
		return false, ErrPasswordTooLong
	}
	if t.Algo == HashRAR3HP || t.Algo == Hash7z {
		password = string(utf16le(password))
	}
	rc, err := checkHashNative(t.Algo, password, t.Salt, t.Data, t.Check, t.IV, t.Iter, t.KeyLen)
	if err != nil {
		return false, err
	}
	return rc == 1, nil
}

// errFromCode 把 cuda.h 的返回码翻译成公共错误。
func errFromCode(code int) error {
	switch code {
	case codeOK:
		return nil
	case codeParam:
		return ErrParam
	case codeNoDevice:
		return ErrNoDevice
	case codeAlgorithm:
		return ErrUnsupported
	case codeAlloc, codeKernel:
		return fmt.Errorf("%w: code %d", ErrRuntime, code)
	default:
		return fmt.Errorf("%w: unknown code %d", ErrRuntime, code)
	}
}
