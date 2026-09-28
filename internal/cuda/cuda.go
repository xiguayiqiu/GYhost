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
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
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
	// HashPDF 加密 PDF 的口令校验（hashcat -m 10400/10500/10600/10700）。
	// 用户口令与所有者口令都会尝试（hashcat 只校验用户口令），命中任意一个即可。
	// 字段布局随 V 分两套（与 cuda.cu 的 gy_generic_hash_check 注释一一对应）：
	//
	//	V<=4（MD5 + RC4 标准安全处理器）：
	//	  Salt   = trailer /ID 的第一个元素（16 字节）
	//	  Data   = /O（32 字节）
	//	  Check  = /U（32 字节）
	//	  Iter   = R（2..4）
	//	  KeyLen = 加密密钥字节数（V=1 为 5，V=2/3/4 通常 16）
	//	  IV     = P 的 4 字节小端 || flags（bit0 = /EncryptMetadata）|| 保留 3 字节
	//
	//	V=5（AES-256，ISO 32000-2）：
	//	  Salt   = 用户校验盐 /U[32:40]（8 字节）|| 所有者校验盐 /O[32:40]（8 字节）
	//	  Data   = /U（48 字节）
	//	  Check  = /O（48 字节）
	//	  Iter   = R（5 或 6）
	HashPDF = 150
	// HashOffice 加密 Office 文档的口令校验（hashcat -m 9400/9500/9600，
	// 哈希行 $office$*2007/2010/2013）。候选口令按 UTF-16LE 编码下发，
	// 最多 127 个码元（254 字节），更长的由 CPU 校验。字段布局：
	//
	//	  Salt   = 盐（16 字节；2010/2013 兼作 AES-CBC 的 IV）
	//	  Data   = LE32(年份 2007/2010/2013) || LE32(verifierHashSize，仅 2007 用，
	//	           2010/2013 置 0) || 加密校验值（16 字节），共 24 字节
	//	  Check  = 加密校验哈希（2007 ≥16 字节；2010/2013 需 32 字节）
	//	  Iter   = KDF 轮数（2007 恒为 50000，即 [MS-OFFCRYPTO] 2.3.4 的定值）
	//	  KeyLen = AES 密钥字节数（16/24/32，来自哈希的密钥位数）
	//
	// 2007 是 SHA-1 KDF + AES-ECB，2010/2013 是 SHA-1/SHA-512 KDF + AES-CBC。
	HashOffice = 160
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

// asyncAlive 持有最近一批异步提交的候选缓冲，VerifyHashEnd 时删除。
// 现在 native 会先把数据拷进页锁定缓冲才返回，正常情况下不依赖它；
// 保留是为了避免将来改回「直接引用 Go 内存」时埋下悬垂引用的坑。
// 键为 device*16+槽位句柄。
var (
	asyncAliveMu sync.Mutex
	asyncAlive   = map[int][]byte{}
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
	// MaxCipherDataLen 需要整段下发的密文类算法（WinZip AES -m 13600、7z AES）的上限。
	// 它们的认证码/CRC 覆盖整段密文，内核必须把密文完整解密一遍；384 字节的通用上限
	// 会让几乎所有真实条目都静默退回 CPU。ZipCrypto 只用 12 字节加密头，不受此限制。
	// 仍超出的条目回退 CPU。必须与 C 侧 GYHOST_HASH_MAX_CIPHER_DATA 一致。
	MaxCipherDataLen = 1 << 20
	// MaxEAPOLDataLen WPA2 四次握手（-m 22000 的 WPA*02*）Data 的上限：
	// Data = MAC 块(12) + ANonce(32) + EAPOL 帧。内核对整帧做 HMAC/MIC，
	// 帧本身要完整下发；真实抓包的 M2/M4 常见 100~1500 字节（M4 带厂商 IE 时更大），
	// 所以同样不能套 384 字节的通用上限。必须与 C 侧 GYHOST_HASH_MAX_EAPOL_DATA 一致。
	MaxEAPOLDataLen = 1 << 16
	// MaxHashIter 允许的最大 KDF 迭代轮数（power 形式的上限见各算法）。
	MaxHashIter = 1 << 24
	// officeEncHashLen Office 2010/2013 必须下发的加密校验哈希字节数：
	// 两个 AES 分组，比对时只用前 officeCompareLen(20) 字节，但少了第二组
	// 就拿不到摘要的第 17~20 字节。
	officeEncHashLen = 32
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
		// Data 是整段密文（认证码覆盖它）：不能为空——空密文的条目（比如加密的空文件）
		// 只剩 2 字节口令校验值可判，parseZIPAES 会选择不挂 GPU 目标
		if len(t.Check) != 12 || len(t.Data) == 0 || len(t.Data) > MaxCipherDataLen {
			return ErrParam
		}
	case HashWPA2PMKID:
		if len(t.Check) != 16 || len(t.Data) != 20 {
			return ErrParam
		}
	case HashZipCrypto:
		// Data 只放 12 字节加密头（内核的弱校验只需要它）
		if len(t.Check) != 4 || len(t.Data) < 12 {
			return ErrParam
		}
		if t.Iter != 1 && t.Iter != 2 {
			return ErrParam
		}
	case HashWPA2EAPOL:
		// Data = MAC块(12) + ANonce(32) + EAPOL 帧，帧长至少到 MIC 结束（97）。
		// 真实抓包里 M2/M4 常带大量 IE/厂商字段，帧长轻松上千字节，
		// 所以这里用专门的上限（见 MaxEAPOLDataLen），不能套 384 字节的通用上限。
		if len(t.Check) != 16 || len(t.Data) < 44+97 || len(t.Data) > MaxEAPOLDataLen {
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
		// 内核要整段解密，Data 允许很大（与 WinZip AES 同理单独放宽上限）
		if len(t.Data) == 0 || len(t.Data) > MaxCipherDataLen || len(t.Data)%16 != 0 {
			return ErrParam
		}
		if t.KeyLen <= 0 || t.KeyLen > len(t.Data) {
			return ErrParam
		}
	case HashPDF:
		// V<=4 与 V=5 两套字段布局，Iter（R）决定用哪套，见 HashPDF 注释。
		if t.Iter >= 5 {
			if (t.Iter != 5 && t.Iter != 6) || len(t.Salt) != 16 ||
				len(t.Data) != 48 || len(t.Check) != 48 {
				return ErrParam
			}
			break
		}
		if len(t.Salt) != 16 || len(t.Data) != 32 || len(t.Check) != 32 {
			return ErrParam
		}
		if t.Iter < 2 || t.Iter > 4 {
			return ErrParam
		}
		if t.KeyLen != 5 && t.KeyLen != 16 {
			return ErrParam
		}
		if len(t.IV) != 8 { // P(4) || flags(1) || 保留(3)
			return ErrParam
		}
	case HashOffice:
		// 字段布局见 HashOffice 注释；年份决定用哪套算法，无法支持的年份直接拒绝。
		if len(t.Salt) != 16 || len(t.Data) != 24 || t.Iter < 0 || t.Iter > MaxHashIter {
			return ErrParam
		}
		if t.KeyLen != 16 && t.KeyLen != 24 && t.KeyLen != 32 {
			return ErrParam
		}
		year := int(binary.LittleEndian.Uint32(t.Data[0:4]))
		switch year {
		case 2007:
			// field2 = verifierHashSize，决定 DeriveKey 要不要第二段 0x5C 填充
			if hashLen := int(binary.LittleEndian.Uint32(t.Data[4:8])); hashLen <= 0 || hashLen > 64 {
				return ErrParam
			}
			if len(t.Check) < 16 {
				return ErrParam
			}
		case 2010, 2013:
			// agile：要解两个 AES 分组才能比对摘要前 20 字节
			if len(t.Check) < officeEncHashLen {
				return ErrParam
			}
		default:
			return ErrParam
		}
	default:
		return ErrUnsupported
	}
	if len(t.Salt) > MaxHashSaltLen || len(t.Check) > MaxHashCheckLen {
		return ErrParam
	}
	// 超过通用上限的只有"必须整段下发"的算法：WinZip AES / 7z 的密文、WPA2 的 EAPOL 帧
	if len(t.Data) > MaxHashDataLen {
		switch t.Algo {
		case HashZIPAES, Hash7z:
			if len(t.Data) > MaxCipherDataLen {
				return ErrParam
			}
		case HashWPA2EAPOL:
			if len(t.Data) > MaxEAPOLDataLen {
				return ErrParam
			}
		default:
			return ErrParam
		}
	}
	return nil
}

// SupportedHash 判断该通用哈希算法编号是否支持 GPU 校验。
func SupportedHash(algo int) bool {
	switch algo {
	case HashRawMD5, HashRawSHA1, HashRawSHA256, HashRawSHA512,
		HashZIPAES, HashZipCrypto, HashWPA2PMKID, HashWPA2EAPOL,
		HashRAR5, HashRAR3HP, Hash7z, HashPDF, HashOffice:
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

// utf16Encoded 报告该算法的候选口令是否要按 UTF-16LE 编码再下发
// （内核拿到的就是编码后的字节流，pw_len 为编码后的字节数）。
func utf16Encoded(algo int) bool {
	switch algo {
	case HashRAR3HP, Hash7z, HashOffice:
		return true
	}
	return false
}

// HashPasswordFits 判断候选密码能否交给 GPU 按该算法校验。
//
// 通用上限是 len(pw) <= MaxPasswordLen；RAR3-hp 额外要求不超过 64 个
// UTF-16 码元、7z 与 Office 不超过 127 个（native 侧缓冲区大小约束，
// 编码后 254 字节，仍小于 GY_MAX_PW=255）。
// 不满足的候选由调用方回退 CPU 校验。
func HashPasswordFits(algo int, pw string) bool {
	if len(pw) > MaxPasswordLen {
		return false
	}
	switch algo {
	case HashRAR3HP:
		return utf16Units(pw) <= 64
	case Hash7z, HashOffice:
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
// RAR3-hp / 7z / Office 的候选密码会先按 UTF-16LE 编码再下发，返回的下标仍对应
// 原始 passwords 切片。
//
// 需要让 GPU 与主机并行（喂下一批时上一批还在跑）请用 VerifyHashAsync +
// VerifyHashEnd 这对异步接口。
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
	data, offs, lens, err := prepare(t, passwords)
	if err != nil {
		return -1, err
	}
	return verifyHashNative(t.Algo, data, offs, lens, t.Salt, t.Data, t.Check, t.IV, t.Iter, t.KeyLen, device)
}

/*
 * VerifyHashAsync / VerifyHashEnd — 异步流水线接口。
 *
 * VerifyHashAsync 把候选拍平、上传并发射内核后立即返回槽位句柄；
 * VerifyHashEnd 等该批内核结束并读回首个命中下标（无命中为 -1）。
 * 两次调用之间主机可以做下一批的准备工作，GPU 不必空等。
 *
 * 注意：异步路径不做「命中即停」的分块提前结束——整批候选都会算完
 * （命中最小子标由设备端 atomicMin 保证正确）。对命中率极低的爆破场景
 * 这点浪费可以忽略，换来的是主机与设备的并行。
 */
func VerifyHashAsync(t HashTarget, passwords []string, device int) (int, error) {
	if !compiled() {
		return -1, ErrNotCompiled
	}
	if err := t.Validate(); err != nil {
		return -1, err
	}
	if len(passwords) == 0 {
		return -1, ErrParam
	}
	if len(passwords) > MaxBatch {
		return -1, ErrParam
	}
	if device < 0 {
		return -1, ErrParam
	}
	data, offs, lens, err := prepare(t, passwords)
	if err != nil {
		return -1, err
	}
	h, err := verifyHashBeginNative(t.Algo, data, offs, lens, t.Salt, t.Data, t.Check, t.IV, t.Iter, t.KeyLen, device)
	if err != nil {
		return -1, err
	}
	// native 侧已把候选拷进页锁定缓冲，这里保留引用只是兜底：
	// 一旦将来改成直接引用 Go 内存，VerifyHashEnd 之前都不能让底层数组被回收。
	asyncAliveMu.Lock()
	asyncAlive[device*16+h] = data
	asyncAliveMu.Unlock()
	return h, nil
}

// VerifyHashEnd 取回 VerifyHashAsync 提交的那批的结果。
func VerifyHashEnd(handle, device int) (int, error) {
	if !compiled() {
		return -1, ErrNotCompiled
	}
	if handle < 0 || device < 0 {
		return -1, ErrParam
	}
	idx, err := verifyHashEndNative(handle, device)
	asyncAliveMu.Lock()
	delete(asyncAlive, device*16+handle)
	asyncAliveMu.Unlock()
	return idx, err
}

/*
 * crypt 目标（shadow 模块）的异步流水线接口。
 *
 * VerifyAsync 把候选拍平、上传并发射内核后立即返回批次句柄；
 * VerifyEnd 等该批完成并读回首个命中下标（无命中为 -1）。
 * 两次调用之间主机可以做下一批的准备工作，GPU 不必空等——这是让
 * --gpu 跑满（而不是一批一等）的关键。
 */
func VerifyAsync(t Target, passwords []string, device int) (int, error) {
	if !compiled() {
		return -1, ErrNotCompiled
	}
	if err := t.Validate(); err != nil {
		return -1, err
	}
	if len(passwords) == 0 {
		return -1, ErrParam
	}
	if len(passwords) > MaxBatch {
		return -1, ErrParam
	}
	if device < 0 {
		return -1, ErrParam
	}
	data, offs, lens, err := flatten(passwords)
	if err != nil {
		return -1, err
	}
	h, err := verifyBeginNative(t.Algo, data, offs, lens, t.Salt, t.Rounds, t.Key, device)
	if err != nil {
		return -1, err
	}
	// 同 VerifyHashAsync：native 侧已拷进页锁定缓冲，这里只是兜底持有引用。
	asyncAliveMu.Lock()
	asyncAlive[device*16+h] = data
	asyncAliveMu.Unlock()
	return h, nil
}

// VerifyEnd 取回 VerifyAsync 提交的那批的结果。
func VerifyEnd(handle, device int) (int, error) {
	if !compiled() {
		return -1, ErrNotCompiled
	}
	if handle < 0 || device < 0 {
		return -1, ErrParam
	}
	idx, err := verifyEndNative(handle, device)
	asyncAliveMu.Lock()
	delete(asyncAlive, device*16+handle)
	asyncAliveMu.Unlock()
	return idx, err
}

// PipelineSlots 返回异步流水线可同时在飞的批次数上限。
//
// 调用方应据此确定 in-flight 批次的环大小：需要同时在飞的批次超过这个数时，
// 提交会在 native 的 begin 里阻塞等最老的槽位完成，这段时间主机既不能准备
// 下一批、GPU 也没有新内核可跑，利用率会明显下降。
func PipelineSlots() int {
	if !compiled() {
		return 0
	}
	return pipelineSlotsNative()
}

/*
 * prepare 拍平候选并按算法做 UTF-16LE 编码（RAR3-hp / 7z / Office）。
 * 超长候选在这里就被拒绝，不进入拍平循环。
 */
func prepare(t HashTarget, passwords []string) (data []byte, offs, lens []int32, err error) {
	if utf16Encoded(t.Algo) {
		cvt := make([]string, len(passwords))
		for i, pw := range passwords {
			if !HashPasswordFits(t.Algo, pw) {
				return nil, nil, nil, ErrPasswordTooLong
			}
			cvt[i] = string(utf16le(pw))
		}
		passwords = cvt
	}
	return flatten(passwords)
}

// CheckHash 使用主机端（CPU）参考实现校验单个密码。
//
// 它与 GPU 内核共用 cuda.cu 中的同一套算法代码，用于一致性自检与调试，
// 不会访问 GPU。RAR3-hp / 7z / Office 的密码按 UTF-16LE 编码后传入。
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
	if utf16Encoded(t.Algo) {
		password = string(utf16le(password))
	}
	rc, err := checkHashNative(t.Algo, password, t.Salt, t.Data, t.Check, t.IV, t.Iter, t.KeyLen)
	if err != nil {
		return false, err
	}
	return rc == 1, nil
}

/*
 * GPU 唤醒（预热）。
 *
 * 消费级显卡空载时会自动降频休眠（实测 RTX 3050 Laptop 空载 P8 / 210MHz，
 * 满载 P0 / 约 2000MHz）。NVIDIA 驱动只对「持续」的负载提频：如果破解时
 * 内核之间有几十微秒以上的空档（主机准备下一批、读回结果），核心频率会一直
 * 停在低档甚至中途回落，表现就是「越跑越慢、速度远低于 hashcat」。
 *
 * 这里的做法是开跑前用真实目标连续打满 WarmUpDuration，让驱动把频率拉到
 * 最高；同时顺带完成内核的首次加载/JIT，正式爆破的第一批不会再额外卡顿。
 */

// WarmUpDuration 预热 GPU 的默认时长。
const WarmUpDuration = 400 * time.Millisecond

// warmUpCandidates 每次预热批次的候选数（够大才能吃满 GPU）。
const warmUpCandidates = 1 << 16

// warmUpBatch 生成预热用候选（内容无意义，只要长度合法、数量足够）。
func warmUpBatch(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "warmup" + strconv.Itoa(i)
	}
	return out
}

// WarmUp 在开始爆破前让设备连续满载一小段时间，把它从低功耗状态唤醒。
//
// 参数 t 是即将爆破的真实目标（预热用同一套内核，顺便触发首次加载）；
// device 为设备编号；d 为预热时长（<= 0 表示不预热）。
// 返回错误时调用方应把它当成「GPU 不可用」，回退 CPU 爆破。
func WarmUp(t Target, device int, d time.Duration) error {
	if !compiled() {
		return ErrNotCompiled
	}
	if err := t.Validate(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	batch := warmUpBatch(warmUpCandidates)
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if _, err := Verify(t, batch, device); err != nil {
			return err
		}
	}
	return nil
}

// WarmUpHash 与 WarmUp 相同，用于通用哈希目标（hashac 模块）。
//
// 预热候选会按目标算法的长度上限过滤（RAR3-hp / 7z / Office 按 UTF-16
// 码元算），过滤后为空时返回 ErrPasswordTooLong。
func WarmUpHash(t HashTarget, device int, d time.Duration) error {
	if !compiled() {
		return ErrNotCompiled
	}
	if err := t.Validate(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	batch := warmUpBatch(warmUpCandidates)
	fit := batch[:0]
	for _, pw := range batch {
		if HashPasswordFits(t.Algo, pw) {
			fit = append(fit, pw)
		}
	}
	if len(fit) == 0 {
		return ErrPasswordTooLong
	}
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if _, err := VerifyHash(t, fit, device); err != nil {
			return err
		}
	}
	return nil
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
