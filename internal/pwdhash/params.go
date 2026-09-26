package pwdhash

import (
	"strconv"
	"strings"
)

// sha-crypt 省略 rounds 参数时的缺省轮数，与 go-crypt 的
// shacrypt.IterationsDefaultOmitted 保持一致。
const defaultSHACryptRounds = 5000

// md5crypt 的固定轮数（算法规定，与 go-crypt 的 KeyMD5Crypt 一致）。
const md5cryptRounds = 1000

// CryptParams 是 $1$ / $5$ / $6$ 编码哈希解析出的可重算参数，
// 供 GPU（internal/cuda）以及其它需要“重算并比对”的场景复用。
type CryptParams struct {
	Algo   string // 算法标识："1" / "5" / "6"
	Salt   string // 盐
	Rounds int    // 迭代轮数：md5crypt 恒为 1000，sha-crypt 省略时为 5000
	Key    string // 目标密文（crypt base64）
}

// ParseCrypt 解析 md5crypt / sha256crypt / sha512crypt 的编码哈希。
// 格式不支持或参数非法时返回 ok=false。
//
// 解析口径必须与 NewChecker（go-crypt 解码）完全一致，
// 否则 GPU 与 CPU 会对同一个哈希给出不同结论：
//   - 结构按段数判定：4 段 = $A$salt$key，5 段 = $A$params$salt$key
//   - 轮数不做 POSIX 钳制，原样使用（go-crypt 亦不钳制）
//   - 密文为空直接拒绝（go-crypt 同样拒绝）
//
// 实际使用时应先用 NewChecker 确认哈希可解码，再调用本函数。
func ParseCrypt(encodedHash string) (p CryptParams, ok bool) {
	h := strings.TrimSpace(encodedHash)
	if !strings.HasPrefix(h, "$") {
		return CryptParams{}, false
	}

	parts := strings.Split(h, "$") // ["", 算法, ...]
	if len(parts) != 4 && len(parts) != 5 {
		return CryptParams{}, false
	}

	algo := parts[1]
	if algo != "1" && algo != "5" && algo != "6" {
		return CryptParams{}, false
	}

	idx := 2
	rounds := 0

	if len(parts) == 5 {
		// $A$params$salt$key：params 只允许 rounds=N
		if !strings.HasPrefix(parts[idx], "rounds=") {
			return CryptParams{}, false
		}
		n, err := strconv.ParseUint(strings.TrimPrefix(parts[idx], "rounds="), 10, 32)
		if err != nil {
			return CryptParams{}, false
		}
		rounds = int(n)
		idx++
	} else if algo == "5" || algo == "6" {
		rounds = defaultSHACryptRounds
	} else {
		rounds = md5cryptRounds
	}

	salt, key := parts[idx], parts[idx+1]
	if key == "" {
		return CryptParams{}, false
	}

	return CryptParams{Algo: algo, Salt: salt, Rounds: rounds, Key: key}, true
}
