// Package pwdhash 提供离线校验密码哈希的统一入口，屏蔽底层算法差异。
//
// 支持 shadow 文件中常见的哈希格式：
//   - $1$  md5crypt
//   - $5$ / $6$  sha256crypt / sha512crypt（含 rounds 参数）
//   - $2a$ / $2b$ / $2y$  bcrypt
//   - $y$  yescrypt（现代发行版默认）
//   - $argon2i/id$、$pbkdf2-*、$scrypt$ 等
package pwdhash

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-crypt/crypt"
	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/algorithm/argon2"
	"github.com/go-crypt/crypt/algorithm/bcrypt"
	"github.com/go-crypt/crypt/algorithm/md5crypt"
	"github.com/go-crypt/crypt/algorithm/pbkdf2"
	"github.com/go-crypt/crypt/algorithm/scrypt"
	"github.com/go-crypt/crypt/algorithm/sha1crypt"
	"github.com/go-crypt/crypt/algorithm/shacrypt"
	"github.com/go-crypt/x/yescrypt"

	"gyhost/internal/i18n"
)

// Checker 校验一个已知的密码哈希。
//
// 实现必须是并发安全的（只读），以便多个爆破协程共享调用逻辑。
type Checker interface {
	// Check 判断明文密码是否匹配该哈希。
	Check(password string) bool
	// Algo 返回哈希算法标识，例如 "6"、"bcrypt"、"yescrypt"。
	Algo() string
}

// NewChecker 解析一个编码后的密码哈希并返回其校验器。
func NewChecker(encodedHash string) (Checker, error) {
	h := strings.TrimSpace(encodedHash)
	if h == "" {
		return nil, errors.New(i18n.T("pwdhash.err.empty"))
	}

	// yescrypt 由 go-crypt/x 单独提供（按 setting 重新计算并整体比较）。
	if strings.HasPrefix(h, "$y$") || strings.HasPrefix(h, "$7$") {
		return &yescryptChecker{encoded: h}, nil
	}

	digest, err := newDecoder().Decode(h)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.Tf("pwdhash.err.unsupported", AlgoOf(h)), err)
	}
	return &digestChecker{digest: digest, algo: AlgoOf(h)}, nil
}

// AlgoOf 从编码哈希中提取算法标识，例如 "$6$rounds=5000$salt$key" -> "6"。
func AlgoOf(encodedHash string) string {
	h := strings.TrimSpace(encodedHash)
	if !strings.HasPrefix(h, "$") {
		return "unknown"
	}
	rest := h[1:]
	if i := strings.IndexByte(rest, '$'); i >= 0 {
		rest = rest[:i]
	}
	// 去掉 rounds 等参数，仅保留算法名
	if i := strings.IndexAny(rest, "="); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "unknown"
	}
	return rest
}

var defaultDecoder = func() *crypt.Decoder {
	// 显式注册需要的算法，避免依赖库默认集合随版本变化。
	d := crypt.NewDecoder()
	for _, reg := range []func(algorithm.DecoderRegister) error{
		md5crypt.RegisterDecoder,
		sha1crypt.RegisterDecoder,
		shacrypt.RegisterDecoder,
		bcrypt.RegisterDecoder,
		argon2.RegisterDecoder,
		pbkdf2.RegisterDecoder,
		scrypt.RegisterDecoder,
	} {
		if err := reg(d); err != nil {
			panic(fmt.Sprintf("%s: %v", i18n.T("pwdhash.err.register"), err))
		}
	}
	return d
}()

func newDecoder() *crypt.Decoder { return defaultDecoder }

type digestChecker struct {
	digest algorithm.Digest
	algo   string
}

func (c *digestChecker) Check(password string) bool {
	match, err := c.digest.MatchAdvanced(password)
	return err == nil && match
}

func (c *digestChecker) Algo() string { return c.algo }

type yescryptChecker struct {
	encoded string
}

func (c *yescryptChecker) Check(password string) bool {
	out, err := yescrypt.Hash([]byte(password), []byte(c.encoded))
	if err != nil {
		return false
	}
	return string(out) == c.encoded
}

func (c *yescryptChecker) Algo() string {
	if strings.HasPrefix(c.encoded, "$7$") {
		return "scrypt-crypt"
	}
	return "yescrypt"
}
