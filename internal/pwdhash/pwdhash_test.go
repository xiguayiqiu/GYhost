package pwdhash

import (
	"testing"
)

// yescrypt 测试向量：由 libxcrypt 生成（与 go-crypt/x/yescrypt 的测试用例同源）。
//
// 覆盖多组参数：N=2^10..2^14，r=8/32。
var yescryptVectors = []struct {
	password string
	hash     string
}{
	{"test1", "$y$j75$z7ztFz2FayrKI79/jEwlL.$u5x/j193MQ09wbFaRGYr0AH/A/jh3kunjuhYRVRNkmC"},
	{"test2", "$y$j85$uFLpki6/G99e8OAxVooij1$64Rji3LKk1v85LYVULHKh2YKeKoDu0ADrGt4l1JhQy8"},
	{"test3", "$y$j7T$aoovSEloTaFiZVMrFisfy.$wLTAPbITTB/XIpAGwcX0xxRCFEcDgPWpXTsij0SEbC5"},
	{"test4", "$y$j8T$P9xODwGnzlle5VHuP1/qA1$bAd4BXv1GBqNQZFzR0Ey42/w0/DFmnFkX1fRpjalAO2"},
	{"test5", "$y$j9T$fqIAg4Vpv9o1MKgWMnyax.$BxkUx27fLJlPOfyIfNEBPzjrDQ95LXKgN5OJii3GL7."},
	{"test6", "$y$jAT$70Rw91iJgO8Uzi3CLWfOo1$aYky8YP.XurVMdZfcXHY1do2RZ7Caav5iliKEkmJjhD"},
	{"test7", "$y$jBT$/YBmADVZsSMw3xfv8M76X0$14s2oH3zHEKh44d5eRVxmDvF8jgM/8SXd8mI4NBQIS1"},
}

// TestYescryptChecker 校验 $y$ 哈希的 CPU 校验器。
func TestYescryptChecker(t *testing.T) {
	for _, v := range yescryptVectors {
		c, err := NewChecker(v.hash)
		if err != nil {
			t.Fatalf("NewChecker(%q): %v", v.hash, err)
		}
		if got := c.Algo(); got != "yescrypt" {
			t.Errorf("Algo() = %q，期望 yescrypt", got)
		}
		if !c.Check(v.password) {
			t.Errorf("口令 %q 未匹配 %s", v.password, v.hash)
		}
		if c.Check(v.password + "x") {
			t.Errorf("错误口令 %q 竟然匹配了 %s", v.password+"x", v.hash)
		}
	}
}

// TestParseYescrypt 校验 $y$ 哈希的参数解析。
func TestParseYescrypt(t *testing.T) {
	cases := []struct {
		hash  string
		nlog2 int
		r     int
	}{
		{"$y$j75$z7ztFz2FayrKI79/jEwlL.$u5x/j193MQ09wbFaRGYr0AH/A/jh3kunjuhYRVRNkmC", 10, 8},
		{"$y$j85$uFLpki6/G99e8OAxVooij1$64Rji3LKk1v85LYVULHKh2YKeKoDu0ADrGt4l1JhQy8", 11, 8},
		{"$y$j9T$fqIAg4Vpv9o1MKgWMnyax.$BxkUx27fLJlPOfyIfNEBPzjrDQ95LXKgN5OJii3GL7.", 12, 32},
		{"$y$jBT$/YBmADVZsSMw3xfv8M76X0$14s2oH3zHEKh44d5eRVxmDvF8jgM/8SXd8mI4NBQIS1", 14, 32},
	}
	for _, c := range cases {
		p, ok := ParseYescrypt(c.hash)
		if !ok {
			t.Fatalf("ParseYescrypt(%q) 失败", c.hash)
		}
		if p.NLog2 != c.nlog2 {
			t.Errorf("NLog2 = %d，期望 %d", p.NLog2, c.nlog2)
		}
		if p.R != c.r {
			t.Errorf("R = %d，期望 %d", p.R, c.r)
		}
		if len(p.Key) != yescryptKeyLen {
			t.Errorf("Key 长度 = %d，期望 %d", len(p.Key), yescryptKeyLen)
		}
		if len(p.Salt) == 0 {
			t.Errorf("盐为空")
		}
	}
}

// TestParseYescryptReject 校验非法/不支持的 $y$ 哈希会被拒绝。
func TestParseYescryptReject(t *testing.T) {
	bad := []string{
		"",
		"$y$",              // 太短
		"$y$j",             // 参数段不全
		"$y$j7.$",          // 参数字符非法
		"$y$j9T$",          // 没有盐
		"$y$j9T$salt",      // 没有密文
		"$y$j9T$salt$abc",  // 密文长度不对
		"$y$k9T$salt$hash", // 参数段前缀不对
	}
	for _, h := range bad {
		if _, ok := ParseYescrypt(h); ok {
			t.Errorf("ParseYescrypt(%q) 本应失败", h)
		}
	}
}

// TestScryptCryptUnsupported 校验 $7$（scrypt-crypt）被明确报为不支持。
//
// 之前 $7$ 会被当成「支持但永远不匹配」，在报告里表现为「没破解出来」，
// 与真正的字典没覆盖完全是两回事——必须明确报不支持。
func TestScryptCryptUnsupported(t *testing.T) {
	if _, err := NewChecker("$7$C6..../....salt$hash"); err == nil {
		t.Error("NewChecker 对 $7$ 应当报错")
	}
}
