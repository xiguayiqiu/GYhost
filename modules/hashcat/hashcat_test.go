package hashcat

import (
	"reflect"
	"testing"
)

// TestIdentifyHash 覆盖几种代表性前缀，重点是 yescrypt（$y$）必须给出
// hashcat v8.0.0 的原生模式 36100，而不是像旧版那样只返回算法名。
func TestIdentifyHash(t *testing.T) {
	cases := []struct {
		hash  string
		algo  string
		modes []int
	}{
		{"$1$ehAsHC4t$4IbK3fHS/H1YGtNYBrIEB1", "md5crypt", []int{500}},
		{"$6$qdMgClgO2dQWB37F$jhexCX1SdsCAi0OZmoRVAPnWSwuP/mHVhXIMJfKlaacxFkwWLDZ0ViF8Ur3Wc", "sha512crypt", []int{1800}},
		{"$2b$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6", "bcrypt", []int{3200}},
		{"$y$j9T$fqIAg4Vpv9o1MKgWMnyax.$BxkUx27fLJlPOfyIfNEBPzjrDQ95LXKgN5OJii3GL7.", "yescrypt", []int{36100}},
		{"8743b52063cd84097a65d1633f5c74f5", "md5-ntlm", []int{0, 1000}},
	}
	for _, c := range cases {
		algo, modes, ok := identifyHash(c.hash)
		if !ok {
			t.Errorf("identifyHash(%q) 未识别", c.hash)
			continue
		}
		if algo != c.algo || !reflect.DeepEqual(modes, c.modes) {
			t.Errorf("identifyHash(%q) = %q %v，期望 %q %v",
				c.hash, algo, modes, c.algo, c.modes)
		}
	}
}

// TestSplitLineYescrypt 校验 shadow 的 user:hash:... 行也能取到用户名与 -m 36100。
func TestSplitLineYescrypt(t *testing.T) {
	line := "root:$y$j9T$fqIAg4Vpv9o1MKgWMnyax.$BxkUx27fLJlPOfyIfNEBPzjrDQ95LXKgN5OJii3GL7.:20000:0:99999:7:::"
	name, algo, modes, ok := splitLineHash(line)
	if !ok {
		t.Fatalf("splitLineHash(%q) 未识别", line)
	}
	if name != "root" || algo != "yescrypt" || !reflect.DeepEqual(modes, []int{36100}) {
		t.Errorf("splitLineHash(%q) = %q %q %v，期望 root yescrypt [36100]",
			line, name, algo, modes)
	}
}
