package mask

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCountLines 校验行数统计的口径。
//
// 口径必须与 FileSource.Each 逐行枚举一致：末尾没有换行符的最后一段也算一行，
// 空行也算一行。
func TestCountLines(t *testing.T) {
	cases := []struct {
		name string
		data string
		want int64
	}{
		{"空文件", "", 0},
		{"单行无换行", "abc", 1},
		{"单行有换行", "abc\n", 1},
		{"多行", "a\nb\nc\n", 3},
		{"多行末行无换行", "a\nb\nc", 3},
		{"空行也算一行", "a\n\nb\n", 3},
		{"只有空行", "\n\n", 2},
		{"CRLF 行尾", "a\r\nb\r\n", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wordlist")
			if err := os.WriteFile(path, []byte(c.data), 0o600); err != nil {
				t.Fatalf("写入测试文件: %v", err)
			}
			got, err := CountLines(path)
			if err != nil {
				t.Fatalf("CountLines: %v", err)
			}
			if got != c.want {
				t.Errorf("CountLines = %d，期望 %d", got, c.want)
			}
		})
	}
}

// TestCountLinesMatchesEach 确认统计出的行数与实际枚举出的候选数一致。
func TestCountLinesMatchesEach(t *testing.T) {
	data := "alpha\nbravo\ncharlie\ndelta\necho"
	path := filepath.Join(t.TempDir(), "wordlist")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("写入测试文件: %v", err)
	}
	n, err := CountLines(path)
	if err != nil {
		t.Fatalf("CountLines: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("打开测试文件: %v", err)
	}
	defer f.Close()

	var got int64
	NewFileSource(f).Each(func(string) bool {
		got++
		return true
	})
	if n != got {
		t.Errorf("CountLines = %d，实际枚举 %d 个候选", n, got)
	}
}

// TestCountLinesMissingFile 确认文件不存在时返回错误而不是静默返回 0。
func TestCountLinesMissingFile(t *testing.T) {
	if _, err := CountLines(filepath.Join(t.TempDir(), "不存在")); err == nil {
		t.Error("文件不存在时应当返回错误")
	}
}
