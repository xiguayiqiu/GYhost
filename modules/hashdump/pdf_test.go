package hashdump

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gyhost/modules/hashac"
)

// pdfFixture 拼一个最小的经典 trailer 版加密 PDF（只有 /Encrypt 与 /ID），
// 用来检查畸形字段下产出的 $pdf$ 哈希行是否仍满足 hashcat 的定长格式。
//
// length<=0 表示不写 /Length；idLiteral=true 时 /ID[0] 写成八进制转义的字面量串
// （部分生产者的写法）；omitID=true 时干脆不给 /ID。/O /U 等一律用字面量串，
// 长度取 V 需要的 32（V=5 为 48）字节。
func pdfFixture(v, r, length int, p string, idLiteral, omitID bool) []byte {
	idHex := "0123456789abcdeffedcba9876543210"
	id, err := hex.DecodeString(idHex)
	if err != nil {
		panic(err)
	}
	n := 32
	if v == 5 {
		n = 48
	}
	o, u := strings.Repeat("A", n), strings.Repeat("B", n)

	enc := fmt.Sprintf("<< /Filter /Standard /V %d /R %d", v, r)
	if length > 0 {
		enc += fmt.Sprintf(" /Length %d", length)
	}
	enc += fmt.Sprintf(" /P %s /O (%s) /U (%s)", p, o, u)
	if v == 5 {
		enc += fmt.Sprintf(" /OE (%s) /UE (%s)", strings.Repeat("C", 32), strings.Repeat("D", 32))
	}
	enc += " >>"

	trailer := "trailer\n<< /Size 2 /Root 1 0 R /Encrypt 1 0 R"
	switch {
	case omitID:
	case idLiteral:
		// 同样 16 字节，但写成八进制转义的字面量串
		trailer += " /ID [" + pdfLiteral(id) + " " + pdfLiteral(id) + "]"
	default:
		trailer += " /ID [<" + idHex + "><" + idHex + ">]"
	}
	trailer += " >>\n%%EOF\n"

	return []byte(fmt.Sprintf("%%PDF-1.7\n1 0 obj\n%s\nendobj\n%s", enc, trailer))
}

// pdfLiteral 把字节渲染成 PDF 字面量串（全部用八进制转义，避免歧义）。
func pdfLiteral(b []byte) string {
	var sb strings.Builder
	sb.WriteByte('(')
	for _, c := range b {
		fmt.Fprintf(&sb, `\%03o`, c)
	}
	sb.WriteByte(')')
	return sb.String()
}

// wantLine 按 pdfFixture 的字段拼出期望的哈希行。
func wantLine(v, r, length, p int, v5 bool) string {
	n := 32
	if v5 {
		n = 48
	}
	line := fmt.Sprintf("$pdf$%d*%d*%d*%d*1*16*%s*%d*%s*%d*%s",
		v, r, length, p, "0123456789abcdeffedcba9876543210",
		n, hex.EncodeToString([]byte(strings.Repeat("B", n))),
		n, hex.EncodeToString([]byte(strings.Repeat("A", n))))
	if v5 {
		line += fmt.Sprintf("*32*%s*32*%s",
			hex.EncodeToString([]byte(strings.Repeat("D", 32))),
			hex.EncodeToString([]byte(strings.Repeat("C", 32))))
	}
	return line
}

// extractOne 把样本落盘后提取，断言恰好一条哈希并返回它。
func extractOne(t *testing.T, data []byte) Entry {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.pdf")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("写样本失败: %v", err)
	}
	res, err := Extract(path)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("entries = %d（期望 1），skipped = %+v", len(res.Entries), res.Skipped)
	}
	return res.Entries[0]
}

// TestPDFHashLine 覆盖畸形字段：/Length 缺失要按 V 补默认值（否则 hashcat 报
// Token length exception）、/P 写成无符号要折回有符号（否则本仓库自己都解析不了）。
func TestPDFHashLine(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		mode int
		want string
	}{
		{"V=2 缺 /Length 补 128", pdfFixture(2, 3, 0, "-4", false, false), 10500,
			wantLine(2, 3, 128, -4, false)},
		{"V=1 缺 /Length 补 40", pdfFixture(1, 2, 0, "-4", false, false), 10400,
			wantLine(1, 2, 40, -4, false)},
		{"V=5 缺 /Length 补 256", pdfFixture(5, 6, 0, "-4", false, false), 10700,
			wantLine(5, 6, 256, -4, true)},
		{"/P 无符号折回 -4", pdfFixture(2, 3, 128, "4294967292", false, false), 10500,
			wantLine(2, 3, 128, -4, false)},
		{"/Length 越界回落默认值", pdfFixture(2, 3, 999, "-4", false, false), 10500,
			wantLine(2, 3, 128, -4, false)},
		{"/Length 正常取值保留", pdfFixture(2, 3, 128, "-4", false, false), 10500,
			wantLine(2, 3, 128, -4, false)},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := extractOne(t, c.data)
			if e.Hash != c.want {
				t.Errorf("哈希行 =\n  %s\n期望 =\n  %s", e.Hash, c.want)
			}
			if e.Mode != c.mode {
				t.Errorf("Mode = %d, 期望 %d", e.Mode, c.mode)
			}
			// hashdump 的产物必须能被本仓库的 hashac 解析（否则"dump 出来却认不出"）
			target, err := hashac.Parse(e.Hash, 0)
			if err != nil {
				t.Fatalf("hashac 解析不了 hashdump 的产物: %v", err)
			}
			if target.Mode != e.Mode {
				t.Errorf("hashac 模式 = %d, hashdump = %d", target.Mode, e.Mode)
			}
			// 10700（R=6）故意不挂 GPU 目标：它的 GPU 内核比不过多线程 CPU
			if wantGPU := e.Mode != 10700; (target.GPU != nil) != wantGPU {
				t.Errorf("GPU 目标 = %v，期望 %v（-m %d）", target.GPU != nil, wantGPU, e.Mode)
			}
			if target.GPU != nil {
				if err := target.GPU.Validate(); err != nil {
					t.Errorf("GPU 目标非法: %v", err)
				}
			}
		})
	}
}

// TestPDFLiteralID 校验 /ID[0] 写成字面量串时与十六进制写法结果一致。
func TestPDFLiteralID(t *testing.T) {
	want := extractOne(t, pdfFixture(2, 3, 128, "-4", false, false)).Hash
	got := extractOne(t, pdfFixture(2, 3, 128, "-4", true, false)).Hash
	if got != want {
		t.Errorf("字面量 /ID 结果不一致:\n  %s\n  %s", got, want)
	}
}

// TestPDFNoID 有 /Encrypt 但没有 /ID 时应明确说明原因，且不产出哈希。
func TestPDFNoID(t *testing.T) {
	data := pdfFixture(2, 3, 128, "-4", false, true)
	path := filepath.Join(t.TempDir(), "noid.pdf")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("写样本失败: %v", err)
	}
	res, err := Extract(path)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(res.Entries) != 0 {
		t.Errorf("entries = %d, 期望 0", len(res.Entries))
	}
	if len(res.Skipped) != 1 || strings.TrimSpace(res.Skipped[0].Reason) == "" {
		t.Fatalf("应给出跳过原因，实际 skipped = %+v", res.Skipped)
	}
}
