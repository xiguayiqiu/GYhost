package hashdump

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gyhost/internal/i18n"
)

// withLang 在测试期间临时切换界面语言，结束后恢复。
func withLang(t *testing.T, l i18n.Lang) {
	t.Helper()
	old := i18n.Current()
	i18n.SetLang(l)
	t.Cleanup(func() { i18n.SetLang(old) })
}

// TestExtractOffice 覆盖 Office 文档的六种加密形态与"未加密"两种情形。
//
// 金标哈希逐字节对齐 john 的 office2john（/usr/lib/john/office2john.py），
// 其中 agile 2013 与 Word97 RC4 两条已用 hashcat v7.1.2 实测破出明文。
func TestExtractOffice(t *testing.T) {
	const (
		agile2013 = "$office$*2013*100000*256*16*7c15b717e0284444532162be3948a372*9829ed02b126dec98fb9a7bc24de9b57*71feee8391620e59d16cec0387f22c1326c26b8a47445b716308ee1add276411"
		std2007   = "$office$*2007*20*128*16*e8772c1d91c56a37964761b280183217*000102030405060708090a0b0c0d0e0f*101112131415161718191a1b1c1d1e1f20212223"
		rc4Old    = "$oldoffice$1*e8772c1d91c56a37964761b280183217*0856ae961331d05f975e9eea0de77cb8*cc3f6e6d1bc575023cb361f82cced3a7"
		rc4XlsOld = "$oldoffice$0*e8772c1d91c56a37964761b280183217*0856ae961331d05f975e9eea0de77cb8*cc3f6e6d1bc575023cb361f82cced3a7"
		capiOld   = "$oldoffice$4*e8772c1d91c56a37964761b280183217*000102030405060708090a0b0c0d0e0f*101112131415161718191a1b1c1d1e1f20212223"
	)

	cases := []struct {
		file string
		hash string
		mode int
		skip string // 非空时期望得到这一条跳过原因
	}{
		{"office_agile_2013.docx", agile2013, 9600, ""},
		{"office_2007.docx", std2007, 9400, ""},
		{"word97_rc4.doc", rc4Old, 9700, ""},
		{"word97_cryptoapi.doc", capiOld, 9800, ""},
		{"excel97_rc4.xls", rc4XlsOld, 9700, ""},
		{"excel97_cryptoapi.xls", capiOld, 9800, ""},
		{"plain.doc", "", 0, "hashdump.office.skip.no_encrypt"},
		{"plain.docx", "", 0, "hashdump.office.skip.no_encrypt"},
	}

	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			res, err := Extract(filepath.Join("testdata", c.file))
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			if c.skip != "" {
				if len(res.Entries) != 0 {
					t.Fatalf("entries = %v, 期望 0", res.Entries)
				}
				if len(res.Skipped) != 1 {
					t.Fatalf("skipped = %v, 期望恰好 1 条", res.Skipped)
				}
				if want := i18n.T(c.skip); res.Skipped[0].Reason != want {
					t.Errorf("reason = %q, 期望 %q", res.Skipped[0].Reason, want)
				}
				return
			}
			if len(res.Entries) != 1 {
				t.Fatalf("entries = %d, 期望 1（skips=%v）", len(res.Entries), res.Skipped)
			}
			e := res.Entries[0]
			if e.Hash != c.hash {
				t.Errorf("hash\n  = %s\n期望 %s", e.Hash, c.hash)
			}
			if e.Mode != c.mode {
				t.Errorf("mode = %d, 期望 %d", e.Mode, c.mode)
			}
			if e.Kind != "office" {
				t.Errorf("kind = %q, 期望 office", e.Kind)
			}
		})
	}
}

// TestOfficeSkipReasonsLocalized 确认跳过原因在中英文下都已登记，
// 不会把裸 i18n key 打给用户。
func TestOfficeSkipReasonsLocalized(t *testing.T) {
	for _, lang := range []i18n.Lang{i18n.Zh, i18n.En} {
		withLang(t, lang)
		for _, f := range []string{"plain.doc", "plain.docx"} {
			res, err := Extract(filepath.Join("testdata", f))
			if err != nil {
				t.Fatalf("Extract(%s): %v", f, err)
			}
			for _, s := range res.Skipped {
				if strings.HasPrefix(s.Reason, "hashdump.") {
					t.Errorf("[%s] %s 的跳过原因是未登记的 key: %s", lang, f, s.Reason)
				}
			}
		}
	}
}

// TestExtractOfficeBroken 验证畸形输入只产出跳过原因，不 panic。
func TestExtractOfficeBroken(t *testing.T) {
	dir := t.TempDir()

	src, err := os.ReadFile(filepath.Join("testdata", "word97_rc4.doc"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"truncated":  src[:700],                        // 目录还没读完就断了
		"magic_only": append([]byte(nil), magicOLE...), // 只有 8 字节魔数
		"tiny":       magicOLE[:4],
		"empty_ole":  append(append([]byte(nil), magicOLE...), make([]byte, 604)...),
		"bad_shift":  withShift(magicOLE, make([]byte, 504), 99),
	}
	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, name+".doc")
			if err := os.WriteFile(p, blob, 0o600); err != nil {
				t.Fatal(err)
			}
			res, err := Extract(p)
			if err != nil {
				return // 无法识别属于可接受的失败路径
			}
			if len(res.Entries) != 0 {
				t.Fatalf("entries = %v, 期望 0", res.Entries)
			}
			if len(res.Skipped) == 0 {
				t.Fatal("既无哈希也无跳过原因")
			}
			for _, s := range res.Skipped {
				if s.Reason == "" || strings.HasPrefix(s.Reason, "hashdump.") {
					t.Errorf("跳过原因异常: %q", s.Reason)
				}
			}
		})
	}
}

// withShift 构造一个扇区 shift 越界的 OLE 头。
func withShift(magic, rest []byte, shift uint16) []byte {
	b := append(append([]byte(nil), magic...), rest...)
	if len(b) >= 32 {
		b[30] = byte(shift)
		b[31] = byte(shift >> 8)
	}
	return b
}
