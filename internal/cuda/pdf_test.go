//go:build cuda

package cuda

// 本文件验证 PDF 口令校验（HashPDF）的内核实现。
//
// cuda.cu 的算法核心是 __host__ __device__ 共用代码，因此：
//   - CheckHash 走主机端参考实现，不需要 GPU 就能逐向量比对；
//   - 有设备时再用 VerifyHash 跑一遍真正的内核，两条路径必须给出同样的下标。

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// goldens 取自 hashcat v7.1.2 的 example-hashes（-m 10400/10500/10600/10700），
// 明文都是 "hashcat"；最后一条是本项目按 ISO 32000-2 合成、覆盖所有者口令路径的向量。
var goldens = []struct {
	name string
	mode int
	t    HashTarget
	pass []string
}{
	{
		name: "10400-rc4-40",
		mode: 10400,
		t: HashTarget{
			Algo:   HashPDF,
			Salt:   hx("01221086741440841668371056103222"),
			Data:   zeros(32),
			Check:  hx("27c3fecef6d46a78eb61b8b4dbc690f5f8a2912bbb9afc842c12d79481568b74"),
			Iter:   2,
			KeyLen: 5,
			IV:     hx("ffffffff00000000"), // P=-1 且 EncryptMetadata=false
		},
		pass: []string{"hashcat"},
	},
	{
		name: "10500-rc4-128",
		mode: 10500,
		t: HashTarget{
			Algo:   HashPDF,
			Salt:   hx("62888255846156252261477183186121"),
			Data:   zeros(32),
			Check:  hx("6879919b1afd520bd3b7dbcc0868a0a500000000000000000000000000000000"),
			Iter:   3,
			KeyLen: 16,
			IV:     hx("fcffffff01000000"), // P=-4 且 EncryptMetadata=true
		},
		pass: []string{"hashcat"},
	},
	{
		name: "10600-aes-256-r5",
		mode: 10600,
		t: HashTarget{
			Algo:  HashPDF,
			Salt:  hx("2856227467642658" + "0000000000000000"),
			Data:  hx("a3aab04cff2c536118870976d768f1fdd445754d6b2dd81fba10bb6e742acd7f285" + "62274676426582441147358074521"),
			Check: zeros(48),
			Iter:  5,
		},
		pass: []string{"hashcat"},
	},
	{
		name: "10700-aes-256-r6",
		mode: 10700,
		t: HashTarget{
			Algo:  HashPDF,
			Salt:  hx("6213764082512454" + "0000000000000000"),
			Data:  hx("0391647179352257f7181236ba371e540c2dbb82fac1c462313eb58b772a5495621" + "37640825124540503886403748430"),
			Check: zeros(48),
			Iter:  6,
		},
		pass: []string{"hashcat"},
	},
	{
		// 合成向量：/U 与 /O 均为 48 字节，用户口令 pdfuser、所有者口令 pdfowner
		name: "10600-owner",
		mode: 10600,
		t: HashTarget{
			Algo:  HashPDF,
			Salt:  hx("0123456789abcdef" + "1122334455667788"),
			Data:  hx("ae1dcc8f81e295d773621c3bec0354474331613187976bf56db5d715cb79e999" + "0123456789abcdeffedcba9876543210"),
			Check: hx("aea44f329a953fc21291dff091389ee26d3691bfab6b3f7ae02015ce3d917876" + "11223344556677888877665544332211"),
			Iter:  5,
		},
		pass: []string{"pdfuser", "pdfowner"},
	},
}

func hx(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// zeros 返回 n 个零字节（hashcat 的 V=5 官方向量里 /O 是全零）。
func zeros(n int) []byte { return make([]byte, n) }

var wrongPasswords = []string{"", "hashcat1", "Hashcat", "wrong", "pdfuser1"}

// TestPDFCheckHash 主机端参考实现：命中口令必须通过，错误口令必须被拒。
func TestPDFCheckHash(t *testing.T) {
	if !Compiled() {
		t.Skip("未启用 CUDA 构建")
	}
	for _, c := range goldens {
		t.Run(c.name, func(t *testing.T) {
			if err := c.t.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if !SupportedHash(c.t.Algo) {
				t.Fatalf("Algo %d 未登记为支持", c.t.Algo)
			}
			for _, pw := range c.pass {
				hit, err := CheckHash(c.t, pw)
				if err != nil {
					t.Fatalf("CheckHash(%q): %v", pw, err)
				}
				if !hit {
					t.Errorf("口令 %q 应命中", pw)
				}
			}
			for _, pw := range wrongPasswords {
				hit, err := CheckHash(c.t, pw)
				if err != nil {
					t.Fatalf("CheckHash(%q): %v", pw, err)
				}
				if hit {
					t.Errorf("口令 %q 不应命中", pw)
				}
			}
		})
	}
}

// TestPDFVerifyHashOnDevice 在真实设备上跑内核，返回的下标必须与主机端一致。
// 没有设备时跳过。
func TestPDFVerifyHashOnDevice(t *testing.T) {
	if !Compiled() {
		t.Skip("未启用 CUDA 构建")
	}
	devs, err := Devices()
	if err != nil || len(devs) == 0 {
		t.Skipf("没有可用的 CUDA 设备: %v", err)
	}
	dev := devs[0]
	for _, c := range goldens {
		t.Run(c.name, func(t *testing.T) {
			// 正确答案放在批次中间，前面塞一批错误口令，确保返回的是最小命中下标
			batch := []string{"a", "bb", "ccc", c.pass[0], "dddd"}
			got, err := VerifyHash(c.t, batch, dev.Index)
			if err != nil {
				t.Fatalf("VerifyHash: %v", err)
			}
			if got != 3 {
				t.Errorf("命中下标 = %d，期望 3", got)
			}

			// 全部错误口令时不应有命中
			got, err = VerifyHash(c.t, []string{"x", "y", "z"}, dev.Index)
			if err != nil {
				t.Fatalf("VerifyHash: %v", err)
			}
			if got != -1 {
				t.Errorf("无口令命中却返回下标 %d", got)
			}
		})
	}
}

// BenchmarkPDFVerifyHash 测 GPU 批量校验吞吐（每个 b.N 迭代固定一批候选）。
// 用来和 hashcat 在同一张卡上的数字对照：hashcat 只校验用户口令，
// 本内核还会试所有者口令，所以这里的数字会略低于 hashcat。
func BenchmarkPDFVerifyHash(b *testing.B) {
	if !Compiled() {
		b.Skip("未启用 CUDA 构建")
	}
	devs, err := Devices()
	if err != nil || len(devs) == 0 {
		b.Skipf("没有可用的 CUDA 设备: %v", err)
	}
	dev := devs[0]

	// 批量大小：R=6 每个候选要算上万次 AES，批量太大单次迭代就要几十秒，
	// 这里取 16384 让 b.N 能自动扩展（吞吐 = 16384 / ns_per_op）
	const n = 1 << 14
	batch := make([]string, n)
	for i := range batch {
		// 全部口令都不会命中，避免命中导致的提前退出影响计时
		batch[i] = fmt.Sprintf("BenchCandidate%d", i)
	}
	for _, c := range goldens {
		c := c
		if c.mode == 10700 {
			// R=6 每个候选要做 64~288 轮 AES，单次迭代要几十秒；
			// 正确性由 TestPDFCheckHash / TestPDFVerifyHashOnDevice 覆盖，
			// 这里就不放进吞吐基准（hashac 侧目前也不把 10700 交给 GPU）。
			continue
		}
		b.Run(c.name, func(b *testing.B) {
			// 预热：第一次发射会触发驱动的 JIT（库是按默认架构编的，
			// 目标卡可能只有 PTX），不预热的话第一次迭代会慢几十秒
			if _, err := VerifyHash(c.t, batch, dev.Index); err != nil {
				b.Fatalf("VerifyHash: %v", err)
			}
			b.SetBytes(int64(n))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := VerifyHash(c.t, batch, dev.Index); err != nil {
					b.Fatalf("VerifyHash: %v", err)
				}
			}
		})
	}
}
