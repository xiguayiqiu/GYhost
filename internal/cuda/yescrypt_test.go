//go:build cuda

package cuda

import (
	"testing"

	"gyhost/internal/pwdhash"
)

// yescrypt 测试向量：由 libxcrypt 生成（与 go-crypt/x/yescrypt 的测试用例同源）。
//
// 覆盖多组参数：
//
//	$y$j75$...  N=1024  r=8
//	$y$j85$...  N=2048  r=6
//	$y$j7T$...  N=1024  r=32
//	$y$j9T$...  N=4096  r=32   （libxcrypt 默认）
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

// yescryptTargetOf 解析测试向量里的 $y$ 哈希，得到 GPU 目标。
func yescryptTargetOf(t *testing.T, hash string) YescryptTarget {
	t.Helper()
	p, ok := pwdhash.ParseYescrypt(hash)
	if !ok {
		t.Fatalf("ParseYescrypt(%q) 失败", hash)
	}
	tgt := YescryptTarget{NLog2: p.NLog2, R: p.R, Salt: p.Salt, Key: p.Key}
	if err := tgt.Validate(); err != nil {
		t.Fatalf("Validate(%q): %v", hash, err)
	}
	return tgt
}

// TestYescryptHostReference 校验 cuda.cu 里的主机端参考实现。
//
// 它与 GPU 内核共用同一套算法代码，因此这一组用例同时锁死了
// “yescrypt 核心实现与 libxcrypt 一致”这件事。
func TestYescryptHostReference(t *testing.T) {
	for _, v := range yescryptVectors {
		tgt := yescryptTargetOf(t, v.hash)

		hit, err := CheckYescrypt(tgt, v.password)
		if err != nil {
			t.Fatalf("CheckYescrypt(%q): %v", v.password, err)
		}
		if !hit {
			t.Errorf("CheckYescrypt: 口令 %q 未匹配 %s", v.password, v.hash)
		}

		hit, err = CheckYescrypt(tgt, v.password+"x")
		if err != nil {
			t.Fatalf("CheckYescrypt(wrong): %v", err)
		}
		if hit {
			t.Errorf("CheckYescrypt: 错误口令 %q 竟然匹配了 %s", v.password+"x", v.hash)
		}
	}
}

// TestYescryptGPU 校验 GPU 内核与主机参考实现结论一致。
func TestYescryptGPU(t *testing.T) {
	devs, err := Devices()
	if err != nil {
		t.Skipf("没有可用的 CUDA 设备: %v", err)
	}
	device := devs[0].Index

	for _, v := range yescryptVectors {
		tgt := yescryptTargetOf(t, v.hash)

		// 命中项放在中间，确认返回的是候选列表里的真实下标
		candidates := []string{"wrong-1", v.password, "wrong-2"}
		idx, err := VerifyYescrypt(tgt, candidates, device)
		if err != nil {
			t.Fatalf("VerifyYescrypt(%q): %v", v.hash, err)
		}
		if idx != 1 {
			t.Errorf("VerifyYescrypt: 命中下标 = %d，期望 1", idx)
		}

		// 全部错误时应返回 -1
		idx, err = VerifyYescrypt(tgt, []string{"wrong-1", "wrong-2"}, device)
		if err != nil {
			t.Fatalf("VerifyYescrypt(全部错误): %v", err)
		}
		if idx != -1 {
			t.Errorf("VerifyYescrypt: 全部错误却返回下标 %d", idx)
		}
	}
}

// TestYescryptWaveSize 校验「一次能并发校验多少个 yescrypt 候选」。
//
// 这个值决定了调用方分块下发时的块大小下限：块小于它等于主动丢掉 GPU 并发度
// （内核是「一线程一候选」，耗时由最慢的一个 warp 决定，块变小并不会更快）。
func TestYescryptWaveSize(t *testing.T) {
	devs, err := Devices()
	if err != nil {
		t.Skipf("没有可用的 CUDA 设备: %v", err)
	}
	device := devs[0].Index

	// 默认参数（N=4096、r=32）：每个候选 16 MiB，4 GB 卡大约装得下 170 来个
	wave, err := YescryptWaveSize(12, 32, device)
	if err != nil {
		t.Fatalf("YescryptWaveSize: %v", err)
	}
	if wave < 1 {
		t.Fatalf("并发候选数 = %d，应当至少为 1", wave)
	}
	// 与显存对得上：wave × 每候选 16 MiB 不能超过显存
	perCand := int64(16) * 4096 * 32 * 8
	if int64(wave)*perCand > devs[0].MemoryMB*1024*1024 {
		t.Errorf("并发候选数 %d 超出显存容量（每候选 %d 字节）", wave, perCand)
	}

	// 参数越小，每候选占的显存越少，能并发校验的候选越多
	small, err := YescryptWaveSize(10, 8, device)
	if err != nil {
		t.Fatalf("YescryptWaveSize: %v", err)
	}
	if small <= wave {
		t.Errorf("N=2^10 r=8 的并发候选数 %d，应当多于默认参数的 %d", small, wave)
	}

	// 非法参数应当报错
	if _, err := YescryptWaveSize(9, 32, device); err == nil {
		t.Error("NLog2 越界时应当报错")
	}
	if _, err := YescryptWaveSize(12, 33, device); err == nil {
		t.Error("r 越界时应当报错")
	}
}

// TestChunkSize 校验 crypt 路径的内核发射粒度。
func TestChunkSize(t *testing.T) {
	n := ChunkSize()
	if n < 1 {
		t.Errorf("ChunkSize() = %d，应当为正数", n)
	}
}
