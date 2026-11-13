package hashac

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// yescrypt 测试向量：由 libxcrypt 生成（与 internal/pwdhash、internal/cuda 的
// 测试用例同源）。这里用最小的 N=1024、r=8，CPU 复核也足够快。
const (
	yescryptVectorHash     = "$y$j75$z7ztFz2FayrKI79/jEwlL.$u5x/j193MQ09wbFaRGYr0AH/A/jh3kunjuhYRVRNkmC"
	yescryptVectorPassword = "test1"
)

// TestParseYescrypt 校验 $y$ 的自动识别、模式号与 GPU 参数。
func TestParseYescrypt(t *testing.T) {
	tgt, err := Parse(yescryptVectorHash, 0)
	if err != nil {
		t.Fatalf("Parse(%q): %v", yescryptVectorHash, err)
	}
	if tgt.Kind != KindYescrypt {
		t.Errorf("Kind = %q，期望 %q", tgt.Kind, KindYescrypt)
	}
	if tgt.Mode != 36100 {
		t.Errorf("Mode = %d，期望 36100", tgt.Mode)
	}
	if tgt.YGPU == nil {
		t.Fatal("YGPU = nil，yescrypt 目标应可交给 GPU")
	}
	// $y$j75$：N = 1<<10、r = 8
	if tgt.YGPU.NLog2 != 10 || tgt.YGPU.R != 8 {
		t.Errorf("GPU 参数 NLog2=%d R=%d，期望 NLog2=10 R=8", tgt.YGPU.NLog2, tgt.YGPU.R)
	}
	if len(tgt.YGPU.Key) != 32 {
		t.Errorf("目标密钥长度 = %d，期望 32", len(tgt.YGPU.Key))
	}

	if !tgt.Check.Check(yescryptVectorPassword) {
		t.Errorf("CPU 校验器未识别正确口令 %q", yescryptVectorPassword)
	}
	if tgt.Check.Check(yescryptVectorPassword + "x") {
		t.Error("CPU 校验器把错误口令判为命中")
	}

	// 强制 --mode 36100 也应解析成同一个目标
	forced, err := Parse(yescryptVectorHash, 36100)
	if err != nil {
		t.Fatalf("Parse(--mode 36100): %v", err)
	}
	if forced.Kind != KindYescrypt || forced.Mode != 36100 {
		t.Errorf("强制模式解析结果 = %q/%d，期望 yescrypt/36100", forced.Kind, forced.Mode)
	}
}

// TestCrackYescryptCPU 走完整的 Crack 流程（无 GPU），确认 $y$ 能被 CPU 爆破出来。
func TestCrackYescryptCPU(t *testing.T) {
	dir := t.TempDir()
	hashPath := filepath.Join(dir, "hash.txt")
	listPath := filepath.Join(dir, "wordlist.txt")
	if err := os.WriteFile(hashPath, []byte(yescryptVectorHash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(listPath, []byte("wrong\n"+yescryptVectorPassword+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := Crack(Options{
		InputPath:    hashPath,
		WordlistPath: listPath,
		Threads:      1,
	})
	if err != nil {
		t.Fatalf("Crack: %v", err)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("破解结果数 = %d，期望 1", len(rep.Results))
	}
	got := rep.Results[0]
	if got.Password != yescryptVectorPassword {
		t.Errorf("命中口令 = %q，期望 %q", got.Password, yescryptVectorPassword)
	}
	if got.Kind != KindYescrypt || got.Mode != 36100 {
		t.Errorf("命中类型 = %q/-m %d，期望 yescrypt/-m 36100", got.Kind, got.Mode)
	}
	// 单线程按顺序处理：错误口令 + 正确口令，命中后立即收工
	if rep.WordlistLen != 2 {
		t.Errorf("字典进度 = %d，期望 2", rep.WordlistLen)
	}
}

// TestWordBatchConsumeN 校验「同一批候选只推进一次字典进度」，
// 且慢速消费者分多次推进时不会超过真实行数。
func TestWordBatchConsumeN(t *testing.T) {
	b := &wordBatch{pw: make([]string, 5)}
	var got atomic.Int64

	b.consumeN(&got, 0)  // 忽略
	b.consumeN(&got, 2)  // 2
	b.consumeN(&got, 2)  // 4
	b.consumeN(&got, 99) // 封顶 5
	b.consumeN(&got, 1)  // 已满，忽略
	b.consume(&got)      // 已满，忽略
	if got.Load() != 5 {
		t.Errorf("consumeN 累计 = %d，期望 5", got.Load())
	}

	// 并发消费者各自推进时也不能重复计数
	b = &wordBatch{pw: make([]string, 100)}
	got.Store(0)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				b.consumeN(&got, 3)
			}
		}()
	}
	wg.Wait()
	if got.Load() != 100 {
		t.Errorf("并发 consumeN 累计 = %d，期望 100", got.Load())
	}
}
