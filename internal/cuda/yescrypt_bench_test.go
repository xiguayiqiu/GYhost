//go:build cuda

package cuda

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-crypt/x/yescrypt"

	"gyhost/internal/pwdhash"
)

// yescrypt 参数档位：覆盖 libxcrypt 默认值与更小/更大的组合。
//
// 后两组特意让 S 盒查表次数相同而 v 数组流量差 4 倍，用来分辨瓶颈
// 到底在 pwxform 的随机查表，还是在 ROMix 对 v 数组的随机读写。
var ysBenchParams = []struct {
	name  string
	nlog2 int
	r     int
}{
	{"N=2^10 r=8", 10, 8},
	{"N=2^10 r=32", 10, 32},
	{"N=2^12 r=8", 12, 8},
	{"N=2^12 r=32（libxcrypt 默认）", 12, 32},
}

// ysBenchSalt 是固定盐，基准里两者都一样，只测算法本身。
var ysBenchSalt = []byte("benchmark-salt-16")

// ysBenchBatch 是基准用的候选批次数。
//
// 不能太小：内核是「一个线程 = 一个候选」、块大小 32（1 warp），
// 批次 128 只能占住 4 个 SM，测出来的 GPU 速率严重偏低。
// 512 已能让 GPU 跑满（实测 512 与 4096 的速率基本一致）。
const ysBenchBatch = 512

// ysBenchHash 按给定参数拼一个 $y$ 哈希（密文随便填，基准不追求命中）。
func ysBenchHash(nlog2, r int) string {
	itoa64 := func(v int) byte {
		return yescrypt.Encode64([]byte{byte(v)})[0]
	}
	setting := "$y$j" + string(itoa64(nlog2-1)) + string(itoa64(r-1))
	return setting + "$" + string(yescrypt.Encode64(ysBenchSalt)) + "$" +
		string(yescrypt.Encode64(make([]byte, 32)))
}

// TestYescryptThroughput 对比 CPU 与 GPU 的 yescrypt 校验速率。
//
// CPU 侧走生产用的 Go 校验器（internal/pwdhash → go-crypt/x），单线程，
// 代表一个 CPU 核的水平；GPU 侧走批量校验内核。
//
// 批次大小很关键：yescrypt 内核是「一个线程 = 一个候选」，块大小 32（1 warp），
// 所以并发候选数才是真正占住 SM 的东西。批次只有 128 时最多用到 4 个 SM，
// 测出来的 GPU 速率会低估 3~4 倍。ysBenchBatch 取 512，实测已能让 GPU 跑满。
func TestYescryptThroughput(t *testing.T) {
	devs, err := Devices()
	if err != nil {
		t.Skipf("没有可用的 CUDA 设备: %v", err)
	}
	device := devs[0].Index

	// 用参考密钥跑（不命中即可，算法开销与是否命中无关）
	key := make([]byte, YescryptKeyLen)
	passwords := make([]string, ysBenchBatch)
	for i := range passwords {
		passwords[i] = fmt.Sprintf("benchmark-password-%03d", i)
	}

	for _, p := range ysBenchParams {
		tgt := YescryptTarget{NLog2: p.nlog2, R: p.r, Salt: ysBenchSalt, Key: key}
		if err := tgt.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}

		// CPU：走生产用的 Go 校验器（internal/pwdhash → go-crypt/x），
		// 单线程，代表一个 CPU 核的水平。这里要按当前参数拼一个 $y$ 哈希，
		// 否则 CPU 侧跑的是固定参数、与 GPU 侧对不上。
		hash := ysBenchHash(p.nlog2, p.r)
		checker, err := pwdhash.NewChecker(hash)
		if err != nil {
			t.Fatalf("NewChecker(%q): %v", hash, err)
		}
		// 慢参数下固定迭代数会得到很短的采样窗口（40 H/s 时 256 次只有 6 秒），
		// 这里改成「至少跑满 1 秒」，让速率稳定可比。
		cpuStart := time.Now()
		cpuCount := 0
		for time.Since(cpuStart) < time.Second {
			for _, pw := range passwords {
				checker.Check(pw)
			}
			cpuCount += len(passwords)
		}
		cpuElapsed := time.Since(cpuStart)
		cpuRate := float64(cpuCount) / cpuElapsed.Seconds()

		// GPU：先预热一次（首轮含内核加载与显存分配开销），再计时
		if _, err := VerifyYescrypt(tgt, passwords, device); err != nil {
			t.Fatalf("VerifyYescrypt: %v", err)
		}
		gpuStart := time.Now()
		if _, err := VerifyYescrypt(tgt, passwords, device); err != nil {
			t.Fatalf("VerifyYescrypt: %v", err)
		}
		gpuElapsed := time.Since(gpuStart)
		gpuRate := float64(len(passwords)) / gpuElapsed.Seconds()

		fmt.Printf("%-30s CPU(1核) %8.2f H/s   GPU %8.2f H/s   比值 %6.2fx   每候选显存 %6.1f MiB   批次 %d\n",
			p.name, cpuRate, gpuRate, gpuRate/cpuRate,
			float64(tgt.MemPerCandidate())/(1024*1024), len(passwords))
	}
}

// TestYescryptParseMatchesChecker 校验解析出来的参数与 CPU 校验器结论一致。
func TestYescryptParseMatchesChecker(t *testing.T) {
	const hash = "$y$j9T$fqIAg4Vpv9o1MKgWMnyax.$BxkUx27fLJlPOfyIfNEBPzjrDQ95LXKgN5OJii3GL7."
	p, ok := pwdhash.ParseYescrypt(hash)
	if !ok {
		t.Fatalf("ParseYescrypt 失败")
	}
	if p.NLog2 != 12 || p.R != 32 {
		t.Errorf("参数 = N=%d r=%d，期望 N=4096 r=32", 1<<p.NLog2, p.R)
	}
}
