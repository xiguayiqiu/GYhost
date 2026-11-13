package shadow

import (
	"strings"
	"testing"
	"time"
)

// TestSourceSeg 校验「字典/掩码」片段的渲染：已枚举数量、总数与百分比。
func TestSourceSeg(t *testing.T) {
	cases := []struct {
		name  string
		read  int64
		total uint64
		known bool
		want  string
	}{
		{"总数未知", 1234, 0, false, "1.2k"},
		{"总数为零", 1234, 0, true, "1.2k"},
		{"刚开始", 0, 10000, true, "0/10.0k (0.0%)"},
		{"进行中", 2500, 10000, true, "2.5k/10.0k (25.0%)"},
		{"刚好完成", 10000, 10000, true, "10.0k/10.0k (100.0%)"},
		{"读数超过总数", 12000, 10000, true, "12.0k/10.0k (100.0%)"}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := progressData{
				dictRead: func() int64 { return c.read },
				total:    func() (uint64, bool) { return c.total, c.known },
			}
			if got := d.sourceSeg(); got != c.want {
				t.Errorf("sourceSeg() = %q，期望 %q", got, c.want)
			}
		})
	}
}

// TestSourceSegNoTotalProvider 确认没接总数来源时不会 panic。
func TestSourceSegNoTotalProvider(t *testing.T) {
	d := progressData{dictRead: func() int64 { return 42 }}
	if got := d.sourceSeg(); got != "42" {
		t.Errorf("sourceSeg() = %q，期望 %q", got, "42")
	}
}

// TestEtaSec 校验剩余时间的估算。
func TestEtaSec(t *testing.T) {
	// 总数未知 → 算不出来
	d := progressData{
		start:    time.Now().Add(-10 * time.Second),
		dictRead: func() int64 { return 100 },
		total:    func() (uint64, bool) { return 0, false },
	}
	if _, ok := d.etaSec(); ok {
		t.Error("总数未知时不应给出剩余时间")
	}

	// 10 秒枚举了 100 个候选，总共 1000 个 → 还剩 90 秒
	d = progressData{
		start:    time.Now().Add(-10 * time.Second),
		dictRead: func() int64 { return 100 },
		total:    func() (uint64, bool) { return 1000, true },
	}
	eta, ok := d.etaSec()
	if !ok {
		t.Fatal("应能算出剩余时间")
	}
	if eta < 80 || eta > 100 {
		t.Errorf("etaSec() = %.1f，期望约 90 秒", eta)
	}

	// 已经枚举完 → 剩余 0
	d = progressData{
		start:    time.Now().Add(-10 * time.Second),
		dictRead: func() int64 { return 1000 },
		total:    func() (uint64, bool) { return 1000, true },
	}
	eta, ok = d.etaSec()
	if !ok || eta != 0 {
		t.Errorf("etaSec() = %.1f, ok = %v，期望 0, true", eta, ok)
	}

	// 全部破解（read = -1）→ 剩余 0
	d = progressData{
		start:    time.Now().Add(-10 * time.Second),
		dictRead: func() int64 { return -1 },
		total:    func() (uint64, bool) { return 1000, true },
	}
	eta, ok = d.etaSec()
	if !ok || eta != 0 {
		t.Errorf("etaSec() = %.1f, ok = %v，期望 0, true", eta, ok)
	}
}

// TestSourceSegAllCracked 确认全部目标破解后进度按完成显示。
func TestSourceSegAllCracked(t *testing.T) {
	d := progressData{
		dictRead: func() int64 { return -1 },
		total:    func() (uint64, bool) { return 10000, true },
	}
	if got := d.sourceSeg(); got != "10.0k/10.0k (100.0%)" {
		t.Errorf("sourceSeg() = %q，期望 %q", got, "10.0k/10.0k (100.0%)")
	}

	d = progressData{
		dictRead: func() int64 { return -1 },
		total:    func() (uint64, bool) { return 0, false },
	}
	if got := d.sourceSeg(); got != "100%" {
		t.Errorf("sourceSeg() = %q，期望 %q", got, "100%")
	}
}

// TestVerifyChunksCountsAfterCompletion 确认进度按「真正校验完」计数。
//
// 旧实现是在下发前一次性把整批记成已完成，导致速率先虚高再持续下滑。
func TestVerifyChunksCountsAfterCompletion(t *testing.T) {
	tgt := &target{}
	s := &session{}

	var seen []int
	verify := func(part []string) (int, error) {
		// 校验期间进度不应该被提前记上
		want := int64(sum(seen))
		if got := tgt.attempts.Load(); got != want {
			t.Errorf("校验期间 attempts = %d，期望 %d（不应提前计数）", got, want)
		}
		seen = append(seen, len(part))
		return -1, nil
	}

	cands := []string{"a", "b", "c", "d", "e"}
	if _, err := s.verifyChunks(tgt, cands, 2, verify); err != nil {
		t.Fatalf("verifyChunks: %v", err)
	}
	if got := tgt.attempts.Load(); got != 5 {
		t.Errorf("attempts = %d，期望 5", got)
	}
	if len(seen) != 3 || seen[0] != 2 || seen[1] != 2 || seen[2] != 1 {
		t.Errorf("分块 = %v，期望 [2 2 1]", seen)
	}
}

// TestVerifyChunksHit 确认命中时返回对应的密码并停止继续下发。
func TestVerifyChunksHit(t *testing.T) {
	tgt := &target{}
	s := &session{}
	cands := []string{"a", "b", "c", "d"}

	calls := 0
	verify := func(part []string) (int, error) {
		calls++
		if calls == 2 {
			return 1, nil // 第二块里的第 2 个命中
		}
		return -1, nil
	}
	pw, err := s.verifyChunks(tgt, cands, 2, verify)
	if err != nil {
		t.Fatalf("verifyChunks: %v", err)
	}
	if pw != "d" {
		t.Errorf("命中密码 = %q，期望 %q", pw, "d")
	}
	if calls != 2 {
		t.Errorf("调用次数 = %d，期望 2（命中后应停止）", calls)
	}
	if got := tgt.attempts.Load(); got != 4 {
		t.Errorf("attempts = %d，期望 4", got)
	}
}

// sum 求整数切片之和（测试辅助）。
func sum(v []int) int {
	n := 0
	for _, x := range v {
		n += x
	}
	return n
}

// TestDictProgress 确认整场进度取「最慢的待破解目标」。
func TestDictProgress(t *testing.T) {
	fast := &target{}
	fast.attempts.Store(10000)
	slow := &target{}
	slow.attempts.Store(250)

	s := &session{targets: []*target{fast, slow}}
	if got := s.dictProgress(); got != 250 {
		t.Errorf("dictProgress() = %d，期望 250（取最慢目标）", got)
	}

	// 已破解的目标不再拖慢进度
	slow.cracked.Store(true)
	if got := s.dictProgress(); got != 10000 {
		t.Errorf("dictProgress() = %d，期望 10000（已破解目标不再计入）", got)
	}

	// 全部破解 → -1
	fast.cracked.Store(true)
	if got := s.dictProgress(); got != -1 {
		t.Errorf("dictProgress() = %d，期望 -1", got)
	}
}

// TestHumanDuration 校验时长的渲染。
func TestHumanDuration(t *testing.T) {
	cases := []struct {
		sec  float64
		want string
	}{
		{0, "0秒"},
		{45, "45秒"},
		{59.9, "59秒"},
		{60, "1分"},
		{125, "2分"},
		// 分钟四舍五入：116 秒应显示 2 分，而不是截断成 1 分
		{116, "2分"},
		{90, "2分"},
		{3600, "1时0分"},
		{3900, "1时5分"},
		{86400, "1天0时"},
		{90000, "1天1时"},
	}
	for _, c := range cases {
		if got := humanDuration(c.sec); got != c.want {
			t.Errorf("humanDuration(%v) = %q，期望 %q", c.sec, got, c.want)
		}
	}
}

// TestHumanCount 校验大数字的压缩显示。
func TestHumanCount(t *testing.T) {
	cases := []struct {
		n    uint64
		want string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1.0k"},
		{12345, "12.3k"},
		{1234567, "1.2M"},
		{1234567890, "1.2G"},
		{1234567890123, "1.2T"},
		{1234567890123456, "1.2P"},
		{1234567890123456789, "1.2E"},
	}
	for _, c := range cases {
		if got := humanCount(c.n); got != c.want {
			t.Errorf("humanCount(%d) = %q，期望 %q", c.n, got, c.want)
		}
	}
}

// TestLineIncludesTotal 确认进度行里带上了总数与百分比。
func TestLineIncludesTotal(t *testing.T) {
	d := progressData{
		start:    time.Now().Add(-time.Second),
		dictRead: func() int64 { return 2500 },
		total:    func() (uint64, bool) { return 10000, true },
		attempts: func() int64 { return 2500 },
	}
	line := d.line(0)
	if !strings.Contains(line, "2.5k/10.0k (25.0%)") {
		t.Errorf("进度行缺少字典进度: %q", line)
	}
}
