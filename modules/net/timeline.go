// 流量时间线：按时间桶统计包数、字节与协议构成。
//
// 抓包是一段时间内的连续事件，但报告只给总量——看不出"什么时候发生的"。
// 时间线补上这一维：既能定位突发（扫描/洪泛/下载），也能看出静默期。
//
// 桶的划分支持三种粒度，并按"首帧时间"对齐而非墙钟秒，这样
// 10:05:30 抓的包与 22:05:30 抓的包分桶行为一致，便于跨抓包比较。
package net

import (
	"sort"
	"time"
)

// timelineBucket 是一个时间桶的统计。
type timelineBucket struct {
	offset  time.Duration // 相对首帧的偏移（桶起点）
	packets int
	bytes   int64
	proto   map[string]int // 协议 → 包数
	// topPeer 是该桶内包数最多的会话，用于把突发定位到具体通信
	topPeer    string
	topPeerN   int
	peerCounts map[string]int
}

// timeline 是整条时间线的统计结果。
type timeline struct {
	buckets  []timelineBucket
	interval time.Duration
	max      int
	first    time.Time
	last     time.Time
	proto    map[string]int // 全时段协议计数
	capped   bool           // 桶数触到上限，时间线不完整
}

// timelineLimits 是时间线的规模上限。
//
// 时间跨度很大时（数小时的密集流量），按秒分桶会瞬间撑爆内存；
// 超限后停止新增并在报告里标明不完整。
type timelineLimits struct {
	interval  time.Duration
	maxBucket int
}

const (
	defaultTimelineBuckets = 600 // 600 秒 = 10 分钟，够看清突发又不至于太多行
)

// parseInterval 解析时间桶粒度（秒）。
func parseInterval(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	return parseDur(s)
}

// collectTimeline 把一帧计入时间线。
func (a *analysis) collectTimeline(p *pkt) {
	if a.tl == nil {
		return
	}
	if a.tl.first.IsZero() {
		a.tl.first = p.ts
	}
	if p.ts.After(a.tl.last) {
		a.tl.last = p.ts
	}
	idx := int(p.ts.Sub(a.tl.first) / a.tl.interval)
	if idx < 0 {
		idx = 0
	}
	// 桶按需创建，末尾补齐（中间没有包的桶也要占位，否则时间轴会跳）
	for len(a.tl.buckets) <= idx {
		if len(a.tl.buckets) >= a.tl.max {
			a.tl.capped = true
			return
		}
		a.tl.buckets = append(a.tl.buckets, timelineBucket{
			offset:     time.Duration(len(a.tl.buckets)) * a.tl.interval,
			proto:      map[string]int{},
			peerCounts: map[string]int{},
		})
	}
	b := &a.tl.buckets[idx]
	b.packets++
	b.bytes += int64(p.wireLen)
	name := tuiProto(p)
	if name == "" {
		name = "?"
	}
	b.proto[name]++

	// 记录本桶最活跃的会话：突发流量往往来自固定的几对端点，
	// 看到"哪一对"比只看到"多少包"更能定位问题。
	if src, dst := p.addrPair(); src != "" || dst != "" {
		ep := src + " <-> " + dst
		b.peerCounts[ep]++
		if b.peerCounts[ep] > b.topPeerN {
			b.topPeerN, b.topPeer = b.peerCounts[ep], ep
		}
	}
}

// enableTimeline 打开流量时间线收集。
func (a *analysis) enableTimeline(interval time.Duration, maxBuckets int) {
	if interval <= 0 {
		interval = time.Second // 默认按秒分桶
	}
	if maxBuckets <= 0 {
		maxBuckets = defaultTimelineBuckets
	}
	a.tl = &timeline{
		interval: interval,
		max:      maxBuckets,
		proto:    map[string]int{},
	}
}

// topBucket 返回包数最多的桶（峰值时刻）。
func (tl *timeline) topBucket() (timelineBucket, bool) {
	if len(tl.buckets) == 0 {
		return timelineBucket{}, false
	}
	best := tl.buckets[0]
	for _, b := range tl.buckets {
		if b.packets > best.packets {
			best = b
		}
	}
	return best, true
}

// avgPacket 计算平均每秒包数（跨整个时间跨度）。
func (tl *timeline) avgPacket() float64 {
	if tl.first.IsZero() || tl.last.IsZero() {
		return 0
	}
	d := tl.last.Sub(tl.first).Seconds()
	if d <= 0 {
		return 0
	}
	return float64(tl.totalPackets()) / d
}

// totalPackets 汇总全部桶的包数。
func (tl *timeline) totalPackets() int {
	n := 0
	for _, b := range tl.buckets {
		n += b.packets
	}
	return n
}

// protoOverTime 返回各协议随时间的包数（按协议聚合，桶序升序）。
func (tl *timeline) protoOverTime() ([]string, []int) {
	m := map[string]int{}
	for _, b := range tl.buckets {
		for k, v := range b.proto {
			m[k] += v
		}
	}
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool { return m[names[i]] > m[names[j]] })
	out := make([]int, len(names))
	for i, n := range names {
		out[i] = m[n]
	}
	return names, out
}
