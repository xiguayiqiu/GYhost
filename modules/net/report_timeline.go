// 流量时间线报告（-z timeline）。
package net

import (
	"fmt"
	"io"
	"strings"
	"time"

	"gyhost/internal/i18n"
	"gyhost/internal/utils"
)

// timelineBar 用字符条直观表示每个桶的包数。
//
// 纯文本终端没有图表，但一条长度正比于数量的横条足以看出突发与静默，
// 比一列数字更容易扫读。
func timelineBar(v, max int) string {
	const width = 40
	if max <= 0 || v <= 0 {
		return ""
	}
	n := v * width / max
	if n < 1 {
		n = 1
	}
	if n > width {
		n = width
	}
	return strings.Repeat("█", n)
}

// writeTimelineSection 输出流量时间线。
func writeTimelineSection(w io.Writer, a *analysis, top int) {
	tl := a.tl
	if tl == nil || len(tl.buckets) == 0 {
		utils.Warnf(w, "[!] %s", i18n.T("net.timeline.empty"))
		return
	}
	section(w, "net.section.timeline")

	peak, ok := tl.topBucket()
	iv := tl.interval
	field(w, "net.tl.interval", i18n.Tf("net.tl.interval_desc", iv.Seconds()))
	field(w, "net.tl.span", i18n.Tf("net.tl.span_desc",
		tl.last.Sub(tl.first).Round(time.Second).String(), len(tl.buckets)))
	field(w, "net.tl.avg", i18n.Tf("net.tl.avg_desc", tl.avgPacket()))
	if ok && peak.packets > 0 {
		field(w, "net.tl.peak", i18n.Tf("net.tl.peak_desc",
			peak.offset.Seconds(), peak.packets, humanBytes(peak.bytes)))
		if peak.topPeer != "" {
			field(w, "net.tl.peak_peer", peak.topPeer)
		}
	}
	if tl.capped {
		utils.Warnf(w, "    [!] %s", i18n.Tf("net.tl.capped", tl.max))
	}

	// 只列出有流量的桶（空桶只占位，不占版面），但保留最多 top 行。
	// 进度条按全局峰值缩放，所以要先扫一遍求出峰值。
	maxPkt := 0
	for _, b := range tl.buckets {
		if b.packets > maxPkt {
			maxPkt = b.packets
		}
	}
	rows := make([][]string, 0, len(tl.buckets))
	for _, b := range tl.buckets {
		if b.packets == 0 {
			continue
		}
		rows = append(rows, []string{
			fmt.Sprintf("%.0f", b.offset.Seconds()),
			fmt.Sprintf("%d", b.packets),
			humanBytes(b.bytes),
			timelineTopProto(b),
			timelineBar(b.packets, maxPkt),
		})
	}
	if len(rows) == 0 {
		utils.Plainf(w, "    %s", i18n.T("net.timeline.empty"))
		return
	}
	if top > 0 && len(rows) > top {
		utils.Warnf(w, "    [!] %s", i18n.Tf("net.tl.rows", len(rows), top))
		rows = rows[:top]
	}
	writeTable(w,
		[]string{i18n.T("net.tl.col_t"), i18n.T("net.tl.col_pkt"),
			i18n.T("net.tl.col_bytes"), i18n.T("net.tl.col_proto"), ""},
		[]bool{false, true, true, false, false}, rows, "  ")
}

// timelineTopProto 返回该桶内包数最多的协议。
func timelineTopProto(b timelineBucket) string {
	best, bestN := "", 0
	for k, v := range b.proto {
		if v > bestN {
			best, bestN = k, v
		}
	}
	return best
}
