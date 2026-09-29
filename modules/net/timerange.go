// 时间范围过滤（-t）：把抓包收敛到某个时间窗口。
//
// 抓包常常横跨很久，而真正要看的事件只发生在几分钟内。没有时间过滤时，
// 只能靠 -f 反复试协议与地址；有了它就能先按时间切开，再在其中做别的分析。
package net

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"gyhost/internal/i18n"
)

// timeRange 是一个时间窗口。
//
// 支持三种写法（都相对于抓包首帧，便于"从抓包开始后 30 秒"这类表达）：
//
//	10:05:00-10:06:00   绝对时刻（同一天）
//	30-90               相对首帧的第 30 秒到第 90 秒
//	-90                 从头到第 90 秒
type timeRange struct {
	from, to time.Duration // 相对首帧的偏移；负值表示未指定
	absFrom  string        // 绝对起点原文（供报告回显）
	absTo    string
	absolute bool
}

// parseTimeRange 解析 -t 参数。
func parseTimeRange(s string) (*timeRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	// 支持逗号或连字符分隔（连字符与绝对时刻里的冒号不冲突）
	sep := strings.IndexAny(s, ",-")
	if sep < 0 {
		// 只有一个值：视为起点
		return parseRangePair(s, "")
	}
	return parseRangePair(s[:sep], s[sep+1:])
}

// parseRangePair 解析起止两端。
func parseRangePair(from, to string) (*timeRange, error) {
	tr := &timeRange{from: -1, to: -1}
	// 优先按绝对时刻解析
	if looksLikeClock(from) || looksLikeClock(to) {
		if from == "" || to == "" {
			return nil, errors.New(i18n.T("net.err.time_range"))
		}
		f, err := parseClock(from)
		if err != nil {
			return nil, err
		}
		t, err := parseClock(to)
		if err != nil {
			return nil, err
		}
		if t.Before(f) {
			return nil, errors.New(i18n.T("net.err.time_range_order"))
		}
		tr.absolute = true
		tr.absFrom, tr.absTo = from, to
		tr.from = f.Sub(timeOfDay(f)) // 相对当天零点
		tr.to = t.Sub(timeOfDay(t))
		if t.Equal(f) {
			tr.to = tr.from
		}
		return tr, nil
	}
	// 否则按相对秒数解析
	if from != "" {
		d, err := parseDur(from)
		if err != nil {
			return nil, err
		}
		tr.from = d
	}
	if to != "" {
		d, err := parseDur(to)
		if err != nil {
			return nil, err
		}
		tr.to = d
	}
	if tr.from < 0 && tr.to < 0 {
		return nil, errors.New(i18n.T("net.err.time_range"))
	}
	return tr, nil
}

// looksLikeClock 判断是否形如 10:05:00（绝对时刻）。
func looksLikeClock(s string) bool {
	if !strings.Contains(s, ":") {
		return false
	}
	_, err := parseClock(s)
	return err == nil
}

// parseClock 解析 HH:MM 或 HH:MM:SS，返回当天该时刻。
func parseClock(s string) (time.Time, error) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) < 2 || len(parts) > 3 {
		return time.Time{}, errors.New(i18n.Tf("net.err.time_range", s))
	}
	nums := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return time.Time{}, errors.New(i18n.Tf("net.err.time_range", s))
		}
		nums[i] = n
	}
	sec := 0
	if len(nums) == 3 {
		sec = nums[2]
	}
	if nums[0] > 23 || nums[1] > 59 || sec > 59 {
		return time.Time{}, errors.New(i18n.Tf("net.err.time_range", s))
	}
	now := time.Now()
	return time.Date(now.Year(), now.Month(), now.Day(),
		nums[0], nums[1], sec, 0, now.Location()), nil
}

// timeOfDay 返回该时刻当天零点。
func timeOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

// parseDur 解析秒数，支持小数。
func parseDur(s string) (time.Duration, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || f < 0 {
		return 0, errors.New(i18n.Tf("net.err.time_range", s))
	}
	return time.Duration(f * float64(time.Second)), nil
}

// match 判断某个时间点是否落在窗口内。
//
// 绝对时刻：与该时刻同一天的偏移做比较。
// 相对秒数：与抓包首帧的偏移做比较（base 由调用方在见到首帧后设置）。
func (tr *timeRange) match(ts time.Time, base time.Time) bool {
	if tr == nil {
		return true
	}
	var d time.Duration
	if tr.absolute {
		d = ts.Sub(timeOfDay(ts))
	} else {
		if base.IsZero() {
			return true // 还没见到首帧，先放过
		}
		d = ts.Sub(base)
	}
	if d < 0 {
		d = 0
	}
	if tr.from >= 0 && d < tr.from {
		return false
	}
	// to == -1 表示"没有上界"：-t 30 这种只给起点时，
	// 起点之后都应命中。若写成 d > tr.to，-1 会被当成"早于 -1 纳秒"而全否掉。
	if tr.to >= 0 && d > tr.to {
		return false
	}
	return true
}

// String 回显原始写法。
func (tr *timeRange) String() string {
	if tr == nil {
		return ""
	}
	if tr.absolute {
		return tr.absFrom + "-" + tr.absTo
	}
	return tr.from.String() + "-" + tr.to.String()
}
