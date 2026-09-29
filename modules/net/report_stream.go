// TCP 会话追踪报告（-z follow,tcp,ascii）。
//
// 单独成文件是因为它与常规统计报告结构完全不同：不是表格，而是两条
// 方向的内容并排/交替展示。
package net

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"gyhost/internal/i18n"
	"gyhost/internal/utils"
)

// followSpec 解析 -z follow,tcp,<格式> 得到的目标。
type followSpec struct {
	format followFormat
	// index 是会话序号（从 0 开始，对应 -z conv 的第几行）；-1 表示全部
	index int
}

// parseFollowSpec 解析 follow 的参数串。
//
// 支持三种写法：
//
//	follow,tcp,ascii        全部会话，ascii 格式
//	follow,tcp,ascii,0      第 0 个会话
//	follow,tcp,0,ascii      同上（顺序可换）
func parseFollowSpec(arg string) (followSpec, error) {
	fields := strings.Split(arg, ",")
	spec := followSpec{format: followASCII, index: -1}
	for _, f := range fields {
		f = strings.TrimSpace(strings.ToLower(f))
		switch f {
		case "", "follow", "stream", "tcp":
			// 前缀与协议名，忽略
		default:
			if n, err := strconv.Atoi(f); err == nil {
				spec.index = n
				continue
			}
			if fmt, ok := parseFollowFormat(f); ok {
				spec.format = fmt
				continue
			}
			return spec, errors.New(i18n.Tf("net.err.bad_follow", f))
		}
	}
	if spec.index < -1 {
		return spec, errors.New(i18n.Tf("net.err.bad_follow", strconv.Itoa(spec.index)))
	}
	return spec, nil
}

// sortedStreams 按会话键排序，保证输出顺序稳定可复现。
func sortedStreams(m map[string]*streamConv) []*streamConv {
	out := make([]*streamConv, 0, len(m))
	for _, s := range m {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

// writeFollowSection 输出 TCP 会话追踪。
func writeFollowSection(w io.Writer, res *captureResult, spec followSpec) {
	a := res.a
	if a.streams == nil || len(a.streams) == 0 {
		utils.Warnf(w, "[!] %s", i18n.T("net.follow.no_stream"))
		return
	}
	all := sortedStreams(a.streams)
	if spec.index >= len(all) {
		utils.Warnf(w, "[!] %s", i18n.Tf("net.follow.no_index", spec.index, len(all)))
		return
	}
	picked := all
	if spec.index >= 0 {
		picked = all[spec.index : spec.index+1]
	}

	section(w, "net.section.follow")
	for i, s := range picked {
		idx := i
		if spec.index >= 0 {
			idx = spec.index
		}
		writeOneStream(w, s, idx, len(all), spec.format)
	}
}

// writeOneStream 输出单条会话的两个方向。
func writeOneStream(w io.Writer, s *streamConv, idx, total int, format followFormat) {
	c0, c1, gaps := s.follow(format)
	fmt.Fprintf(w, "\n%s\n", i18n.Tf("net.follow.stream", idx, total, s.key))
	if s.truncated {
		utils.Warnf(w, "    [!] %s", i18n.T("net.follow.truncated"))
	}
	if gaps > 0 {
		utils.Warnf(w, "    [!] %s", i18n.Tf("net.follow.gaps", gaps))
	}
	ep0, ep1 := "(无数据)", "(无数据)"
	if s.dirs[0] != nil {
		ep0 = s.dirs[0].endpoint
	}
	if s.dirs[1] != nil {
		ep1 = s.dirs[1].endpoint
	}
	// 两个方向各自成块，用箭头标明方向；对齐 tshark 的阅读习惯
	fmt.Fprintln(w, i18n.Tf("net.follow.from", ep0))
	writeFollowBody(w, c0, format)
	fmt.Fprintln(w, i18n.Tf("net.follow.to", ep1))
	writeFollowBody(w, c1, format)
}

// writeFollowBody 输出一个方向的内容块。
func writeFollowBody(w io.Writer, body string, format followFormat) {
	if body == "" {
		utils.Plainf(w, "    %s", i18n.T("net.follow.empty"))
		return
	}
	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		utils.Plainf(w, "    %s", line)
	}
}
