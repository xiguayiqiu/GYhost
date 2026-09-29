// -z 章节选择：只输出报告的某几段，便于配合管道做后续处理。
//
// 设计取向是"可组合"：报告的每一段都能单独取出来，配合 grep/awk/jq
// 做二次加工，而不是每次都从头解析整份人读报告。
package net

import (
	"errors"
	"sort"
	"strings"

	"gyhost/internal/i18n"
)

// sectionList 是 -z 参数的取值类型：逗号分隔、可重复。
type sectionList []string

// String 实现 flag.Value，用于回显当前取值。
func (l *sectionList) String() string { return strings.Join(*l, ",") }

// Set 追加一个参数值（原样保存，解释交给 resolveSections）。
func (l *sectionList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// 章节标识。
const (
	secIO       = "io"        // 概览
	secProto    = "proto"     // 协议分布
	secConv     = "conv"      // 会话
	secEndpoint = "endpoints" // 端点
	secPort     = "ports"     // 端口
	secDNS      = "dns"       // DNS
	secSNI      = "sni"       // TLS SNI
	secHTTP     = "http"      // HTTP
	secFindings = "findings"  // 安全发现
	secAttack   = "attack"    // 攻击分析
	secFollow   = "follow"    // TCP 会话追踪
	secTimeline = "timeline"  // 流量时间线
)

// sectionAlias 是章节名的别名，让 -z 贴近 tshark 的习惯写法。
var sectionAlias = map[string]string{
	"io": secIO, "info": secIO, "summary": secIO,
	"phs": secProto, "proto": secProto, "protocols": secProto,
	"conv": secConv, "conversations": secConv, "flows": secConv,
	"endpoints": secEndpoint, "ep": secEndpoint, "hosts": secEndpoint,
	"ports": secPort, "port": secPort,
	"dns": secDNS, "sni": secSNI, "tls": secSNI,
	"http": secHTTP, "https": secHTTP,
	"findings": secFindings, "security": secFindings,
	"attack": secAttack, "attacks": secAttack,
	"follow": secFollow, "stream": secFollow, "streams": secFollow,
	"timeline": secTimeline, "time": secTimeline, "graph": secTimeline,
}

// allSections 是 -z all 展开后的章节顺序（与报告输出一致）。
var allSections = []string{
	secIO, secTimeline, secAttack, secProto, secConv, secEndpoint, secPort,
	secDNS, secSNI, secHTTP, secFindings,
}

// resolveSections 把 -z 的原始参数解析成有序、去重的章节集合。
//
// 返回 followSpec 时 section 列表里不含 follow（它单独走会话追踪输出）。
func resolveSections(raw []string) (secs []string, follow followSpec, hasFollow bool, err error) {
	if len(raw) == 0 {
		return nil, followSpec{}, false, nil
	}
	seen := map[string]bool{}
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			secs = append(secs, name)
		}
	}
	for _, item := range raw {
		// follow 的参数后面跟着格式与会话序号（follow,tcp,ascii,0），
		// 整串交给 follow 解析，不能逐逗号段当章节名处理。
		trimmed := strings.TrimSpace(strings.ToLower(item))
		if trimmed == "follow" || strings.HasPrefix(trimmed, "follow,") ||
			strings.HasPrefix(trimmed, "stream,") {
			sp, e := parseFollowSpec(trimmed)
			if e != nil {
				return nil, followSpec{}, false, e
			}
			follow, hasFollow = sp, true
			continue
		}
		for _, part := range strings.Split(item, ",") {
			part = strings.TrimSpace(strings.ToLower(part))
			if part == "" {
				continue
			}
			if part == "all" {
				for _, s := range allSections {
					add(s)
				}
				continue
			}
			canon, ok := sectionAlias[part]
			if !ok {
				return nil, followSpec{}, false,
					errors.New(i18n.Tf("net.err.bad_section", part))
			}
			add(canon)
		}
	}
	// 按报告顺序输出，保证 -z 的结果与整份报告的排列一致
	order := map[string]int{}
	for i, s := range allSections {
		order[s] = i
	}
	sort.SliceStable(secs, func(i, j int) bool { return order[secs[i]] < order[secs[j]] })
	return secs, follow, hasFollow, nil
}

// wantSec 判断某章节是否被选中（未指定 -z 时返回 false，表示"全都要"）。
func wantSec(secs []string, name string) bool {
	if len(secs) == 0 {
		return false
	}
	for _, s := range secs {
		if s == name {
			return true
		}
	}
	return false
}
