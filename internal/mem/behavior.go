package mem

import (
	"regexp"
	"sort"
	"strings"
)

// Indicator 是一类“程序行为痕迹”，用于从内存字符串里还原程序在做什么。
type Indicator struct {
	// Kind 分类标识，如 "url" / "ip" / "registry"；i18n 用它做 key。
	Kind string
	// Label 面向用户的默认分类名（i18n 缺 key 时回退到它）。
	Label string
	// Risk 风险等级 0~3：0 无害、1 信息、2 可疑、3 高危。
	Risk int
	// Pattern 匹配的正则。
	Pattern *regexp.Regexp
	// Dedupe 是否按“值”去重（同一 URL 出现多次只报一次）。
	Dedupe bool
}

// BehaviorHit 是一条行为痕迹。
type BehaviorHit struct {
	Kind    string // Indicator.Kind
	Label   string
	Risk    int
	Value   string // 命中的内容
	Offset  uint64 // 在镜像中的偏移
	Region  string // 所在区域类型
	Enc     StringEnc
	Context string // 命中串的上下文（截断后）
}

// indicators 是全部行为痕迹规则。
//
// 正则统一使用 (?i) 忽略大小写：内存里的路径、注册表键名大小写并不固定。
var indicators = []Indicator{
	// ---- 网络行为 ----
	{Kind: "url", Label: "URL", Risk: 1, Dedupe: true,
		Pattern: regexp.MustCompile(`(?i)\b(?:https?|ftps?|wss?)://[^\s"'<>\\)\]]{4,512}`)},
	{Kind: "ip", Label: "IPv4", Risk: 1, Dedupe: true,
		Pattern: regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`)},
	{Kind: "domain", Label: "域名", Risk: 1, Dedupe: true,
		Pattern: regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|cn|ru|io|xyz|top|info|cc|biz|tk|onion|co|me|dev|site|club|shop|fun|app)\b`)},
	{Kind: "email", Label: "邮箱", Risk: 1, Dedupe: true,
		Pattern: regexp.MustCompile(`(?i)\b[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,255}\.[a-z]{2,24}\b`)},
	{Kind: "port", Label: "端口", Risk: 0, Dedupe: true,
		Pattern: regexp.MustCompile(`(?i)\bport\s*[:=]?\s*(\d{1,5})\b`)},

	// ---- 凭据与密钥（高危） ----
	{Kind: "password", Label: "口令/凭据", Risk: 3, Dedupe: true,
		Pattern: regexp.MustCompile(`(?i)\b(?:pass(?:word|wd|phrase)?|pwd|secret|token|apikey|api[_-]?key|auth[_-]?key|credential)\b\s*[:=]\s*["']?[^\s"'&,;]{3,128}`)},
	{Kind: "private_key", Label: "私钥材料", Risk: 3, Dedupe: true,
		Pattern: regexp.MustCompile(`-----BEGIN [A-Z ]{0,32}PRIVATE KEY-----`)},
	{Kind: "aws_key", Label: "云访问密钥", Risk: 3, Dedupe: true,
		Pattern: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{Kind: "jwt", Label: "JWT 令牌", Risk: 2, Dedupe: true,
		Pattern: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}`)},
	{Kind: "basic_auth", Label: "HTTP Basic 认证头", Risk: 2, Dedupe: true,
		Pattern: regexp.MustCompile(`(?i)\bbasic\s+[A-Za-z0-9+/]{8,}={0,2}`)},
	{Kind: "shadow", Label: "shadow 口令行", Risk: 3,
		Pattern: regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}:\$[0-9a-z]{1,4}\$[^\s:]{5,200}:`)},

	// ---- 主机行为 ----
	{Kind: "path_unix", Label: "Unix 路径", Risk: 0, Dedupe: true,
		Pattern: regexp.MustCompile(`(?:^|[\s"'(=])(/(?:etc|var|tmp|home|root|usr|opt|proc|sys|dev|Users|private)/[^\s"'<>:]{2,200})`)},
	{Kind: "path_win", Label: "Windows 路径", Risk: 0, Dedupe: true,
		Pattern: regexp.MustCompile(`(?i)\b[a-z]:\\(?:windows|users|program files(?: \(x86\))?|programdata|appdata|temp|tmp|system32|syswow64)\\[^\s"'<>|]{2,200}`)},
	{Kind: "registry", Label: "注册表键", Risk: 1, Dedupe: true,
		Pattern: regexp.MustCompile(`(?i)\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s"'<>|]{2,200}`)},
	{Kind: "env", Label: "环境变量", Risk: 0, Dedupe: true,
		Pattern: regexp.MustCompile(`\b[A-Z][A-Z0-9_]{2,30}=[^\s"'\x00]{0,200}`)},
	{Kind: "command", Label: "命令行", Risk: 2, Dedupe: true,
		Pattern: regexp.MustCompile(`(?i)\b(?:cmd(?:\.exe)?\s+/c|powershell(?:\.exe)?\s+-|\w*sh\s+-c)\s+[^\s"']{1,300}`)},

	// ---- 取证高价值痕迹 ----
	{Kind: "injection", Label: "进程注入 API", Risk: 3, Dedupe: true,
		Pattern: regexp.MustCompile(`(?i)\b(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtMapViewOfSection|SetWindowsHookEx|QueueUserAPC|NtQueueApcThread|RtlCreateUserThread|ptrace|PTRACE_ATTACH)\b`)},
	{Kind: "cred_dump", Label: "凭据窃取痕迹", Risk: 3, Dedupe: true,
		Pattern: regexp.MustCompile(`(?i)\b(?:lsass\.exe|MiniDumpWriteDump|comsvcs\.dll|ntdsutil|mimikatz|sekurlsa|logonpasswords|procdump)\b`)},
	{Kind: "persist", Label: "持久化痕迹", Risk: 3, Dedupe: true,
		Pattern: regexp.MustCompile(`(?i)\b(?:CurrentVersion\\Run|schtasks(?:\.exe)?\s+/?create|crontab\s+-|\.bashrc|\.profile|launchd)\b`)},
	{Kind: "anti_forensic", Label: "反取证痕迹", Risk: 3, Dedupe: true,
		Pattern: regexp.MustCompile(`(?i)\b(?:wevtutil\s+cl|SRDB|TrustedInstaller|delete\s+shadow|wipe\s+memory)\b`)},
	{Kind: "mining", Label: "挖矿痕迹", Risk: 2, Dedupe: true,
		Pattern: regexp.MustCompile(`(?i)\b(?:stratum\+tcp://|xmrig|cryptonight|randomx)\b`)},
	{Kind: "ransom", Label: "勒索痕迹", Risk: 3, Dedupe: true,
		Pattern: regexp.MustCompile(`(?i)\b(?:your files have been encrypted|how[_ ]to[_ ]decrypt|readme\.txt)\b`)},
}

// Indicators 返回全部行为痕迹规则（副本，避免调用方改动内部状态）。
func Indicators() []Indicator {
	out := make([]Indicator, len(indicators))
	copy(out, indicators)
	return out
}

// IndicatorKinds 返回全部分类标识（供 -a 参数校验与帮助使用）。
func IndicatorKinds() []string {
	out := make([]string, 0, len(indicators))
	for _, ind := range indicators {
		out = append(out, ind.Kind)
	}
	return out
}

// LabelOfKind 返回分类标识对应的默认标签（i18n 缺 key 时的回退）。
func LabelOfKind(kind string) string {
	for _, ind := range indicators {
		if ind.Kind == kind {
			return ind.Label
		}
	}
	return kind
}

// BehaviorScanner 从字符串流中提取行为痕迹，并按需去重。
type BehaviorScanner struct {
	kinds map[string]bool // nil 表示启用全部分类
	seen  map[string]bool // Dedupe 规则的去重表
	hits  []BehaviorHit
	max   int // 结果上限（0 表示不限）
}

// NewBehaviorScanner 创建扫描器。kinds 为空表示启用全部分类。
func NewBehaviorScanner(kinds []string, max int) *BehaviorScanner {
	s := &BehaviorScanner{max: max, seen: map[string]bool{}}
	if len(kinds) > 0 {
		s.kinds = map[string]bool{}
		for _, k := range kinds {
			s.kinds[strings.ToLower(strings.TrimSpace(k))] = true
		}
	}
	return s
}

// Full 返回结果是否已达上限。
func (s *BehaviorScanner) Full() bool { return s.max > 0 && len(s.hits) >= s.max }

// Feed 送入一条字符串（来自 ExtractStrings），返回本次命中的痕迹。
func (s *BehaviorScanner) Feed(hit StringHit, region string) []BehaviorHit {
	if s.Full() {
		return nil
	}
	// 上下文取整条字符串并限制长度，便于人工判断痕迹所处语境
	ctx := hit.Value
	if len(ctx) > 160 {
		ctx = ctx[:80] + "…" + ctx[len(ctx)-80:]
	}
	var out []BehaviorHit
	for _, ind := range indicators {
		if s.kinds != nil && !s.kinds[ind.Kind] {
			continue
		}
		m := ind.Pattern.FindString(hit.Value)
		if m == "" {
			continue
		}
		if ind.Dedupe {
			key := ind.Kind + "\x00" + m
			if s.seen[key] {
				continue
			}
			s.seen[key] = true
		}
		b := BehaviorHit{
			Kind: ind.Kind, Label: ind.Label, Risk: ind.Risk,
			Value: m, Offset: hit.Offset, Region: region,
			Enc: hit.Enc, Context: ctx,
		}
		out = append(out, b)
		s.hits = append(s.hits, b)
		if s.Full() {
			break
		}
	}
	return out
}

// Hits 返回全部命中的痕迹（按偏移升序）。
func (s *BehaviorScanner) Hits() []BehaviorHit {
	out := make([]BehaviorHit, len(s.hits))
	copy(out, s.hits)
	sort.Slice(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	return out
}

// KindStat 是一个分类的命中计数。
type KindStat struct {
	Kind  string
	Count int
}

// Count 按分类统计命中数量，按次数降序（次数相同按首次出现顺序）。
func (s *BehaviorScanner) Count() []KindStat {
	m := map[string]int{}
	order := map[string]int{}
	for i, h := range s.hits {
		m[h.Kind]++
		if _, ok := order[h.Kind]; !ok {
			order[h.Kind] = i
		}
	}
	stats := make([]KindStat, 0, len(m))
	for k, n := range m {
		stats = append(stats, KindStat{Kind: k, Count: n})
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Count != stats[j].Count {
			return stats[i].Count > stats[j].Count
		}
		return order[stats[i].Kind] < order[stats[j].Kind]
	})
	return stats
}
