// Package cliflag 提供「值可省略」的 flag 参数支持。
//
// 为什么需要它：Go 的 flag 包不支持可选值参数，
// 写 `-l` 不给值会直接报 “flag needs an argument”。
// 而命令行上「列全部」和「只列某个」用同一个参数表达很自然：
//
//	gyhost mem -l            → 列出全部程序
//	gyhost mem -l 1234       → 只看 pid 1234
//	gyhost mem -l=1234       → 同上
//
// 解法是在调用 flag.Parse 之前扫一遍原始参数，
// 给「裸出现且后面没有值」的参数补一个哨兵值（Normalize），
// 再由 Optional 这个 flag.Value 解析哨兵 → “出现过但无值”。
package cliflag

import "strings"

// Optional 表示一个值可省略的 flag 参数。
type Optional struct {
	// sentinel 是内部用来区分「出现过但没给值」的标记。
	// 取一个用户不会输入的字符串即可。
	sentinel string
	// present 记录参数是否出现过。
	present bool
	// value 是实际取值；出现但没给值时为空串。
	value string
}

// New 创建一个 Optional，sentinel 是内部哨兵值。
func New(sentinel string) *Optional { return &Optional{sentinel: sentinel} }

// Present 报告该参数是否出现过。
func (o *Optional) Present() bool { return o.present }

// Value 返回实际取值（出现过但没给值时为空串）。
func (o *Optional) Value() string { return o.value }

// HasValue 报告该参数是否出现过并且带了值。
func (o *Optional) HasValue() bool { return o.present && o.value != "" }

// String 实现 flag.Value，用于回显当前取值。
func (o *Optional) String() string {
	if !o.present {
		return ""
	}
	if o.value == "" {
		return o.sentinel
	}
	return o.value
}

// Set 实现 flag.Value：哨兵值表示「出现过但无值」。
func (o *Optional) Set(v string) error {
	v = strings.TrimSpace(v)
	o.present = true
	if v == o.sentinel {
		o.value = ""
		return nil
	}
	o.value = v
	return nil
}

// Normalize 给 args 里「裸出现、后面不跟值」的 names 补上哨兵值。
//
// 判定「后面没有值」：不存在，或下一个 token 以 - 开头（是另一个参数）。
// 已经是 -name=value 形式的不会被改写。
func Normalize(args []string, sentinel string, names ...string) []string {
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	out := make([]string, 0, len(args)+len(names))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !want[a] {
			out = append(out, a)
			continue
		}
		// 下一个 token 是值时原样保留，交给 flag 自己解析
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			out = append(out, a, args[i+1])
			i++
			continue
		}
		// 裸参数：补哨兵
		out = append(out, a+"="+sentinel)
	}
	return out
}
