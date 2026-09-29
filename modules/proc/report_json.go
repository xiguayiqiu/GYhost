//go:build (linux && !android) || darwin

// 本文件的构建约束是「模块只在 (linux 且非 android) 或 darwin 上存在」：
//   - Windows 走 WMI/CIM，进程模型与本模块完全不同，不提供该功能
//   - Android / Termux 受限（Android 7+ 起限制访问其它应用的 /proc），
//     procfs 拿不到有用的进程表，不提供该功能
//
// 注意约束里必须显式写 !android：GOOS=android 会同时满足 linux 这个
// 构建标签，只写 linux 的话 Termux 构建仍会把本包编进去。

// JSON 输出（-j）：与 net / mem 一致，JSON 面向管道（jq 等）。
package proc

import (
	"encoding/json"
	"io"
	"runtime"

	"gyhost/internal/proc"
)

// jsonReport 是 -j 的输出结构。
type jsonReport struct {
	Target  jsonTarget   `json:"target"`
	Summary jsonSummary  `json:"summary"`
	List    []jsonProc   `json:"processes,omitempty"`
	Tree    []jsonNode   `json:"tree,omitempty"`
	Users   []jsonUser   `json:"users,omitempty"`
	Threads []jsonThread `json:"threads,omitempty"`
	Detail  *jsonDetail  `json:"detail,omitempty"`
}

// jsonTarget 描述分析目标与运行环境。
type jsonTarget struct {
	Platform string `json:"platform"`
	GOOS     string `json:"goos"`
	GOArch   string `json:"goarch"`
	Query    string `json:"query,omitempty"`
	PID      int    `json:"pid,omitempty"`
	SortBy   string `json:"sort_by"`
}

// jsonSummary 是本次分析的汇总。
type jsonSummary struct {
	TotalProcesses int    `json:"total_processes"`
	Selected       int    `json:"selected"`
	Filtered       int    `json:"filtered_out"`
	TotalThreads   int    `json:"total_threads"`
	TotalFDs       int    `json:"total_fds"`
	TotalRSize     uint64 `json:"total_rss"`
	TotalVSize     uint64 `json:"total_vsize"`
}

// jsonProc 是列表里的一个进程。
type jsonProc struct {
	PID     int      `json:"pid"`
	PPID    int      `json:"ppid"`
	Name    string   `json:"name,omitempty"`
	Exe     string   `json:"exe,omitempty"`
	User    string   `json:"user,omitempty"`
	State   string   `json:"state,omitempty"`
	Threads int      `json:"threads"`
	FDs     int      `json:"fds,omitempty"`
	RSize   uint64   `json:"rss,omitempty"`
	VSize   uint64   `json:"vsize,omitempty"`
	Cmdline []string `json:"cmdline,omitempty"`
}

// jsonNode 是进程树节点。
type jsonNode struct {
	jsonProc
	Depth int `json:"depth"`
}

// jsonUser 是按用户聚合的统计。
type jsonUser struct {
	User    string `json:"user"`
	Count   int    `json:"count"`
	Threads int    `json:"threads"`
	RSize   uint64 `json:"rss"`
	VSize   uint64 `json:"vsize"`
}

// jsonThread 是一个线程。
type jsonThread struct {
	TID   int    `json:"tid"`
	PID   int    `json:"pid"`
	Name  string `json:"name,omitempty"`
	State string `json:"state,omitempty"`
}

// jsonDetail 是单进程详情。
type jsonDetail struct {
	jsonProc
	Start    string   `json:"start,omitempty"`
	Cwd      string   `json:"cwd,omitempty"`
	Arch     string   `json:"arch,omitempty"`
	Env      []string `json:"env,omitempty"`
	FDList   []string `json:"fd_list,omitempty"`
	Modules  []string `json:"modules,omitempty"`
	MapCount int      `json:"map_count,omitempty"`
	ExeCount int      `json:"exe_count,omitempty"`
	// Capabilities 标注该平台上哪些字段拿不到，避免下游误判为“空即没有”。
	Capabilities map[string]bool `json:"capabilities,omitempty"`
}

// writeJSON 输出 JSON 报告。
func writeJSON(dest io.Writer, res *result, opt options) error {
	rep := jsonReport{
		Target: jsonTarget{
			Platform: res.Platform,
			GOOS:     runtime.GOOS,
			GOArch:   runtime.GOARCH,
			PID:      opt.spec2pid(),
			SortBy:   string(opt.sortField),
		},
	}
	for _, p := range res.Selected {
		rep.Summary.TotalProcesses++
		rep.Summary.TotalThreads += p.Threads
		rep.Summary.TotalFDs += p.FDs
		rep.Summary.TotalRSize += p.RSize
		rep.Summary.TotalVSize += p.VSize
	}
	rep.Summary.TotalProcesses = res.Total
	rep.Summary.Selected = len(res.Selected)
	rep.Summary.Filtered = res.Skipped

	if opt.actions[actList] {
		for _, p := range clip(res.Selected, opt.limit) {
			rep.List = append(rep.List, toJSONProc(p))
		}
	}
	if opt.actions[actTree] {
		for _, n := range clipTree(res.Tree, opt.limit) {
			rep.Tree = append(rep.Tree, jsonNode{jsonProc: toJSONProc(n.Process), Depth: n.Depth})
		}
	}
	if opt.actions[actUser] {
		for _, u := range clipUsers(res.Users, opt.limit) {
			rep.Users = append(rep.Users, jsonUser{
				User: u.User, Count: u.Count, Threads: u.Threads,
				RSize: u.RSize, VSize: u.VSize,
			})
		}
	}
	if opt.actions[actThread] {
		for _, t := range clipThreads(res.Threads, opt.limit) {
			rep.Threads = append(rep.Threads, jsonThread{
				TID: t.TID, PID: t.PID, Name: t.Name, State: string(t.State),
			})
		}
	}
	if res.Detail != nil {
		d := *res.Detail
		jd := jsonDetail{
			jsonProc: toJSONProc(d),
			Start:    d.Start, Cwd: d.Cwd, Arch: d.Arch,
			Env: d.Env, FDList: d.FDList, Modules: d.Modules,
			MapCount: d.MapCount, ExeCount: d.ExeCount,
			Capabilities: map[string]bool{
				"env":     len(d.Env) > 0,
				"fd_list": len(d.FDList) > 0,
			},
		}
		rep.Detail = &jd
	}
	enc := json.NewEncoder(dest)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// spec2pid 返回目标 pid（仅用于 JSON 的 target 段）。
func (o options) spec2pid() int {
	if o.spec == "" || o.isName {
		return 0
	}
	s, err := proc.ParseSpec(o.spec)
	if err != nil {
		return 0
	}
	if s.Self {
		return proc.SelfPID()
	}
	return s.PID
}

// toJSONProc 把进程转成 JSON 结构。
func toJSONProc(p proc.Process) jsonProc {
	return jsonProc{
		PID: p.PID, PPID: p.PPID, Name: p.Name, Exe: p.Exe, User: p.User,
		State: string(p.State), Threads: p.Threads, FDs: p.FDs,
		RSize: p.RSize, VSize: p.VSize, Cmdline: p.Cmdline,
	}
}

// ---- 按 -n 截断（0 表示不限） ----

func clip(list []proc.Process, n int) []proc.Process {
	if n > 0 && len(list) > n {
		return list[:n]
	}
	return list
}

func clipTree(list []proc.TreeNode, n int) []proc.TreeNode {
	if n > 0 && len(list) > n {
		return list[:n]
	}
	return list
}

func clipUsers(list []proc.UserStat, n int) []proc.UserStat {
	if n > 0 && len(list) > n {
		return list[:n]
	}
	return list
}

func clipThreads(list []proc.Thread, n int) []proc.Thread {
	if n > 0 && len(list) > n {
		return list[:n]
	}
	return list
}
