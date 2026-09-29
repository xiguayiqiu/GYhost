// JSON 输出（-j）：与 net 模块一致，JSON 面向管道（jq 等），
// 因此不与 -c（恢复文件落盘）同时使用。
package mem

import (
	"encoding/json"
	"io"
	"runtime"

	"gyhost/internal/i18n"
	memcore "gyhost/internal/mem"
)

// jsonReport 是 -j 的输出结构。
type jsonReport struct {
	Target    jsonTarget     `json:"target"`
	Summary   jsonSummary    `json:"summary"`
	Maps      []jsonRegion   `json:"maps,omitempty"`
	Entropy   []jsonEntropy  `json:"entropy,omitempty"`
	Hashes    []jsonHash     `json:"hashes,omitempty"`
	Behaviors []jsonBehavior `json:"behaviors,omitempty"`
	Strings   []jsonString   `json:"strings,omitempty"`
	Carved    []jsonCarved   `json:"carved,omitempty"`
}

// jsonTarget 描述分析目标。
type jsonTarget struct {
	Kind   string `json:"kind"`
	Input  string `json:"input"`
	PID    int    `json:"pid,omitempty"`
	Name   string `json:"name,omitempty"`
	Exe    string `json:"exe,omitempty"`
	Arch   string `json:"arch,omitempty"`
	User   string `json:"user,omitempty"`
	Start  string `json:"start,omitempty"`
	VSize  uint64 `json:"vsize,omitempty"`
	GoOS   string `json:"goos"`
	GoArch string `json:"goarch"`
}

// jsonSummary 是本次分析的统计汇总。
type jsonSummary struct {
	Regions       int             `json:"regions"`
	Selected      int             `json:"selected"`
	Skipped       int             `json:"skipped"`
	ScannedBytes  uint64          `json:"scanned_bytes"`
	ScannedOK     int             `json:"scanned_regions"`
	ScannedFailed int             `json:"failed_regions"`
	ModuleCount   int             `json:"modules,omitempty"`
	ByKind        map[string]int  `json:"by_kind"`
	Total         memcore.HashSet `json:"total_hash,omitempty"`
}

// jsonRegion 是一个内存区域。
type jsonRegion struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
	Size  uint64 `json:"size"`
	Perm  string `json:"perm"`
	Kind  string `json:"kind"`
	Path  string `json:"path,omitempty"`
}

// jsonEntropy 是一个区域的熵。
type jsonEntropy struct {
	jsonRegion
	Entropy float64 `json:"entropy"`
	Class   string  `json:"class"`
}

// jsonHash 是一个区域的哈希。
type jsonHash struct {
	jsonRegion
	MD5    string `json:"md5"`
	SHA256 string `json:"sha256"`
}

// jsonBehavior 是一条行为痕迹。
type jsonBehavior struct {
	Kind   string `json:"kind"`
	Label  string `json:"label,omitempty"`
	Risk   int    `json:"risk"`
	Offset uint64 `json:"offset"`
	Region string `json:"region,omitempty"`
	Enc    string `json:"enc"`
	Value  string `json:"value"`
}

// jsonString 是一条字符串。
type jsonString struct {
	Offset uint64 `json:"offset"`
	Enc    string `json:"enc"`
	Value  string `json:"value"`
}

// jsonCarved 是一个恢复出来的文件。
type jsonCarved struct {
	Type      string `json:"type"`
	Offset    uint64 `json:"offset"`
	Size      int    `json:"size"`
	Score     int    `json:"score"`
	SHA256    string `json:"sha256"`
	Truncated bool   `json:"truncated,omitempty"`
	Saved     string `json:"saved,omitempty"`
}

// writeJSON 输出 JSON 报告。
func writeJSON(dest io.Writer, res *result, opt options) error {
	rep := jsonReport{
		Target: jsonTarget{
			Kind:   res.Kind,
			Input:  opt.spec,
			PID:    res.Info.PID,
			Name:   res.Info.Name,
			Exe:    res.Info.Exe,
			Arch:   res.Info.Arch,
			User:   res.Info.User,
			Start:  res.Info.StartTime,
			VSize:  res.Info.TotalMemory,
			GoOS:   runtime.GOOS,
			GoArch: runtime.GOARCH,
		},
		Summary: jsonSummary{
			Regions:       len(res.Regions),
			Selected:      len(res.Selected),
			Skipped:       res.Skipped,
			ScannedBytes:  res.ScannedBytes,
			ScannedOK:     res.ScannedRegion,
			ScannedFailed: res.FailedRegion,
			ModuleCount:   len(res.Info.Modules),
			ByKind:        map[string]int{},
			Total:         res.TotalHash,
		},
	}
	for _, r := range res.Regions {
		rep.Summary.ByKind[r.Kind]++
	}
	if opt.actions[actMaps] {
		for _, r := range res.Selected {
			rep.Maps = append(rep.Maps, toJSONRegion(r))
		}
	}
	if opt.actions[actEntropy] {
		for _, m := range res.RegionEntropy {
			rep.Entropy = append(rep.Entropy, jsonEntropy{
				jsonRegion: toJSONRegion(m.Region),
				Entropy:    m.Entropy,
				Class:      m.Class.String(),
			})
		}
	}
	if opt.actions[actHash] {
		for _, m := range res.RegionHash {
			rep.Hashes = append(rep.Hashes, jsonHash{
				jsonRegion: toJSONRegion(m.Region),
				MD5:        m.Hash.MD5,
				SHA256:     m.Hash.SHA256,
			})
		}
	}
	if opt.actions[actBehavior] {
		for _, b := range res.Behaviors {
			rep.Behaviors = append(rep.Behaviors, jsonBehavior{
				Kind: b.Kind, Label: i18n.Tf("mem.kind." + b.Kind), Risk: b.Risk,
				Offset: b.Offset, Region: b.Region, Enc: b.Enc.String(), Value: b.Value,
			})
		}
	}
	if opt.actions[actStrings] {
		for _, s := range res.Strings {
			rep.Strings = append(rep.Strings, jsonString{
				Offset: s.Offset, Enc: s.Enc.String(), Value: s.Value,
			})
		}
	}
	if opt.actions[actCarve] {
		for i, c := range res.Carved {
			entry := jsonCarved{
				Type: c.Type, Offset: c.Offset, Size: c.Size,
				Score: c.Score, SHA256: c.Hash.SHA256, Truncated: c.Truncated,
			}
			if i < len(res.CarveSaved) {
				entry.Saved = res.CarveSaved[i]
			}
			rep.Carved = append(rep.Carved, entry)
		}
	}
	enc := json.NewEncoder(dest)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// toJSONRegion 把区域转成 JSON 结构。
func toJSONRegion(r memcore.Region) jsonRegion {
	return jsonRegion{
		Start: r.Start, End: r.End, Size: r.Size(),
		Perm: r.Perm, Kind: r.Kind, Path: r.Path,
	}
}

// jsonProcList 是 -l -j 的输出结构。
type jsonProcList struct {
	Query         string     `json:"query,omitempty"`
	All           bool       `json:"all"`
	TotalPrograms int        `json:"total_programs"`
	TotalThreads  int        `json:"total_threads"`
	Truncated     int        `json:"truncated,omitempty"`
	Unsupported   bool       `json:"threads_unsupported,omitempty"`
	Platform      string     `json:"platform"`
	Programs      []jsonProc `json:"programs"`
}

// jsonProc 是一个程序及其子线程。
type jsonProc struct {
	PID     int          `json:"pid"`
	PPID    int          `json:"ppid,omitempty"`
	Name    string       `json:"name,omitempty"`
	Exe     string       `json:"exe,omitempty"`
	Arch    string       `json:"arch,omitempty"`
	User    string       `json:"user,omitempty"`
	Threads int          `json:"threads"`
	List    []jsonThread `json:"thread_list,omitempty"`
}

// jsonThread 是一个线程。
type jsonThread struct {
	TID   int    `json:"tid"`
	State string `json:"state,omitempty"`
	Name  string `json:"name,omitempty"`
}

// writeProcessListJSON 输出 -l 的 JSON 结果。
func writeProcessListJSON(dest io.Writer, res *procListResult, opt options) error {
	out := jsonProcList{
		Query:         res.Query,
		All:           res.All,
		TotalPrograms: res.TotalPrograms,
		TotalThreads:  res.TotalThreads,
		Truncated:     res.Truncated,
		Unsupported:   res.Unsupported,
		Platform:      backend.Name(),
	}
	procs := res.Programs
	if opt.limit > 0 && len(procs) > opt.limit {
		procs = procs[:opt.limit]
	}
	for _, p := range procs {
		jp := jsonProc{
			PID: p.PID, PPID: p.PPID, Name: p.Name, Exe: p.Exe,
			Arch: p.Arch, User: p.User,
		}
		// 线程数取实际列出的条数；枚举失败时退回 List() 拿到的计数
		jp.Threads = len(res.Threads[p.PID])
		if jp.Threads == 0 {
			jp.Threads = p.ThreadCount
		}
		for _, th := range res.Threads[p.PID] {
			jp.List = append(jp.List, jsonThread{TID: th.TID, State: th.State, Name: th.Name})
		}
		out.Programs = append(out.Programs, jp)
	}
	enc := json.NewEncoder(dest)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
