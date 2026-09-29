//go:build (linux && !android) || darwin

// 本文件的构建约束是「模块只在 (linux 且非 android) 或 darwin 上存在」：
//   - Windows 走 WMI/CIM，进程模型与本模块完全不同，不提供该功能
//   - Android / Termux 受限（Android 7+ 起限制访问其它应用的 /proc），
//     procfs 拿不到有用的进程表，不提供该功能
//
// 注意约束里必须显式写 !android：GOOS=android 会同时满足 linux 这个
// 构建标签，只写 linux 的话 Termux 构建仍会把本包编进去。

// 分析编排：取进程 → 过滤 → 排序 → 分动作渲染。
//
// 这一层与操作系统无关：所有取数都通过 internal/proc.Backend 完成，
// 因此同一份代码在 Linux(/proc) 与 macOS(libproc) 上产出同一份报告。
package proc

import (
	"errors"
	"io"
	"strings"

	"gyhost/internal/i18n"
	"gyhost/internal/proc"
)

// 动作标识（-a）。
const (
	actList   = "list"   // 进程列表
	actTree   = "tree"   // 父子树
	actUser   = "user"   // 按用户聚合统计
	actThread = "thread" // 线程列表
	actDetail = "detail" // 单进程详情
	actAll    = "all"    // 以上全部
)

// allActions 是 -a all 展开后的动作集合。
var allActions = []string{actList, actTree, actUser}

// allNames 是 -a 可取的全部动作名。
var allNames = append([]string{actAll}, append(allActions, actThread, actDetail)...)

// ActionNames 返回 -a 的全部合法取值（供帮助文案使用）。
func ActionNames() []string { return allNames }

func isValidAction(a string) bool {
	for _, n := range allNames {
		if n == a {
			return true
		}
	}
	return false
}

// resolveActions 解析 -a。
//
// 默认只列 list：树和用户统计在几百个进程上会刷屏，
// 需要时显式点名；thread / detail 依赖 -i，本来就要显式给。
func resolveActions(list []string) (map[string]bool, error) {
	if len(list) == 0 {
		return map[string]bool{actList: true}, nil
	}
	sel := map[string]bool{}
	for _, item := range list {
		for _, part := range strings.Split(item, ",") {
			p := strings.ToLower(strings.TrimSpace(part))
			switch {
			case p == "":
			case p == actAll:
				for _, a := range allActions {
					sel[a] = true
				}
			case isValidAction(p):
				sel[p] = true
			default:
				return nil, errors.New(i18n.Tf("proc.err.bad_action", p))
			}
		}
	}
	if len(sel) == 0 {
		sel[actList] = true
	}
	return sel, nil
}

// result 是一次分析的全部产出。
type result struct {
	Platform string
	Total    int // 系统进程总数
	Selected []proc.Process
	Tree     []proc.TreeNode
	Users    []proc.UserStat
	Threads  []proc.Thread
	Detail   *proc.Process
	// Target 是 -i 解析出的目标描述。
	Target string
	// Skipped 是被过滤掉的进程数。
	Skipped int
}

// runAnalysis 是主流程。
func runAnalysis(dest io.Writer, notice func(NoticeLevel, string), opt options) error {
	res := &result{Platform: backend.Name()}

	// -r 走自己的两段式流程：先扫 /proc 清单，再按指定恢复
	if opt.recover.Present() {
		return runRecover(dest, notice, opt)
	}

	// 1) 解析 -i：detail/thread 需要具体目标，其它动作允许按名字收敛
	var targetPID int
	needDetail := opt.actions[actDetail] || opt.actions[actThread]
	if opt.spec != "" {
		p, err := resolveTarget(opt, needDetail)
		if err != nil {
			return err
		}
		targetPID = p
	}

	// 2) 取进程表
	all, err := backend.List()
	if err != nil {
		return wrapListError(err)
	}
	res.Total = len(all)

	// 3) 过滤 + 排序
	filtered := proc.Apply(all, proc.Filter{
		Query:      opt.filter,
		User:       opt.user,
		Parent:     opt.parent,
		NoKernel:   opt.noKernel,
		MinThreads: opt.minThreads,
		MinRSize:   uint64(opt.minRSize),
	})
	// -i 给的是程序名时，用它进一步收敛（detail 除外：要的就是那一个）
	if opt.isName && !needDetail {
		filtered = proc.FindProcess(filtered, opt.spec)
	}
	res.Selected = filtered
	res.Skipped = len(all) - len(filtered)
	proc.Sort(res.Selected, opt.sortField)

	if targetPID > 0 {
		res.Target = i18n.Tf("proc.info.target", targetPID)
	}

	// 4) 按动作补充数据
	if opt.actions[actTree] {
		res.Tree = proc.BuildTree(res.Selected)
	}
	if opt.actions[actUser] {
		res.Users = proc.ByUser(res.Selected)
	}
	if opt.actions[actThread] {
		ths, err := backend.Threads(targetPID)
		if err != nil {
			notice(NoticeWarn, i18n.Tf("proc.warn.threads", targetPID, err))
		}
		res.Threads = ths
	}
	if opt.actions[actDetail] {
		d, err := backend.Detail(targetPID)
		if err != nil {
			return wrapDetailError(err, targetPID)
		}
		res.Detail = &d
	}

	// 5) 渲染
	if opt.jsonOut {
		return writeJSON(dest, res, opt)
	}
	return renderReport(dest, res, opt)
}

// resolveTarget 把 -i 解析成 pid。
//
// 纯数字直接当 pid；否则按程序名在进程表里找，
// 命中多个时取最靠前的那个并给出提示（列表场景可配合 -a list 自行挑选）。
func resolveTarget(opt options, needDetail bool) (int, error) {
	if !opt.isName {
		s, err := proc.ParseSpec(opt.spec)
		if err != nil {
			return 0, errors.New(i18n.Tf("proc.err.bad_target", opt.spec))
		}
		if s.Self {
			return proc.SelfPID(), nil
		}
		return s.PID, nil
	}
	all, err := backend.List()
	if err != nil {
		return 0, wrapListError(err)
	}
	matched := proc.FindProcess(all, opt.spec)
	if len(matched) == 0 {
		return 0, errors.New(i18n.Tf("proc.err.no_match", opt.spec))
	}
	if len(matched) > 1 && needDetail {
		// 详情要精确：让用户用 pid 明确指定，避免分析错进程
		return 0, errors.New(i18n.Tf("proc.err.ambiguous", opt.spec, len(matched)))
	}
	return matched[0].PID, nil
}

// wrapListError 翻译枚举进程失败。
func wrapListError(err error) error {
	switch {
	case errors.Is(err, proc.ErrUnsupported):
		return errors.New(i18n.Tf("proc.err.unsupported", backend.Name()))
	case errors.Is(err, proc.ErrPrivilege):
		return errors.New(i18n.Tf("proc.err.privilege", backend.Name(), backend.PrivilegeHint()))
	default:
		return errors.New(i18n.Tf("proc.err.list", backend.Name(), err))
	}
}

// wrapDetailError 翻译取详情失败。
func wrapDetailError(err error, pid int) error {
	switch {
	case errors.Is(err, proc.ErrNoProcess):
		return errors.New(i18n.Tf("proc.err.no_process", pid))
	case errors.Is(err, proc.ErrPrivilege):
		return errors.New(i18n.Tf("proc.err.privilege", backend.Name(), backend.PrivilegeHint()))
	default:
		return errors.New(i18n.Tf("proc.err.detail", pid, err))
	}
}
