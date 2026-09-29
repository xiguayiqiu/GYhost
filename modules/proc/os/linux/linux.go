//go:build linux && !android

// Package linux 实现 Linux 平台的进程分析，数据全部来自 procfs。
//
// 信息源映射：
//
//	/proc/<pid>/stat      状态、ppid、虚拟内存、启动时钟
//	/proc/<pid>/status    用户、资源限制、线程数
//	/proc/<pid>/cmdline    完整命令行
//	/proc/<pid>/environ   环境变量
//	/proc/<pid>/exe        可执行文件
//	/proc/<pid>/cwd        工作目录
//	/proc/<pid>/maps       内存映射摘要
//	/proc/<pid>/fd/        打开的文件
//	/proc/<pid>/task/<tid> 线程
//
// 权限：读自己的进程无需任何权限；读别的用户需要 root。
package linux

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gyhost/internal/proc"
)

// Backend 是 Linux 的 proc.Backend 实现。
type Backend struct{}

// New 创建 Linux 后端。
func New() proc.Backend { return &Backend{} }

// Name 返回平台标识。
func (b *Backend) Name() string { return "linux" }

// Supported 恒为 true：procfs 在所有 Linux 内核上都存在。
func (b *Backend) Supported() bool { return true }

// PrivilegeHint 返回权限不足时的提示。
func (b *Backend) PrivilegeHint() string {
	return "need root to inspect other users' processes: sudo ./gyhost proc ..."
}

// procRoot 允许测试时替换 procfs 根目录。
var procRoot = "/proc"

func procPath(parts ...string) string {
	return filepath.Join(append([]string{procRoot}, parts...)...)
}

// List 遍历 /proc 列出所有进程。
func (b *Backend) List() ([]proc.Process, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", proc.ErrPrivilege, err)
	}
	var out []proc.Process
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		p, err := readProcess(pid)
		if err != nil {
			continue // 进程可能刚好退出
		}
		out = append(out, p)
	}
	return out, nil
}

// readProcess 读取单个进程的全部信息。
func readProcess(pid int) (proc.Process, error) {
	p := proc.Process{PID: pid, Arch: archName(), State: proc.StateUnknown}
	readStat(&p)
	readStatus(&p)
	readCmdline(&p)
	// 名字优先级：exe 基名 > stat 的 comm > argv[0] 基名。
	// 绝不能用 argv[0]：Electron 的 zygote 会把 "code --type=zygote"
	// 整串塞进 argv[0]，直接拿它当进程名会让一堆进程显示成同一长串。
	if exe, err := os.Readlink(procPath(strconv.Itoa(pid), "exe")); err == nil {
		p.Exe = exe
		p.Name = filepath.Base(exe)
	}
	if p.Name == "" && len(p.Cmdline) > 0 {
		if first := strings.Fields(p.Cmdline[0]); len(first) > 0 {
			p.Name = filepath.Base(first[0])
		}
	}
	if p.Name == "" {
		p.Name = fmt.Sprintf("pid%d", pid)
	}
	if cwd, err := os.Readlink(procPath(strconv.Itoa(pid), "cwd")); err == nil {
		p.Cwd = cwd
	}
	p.Modules = mappedFiles(pid)
	p.FDs = fdCount(pid)
	return p, nil
}

// readStat 解析 /proc/<pid>/stat。
func readStat(p *proc.Process) {
	raw, err := os.ReadFile(procPath(strconv.Itoa(p.PID), "stat"))
	if err != nil {
		return
	}
	s := string(raw)
	// comm 字段带括号且可能含空格/括号，必须从右往左找右括号
	rp := strings.LastIndex(s, ")")
	if rp < 0 || rp+2 >= len(s) {
		return
	}
	fields := strings.Fields(s[rp+2:])
	if len(fields) > 0 {
		p.State = proc.State(fields[0])
	}
	if len(fields) > 1 {
		p.PPID, _ = strconv.Atoi(fields[1])
	}
	// /proc/<pid>/stat 在 comm 之后的字段下标（0 = state）：
	// 19=starttime 20=vsize 21=rss(页) 17=num_threads
	if len(fields) > statNumThreads {
		p.Threads, _ = strconv.Atoi(fields[statNumThreads])
	}
	if len(fields) > statStartTime {
		startTicks, _ := strconv.ParseUint(fields[statStartTime], 10, 64)
		if t, err := bootTime(); err == nil {
			const clkTck = 100 // CONFIG_HZ 的通用值，Go 未暴露 sysconf(_SC_CLK_TCK)
			p.Start = t.Add(time.Duration(float64(startTicks) / clkTck * float64(time.Second))).
				Format("2006-01-02 15:04:05")
		}
	}
	if len(fields) > statVSize {
		p.VSize, _ = strconv.ParseUint(fields[statVSize], 10, 64)
	}
	if len(fields) > statRSS {
		p.RSize, _ = strconv.ParseUint(fields[statRSS], 10, 64) // 单位是页
		p.RSize *= uint64(os.Getpagesize())
	}
	if lp := strings.IndexByte(s, '('); lp >= 0 && rp > lp && p.Name == "" {
		p.Name = s[lp+1 : rp]
	}
}

// readStatus 解析 /proc/<pid>/status：用户、线程数、启动时间。
func readStatus(p *proc.Process) {
	raw, err := os.ReadFile(procPath(strconv.Itoa(p.PID), "status"))
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(line, "Uid:"):
			f := strings.Fields(line)
			if len(f) >= 2 {
				if u, err := strconv.Atoi(f[1]); err == nil {
					p.User = uidName(u)
				}
			}
		case strings.HasPrefix(line, "Threads:"):
			if n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Threads:"))); err == nil {
				p.Threads = n
			}
		}
	}
}

// readCmdline 解析 /proc/<pid>/cmdline（\0 分隔）。
func readCmdline(p *proc.Process) {
	raw, err := os.ReadFile(procPath(strconv.Itoa(p.PID), "cmdline"))
	if err != nil {
		return
	}
	for _, part := range strings.Split(string(raw), "\x00") {
		if part != "" {
			p.Cmdline = append(p.Cmdline, part)
		}
	}
}

// Threads 列出进程线程。
func (b *Backend) Threads(pid int) ([]proc.Thread, error) {
	dir := procPath(strconv.Itoa(pid), "task")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsPermission(err) {
			return nil, fmt.Errorf("%w: pid %d: %v", proc.ErrPrivilege, pid, err)
		}
		return nil, fmt.Errorf("%w: pid %d: %v", proc.ErrNoProcess, pid, err)
	}
	var out []proc.Thread
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil || tid <= 0 {
			continue
		}
		th := proc.Thread{TID: tid, PID: pid}
		if raw, err := os.ReadFile(procPath(strconv.Itoa(pid), "task", e.Name(), "stat")); err == nil {
			s := string(raw)
			lp, rp := strings.Index(s, "("), strings.LastIndex(s, ")")
			if lp >= 0 && rp > lp {
				th.Name = s[lp+1 : rp]
			}
			if rp >= 0 && rp+2 < len(s) {
				if f := strings.Fields(s[rp+2:]); len(f) > 0 {
					th.State = proc.State(f[0])
				}
			}
		}
		out = append(out, th)
	}
	return out, nil
}

// Detail 取进程深度信息：环境变量、打开的文件、内存映射摘要、启动时间。
func (b *Backend) Detail(pid int) (proc.Process, error) {
	p, err := readProcess(pid)
	if err != nil {
		return p, err
	}
	// 环境变量
	if raw, err := os.ReadFile(procPath(strconv.Itoa(pid), "environ")); err == nil {
		for _, part := range strings.Split(string(raw), "\x00") {
			if part != "" {
				p.Env = append(p.Env, part)
			}
		}
	}
	// 打开的文件
	p.FDList = openFiles(pid)
	p.FDs = len(p.FDList)
	// 内存映射摘要
	if maps, execs := mapSummary(pid); maps > 0 {
		p.MapCount, p.ExeCount = maps, execs
	}
	return p, nil
}

// fdCount 统计打开的文件描述符数量。
//
// 只做 readdir、不 readlink：后者要对每个 fd 解一次符号链接，
// 遍历全系统进程时代价明显；取详细路径留给 Detail。
func fdCount(pid int) int {
	entries, err := os.ReadDir(procPath(strconv.Itoa(pid), "fd"))
	if err != nil {
		return 0
	}
	return len(entries)
}

// openFiles 列出 /proc/<pid>/fd/ 指向的目标。
func openFiles(pid int) []string {
	dir := procPath(strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(dir, e.Name()))
		if err != nil {
			// 权限不足时至少把 fd 号列出来
			out = append(out, "fd:"+e.Name())
			continue
		}
		out = append(out, target)
	}
	return out
}

// mappedFiles 汇总进程已加载的可执行文件。
func mappedFiles(pid int) []string {
	return mapPaths(pid, true)
}

// mapSummary 统计内存映射区域数与其中的可执行文件数。
func mapSummary(pid int) (int, int) {
	paths := mapPaths(pid, false)
	uniq := map[string]bool{}
	for _, p := range paths {
		uniq[p] = true
	}
	return len(paths), len(uniq)
}

// mapPaths 解析 /proc/<pid>/maps。
//
// execOnly 为 true 时只返回带执行权限的宿主文件（即已加载的模块）。
func mapPaths(pid int, execOnly bool) []string {
	f, err := os.Open(procPath(strconv.Itoa(pid), "maps"))
	if err != nil {
		return nil
	}
	defer f.Close()
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		path := strings.Join(fields[5:], " ")
		if path == "" || seen[path] || strings.HasPrefix(path, "[") {
			continue
		}
		if execOnly && !strings.Contains(fields[1], "x") {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	return out
}

// threadCount 统计线程数（读不到时返回 0）。
func threadCount(pid int) int {
	entries, err := os.ReadDir(procPath(strconv.Itoa(pid), "task"))
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err == nil {
			n++
		}
	}
	return n
}

// bootTime 读 /proc/stat 的 btime。
func bootTime() (time.Time, error) {
	raw, err := os.ReadFile(procPath("stat"))
	if err != nil {
		return time.Time{}, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "btime ") {
			sec, err := strconv.ParseInt(strings.TrimSpace(line[6:]), 10, 64)
			if err != nil {
				return time.Time{}, err
			}
			return time.Unix(sec, 0), nil
		}
	}
	return time.Time{}, fmt.Errorf("btime not found")
}

// uidName 把 uid 映射成用户名。
func uidName(uid int) string {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil && u != nil {
		return u.Username
	}
	return strconv.Itoa(uid)
}

// /proc/<pid>/stat 中 comm 之后的关键字段下标。
//
// 0=state、1=ppid、17=num_threads、19=starttime、20=vsize、21=rss。
// 这几个下标与内核 proc(5) 文档一致；写错一位会让整列数据静默偏移，
// 因此集中成常量而不是散落魔法数。
const (
	statNumThreads = 17
	statStartTime  = 19
	statVSize      = 20
	statRSS        = 21
)

// archName 返回当前架构名（同机读取，目标进程架构必然一致）。
func archName() string {
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return "unknown"
	}
	return cBytesToString(uts.Machine[:])
}

// cBytesToString 把 syscall 的 C 风格字符数组（到 NUL 为止）转成字符串。
func cBytesToString(b []int8) string {
	buf := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}
