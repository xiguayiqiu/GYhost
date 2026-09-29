// Package linux 实现 Linux/ Android（含 Termux）平台的活体内存访问。
//
// 数据来源全部是 procfs：
//   - 进程列表：/proc/<pid>/{stat,cmdline,status,exe}
//   - 内存布局：/proc/<pid>/maps
//   - 内存内容：/proc/<pid>/mem（pread 语义，可跨页读取）
//
// 权限：读取其它用户的进程需要 root；读取自己的进程无需任何权限。
//go:build linux || android

package linux

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"gyhost/internal/mem"
)

// Backend 是 Linux 的 mem.Backend 实现。
type Backend struct{}

// New 创建 Linux 后端。
func New() mem.Backend { return &Backend{} }

// Name 返回平台标识。
func (b *Backend) Name() string { return "linux" }

// Supported 恒为 true：procfs 在所有 Linux 内核上都存在。
func (b *Backend) Supported() bool { return true }

// PrivilegeHint 返回权限不足时的提示。
func (b *Backend) PrivilegeHint() string {
	return "need root (or read your own process): sudo gyhost mem -i <pid> ..."
}

// procRoot 允许测试时替换 procfs 根目录。
var procRoot = "/proc"

func procPath(parts ...string) string {
	return filepath.Join(append([]string{procRoot}, parts...)...)
}

// List 遍历 /proc 列出所有进程。
func (b *Backend) List() ([]mem.ProcessInfo, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", mem.ErrPrivilege, err)
	}
	var out []mem.ProcessInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		// 内核线程没有 cmdline也没有可读的 exe 链接，跳过（对取证没有价值）；
		// 其它用户进程的 exe 可能因权限读不到，那种仍然要列出来，
		// 只是名字退回到 stat 的 comm —— -l 的语义是「显示所有程序」。
		if !hasUsefulIdentity(e.Name()) {
			continue
		}
		if info, err := readProcessInfo(pid); err == nil {
			info.ThreadCount = threadCount(pid)
			out = append(out, info)
		}
	}
	return out, nil
}

// hasUsefulIdentity 判断 /proc/<pid> 是否是一个“用户可见”的进程。
//
// 判据按可靠性排序：
//  1. cmdline 非空 —— 一定是用户程序（内核线程的 cmdline 恒为空）
//  2. exe 软链接存在 —— 用户程序
//  3. exe 读不了但报的是“权限不足” —— 也是用户程序，只是我们无权看
//     （内核线程的 exe 链接根本不存在，报的是 ENOENT）
//
// 注意不能靠 ppid==0 判断：只有 kthreadd 自己 ppid 为 0，
// ksoftirqd/N（常见的内核线程）ppid 分别是 2、3…… 用 errno 才可靠。
func hasUsefulIdentity(pidDir string) bool {
	if raw, err := os.ReadFile(procPath(pidDir, "cmdline")); err == nil {
		for _, b := range raw {
			if b != 0 {
				return true
			}
		}
	}
	_, err := os.Readlink(procPath(pidDir, "exe"))
	if err == nil {
		return true
	}
	// 链接不存在 → 内核线程；其它错误（多为权限）→ 当作用户程序处理
	return !errors.Is(err, fs.ErrNotExist)
}

// readProcessInfo 读取单个进程的信息。
func readProcessInfo(pid int) (mem.ProcessInfo, error) {
	info := mem.ProcessInfo{PID: pid, Arch: archName()}

	// /proc/<pid>/stat：第 4 个字段是 exe 名（含括号，可能含空格）
	if raw, err := os.ReadFile(procPath(strconv.Itoa(pid), "stat")); err == nil {
		s := string(raw)
		if i := strings.LastIndex(s, ")"); i >= 0 && i+2 < len(s) {
			fields := strings.Fields(s[i+2:])
			// fields[0]=state, [1]=ppid, ...
			if len(fields) > 1 {
				info.PPID, _ = strconv.Atoi(fields[1])
			}
			if len(fields) > 19 {
				// fields[19]=vsize
				if v, err := strconv.ParseUint(fields[19], 10, 64); err == nil {
					info.TotalMemory = v
				}
			}
		}
		if j := strings.IndexByte(s, '('); j >= 0 {
			info.Name = s[j+1 : strings.LastIndex(s, ")")]
		}
	}
	// /proc/<pid>/cmdline：用 \0 分隔
	//
	// 注意 argv[0] 未必只是程序名：Electron 的 zygote 进程会把
	// "code --type=zygote" 整串塞进 argv[0]，因此不能拿它当进程名。
	// 进程名以 exe 软链接 / stat 的 comm 为准，cmdline 只用于展示。
	if raw, err := os.ReadFile(procPath(strconv.Itoa(pid), "cmdline")); err == nil {
		for _, part := range strings.Split(string(raw), "\x00") {
			if part != "" {
				info.Cmdline = append(info.Cmdline, part)
			}
		}
	}
	// exe 软链接：进程名的首选来源
	if exe, err := os.Readlink(procPath(strconv.Itoa(pid), "exe")); err == nil {
		info.Exe = exe
		info.Name = filepath.Base(exe)
	} else if strings.Contains(err.Error(), "permission denied") {
		info.Exe = info.Name + " (permission denied)"
	}
	// exe 读不到时退回 stat 的 comm（上限 15 字符），再不行才用 argv[0]
	if info.Name == "" && len(info.Cmdline) > 0 {
		info.Name = filepath.Base(strings.Fields(info.Cmdline[0])[0])
	}
	// /proc/<pid>/status：Uid 与启动时钟
	if raw, err := os.ReadFile(procPath(strconv.Itoa(pid), "status")); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			switch {
			case strings.HasPrefix(line, "Uid:"):
				f := strings.Fields(line)
				if len(f) >= 2 {
					if u, err := strconv.Atoi(f[1]); err == nil {
						info.User = uidName(u)
					} else {
						info.User = f[1]
					}
				}
			case strings.HasPrefix(line, "Name:"):
				if info.Name == "" {
					info.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
				}
			}
		}
	}
	if t, ok := processStart(pid); ok {
		info.StartTime = t
	}
	info.Modules = mappedFiles(pid)
	return info, nil
}

// mappedFiles 汇总进程已映射的可执行文件（= 已加载模块）。
func mappedFiles(pid int) []string {
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
		p := fields[5]
		if p == "" || seen[p] || strings.HasPrefix(p, "[") {
			continue
		}
		// 只保留可执行映射的宿主文件
		if !strings.Contains(fields[1], "x") {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// processStart 读取 /proc/<pid>/stat 的启动时钟并换算为绝对时间。
func processStart(pid int) (string, bool) {
	raw, err := os.ReadFile(procPath(strconv.Itoa(pid), "stat"))
	if err != nil {
		return "", false
	}
	s := string(raw)
	i := strings.LastIndex(s, ")")
	if i < 0 || i+2 >= len(s) {
		return "", false
	}
	fields := strings.Fields(s[i+2:])
	// fields[19]=starttime（自 boot 起的时钟数）
	if len(fields) <= 19 {
		return "", false
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return "", false
	}
	boot, err := bootTime()
	if err != nil {
		return "", false
	}
	return boot.Add(time.Duration(float64(ticks) / clkTck * float64(time.Second))).
		Format("2006-01-02 15:04:05"), true
}

// clkTck 是内核时钟频率（CONFIG_HZ），Linux 通用值为 100。
//
// Go 的 syscall / x/sys/unix 都没有暴露 sysconf(_SC_CLK_TCK)，
// 因此这里取内核在几乎所有发行版上的默认值；
// 换算出的启动时间只用于展示，偏差一秒不影响取证结论。
const clkTck = 100

// bootTime 由 /proc/stat 的 btime 字段得到开机时间。
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

// uidName 把 uid 映射成用户名（查不到就用数字）。
func uidName(uid int) string {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil || u == nil {
		return strconv.Itoa(uid)
	}
	return u.Username
}

// Threads 列出进程的“子线程”。
//
// Linux 没有独立的线程对象，每个线程都是一个 task：
// /proc/<pid>/task/<tid>/ 就是它的根，stat 的第 3 个字段是线程名。
func (b *Backend) Threads(pid int) ([]mem.ThreadInfo, error) {
	dir := procPath(strconv.Itoa(pid), "task")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsPermission(err) {
			return nil, fmt.Errorf("%w: pid %d: %v", mem.ErrPrivilege, pid, err)
		}
		return nil, fmt.Errorf("%w: pid %d: %v", mem.ErrGone, pid, err)
	}
	var out []mem.ThreadInfo
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil || tid <= 0 {
			continue
		}
		th := mem.ThreadInfo{TID: tid, PID: pid}
		if raw, err := os.ReadFile(procPath(strconv.Itoa(pid), "task", e.Name(), "stat")); err == nil {
			// 格式: pid (comm) state ppid …；comm 里可能含空格与括号，
			// 所以左括号取第一个、右括号取最后一个，才不会切错。
			stat := string(raw)
			lp, rp := strings.Index(stat, "("), strings.LastIndex(stat, ")")
			if lp >= 0 && rp > lp {
				th.Name = stat[lp+1 : rp]
			}
			if rp >= 0 && rp+2 < len(stat) {
				rest := strings.Fields(stat[rp+2:])
				if len(rest) > 0 {
					th.State = rest[0] // R/S/D/Z/T…
				}
			}
		}
		out = append(out, th)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TID < out[j].TID })
	return out, nil
}

// threadCount 统计进程的线程数（读不到时返回 0，表示未知）。
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

// OpenLive 打开一个活体进程。
func (b *Backend) OpenLive(spec string) (mem.Target, error) {
	pid := os.Getpid()
	if spec != "self" {
		p, err := strconv.Atoi(spec)
		if err != nil {
			return nil, mem.ErrBadSpec
		}
		pid = p
	}
	if pid <= 0 {
		return nil, mem.ErrBadSpec
	}
	if _, err := os.Stat(procPath(strconv.Itoa(pid))); err != nil {
		return nil, fmt.Errorf("%w: pid %d", mem.ErrNoProcess, pid)
	}
	info, err := readProcessInfo(pid)
	if err != nil {
		return nil, fmt.Errorf("%w: pid %d: %v", mem.ErrNoProcess, pid, err)
	}
	return newTarget(pid, info)
}

// archName 返回当前架构名（同机读取，目标进程架构必然一致）。
func archName() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "unknown"
	}
	return unix.ByteSliceToString(uts.Machine[:])
}

// Target 是 /proc/<pid> 的活体内存镜像。
type Target struct {
	pid  int
	info mem.ProcessInfo
	mem  *os.File
	// writable 表示 /proc/<pid>/mem 是以 O_RDWR 打开的。
	//
	// 写其它进程的内存需要通过 ptrace 权限检查（PTRACE_MODE_ATTACH），
	// 拿不到时自动退回只读，保证只读取证路径不受影响。
	writable bool
}

// newTarget 打开进程句柄。
func newTarget(pid int, info mem.ProcessInfo) (*Target, error) {
	// 先试可写：只有拿到写权限才允许「在内存中操作」
	f, err := os.OpenFile(procPath(strconv.Itoa(pid), "mem"), os.O_RDWR, 0)
	writable := err == nil
	if !writable {
		if f, err = os.Open(procPath(strconv.Itoa(pid), "mem")); err != nil {
			if os.IsPermission(err) {
				return nil, fmt.Errorf("%w: pid %d: %v", mem.ErrPrivilege, pid, err)
			}
			return nil, fmt.Errorf("%w: pid %d: %v", mem.ErrGone, pid, err)
		}
	}
	info.PID = pid
	return &Target{pid: pid, info: info, mem: f, writable: writable}, nil
}

// Kind 返回 "live"。
func (t *Target) Kind() string { return "live" }

// Info 返回进程信息。
func (t *Target) Info() mem.ProcessInfo { return t.info }

// Regions 解析 /proc/<pid>/maps。
func (t *Target) Regions() ([]mem.Region, error) {
	f, err := os.Open(procPath(strconv.Itoa(t.pid), "maps"))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", mem.ErrGone, err)
	}
	defer f.Close()

	var out []mem.Region
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		// 格式: start-end perms offset dev inode pathname
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		bounds := strings.SplitN(fields[0], "-", 2)
		if len(bounds) != 2 {
			continue
		}
		start, err1 := strconv.ParseUint(bounds[0], 16, 64)
		end, err2 := strconv.ParseUint(bounds[1], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		perms := fields[1]
		path := ""
		if len(fields) >= 6 {
			path = strings.Join(fields[5:], " ")
		}
		isMain := t.info.Exe != "" && path == t.info.Exe
		r := mem.Region{
			Start: start,
			End:   end,
			Perm:  perms,
			Path:  path,
			Kind:  mem.Classify(perms, path, isMain),
		}
		// 不可读区域直接剔除（分析它们没有意义，且读必然失败）
		if !r.Readable() {
			continue
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	mem.SortRegions(out)
	return out, nil
}

// ReadAt 通过 /proc/<pid>/mem 的 pread 语义按虚拟地址读取。
//
// 该文件在未映射页上会返回 EIO/EFAULT 而不是 0 字节，因此部分成功时
// 返回实际字节数，调用方按需继续下一个块。
func (t *Target) ReadAt(addr uint64, p []byte) (int, error) {
	n, err := t.mem.ReadAt(p, int64(addr))
	if n > 0 {
		return n, nil
	}
	return n, err
}

// Writable 报告该目标是否可写。
func (t *Target) Writable() bool { return t.writable }

// WriteAt 通过 /proc/<pid>/mem 改写目标进程内存。
func (t *Target) WriteAt(addr uint64, p []byte) (int, error) {
	if !t.writable {
		return 0, mem.ErrNotWritable
	}
	n, err := t.mem.WriteAt(p, int64(addr))
	if n == 0 && err != nil {
		return 0, err
	}
	return n, nil
}

// Close 关闭 mem 句柄。
func (t *Target) Close() error { return t.mem.Close() }
