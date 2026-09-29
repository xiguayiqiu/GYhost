//go:build (linux && !android) || darwin

package i18n

// procMessages 是 proc 模块的文案。
//
// 为什么单独成文件：proc 模块只在 Linux（不含 Android/Termux）与 macOS 上存在
// （见 modules/proc 的包级构建约束），把它约 9 KB 中英文案放在这里并用构建标签
// 控制，就不会���链进 Windows / Termux 的二进制。
// proc_off.go 那一侧是空表，保证 lookup 在任何平台都能正常回退。
var procMessages = map[Lang]map[string]string{
	Zh: {
		"proc.group":                   "进程分析",
		"proc.summary":                 "进程分析：进程列表、父子树、命令行、环境变量、打开的文件与资源占用（Linux/macOS）",
		"proc.flag.input":              "目标进程：PID、self（当前进程）或程序名（程序名需配合 -a detail/thread）",
		"proc.flag.action":             "要执行的动作，逗号分隔可重复（list/tree/user/thread/detail/all）",
		"proc.flag.filter":             "只保留名字或命令行含该关键字的进程",
		"proc.flag.user":               "只保留该用户的进程",
		"proc.flag.parent":             "只保留该父进程的直接子进程（填父进程 PID）",
		"proc.flag.sort":               "排序依据：threads(默认)/pid/name/user/rss/vsize/fds/start",
		"proc.flag.minthreads":         "只保留线程数不少于该值的进程",
		"proc.flag.minrss":             "只保留常驻内存不少于该字节数的进程（如 10M）",
		"proc.flag.nokernel":           "排除内核线程（默认开启，用 -K=false 关闭）",
		"proc.flag.limit":              "每张表最多输出条数（默认 30，-X 不限）",
		"proc.flag.showall":            "不限制条数（输出可能很长）",
		"proc.flag.out":                "把报告写入该文件（默认打印到 stdout）",
		"proc.flag.json":               "输出 JSON 而非人读报告，便于 jq 等工具二次处理",
		"proc.flag.verbose":            "显示完整命令行，不做截断",
		"proc.flag.quiet":              "静默模式，不向 stderr 输出提示",
		"proc.flag.recover":            "从 /proc 恢复文件：不带值时扫描并列出清单，带编号/关键字时恢复（Linux 专有）",
		"proc.flag.outdir":             "恢复件的输出目录（默认 ./gyhost-proc-<pid>-recovered）",
		"proc.info.saved":              "报告已写入: %s",
		"proc.info.target":             "pid %d",
		"proc.info.selected":           "%d 个（过滤掉 %d 个）",
		"proc.info.agg":                "%d 线程 / %d fd / %s 虚拟 / %s 常驻",
		"proc.info.no_match_filter":    "没有进程满足过滤条件",
		"proc.info.agg_note":           "（合计的虚拟内存是各进程 VSZ 之和；常驻内存里共享页会被重复计入，两者仅供量级参考）",
		"proc.warn.threads":            "pid %d 的线程读取失败: %v",
		"proc.err.unsupported":         "proc 模块只支持 Linux 与 macOS，当前平台 (%s) 未实现",
		"proc.err.privilege":           "权限不足（%s 平台）: %s",
		"proc.err.list":                "枚举 %s 上的进程失败: %v",
		"proc.err.detail":              "取 pid %d 的详情失败: %v",
		"proc.err.no_process":          "进程不存在: pid %d",
		"proc.err.no_match":            "没有匹配的程序: %s",
		"proc.err.ambiguous":           "%s 匹配到 %d 个进程，详情请用 pid 明确指定",
		"proc.err.need_target":         "该动作需要指定目标: -i <pid|self|程序名>",
		"proc.err.bad_action":          "未知的 -a 动作: %s（可用: list/tree/user/thread/detail/all）",
		"proc.err.bad_sort":            "未知的 -t 排序字段: %s（可用: threads/pid/name/user/rss/vsize/fds/start）",
		"proc.err.bad_minthreads":      "--min-threads 必须 >= 0（当前 %d）",
		"proc.err.bad_limit":           "-n 条数上限必须 >= 0（当前 %d）",
		"proc.err.bad_parent":          "-P 父进程 PID 必须 >= 0（当前 %d）",
		"proc.err.bad_target":          "无法识别的 -i 目标: %s",
		"proc.err.create_out":          "创建输出文件失败: %v",
		"proc.sec.overview":            "概览",
		"proc.sec.list":                "进程列表",
		"proc.sec.tree":                "父子关系树",
		"proc.sec.user":                "按用户统计",
		"proc.sec.thread":              "线程列表",
		"proc.sec.detail":              "进程详情",
		"proc.col.platform":            "平台",
		"proc.col.total":               "进程总数",
		"proc.col.target":              "目标",
		"proc.col.selected":            "参与分析",
		"proc.col.agg":                 "合计",
		"proc.col.cond":                "过滤条件",
		"proc.col.pid":                 "PID",
		"proc.col.ppid":                "父进程",
		"proc.col.state":               "状态",
		"proc.col.user":                "用户",
		"proc.col.name":                "进程名",
		"proc.col.exe":                 "可执行文件",
		"proc.col.arch":                "架构",
		"proc.col.cwd":                 "工作目录",
		"proc.col.start":               "启动时间",
		"proc.col.threads":             "线程",
		"proc.col.count":               "进程数",
		"proc.col.fds":                 "FD",
		"proc.col.rss":                 "常驻内存",
		"proc.col.vsize":               "虚拟内存",
		"proc.col.cmd":                 "命令行",
		"proc.col.cmdline":             "完整命令行",
		"proc.col.mem":                 "资源",
		"proc.col.maps":                "内存映射",
		"proc.col.tid":                 "线程ID",
		"proc.sec.recover":             "从 /proc 恢复文件",
		"proc.col.idx":                 "编号",
		"proc.col.source":              "来源",
		"proc.col.flag":                "标记",
		"proc.col.size":                "大小",
		"proc.col.path":                "路径",
		"proc.rec.summary":             "扫描结果",
		"proc.rec.stat":                "共 %d 项 · 可恢复 %d 项 · 其中已删除但仍被进程持有 %d 项",
		"proc.rec.header":              "%4s  %-8s %10s  %-10s %s",
		"proc.rec.deleted":             "已删除",
		"proc.rec.none":                "没有可恢复的文件",
		"proc.rec.scan_failed":         "未能扫描到任何文件条目（/proc/<pid> 可能不可读，或进程已退出）",
		"proc.rec.hint":                "以上是候选清单；用 -r <编号> 恢复指定项，或 -r <关键字> 按路径筛选后恢复",
		"proc.rec.done":                "已恢复 %d 个文件到: %s",
		"proc.rec.done_one":            "已存 %s(%s)",
		"proc.info.recovered":          "已恢复第 %d 项 → %s（%s）",
		"proc.warn.recover":            "第 %d 项恢复失败（%s）: %v",
		"proc.err.recover_unsupported": "当前平台 (%s) 不支持从 /proc 恢复文件（该能力是 Linux 专有的）",
		"proc.err.scan":                "扫描 pid %d 的可恢复文件失败: %v",
		"proc.err.no_ref_match":        "没有匹配到可恢复的文件: %s（共 %d 项可恢复）",
		"proc.err.recover_failed":      "所有选中的文件都恢复失败",
		"proc.more":                    "还有 %d 条未显示（用 -n 调整或 -X 显示全部）",
		"proc.cond.k":                  "关键字=%s",
		"proc.cond.u":                  "用户=%s",
		"proc.cond.p":                  "父进程=%d",
		"proc.cond.t":                  "线程≥%d",
		"proc.cond.rss":                "常驻≥%s",
		"proc.cond.kernel":             "排除内核线程",
		"proc.list.header":             "%7s  %7s  %-5s %-12s %5s  %5s  %9s  %9s  %s",
		"proc.tree.hint":               "父子层级（└─ 为子进程）:",
		"proc.user.header":             "%-16s %6s  %8s  %9s  %9s",
		"proc.user.none":               "没有可统计的进程",
		"proc.thread.header":           "%8s  %-5s  %s",
		"proc.thread.none":             "没有可列出的线程（该平台可能需要更高权限）",
		"proc.detail.none":             "没有取到进程详情",
		"proc.detail.mem":              "常驻 %s / 虚拟 %s / %d 线程 / %d fd",
		"proc.detail.maps":             "%d 个区域，其中 %d 个可执行映像",
		"proc.detail.env":              "环境变量（%d 个）:",
		"proc.detail.env_na":           "环境变量不可用（macOS 出于安全限制不开放他人进程的环境变量）",
		"proc.detail.fd":               "打开的文件（%d 个）:",
		"proc.detail.fd_count_only":    "打开文件 %d 个（macOS 不提供他人进程的 fd 路径）",
		"proc.detail.fd_na":            "打开文件信息不可用",
		"proc.detail.modules":          "加载的映像（%d 个）:",
		"proc.usage": `gyhost proc - 进程分析（Linux / macOS）

用法:
  gyhost proc [-a 动作] [-i 目标] [选项...]

参数（Linux 与 macOS 完全一致；底层分别走 procfs 与 libproc）:

  -i, -input     目标进程：PID、self 或程序名（程序名需配合 -a detail/thread）
  -a, -action    执行动作，逗号分隔可重复（默认 list）
  -o, -out       报告写入文件，stdout 保持干净
  -q, -quiet     不向 stderr 输出提示

  收敛范围
  -k, -filter    只保留名字或命令行含该关键字的进程
  -u, -user      只保留该用户的进程
  -P, -parent    只保留该父进程的直接子进程
  -t, -sort      排序依据：threads(默认)/pid/name/user/rss/vsize/fds/start
  --min-threads  线程数下限
  --min-rss      常驻内存下限（字节，支持 10M 这类写法）
  -K, -no-kernel 排除内核线程（默认开启）
  -n, -limit     每张表最多输出条数（默认 30）
  -X, -showall   不限制条数
  -V, -verbose   显示完整命令行，不截断
  -j, -json      JSON 结构化输出，便于 jq 等工具处理

从 /proc 恢复文件（Linux 专有，需 -i 指定进程）
  -r, -recover   值可省略，这是两段式用法：
                    -r            扫描并列出候选清单（带编号）
                    -r <编号>      恢复该编号对应的文件
                    -r <关键字>    恢复路径含该关键字的全部（逗号分隔多个）
                    -r all        恢复全部可恢复项
  -O, -outdir    恢复件的输出目录（默认 ./gyhost-proc-<pid>-recovered）

  扫描范围来自 /proc/<pid> 下的四个入口：
    exe            正在执行的可执行文件
    cwd / root     工作目录、根目录（只列出，不作为文件恢复）
    fd/<n>         打开的文件描述符 —— 重点是「已从磁盘删除、
                   但进程仍持有 fd」的文件，内容照样能取回来
    map_files/     内存映射的文件（需 root，且只保留已删除的）

动作 (-a):
  list     进程列表：pid/ppid/状态/用户/线程/fd/内存/命令行
  tree     父子关系树，按 PPID 分层
  user     按用户聚合统计（进程数/线程数/内存）
  thread   线程列表（需 -i）
  detail   单进程详情（需 -i）：命令行、环境变量、打开的文件、加载的映像
  all      list + tree + user

示例:
  gyhost proc                                          # 进程列表（按线程数排序）
  gyhost proc -t rss -n 20                             # 按常驻内存排序看前 20
  gyhost proc -k nginx -a detail                       # 叫 nginx 的进程详情
  gyhost proc -i 1234 -a thread                        # 某进程的线程
  gyhost proc -u root -a user                          # root 用户的进程统计
  gyhost proc -P 1 -a tree                             # 以 pid 1 为根看进程树
  gyhost proc --min-threads 50 -X                      # 只看线程数 ≥ 50 的进程
  gyhost proc -a list -j | jq '.processes[0]'          # JSON 接管道
  gyhost proc -i 1234 -r                              # 扫描可恢复文件（先看清单）
  gyhost proc -i 1234 -r 1                            # 恢复清单里的第 1 项
  gyhost proc -i 1234 -r 1,3 -O ./evidence            # 恢复多项并指定输出目录
  gyhost proc -i 1234 -r all -O ./evidence -X         # 恢复全部可恢复项
  gyhost help proc

平台说明:
  Linux      读 /proc（进程表、命令行、环境变量、打开的文件、内存映射）
  macOS      读 libproc；受 SIP 与权限限制，他人进程的环境变量与
             fd 路径取不到（只给数量），需要 root
  其它平台   明确提示未实现（proc 模块只覆盖 Linux 与 macOS）`,
	},
	En: {
		"proc.group":                   "Process Analysis",
		"proc.summary":                 "Process analysis: list, parent/child tree, command line, env, open files and resource usage (Linux/macOS)",
		"proc.flag.input":              "target process: PID, self, or a program name (a name requires -a detail/thread)",
		"proc.flag.action":             "actions to run, comma separated and repeatable (list/tree/user/thread/detail/all)",
		"proc.flag.filter":             "only keep processes whose name or command line contains this keyword",
		"proc.flag.user":               "only keep processes of this user",
		"proc.flag.parent":             "only keep direct children of this parent PID",
		"proc.flag.sort":               "sort by: threads (default) / pid / name / user / rss / vsize / fds / start",
		"proc.flag.minthreads":         "only keep processes with at least this many threads",
		"proc.flag.minrss":             "only keep processes with at least this much resident memory (bytes, 10M style allowed)",
		"proc.flag.nokernel":           "exclude kernel threads (on by default, turn off with -K=false)",
		"proc.flag.limit":              "maximum rows per table (default 30, -X for no limit)",
		"proc.flag.showall":            "do not limit the number of rows (output can be long)",
		"proc.flag.out":                "write the report to this file (default: print to stdout)",
		"proc.flag.json":               "emit JSON instead of the human report, for jq and other tooling",
		"proc.flag.verbose":            "show the full command line without truncating it",
		"proc.flag.quiet":              "quiet mode, do not print notices to stderr",
		"proc.flag.recover":            "recover files from /proc: with no value scan and list candidates, with an index or keyword actually recover (Linux only)",
		"proc.flag.outdir":             "output directory for recovered files (default ./gyhost-proc-<pid>-recovered)",
		"proc.info.saved":              "report written to: %s",
		"proc.info.target":             "pid %d",
		"proc.info.selected":           "%d (%d filtered out)",
		"proc.info.agg":                "%d threads / %d fds / %s virtual / %s resident",
		"proc.info.no_match_filter":    "no process matches the filters",
		"proc.info.agg_note":           "(the virtual total is the sum of per-process VSZ, and shared pages are counted repeatedly in RSS; treat both as order-of-magnitude only)",
		"proc.warn.threads":            "failed to read threads of pid %d: %v",
		"proc.err.unsupported":         "the proc module supports Linux and macOS only; %s is not implemented",
		"proc.err.privilege":           "insufficient privileges on %s: %s",
		"proc.err.list":                "failed to enumerate processes on %s: %v",
		"proc.err.detail":              "failed to get details of pid %d: %v",
		"proc.err.no_process":          "process not found: pid %d",
		"proc.err.no_match":            "no program matched: %s",
		"proc.err.ambiguous":           "%s matched %d processes; use an explicit pid for details",
		"proc.err.need_target":         "this action needs a target: -i <pid|self|program>",
		"proc.err.bad_action":          "unknown -a action: %s (available: list/tree/user/thread/detail/all)",
		"proc.err.bad_sort":            "unknown -t sort field: %s (available: threads/pid/name/user/rss/vsize/fds/start)",
		"proc.err.bad_minthreads":      "--min-threads must be >= 0 (got %d)",
		"proc.err.bad_limit":           "-n row limit must be >= 0 (got %d)",
		"proc.err.bad_parent":          "-P parent PID must be >= 0 (got %d)",
		"proc.err.bad_target":          "unrecognized -i target: %s",
		"proc.err.create_out":          "failed to create the output file: %v",
		"proc.sec.overview":            "Overview",
		"proc.sec.list":                "Process List",
		"proc.sec.tree":                "Parent/Child Tree",
		"proc.sec.user":                "Per-User Stats",
		"proc.sec.thread":              "Threads",
		"proc.sec.detail":              "Process Detail",
		"proc.col.platform":            "platform",
		"proc.col.total":               "total processes",
		"proc.col.target":              "target",
		"proc.col.selected":            "analyzed",
		"proc.col.agg":                 "aggregate",
		"proc.col.cond":                "filters",
		"proc.col.pid":                 "PID",
		"proc.col.ppid":                "PPID",
		"proc.col.state":               "state",
		"proc.col.user":                "user",
		"proc.col.name":                "name",
		"proc.col.exe":                 "executable",
		"proc.col.arch":                "arch",
		"proc.col.cwd":                 "cwd",
		"proc.col.start":               "start time",
		"proc.col.threads":             "threads",
		"proc.col.count":               "processes",
		"proc.col.fds":                 "FD",
		"proc.col.rss":                 "RSS",
		"proc.col.vsize":               "VSZ",
		"proc.col.cmd":                 "command line",
		"proc.col.cmdline":             "full command line",
		"proc.col.mem":                 "resources",
		"proc.col.maps":                "memory maps",
		"proc.col.tid":                 "TID",
		"proc.sec.recover":             "Recover Files From /proc",
		"proc.col.idx":                 "idx",
		"proc.col.source":              "source",
		"proc.col.flag":                "flags",
		"proc.col.size":                "size",
		"proc.col.path":                "path",
		"proc.rec.summary":             "scan",
		"proc.rec.stat":                "%d entries / %d recoverable / %d of them deleted but still held open",
		"proc.rec.header":              "%4s  %-8s %10s  %-10s %s",
		"proc.rec.deleted":             "deleted",
		"proc.rec.none":                "nothing recoverable",
		"proc.rec.scan_failed":         "no file entries could be scanned (/proc/<pid> unreadable, or the process exited)",
		"proc.rec.hint":                "this is the candidate list; recover with -r <idx>, or filter by path with -r <keyword>",
		"proc.rec.done":                "recovered %d file(s) into: %s",
		"proc.rec.done_one":            "saved %s (%s)",
		"proc.info.recovered":          "recovered #%d -> %s (%s)",
		"proc.warn.recover":            "failed to recover #%d (%s): %v",
		"proc.err.recover_unsupported": "recovering files from /proc is not available on %s (it is a Linux-only capability)",
		"proc.err.scan":                "failed to scan recoverable files of pid %d: %v",
		"proc.err.no_ref_match":        "nothing matched %s (%d entries are recoverable)",
		"proc.err.recover_failed":      "all selected files failed to recover",
		"proc.more":                    "%d more rows not shown (use -n to adjust or -X for everything)",
		"proc.cond.k":                  "keyword=%s",
		"proc.cond.u":                  "user=%s",
		"proc.cond.p":                  "parent=%d",
		"proc.cond.t":                  "threads>=%d",
		"proc.cond.rss":                "rss>=%s",
		"proc.cond.kernel":             "exclude kernel threads",
		"proc.list.header":             "%7s  %7s  %-5s %-12s %5s  %5s  %9s  %9s  %s",
		"proc.tree.hint":               "hierarchy (└─ marks a child):",
		"proc.user.header":             "%-16s %6s  %8s  %9s  %9s",
		"proc.user.none":               "no process to aggregate",
		"proc.thread.header":           "%8s  %-5s  %s",
		"proc.thread.none":             "no listable thread (this platform may need higher privileges)",
		"proc.detail.none":             "no process details available",
		"proc.detail.mem":              "rss %s / vsize %s / %d threads / %d fds",
		"proc.detail.maps":             "%d regions, %d of them executable images",
		"proc.detail.env":              "environment (%d entries):",
		"proc.detail.env_na":           "environment unavailable (macOS does not expose another process's env to non-root)",
		"proc.detail.fd":               "open files (%d):",
		"proc.detail.fd_count_only":    "%d open files (macOS does not provide another process's fd paths)",
		"proc.detail.fd_na":            "open file information unavailable",
		"proc.detail.modules":          "loaded images (%d):",
		"proc.usage": `gyhost proc - process analysis (Linux / macOS)

Usage:
  gyhost proc [-a action] [-i target] [options...]

Flags (identical on Linux and macOS; the backend uses procfs vs libproc):

  -i, -input     target process: PID, self, or a program name
                  (a program name needs -a detail/thread)
  -a, -action    actions to run, comma separated and repeatable (default list)
  -o, -out       write the report to a file, keeping stdout clean
  -q, -quiet     do not print notices to stderr

  Narrow the scope
  -k, -filter    only processes whose name or command line contains this keyword
  -u, -user      only processes of this user
  -P, -parent    only direct children of this parent PID
  -t, -sort      sort by: threads (default)/pid/name/user/rss/vsize/fds/start
  --min-threads  minimum thread count
  --min-rss      minimum resident memory (bytes, 10M style allowed)
  -K, -no-kernel exclude kernel threads (on by default)
  -n, -limit     maximum rows per table (default 30)
  -X, -showall   do not limit rows
  -V, -verbose   full command line, no truncation
  -j, -json      JSON output, ready for jq and other tooling

Recover files from /proc (Linux only, requires -i)
  -r, -recover   the value is optional; this is a two-step flow:
                    -r            scan and list the candidates (with indexes)
                    -r <idx>      recover the file at that index
                    -r <keyword>  recover every file whose path contains it
                    -r all        recover everything recoverable
  -O, -outdir    output directory (default ./gyhost-proc-<pid>-recovered)

  The scan covers four entry points under /proc/<pid>:
    exe            the executable being run
    cwd / root     working directory and root (listed, not recovered as files)
    fd/<n>         open file descriptors — the interesting case is a file that
                   was deleted from disk but is still held open by the process;
                   its content can still be read back
    map_files/     memory-mapped files (needs root; only deleted ones kept)

Recover files from /proc (Linux only, requires -i)
  -r, -recover   the value is optional; this is a two-step flow:
                    -r            scan and list the candidates (with indexes)
                    -r <idx>      recover the file at that index
                    -r <keyword>  recover every file whose path contains it
                    -r all        recover everything recoverable
  -O, -outdir    output directory (default ./gyhost-proc-<pid>-recovered)

  The scan covers four entry points under /proc/<pid>:
    exe            the executable being run
    cwd / root     working directory and root (listed, not recovered as files)
    fd/<n>         open file descriptors — the interesting case is a file that
                   was deleted from disk but is still held open by the process;
                   its content can still be read back
    map_files/     memory-mapped files (needs root; only deleted ones kept)

Actions (-a):
  list     process list: pid/ppid/state/user/threads/fd/memory/command line
  tree     parent-child tree, layered by PPID
  user     per-user aggregation (processes/threads/memory)
  thread   thread list (needs -i)
  detail   single process detail (needs -i): cmdline, env, open files, loaded images
  all      list + tree + user

Examples:
  gyhost proc                                          # list, sorted by threads
  gyhost proc -t rss -n 20                             # top 20 by resident memory
  gyhost proc -k nginx -a detail                       # details of a process named nginx
  gyhost proc -i 1234 -a thread                        # threads of pid 1234
  gyhost proc -u root -a user                          # per-user stats for root
  gyhost proc -P 1 -a tree                             # process tree rooted at pid 1
  gyhost proc --min-threads 50 -X                      # only processes with >= 50 threads
  gyhost proc -a list -j | jq '.processes[0]'          # JSON into a pipeline
  gyhost proc -i 1234 -r                              # scan recoverable files
  gyhost proc -i 1234 -r 1                            # recover entry #1
  gyhost proc -i 1234 -r 1,3 -O ./evidence            # several, custom dir
  gyhost proc -i 1234 -r all -O ./evidence -X         # everything recoverable
  gyhost help proc

Platform notes:
  Linux      reads /proc (process table, cmdline, env, open files, memory maps)
  macOS      reads libproc; due to SIP and the permission model, another user's
             environment and fd paths are unavailable (counts only) and need root
  others     clearly reported as not implemented (proc covers Linux and macOS)`,
	},
}
