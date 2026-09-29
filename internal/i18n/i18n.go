// Package i18n 提供极简国际化能力。
//
// 设计约定：
//   - 语言只由环境变量 LANG 决定（zh* → 中文；en* → 英文；C/POSIX/未设置 → 默认中文；
//     其它语言回退到英文），不引入其它环境变量或命令行开关。
//   - 所有面向用户的可见文案以 key 的形式登记在本包的 messages 表中，
//     程序里一律通过 T / Tf 获取，不允许在业务代码里硬编码中文。
//   - 某语言缺少 key 时依次回退：当前语言 → 默认语言 → 英文 → 返回 key 本身。
package i18n

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// Lang 支持的语言。
type Lang string

const (
	// Zh 中文。
	Zh Lang = "zh"
	// En 英文。
	En Lang = "en"
)

// DefaultLang 默认语言：LANG 缺失或为 C/POSIX 时使用。
const DefaultLang = Zh

var (
	mu      sync.RWMutex
	current Lang
)

func init() {
	current = Detect()
}

// Detect 读取 LANG 环境变量判定语言。
func Detect() Lang {
	lang := strings.ToLower(strings.TrimSpace(os.Getenv("LANG")))
	switch {
	case strings.HasPrefix(lang, "zh"):
		return Zh
	case lang == "" || lang == "c" || lang == "posix":
		return DefaultLang
	default:
		return En
	}
}

// SetLang 切换当前语言（测试或将来支持显式开关时使用）。
func SetLang(l Lang) {
	mu.Lock()
	defer mu.Unlock()
	current = l
}

// Current 返回当前语言。
func Current() Lang {
	mu.RLock()
	defer mu.RUnlock()
	return current
}

// T 取 key 对应的当前语言文案；缺失时按回退链查找，最终回退为 key 本身。
func T(key string) string {
	if s, ok := lookup(Current(), key); ok {
		return s
	}
	return key
}

// Tf 取文案并做 fmt.Sprintf 格式化。
func Tf(key string, a ...interface{}) string {
	return fmt.Sprintf(T(key), a...)
}

// lookup 在指定语言及其回退链中查找 key。
func lookup(l Lang, key string) (string, bool) {
	if s, ok := messages[l][key]; ok && s != "" {
		return s, true
	}
	// 平台相关的文案（如 proc）只在该平台存在时才有
	if s, ok := procMessages[l][key]; ok && s != "" {
		return s, true
	}
	if l != DefaultLang {
		if s, ok := messages[DefaultLang][key]; ok && s != "" {
			return s, true
		}
	}
	if l != En {
		if s, ok := messages[En][key]; ok && s != "" {
			return s, true
		}
	}
	return "", false
}

// messages 文案表：[语言][key] = 文案。
var messages = map[Lang]map[string]string{
	Zh: {
		// ==================== 应用横幅 ====================
		"app.title":    "gyhost - Go语言本地分析工具",
		"app.author":   "作者: xiguayiqiua",
		"app.version":  "工具版本: %s",
		"app.desc":     "描述: 本地分析工具，着重本地离线的网络安全分析",
		"app.warning":  "警告: 仅用于授权测试，严禁未授权使用！",
		"app.get_help": `使用 "./gyhost help" 获取帮助信息`,

		// ==================== 根帮助 ====================
		"help.usage":                   "用法:",
		"help.commands":                "可用模块:",
		"help.flags":                   "参数:",
		"help.get_cmd_help":            `使用 "gyhost help [模块]" 获取模块帮助信息`,
		"help.usage_line1":             "  gyhost [help] [flags]",
		"help.usage_line2":             "  gyhost [command]",
		"root.err.unknown_module":      "未知模块: %s",
		"root.err.unknown_global_flag": "未知的全局参数: %s",
		"root.err.prefix":              "错误: %v",

		// ==================== 全局参数 ====================
		"flag.help":      "显示帮助信息",
		"flag.version":   "显示版本信息",
		"flag.no_banner": "不显示启动横幅",
		"flag.no_color":  "禁用颜色输出",

		// ==================== 模块契约 ====================
		"mod.group.default": "基础功能",
		"mod.err.nil":       "module: 不能注册 nil 模块",
		"mod.err.empty":     "module: 模块名不能为空",
		"mod.err.dup":       "module: 模块 %q 重复注册",

		// ==================== pwdhash ====================
		"pwdhash.err.empty":       "pwdhash: 哈希为空",
		"pwdhash.err.unsupported": "pwdhash: 不支持的哈希格式 %q",
		"pwdhash.err.register":    "pwdhash: 注册解码器失败",

		// ==================== shadow 模块 ====================
		"shadow.group":        "本地分析",
		"shadow.summary":      "离线爆破 shadow 文件中的密码哈希",
		"shadow.flag.input":   "shadow 文件路径",
		"shadow.flag.dict":    "密码字典路径（与 -m 二选一）",
		"shadow.flag.mask":    "掩码表达式（hashcat 风格，如 ?l?l?d?d）；与 -p 二选一",
		"shadow.flag.user":    "只爆破指定用户（逗号分隔或重复指定，如 -u root,alice；默认全部）",
		"shadow.flag.threads": "并发线程数",
		"shadow.flag.out":     "结果输出文件",
		"shadow.flag.quiet":   "静默模式，不显示实时进度",
		"shadow.flag.gpu":     "用 GPU (CUDA) 加速破解，不可用时自动回退 CPU（需要 root/管理员权限）",
		"shadow.usage": `gyhost shadow - 离线爆破 shadow 文件中的密码哈希

用法:
  gyhost shadow -i [shadow文件] (-p [密码字典] | -m [掩码]) [选项...]

参数:
  -i, -input    shadow 文件路径（如 /etc/shadow、影子文件备份）
  -p, -pass     密码字典路径，每行一个候选密码（与 -m 二选一）
  -m, -mask     掩码表达式，实时生成候选（与 -p 二选一）
                hashcat 风格: ?l 小写 ?u 大写 ?d 数字 ?h/?H 十六进制
                ?s 特殊字符 ?a 全部可见字符 ?b 全字节 ?? 字面量 '?'
                例: -m '?l?l?d?d'、-m 'pass?d?d?d'
  -u, -user     只爆破指定用户（逗号分隔或重复指定，如 -u root,alice；默认全部）
  -t, -threads  并发线程数（默认: CPU 核数）
  -o, -out      可选，将破解结果以 user:password 写入该文件
  -q, -quiet    静默模式，不显示实时进度
  --gpu         用 GPU (CUDA) 加速，不可用时回退 CPU（需要 root/管理员权限）

输出:
  结果/统计 -> stdout（彩色），实时进度 -> stderr（TTY 上单行刷新）
  进度包含：候选消耗、校验次数、当前正在尝试的用户与哈希类型、速率、耗时

支持的哈希:
  $1$ md5crypt、$5$/$6$ sha-crypt（含 rounds）、$2*$ bcrypt、$y$ yescrypt、
  $argon2*$、$pbkdf2-*$、$scrypt$

示例:
  gyhost shadow -i /etc/shadow -p rockyou.txt
  gyhost shadow -i /etc/shadow -m '?d?d?d?d'          # 4 位数字穷举
  gyhost shadow -i /etc/shadow -p rockyou.txt -u root,alice
  gyhost shadow -i shadow.bak -p pass.txt -u root -u alice -t 8 -o result.txt
  gyhost shadow -i /etc/shadow -p rockyou.txt 2>/dev/null   # 只看破解结果
  gyhost help shadow`,

		// ---- shadow 错误 ----
		"shadow.err.missing_args":   "缺少必填参数: -i [shadow文件]，以及 -p [密码字典] 或 -m [掩码] 之一",
		"shadow.err.mask_conflict":  "不能同时指定 -p 字典与 -m 掩码，二者只能选一个",
		"shadow.err.mask":           "掩码表达式非法",
		"shadow.err.threads":        "-t 线程数必须 >= 1（当前 %d）",
		"shadow.err.open_shadow":    "打开 shadow 文件失败",
		"shadow.err.open_dict":      "打开密码字典失败",
		"shadow.err.bad_line":       "shadow 文件第 %d 行格式非法: %q",
		"shadow.err.no_user":        "shadow 文件第 %d 行缺少用户名",
		"shadow.err.read":           "读取 shadow 文件失败",
		"shadow.err.empty_file":     "shadow 文件 %s 中没有任何记录",
		"shadow.err.no_targets":     "没有可爆破的目标（共 %d 条记录，全部锁定或不受支持）",
		"shadow.err.user_not_found": "指定的用户在 shadow 文件中不存在: %s",
		"shadow.err.create_out":     "创建结果文件失败",
		"shadow.err.write_out":      "写入结果文件失败",

		// ---- shadow 跳过原因 ----
		"shadow.skip.locked":      "锁定/无密码",
		"shadow.skip.unsupported": "不支持的哈希 (%s)",

		// ---- shadow GPU ----
		"shadow.gpu.enabled":       "[✓] GPU 加速已启用: %s（%d MB 显存）",
		"shadow.gpu.partial":       "[*] GPU 负责 %d 个目标，其余 %d 个由 CPU 处理",
		"shadow.gpu.needs_root":    "[!] 启用 GPU 需要 root 权限（Windows 上为管理员），已回退 CPU 爆破；请用 sudo 或以管理员身份重新运行",
		"shadow.gpu.not_compiled":  "[!] 当前程序未启用 CUDA 编译，已回退 CPU 爆破（用 make 重新构建即可启用 GPU）",
		"shadow.gpu.no_device":     "[!] 未检测到可用的 CUDA 设备，已回退 CPU 爆破",
		"shadow.gpu.unsupported":   "[!] 目标哈希不支持 GPU（仅 $1$/$5$/$6$），已回退 CPU 爆破",
		"shadow.gpu.warmup":        "[*] 正在唤醒 GPU 并提升核心频率（约 %s）…",
		"shadow.gpu.runtime_error": "[!] GPU 校验出错，已回退 CPU 爆破: %s",
		"shadow.report.gpu":        "[*] GPU 设备: %s（%s MB 显存）",

		// ---- shadow 统计报告 ----
		"shadow.mask.keyspace":     "[*] 掩码 %s 展开 %s 个候选",
		"shadow.report.summary":    "[*] 目标 %s 个 | 跳过 %s 个 | 已破解 %s 个",
		"shadow.report.stats":      "[*] 字典候选 %s | 校验 %s 次 | 耗时 %s | 速率 %s 次/秒",
		"shadow.report.stats_mask": "[*] 掩码候选 %s | 校验 %s 次 | 耗时 %s | 速率 %s 次/秒",
		"shadow.report.skip":       "[-] %s: 跳过（%s）  %s",
		"shadow.report.pending":    "[!] 未破解 (%s): %s",
		"shadow.report.hint":       "[!] 可尝试更大的字典或规则变异后再跑一次",
		"shadow.report.all_done":   "[+] 全部目标已破解",

		// ---- shadow 实时进度 ----
		"shadow.progress.head":      "[~] 进度 %s | 字典 %s | 校验 %s |",
		"shadow.progress.head_mask": "[~] 进度 %s | 掩码 %s | 校验 %s |",
		"shadow.progress.cracked":   "%d/%d 已破",
		"shadow.progress.trying":    "尝试中 %s |",
		"shadow.progress.more":      " 等%s个",
		"shadow.progress.finished":  " 全部命中，收尾中…",
		"shadow.progress.tail":      "%s | %s",
		"shadow.progress.rate":      "%s次/秒",

		// ---- shadow 破解命中 ----
		"shadow.hit.format": "%s %s  %s",

		// ==================== hashdump 模块 ====================
		"hashdump.group":      "本地分析",
		"hashdump.summary":    "从加密压缩包、加密文档或无线抓包中提取可枚举的哈希",
		"hashdump.flag.input": "压缩包/文档/抓包路径（可重复；给目录时扫描其中的 zip/7z/rar/pdf/cap）",
		"hashdump.flag.out":   "将提取的哈希写入该文件（默认输出到 stdout）",
		"hashdump.flag.quiet": "静默模式，不在 stderr 显示统计与提示",
		"hashdump.usage": `gyhost hashdump - 从加密压缩包、加密文档或无线抓包中提取可枚举的哈希

用法:
  gyhost hashdump -i [压缩包/文档/抓包] [选项...]

参数:
  -i, -input    输入路径，可重复；给目录时按扩展名扫描
                （zip/7z/rar、doc/docx/xls/xlsx/ppt/wps、pdf、cap/pcap/pcapng）
  -o, -out      可选，将提取的哈希写入该文件（默认输出到 stdout）
  -q, -quiet    静默模式，不在 stderr 显示统计与提示

输出:
  哈希 -> stdout（每行一个 hashcat 哈希，可直接管道），统计与提示 -> stderr
  指定 -o 时哈希写入文件，stdout 不再输出哈希

支持的格式:
  zip   ZipCrypto -> -m 17200（deflate）/ -m 17210（stored）；WinZip AES -> -m 13600
  7z    AES-256+SHA256 -> -m 11600（含文件名加密）
  rar   RAR5 -> -m 13000（含头加密 -hp）；RAR4/RAR3 需要已知明文，暂不支持
  doc   加密 Office/WPS 文档：OOXML agile -> -m 9500（SHA-1）/ -m 9600（SHA-512）
        OOXML 标准加密 -> -m 9400；Word/Excel 97-2003 -> -m 9700（RC4+MD5）
        / -m 9800（RC4+SHA1）；输出与 john 的 office2john 逐字节一致
        未加密文档、WPS 私有格式与 PPT/Access 加密会给出具体跳过原因
  cap   pcap/pcapng 无线抓包 -> -m 22000（WPA/WPA2 PMKID 与四次握手）
        链路类型支持 802.11 / radiotap / Prism / AVS；ESSID 取自 beacon、
        probe response 与 (re)association request，缺失 ESSID 或不完整握手会被跳过
  pdf   加密 PDF -> -m 10400（RC4-40）/ 10500（RC4-128、AES-128）
        / 10600（AES-256）/ 10700（AES-256 强化 KDF），按 /Encrypt 的 V/R 自动选择

说明:
  单条数据超过 hashcat 上限的条目会被跳过，并在 stderr 逐条提示原因

示例:
  gyhost hashdump -i secret.zip > hashes.txt
  hashcat -m 17200 hashes.txt wordlist.txt
  gyhost hashdump -i secret.7z -o hashes.txt -q && hashcat -m 11600 hashes.txt wordlist.txt
  gyhost hashdump -i private.docx > office.hashes && hashcat -m 9600 office.hashes wordlist.txt
  gyhost hashdump -i wifite/wifi-01.cap > wpa.hc22000
  hashcat -m 22000 wpa.hc22000 wordlist.txt
  gyhost hashdump -i /path/to/dir 2>/dev/null | sort -u > all.txt
  gyhost help hashdump`,

		// ---- hashdump 错误 ----
		"hashdump.err.missing_args": "缺少必填参数: -i [压缩包/文档/抓包]",
		"hashdump.err.open":         "无法读取 %s: %v",
		"hashdump.err.no_archive":   "没有可处理的输入文件",
		"hashdump.err.unrecognized": "无法识别的文件（不是 zip/7z/rar、Office 文档或无线抓包）: %s",
		"hashdump.err.rar4":         "暂不支持 RAR4/RAR3 压缩包（需要已知明文）: %s",
		"hashdump.err.bad_header":   "压缩包结构异常: %s",
		"hashdump.err.bad_capture":  "无线抓包结构异常: %s",
		"hashdump.err.create_out":   "创建结果文件失败: %v",
		"hashdump.err.write_out":    "写入结果文件失败: %v",

		// ---- hashdump 统计与提示 ----
		"hashdump.info.archive": "%s (%s): 提取到 %d 个哈希，hashcat -m %s",
		"hashdump.info.entry":   "    %s  (-m %d)",
		"hashdump.info.total":   "[*] 共提取 %d 个哈希",
		"hashdump.info.saved":   "[*] 共提取 %d 个哈希，已写入 %s",
		"hashdump.info.empty":   "[!] 未从 %s 中提取到可枚举的哈希",
		"hashdump.info.header":  "（加密的头部/文件名）",
		"hashdump.warn.skip":    "[-] %s: 跳过 %s（%s）",

		// ---- hashdump 跳过原因 ----
		"hashdump.skip.method":     "不支持的加密/压缩方式 %s",
		"hashdump.skip.codec":      "暂不支持的 7z 算法 %s",
		"hashdump.skip.large":      "数据超过 hashcat 上限 %d 字节",
		"hashdump.skip.short":      "加密数据过短，无法提取",
		"hashdump.skip.no_check":   "缺少密码校验值，无法提取",
		"hashdump.skip.no_crc":     "缺少 CRC32 校验值，无法提取",
		"hashdump.skip.broken":     "数据偏移或长度异常",
		"hashdump.skip.no_ssid":    "未捕获到可用的 ESSID，无法生成哈希",
		"hashdump.skip.incomplete": "四次握手不完整，无法生成哈希",
		"hashdump.skip.linktype":   "不支持的链路类型 %d（仅支持 802.11/radiotap/Prism/AVS）",

		// ---- hashdump 无线抓包 ----
		"hashdump.wifi.capture":     "抓包",
		"hashdump.wifi.entry.eapol": "握手 %s（%s/%s）",
		"hashdump.wifi.entry.pmkid": "PMKID %s（%s）",

		// ---- hashdump 加密 PDF ----
		"hashdump.pdf.skip.size":       "PDF 为空或过大（%d 字节），跳过",
		"hashdump.pdf.skip.no_encrypt": "PDF 未加密（找不到 /Encrypt），无可提取的哈希",
		"hashdump.pdf.skip.no_id":      "加密字典缺少 /ID[0]，无法提取可校验口令的哈希",
		"hashdump.pdf.skip.version":    "暂不支持该 PDF 加密版本（V=%d R=%d）",
		"hashdump.pdf.skip.broken":     "PDF 加密字典不完整（V=%d R=%d）",

		// ---- hashdump Office 文档 ----
		"hashdump.office.skip.size":       "Office 文档为空或过大（%d 字节），跳过",
		"hashdump.office.skip.ole":        "OLE 复合文档结构异常: %v",
		"hashdump.office.skip.broken":     "加密元数据不完整或已损坏",
		"hashdump.office.skip.external":   "使用外部加密提供程序，暂不支持",
		"hashdump.office.skip.flags":      "加密标志与加密类型不一致，文件可能已损坏",
		"hashdump.office.skip.hash_alg":   "不支持的哈希算法 %s",
		"hashdump.office.skip.cipher":     "暂不支持的加密算法 %s（仅支持 AES）",
		"hashdump.office.skip.access":     "暂不支持 Access 加密数据库",
		"hashdump.office.skip.ppt":        "暂不支持 PowerPoint 加密文档",
		"hashdump.office.skip.no_streams": "OLE 文档里没有受支持的加密数据",
		"hashdump.office.skip.xor":        "XOR 混淆加密，hashcat 不支持",
		"hashdump.office.skip.wps":        "WPS 私有格式的文档，hashcat 无对应模式",
		"hashdump.office.skip.no_encrypt": "文档未加密，无可提取的哈希",
		"hashdump.office.skip.doc_header": "无法识别的 Word 加密头",
		"hashdump.office.skip.key_size":   "不支持的 RC4 密钥长度 %d 位",

		// ==================== hashcat 模块 ====================
		"hashcat.group":      "本地分析",
		"hashcat.summary":    "识别加密文件与哈希的算法类型，给出对应的 hashcat 模式号",
		"hashcat.flag.input": "待分析的文件/目录路径（可重复；给目录时扫描其中的压缩包、文档、抓包与哈希清单）",
		"hashcat.flag.quiet": "静默模式，不显示跳过原因与结尾提示",
		"hashcat.flag.list":  "列出 GYhost 可识别的算法与对应 hashcat 模式",
		"hashcat.usage": `gyhost hashcat - 识别加密文件与哈希的算法类型，给出 hashcat 模式号

用法:
  gyhost hashcat -i [文件...] [选项...]

参数:
  -i, -input    待分析的路径，可重复；给目录时扫描其中的
                zip/7z/rar/pdf/cap/pcap/pcapng 与 txt/hash/hashes
  -q, -quiet    静默模式，不显示跳过原因与结尾提示
  --list        只看算法与 hashcat 模式的对照表

输出:
  分析结果 -> stdout，每个条目给出算法名与可直接使用的 -m 模式号

识别范围:
  容器   zip / 7z / rar / 加密 PDF / 无线抓包
  清单   每行一条哈希；兼容 shadow 的 user:hash:... 与 potfile 的 hash:密码
  摘要   MD5/NTLM、SHA-1、SHA-256、SHA-512（32/40/64/128 位十六进制）
  口令   $1$ $apr1$ $5$ $6$ $2*$ $argon2*$ $scrypt$ $pbkdf2-sha256$ $y$
  文档   $office$ 2007/2010/2013/2016、$oldoffice$ 0/1/3/4

说明:
  32 位十六进制在 MD5 与 NTLM 之间有歧义，两个模式号都会给出；
  yescrypt（$y$）在 hashcat 中没有原生模式，只给出算法名

示例:
  gyhost hashcat -i secret.zip              # 这个压缩包用了什么算法
  gyhost hashcat -i hashes.txt              # 逐行识别哈希类型
  gyhost hashcat -i /etc/shadow             # shadow 里都是什么口令哈希
  gyhost hashcat -i /path/to/dir            # 批量分析整个目录
  gyhost hashcat --list                     # 只看对照表
  gyhost help hashcat`,

		// ---- hashcat 错误 ----
		"hashcat.err.missing_args": "缺少必填参数: -i [文件...]",
		"hashcat.err.no_input":     "没有可分析的输入文件",
		"hashcat.err.empty":        "未识别到可分析的条目",
		"hashcat.err.unknown":      "无法识别的哈希类型",
		"hashcat.err.binary":       "不是文本哈希清单，也不是受支持的加密容器（二进制文件）",

		// ---- hashcat 输出 ----
		"hashcat.line":            "第 %d 行",
		"hashcat.named":           "%s（第 %d 行）",
		"hashcat.label.algo":      "算法",
		"hashcat.label.mode":      "模式",
		"hashcat.label.container": "容器",
		"hashcat.label.hint":      "提示",
		"hashcat.hint.dump":       "条目在文件内部，先用 gyhost hashdump 导出，再交给 hashcat",
		"hashcat.hint.crack":      "该文件本身就是哈希清单，可直接交给 hashcat 或 gyhost hashac",
		"hashcat.mode.none":       "无原生模式",
		"hashcat.list.title":      "GYhost 可识别的算法与 hashcat 模式对照表",

		// ---- hashcat 分类 ----
		"hashcat.kind.digest": "裸摘要",
		"hashcat.kind.crypt":  "口令哈希（shadow/Unix）",
		"hashcat.kind.office": "MS Office 文档",
		"hashcat.kind.zip":    "ZIP 压缩包",
		"hashcat.kind.7z":     "7z 压缩包",
		"hashcat.kind.rar":    "RAR 压缩包",
		"hashcat.kind.pdf":    "加密 PDF",
		"hashcat.kind.wifi":   "无线抓包",

		// ---- hashcat 算法 ----
		"hashcat.algo.md5-ntlm":          "MD5 / NTLM（32 位十六进制，歧义）",
		"hashcat.algo.sha1":              "SHA-1",
		"hashcat.algo.sha256":            "SHA-256",
		"hashcat.algo.sha512":            "SHA-512",
		"hashcat.algo.md5crypt":          "md5crypt（$1$）",
		"hashcat.algo.md5crypt-apr1":     "md5crypt-apr1（$apr1$）",
		"hashcat.algo.sha256crypt":       "sha256crypt（$5$）",
		"hashcat.algo.sha512crypt":       "sha512crypt（$6$）",
		"hashcat.algo.bcrypt":            "bcrypt（$2*$）",
		"hashcat.algo.scrypt":            "scrypt（$scrypt$）",
		"hashcat.algo.argon2":            "Argon2（$argon2*$）",
		"hashcat.algo.django-pbkdf2":     "Django PBKDF2-SHA256",
		"hashcat.algo.yescrypt":          "yescrypt（$y$）",
		"hashcat.algo.office-2007":       "MS Office 2007",
		"hashcat.algo.office-2010":       "MS Office 2010",
		"hashcat.algo.office-2013":       "MS Office 2013",
		"hashcat.algo.office-2016":       "MS Office 2016（SheetProtection）",
		"hashcat.algo.office-2003-md5":   "MS Office ≤2003（MD5+RC4）",
		"hashcat.algo.office-2003-sha1":  "MS Office ≤2003（SHA1+RC4）",
		"hashcat.algo.zipcrypto-deflate": "ZipCrypto（deflate 压缩）",
		"hashcat.algo.zipcrypto-stored":  "ZipCrypto（未压缩）",
		"hashcat.algo.zip-aes128":        "WinZip AES-128",
		"hashcat.algo.zip-aes192":        "WinZip AES-192",
		"hashcat.algo.zip-aes256":        "WinZip AES-256",
		"hashcat.algo.7z-aes":            "7z AES-256",
		"hashcat.algo.rar5-aes":          "RAR5 AES-256",
		"hashcat.algo.pdf-rc4-40":        "PDF RC4-40",
		"hashcat.algo.pdf-rc4-128":       "PDF RC4-128",
		"hashcat.algo.pdf-aes-128":       "PDF AES-128",
		"hashcat.algo.pdf-aes-256":       "PDF AES-256",
		"hashcat.algo.pdf-aes-256-r6":    "PDF AES-256（强化 KDF）",
		"hashcat.algo.wpa2-pmkid":        "WPA2 PMKID",
		"hashcat.algo.wpa2-eapol":        "WPA2 四次握手（EAPOL）",
		"hashcat.algo.unknown":           "未知/无法识别",

		// ==================== hashac 模块 ====================
		"hashac.group":   "本地分析",
		"hashac.summary": "枚举 MD5/WPA2/RAR/ZIP/7z/PDF/office 等常见哈希的明文碰撞",
		"hashac.usage": `gyhost hashac - 枚举常见哈希的明文碰撞

用法:
  gyhost hashac -i [哈希文件] (-p [密码字典] | -m [掩码]) [选项...]

参数:
  -i, -input    哈希文件路径，每行一条哈希（# 开头与空行为注释）
  -p, -pass     密码字典路径，每行一个候选密码（与 -m 二选一）
  -m, --mask    掩码表达式，实时生成候选（与 -p 二选一）
                hashcat 风格: ?l 小写 ?u 大写 ?d 数字 ?h/?H 十六进制
                ?s 特殊字符 ?a 全部可见字符 ?b 全字节 ?? 字面量 '?'
                例: -m '?l?l?d?d'、-m 'pass?d?d?d'
  -o, -out      可选，把命中的 hash:password 写入该文件
  -t, -threads  并发线程数（默认 CPU 核数）
  --mode        可选，强制指定 hashcat 模式号（0 表示自动识别）
  -q, -quiet    静默模式，不显示实时进度
  --gpu         用 GPU (CUDA) 加速可支持的算法，其余自动回退 CPU（需要 root/管理员权限）

支持的类型（自动识别；括号内为 hashcat 模式号）:
  md5 / sha1 / sha256 / sha512   裸摘要（32/40/64/128 位十六进制）
  wpa2-pmkid / wpa2-eapol        WPA*01* / WPA*02*（-m 22000）
  rar5                           $rar5$...（-m 13000）
  zip-aes                        $zip2$...（-m 13600）
  zipcrypto                      $pkzip2$...（-m 17200/17210）
  7z                             $7z$...（-m 11600）
  pdf                            $pdf$...（-m 10400/10500/10600/10700）
                                 V<=4 的 RC4/AES 与 V=5 的 AES-256，用户/所有者口令都试
  office-2007 / 2010 / 2013      $office$...（-m 9400/9500/9600）
                                 加密的 docx/xlsx/pptx（含 WPS 兼容保存）口令校验
  其中 $... 格式可由 gyhost hashdump 直接从加密压缩包、加密 PDF 或加密 Office 文档提取

输出:
  命中与统计 -> stdout，实时进度与提示 -> stderr（2>/dev/null 只看结果）
  指定 -o 时结果写入文件（hash:password），stdout 仍打印统计

示例:
  gyhost hashac -i hashes.txt -p wordlist.txt
  gyhost hashac -i hashes.txt -m '?d?d?d?d'            # 4 位数字穷举
  gyhost hashac -i hashes.txt -m '?d?d?d?d?d?d?d?d' --gpu
  gyhost hashac -i hashes.txt -p wordlist.txt --gpu
  gyhost hashac -i hashes.txt -p wordlist.txt -o cracked.txt -q
  gyhost hashdump -i secret.rar -o hashes.txt && gyhost hashac -i hashes.txt -p wordlist.txt
  gyhost help hashac`,
		"hashac.flag.input":   "哈希文件路径，每行一条哈希",
		"hashac.flag.dict":    "密码字典路径，每行一个候选密码（与 -m 二选一）",
		"hashac.flag.mask":    "掩码表达式（hashcat 风格，如 ?l?l?d?d）；与 -p 二选一",
		"hashac.flag.out":     "把命中的 hash:password 写入该文件（默认只打印到 stdout）",
		"hashac.flag.threads": "并发线程数（默认 CPU 核数）",
		"hashac.flag.mode":    "强制指定 hashcat 模式号（0 表示自动识别；仅长选项，-m 已用于掩码）",
		"hashac.flag.quiet":   "静默模式，不显示实时进度",
		"hashac.flag.gpu":     "用 GPU (CUDA) 加速可支持的算法，其余自动回退 CPU（需要 root/管理员权限）",

		// ---- hashac 目标类型 ----
		"hashac.algo.md5":            "MD5",
		"hashac.algo.sha1":           "SHA-1",
		"hashac.algo.sha256":         "SHA-256",
		"hashac.algo.sha512":         "SHA-512",
		"hashac.algo.wpa2-pmkid":     "WPA2-PMKID",
		"hashac.algo.wpa2-eapol":     "WPA2-EAPOL",
		"hashac.algo.rar5":           "RAR5",
		"hashac.algo.zip-aes":        "ZIP-AES",
		"hashac.algo.zipcrypto":      "ZIP-ZipCrypto",
		"hashac.algo.7z":             "7z-AES",
		"hashac.algo.pdf-rc4-40":     "PDF RC4-40",
		"hashac.algo.pdf-rc4-128":    "PDF RC4-128",
		"hashac.algo.pdf-aes-128":    "PDF AES-128",
		"hashac.algo.pdf-aes-256":    "PDF AES-256",
		"hashac.algo.pdf-aes-256-r6": "PDF AES-256（强化 KDF）",
		"hashac.algo.office-2007":    "Office 2007",
		"hashac.algo.office-2010":    "Office 2010",
		"hashac.algo.office-2013":    "Office 2013",

		// ---- hashac 错误 ----
		"hashac.err.missing_args":  "缺少必填参数: -i [哈希文件]，以及 -p [密码字典] 或 -m [掩码] 之一",
		"hashac.err.mask_conflict": "不能同时指定 -p 字典与 -m 掩码，二者只能选一个",
		"hashac.err.mask":          "掩码表达式非法",
		"hashac.err.threads":       "线程数必须大于 0: %d",
		"hashac.err.mode":          "不支持的 hashcat 模式号: %d",
		"hashac.err.pdf_version":   "不支持的 PDF 加密版本 V=%d R=%d",
		"hashac.err.pdf_mode":      "该 PDF 哈希的 V/R 对应 -m %d，与 --mode %d 不符",
		"hashac.err.office_year":   "不支持的 Office 加密版本年份 %d（仅支持 2007/2010/2013）",
		"hashac.err.office_mode":   "该 Office 哈希对应 -m %d，与 --mode %d 不符",
		"hashac.err.oldoffice":     "暂不支持 $oldoffice$（-m 9700/9800，Word/Excel 97-2003 的 RC4 口令校验）",
		"hashac.err.open_input":    "无法读取哈希文件 %s",
		"hashac.err.read_input":    "读取哈希文件失败",
		"hashac.err.open_dict":     "打开密码字典失败",
		"hashac.err.empty_hash":    "空哈希行",
		"hashac.err.unknown":       "无法识别的哈希类型: %s",
		"hashac.err.bad_syntax":    "哈希格式非法: %s",
		"hashac.err.no_targets":    "没有可爆破的目标（共跳过 %d 条）",
		"hashac.err.create_out":    "创建结果文件失败",
		"hashac.err.write_out":     "写入结果文件失败",

		// ---- hashac GPU ----
		"hashac.gpu.enabled":       "[✓] GPU 加速已启用: %s（%d MB 显存）",
		"hashac.gpu.partial":       "[*] GPU 负责 %d 个目标，其余 %d 个由 CPU 处理",
		"hashac.gpu.needs_root":    "[!] 启用 GPU 需要 root 权限（Windows 上为管理员），已回退 CPU 爆破；请用 sudo 或以管理员身份重新运行",
		"hashac.gpu.not_compiled":  "[!] 当前程序未启用 CUDA 编译，已回退 CPU 爆破（用 make 重新构建即可启用 GPU）",
		"hashac.gpu.no_device":     "[!] 未检测到可用的 CUDA 设备，已回退 CPU 爆破",
		"hashac.gpu.unsupported":   "[!] 目标哈希不支持 GPU，已回退 CPU 爆破",
		"hashac.gpu.note_r6":       "[*] -m 10700（PDF R=6 强化 KDF）的 GPU 内核比多线程 CPU 慢，已留在 CPU；设 GYHOST_PDF_R6_GPU=1 可强制用 GPU",
		"hashac.gpu.note_7z":       "[*] 该 7z 条目用 LZMA/Deflate 压缩，GPU 只能校验 Copy 编码器，已留在 CPU",
		"hashac.gpu.note_cipher":   "[*] 该条目的密文超过 GPU 上限（%d 字节），已留在 CPU",
		"hashac.gpu.warmup":        "[*] 正在唤醒 GPU 并提升核心频率（约 %s）…",
		"hashac.gpu.runtime_error": "[!] GPU 校验出错，已回退 CPU 爆破: %s",

		// ---- hashac 实时进度 ----
		"hashac.progress.head":      "[~] 进度 %s | 字典 %s | 校验 %s |",
		"hashac.progress.head_mask": "[~] 进度 %s | 掩码 %s | 校验 %s |",
		"hashac.progress.cracked":   "%d/%d 已破",
		"hashac.progress.trying":    "尝试中 %s |",
		"hashac.progress.more":      " 等%s个",
		"hashac.progress.finished":  " 全部命中，收尾中…",
		"hashac.progress.tail":      "%s | %s",
		"hashac.progress.rate":      "%s次/秒",

		// ---- hashac 命中与统计 ----
		"hashac.hit.format":        "%s %s  %s %s",
		"hashac.mask.keyspace":     "[*] 掩码 %s 展开 %s 个候选",
		"hashac.report.summary":    "[*] 目标 %s 个 | 跳过 %s 个 | 已破解 %s 个",
		"hashac.report.stats":      "[*] 字典候选 %s | 校验 %s 次 | 耗时 %s | 速率 %s 次/秒",
		"hashac.report.stats_mask": "[*] 掩码候选 %s | 校验 %s 次 | 耗时 %s | 速率 %s 次/秒",
		"hashac.report.gpu":        "[*] GPU 设备: %s（%s MB 显存）",
		"hashac.report.skip":       "[-] 跳过 %s（%s）",
		"hashac.report.pending":    "[!] 未破解 (%s): %s",
		"hashac.report.hint":       "[!] 可尝试更大的字典或针对性的规则后再跑一次",
		"hashac.report.all_done":   "[+] 全部目标已破解",

		// ==================== net 模块 ====================
		"net.group":   "网络分析",
		"net.summary": "离线分析 pcap/cap 抓包：协议、会话、DNS/TLS/HTTP 与明文安全发现",

		"net.flag.input":           "抓包文件路径（pcap/pcapng/cap，可重复；给目录时扫描其中的抓包文件）",
		"net.flag.out":             "把报告写入该文件（默认打印到 stdout）",
		"net.flag.list":            "逐包列出（默认输出统计报告）",
		"net.flag.filter":          "过滤表达式，作用于统计与列表，如: -f \"tcp and port 443\"",
		"net.flag.top":             "各统计表最多显示的条目数（默认 10）",
		"net.flag.limit":           "列表模式下最多列出的包数（0 表示不限）",
		"net.flag.quiet":           "静默模式，不向 stderr 输出提示",
		"net.flag.section":         "只输出报告的指定章节，逗号分隔，可重复（io/proto/conv/endpoints/ports/dns/sni/http/findings/attack/all）",
		"net.flag.json":            "输出 JSON 而非人读报告，便于 jq 等工具二次处理",
		"net.flag.time":            "时间范围过滤：绝对时刻 10:05:00-10:06:00，或相对首帧的秒数 30-90",
		"net.flag.interval":        "时间线桶粒度（秒），仅配合 -z timeline（默认 1）",
		"net.section.timeline":     "流量时间线",
		"net.tl.interval":          "分桶粒度",
		"net.tl.interval_desc":     "%.0f 秒",
		"net.tl.span":              "时间跨度",
		"net.tl.span_desc":         "%s，共 %d 桶",
		"net.tl.avg":               "平均速率",
		"net.tl.avg_desc":          "%.1f 包/秒",
		"net.tl.peak":              "峰值时刻",
		"net.tl.peak_desc":         "第 %.0f 秒，%d 包 / %s",
		"net.tl.peak_peer":         "峰值来源",
		"net.tl.capped":            "时间线桶数已达上限 %d，超出部分未统计；请用 -I 增大粒度",
		"net.tl.rows":              "共 %d 个有流量的时间桶，此处只显示前 %d 个（用 --top 调整）",
		"net.tl.col_t":             "时刻(s)",
		"net.tl.col_pkt":           "包数",
		"net.tl.col_bytes":         "流量",
		"net.tl.col_proto":         "主要协议",
		"net.err.bad_section":      "未知的 -z 章节: %s（可用: io/timeline/proto/conv/endpoints/ports/dns/sni/http/findings/attack/follow/all）",
		"net.err.bad_follow":       "无法识别的 -z follow 参数: %s（格式: ascii/raw/hex，可选会话序号）",
		"net.err.time_range":       "无法识别的时间范围: %s（例: 10:05:00-10:06:00 或 30-90）",
		"net.err.time_range_order": "时间范围的结束早于开始",
		"net.err.json_tui":         "-j 与 -T 不能同时使用（JSON 面向管道，交互界面会被其输出冲掉）",
		"net.err.list_section":     "-l 与 -z 不能同时使用（列表模式是逐包流式输出，没有章节概念）",
		"net.section.follow":       "TCP 会话追踪",
		"net.follow.stream":        "会话 #%d/%d  %s",
		"net.follow.from":          "方向 0（%s）：",
		"net.follow.to":            "方向 1（%s）：",
		"net.follow.empty":         "（无载荷）",
		"net.follow.truncated":     "该会话载荷超出重组上限，内容不完整",
		"net.follow.gaps":          "重组发现 %d 处缺号，缺失部分已用 0 填充",
		"net.follow.no_stream":     "没有可追踪的 TCP 会话（需要 TCP 且带载荷）",
		"net.follow.no_index":      "会话序号 %d 越界（共有 %d 条）",
		"net.atk.capped":           "统计触到映射上限，部分指标不完整",
		"net.flag.model":           "启用攻击分析模型，逗号分隔（syn/udp/icmp/flood/cc/loss/frag/all），如: -m syn,cc",

		"net.usage": `gyhost net - 离线分析 pcap/cap 抓包文件的网络流量

用法:
  gyhost net -i [抓包文件] [选项...]

参数（按用途分组，每项只讲作用；详细语法见下方各节）:

  输入与输出
    -i, -input    抓包文件路径；可重复，给目录时扫描其中的抓包
    -o, -out      把报告写入文件，stdout 保持干净
    -q, -quiet    不向 stderr 输出提示与告警

  收敛分析范围
    -f, -filter   过滤表达式，作用于统计与列表
    -t, -time     时间范围过滤
    -n, -limit    列表模式最多列出多少个包（0 表示不限）
    -I, -interval 时间线分桶粒度（秒），仅配合 -z timeline
    --top N       各统计表最多显示的条目数（默认 10）

  选择输出形式（互斥；默认输出统计报告）
    -l, -list     逐包列出：序号、相对时间、端点、协议、长度、摘要
    -V, -verbose  逐包协议树：按 tshark -V 列出每个字段与 hexdump
    -T, -tui      交互式全屏抓包浏览器
    -j, -json     JSON 结构化输出，便于 jq 等工具二次处理

  启用分析模型
    -m, -model    攻击分析模型，见"攻击模型"

  裁剪报告章节
    -z, -section  只输出指定章节，见"报告章节"

过滤语法 (-f):
  简写形式
    空格分隔的多个条件取"与"，or 取"或"，not 取反
    条件        协议名（tcp/udp/icmp/arp/dns/http/tls/ssh…）
                [src|dst] host IP      [src|dst] port 端口
                纯数字等价于 port N
  显示过滤器形式（Wireshark 风格）
    表达式      字段 运算符 值        运算符: == != > < >= <= contains
    逻辑        && || ! 与括号 ()     裸写协议名表示"存在"
    字段        frame.*  ip.*  ipv6.*  tcp.*  udp.*  icmp.*  arp.*
                http.*  dns.*  tls.*  eth.*
    交互界面里按 / 可边输入边提示，按 ? 查看全部字段

时间范围 (-t):
  绝对时刻    10:05:00-10:06:00
  相对秒数    30-90（相对首帧；也可只给一端）

报告章节 (-z):
  io          抓包概览
  proto       协议分布
  conv        会话
  endpoints   端点
  ports       端口
  dns         DNS 查询
  sni         TLS SNI
  http        HTTP 主机与请求
  findings    安全发现
  attack      攻击分析
  all         以上全部
  timeline    流量时间线（按时间桶看包数与流量，定位突发与静默）
  会话追踪    follow,tcp,ascii|raw|hex[,<序号>]
              把乱序/重传/分段的报文按 TCP 序号拼回两个方向的字节流
              ascii 可打印字符   raw 转义原始字节   hex hexdump
  别名        phs=proto   conv=flows   ep=endpoints   tls=sni   stream=follow

攻击模型 (-m):
  syn    SYN 洪泛与源 IP 随机化/伪造
  udp    UDP 洪泛
  icmp   ICMP 洪泛
  flood  通用洪泛（syn + udp + icmp）
  cc     CC 攻击（HTTP 层速率/单源/分布式）
  loss   丢包与 TCP 传输异常（重传/重复 ACK/零窗口/截断）
  frag   IP 分片异常（重叠/畸形，泪滴类）
  all    以上全部（-m 留空等价于 all）

分析内容:
  抓包概览、四层协议分布、会话/主机/端口 TOP、DNS 查询、TLS SNI、
  明文 HTTP 主机与请求 URI，以及安全发现（明文凭据、HTTP 口令字段、
  ARP 冲突、未加密的明文协议流量）
  指定 -m 时额外输出逐模型判定（命中/疑似/未命中）、关键指标与命中迹象

输出:
  报告与列表 -> stdout，提示与告警 -> stderr（2>/dev/null 只看报告）
  指定 -o 时报告写入文件（不含颜色码），stdout 不再输出
  TUI 的完整按键与过滤说明见界面内的 ? 面板

示例:
  基础
    gyhost net -i capture.pcap
    gyhost net -i capture.pcap --top 20

  过滤
    gyhost net -i capture.pcap -f "host 10.0.0.5"
    gyhost net -i capture.pcap -f "tcp.port == 443 && !http"
    gyhost net -i capture.pcap -t 30-90 -f "udp"

  逐包查看
    gyhost net -i capture.pcap -l -n 50
    gyhost net -i capture.pcap -V -n 5 -f "port 22"

  交互浏览
    gyhost net -i capture.pcap -T -f "tcp"

  脚本化分析
    gyhost net -i capture.pcap -j | jq ".conversations | sort_by(-.packets) | .[0]"
    gyhost net -i capture.pcap -j -z http | jq ".http.credentials"
    gyhost net -i capture.pcap -z dns,http

  会话重组与时间线
    gyhost net -i capture.pcap -z "follow,tcp,ascii,0"
    gyhost net -i capture.pcap -z timeline            # 按秒看流量起伏
    gyhost net -i capture.pcap -z timeline -I 5       # 5 秒一桶

  攻击分析
    gyhost net -i capture.pcap -m all
    gyhost net -i capture.pcap -m syn,cc`,

		// ---- net 错误 ----
		"net.err.missing_args":          "缺少必填参数: -i [抓包文件]",
		"net.err.no_input":              "没有可用的输入抓包（路径不存在，或目录里没有抓包文件）",
		"net.err.bad_top":               "--top 必须大于 0: %d",
		"net.err.bad_limit":             "-n/--limit 不能为负数: %d",
		"net.err.open":                  "无法读取 %s: %v",
		"net.err.unrecognized":          "%s 不是受支持的抓包容器（仅支持 pcap/pcapng）",
		"net.err.bad_capture":           "解析抓包失败: %v",
		"net.err.create_out":            "创建报告文件失败: %v",
		"net.err.filter_missing":        "过滤表达式不完整，%s 后面缺少参数",
		"net.err.filter_ip":             "无法识别的 IP 地址: %s",
		"net.err.filter_port":           "无法识别的端口号: %s",
		"net.err.filter_token":          "无法识别的过滤条件: %s",
		"net.err.filter_dir":            "%s 只能与 host 或 port 连用",
		"net.err.filter_unknown_field":  "未知字段: %s（输入 \x1b[5m?\x1b[0m 查看可用字段）",
		"net.err.filter_char":           "过滤表达式含非法字符: %s",
		"net.err.filter_unterminated":   "过滤表达式里的字符串没有闭合引号",
		"net.err.filter_unclosed_paren": "过滤表达式括号未闭合",
		"net.err.filter_number":         "不是合法的数字: %s",
		"net.err.filter_empty":          "过滤表达式为空",
		"net.err.bad_model":             "无法识别的分析模型: %s（可用: %s）",

		// ---- net 提示 ----
		"net.info.saved": "报告已写入 %s",

		// ---- net 概览 ----
		"net.label.format":          "格式",
		"net.label.linktype":        "链路类型",
		"net.label.filter":          "过滤条件",
		"net.label.packets":         "数据包",
		"net.label.time":            "时间范围",
		"net.label.bytes":           "流量",
		"net.label.models":          "分析模型",
		"net.label.peak":            "峰值速率",
		"net.packets.filtered":      "%d（过滤后 %d）",
		"net.time.desc":             "%s → %s（%s）",
		"net.bytes.desc":            "抓取 %s，线上 %s",
		"net.endian.le":             "小端",
		"net.endian.be":             "大端",
		"net.ts.sec":                "秒时间戳",
		"net.ts.msec":               "毫秒时间戳",
		"net.ts.usec":               "微秒时间戳",
		"net.ts.nsec":               "纳秒时间戳",
		"net.format.ifaces":         "%d 个接口",
		"net.link.unknown":          "未知链路类型 (DLT %d)",
		"net.warn.unsupported_link": "不支持的链路类型 %d，跳过 %d 帧",
		"net.report.no_match":       "没有匹配过滤条件的数据包",

		// ---- net 段落与表头 ----
		"net.section.protocols": "协议分布",
		"net.section.flows":     "会话 TOP %d",
		"net.section.endpoints": "主机 TOP %d",
		"net.section.ports":     "端口 TOP %d",
		"net.section.dns":       "DNS 查询",
		"net.section.sni":       "TLS SNI",
		"net.section.http":      "HTTP",
		"net.section.findings":  "安全发现",
		"net.section.attack":    "攻击分析",
		"net.layer.l2":          "链路层",
		"net.layer.l3":          "网络层",
		"net.layer.l4":          "传输层",
		"net.layer.l7":          "应用层",
		"net.subsection.hosts":  "主机",
		"net.subsection.uris":   "请求 URI",
		"net.head.layer":        "层级",
		"net.head.proto":        "协议",
		"net.head.packets":      "包数",
		"net.head.percent":      "占比",
		"net.head.bytes":        "字节",
		"net.head.rank":         "序",
		"net.head.flow":         "会话",
		"net.head.host":         "主机",
		"net.head.ip":           "IP",
		"net.head.mac":          "MAC",
		"net.head.sent":         "发包",
		"net.head.recv":         "收包",
		"net.head.port":         "端口",
		"net.head.service":      "服务",
		"net.head.name":         "名称",
		"net.head.count":        "次数",
		"net.head.uri":          "URI",
		"net.head.idx":          "#",
		"net.head.time":         "时间",
		"net.head.endpoints":    "端点",
		"net.head.len":          "长度",
		"net.head.info":         "信息",
		"net.head.model":        "模型",
		"net.head.verdict":      "判定",
		"net.head.metrics":      "关键指标",

		// ---- net 统计口径 ----
		"net.proto.unidentified": "未识别",
		"net.proto.other":        "其它",
		"net.service.unknown":    "未登记",
		"net.packets_fmt":        "%d 包",
		"net.dns.summary":        "查询 %d 条，唯一域名 %d 个，失败响应 %d 条",
		"net.http.summary":       "明文 HTTP 请求 %d 条",
		"net.list.summary":       "共 %d 个包，匹配 %d 个，已列出 %d 个",

		// ---- net 逐包摘要 ----
		"net.info.beacon":       "信标（SSID: %s）",
		"net.info.probe_req":    "探测请求（SSID: %s）",
		"net.info.arp_req":      "谁是 %s？告诉 %s",
		"net.info.arp_rep":      "%s 的 MAC 是 %s",
		"net.info.echo_req":     "Echo 请求 id=%d seq=%d",
		"net.info.echo_rep":     "Echo 响应 id=%d seq=%d",
		"net.info.icmp_unreach": "目标不可达 (code=%d)",
		"net.info.icmp_ttl":     "传输超时 (code=%d)",
		"net.info.icmp":         "type=%d code=%d",
		"net.info.nd_ns":        "邻居请求 %s",
		"net.info.nd_na":        "邻居通告 %s",
		"net.info.nd_rs":        "路由请求",
		"net.info.nd_ra":        "路由通告",
		"net.info.ipv4_frag":    "IPv4 分片 offset=%d",
		"net.info.ipv6_frag":    "IPv6 分片 offset=%d",

		// ---- net 攻击分析 ----
		"net.verdict.hit":       "命中",
		"net.verdict.suspect":   "疑似",
		"net.verdict.miss":      "未命中",
		"net.model.syn":         "SYN 洪泛",
		"net.model.udp":         "UDP 洪泛",
		"net.model.icmp":        "ICMP 洪泛",
		"net.model.cc":          "CC 攻击",
		"net.model.loss":        "流量丢包/传输异常",
		"net.model.frag":        "IP 分片异常",
		"net.metric.syn":        "SYN %d（峰值 %d/s），SYN-ACK %d，源 IP %d 个，占 TCP %s",
		"net.metric.udp":        "UDP %d 包（峰值 %d/s），占总包 %s",
		"net.metric.icmp":       "ICMP %d 包（峰值 %d/s），占总包 %s",
		"net.metric.cc":         "HTTP 请求 %d 条（峰值 %d/s），Top 源 %s %d 次，Top URI %s %d 次",
		"net.metric.loss":       "重传 %d（占数据段 %s），重复 ACK %d，seq 间隙 %d，零窗口 %d，截断 %d",
		"net.metric.frag":       "分片 %d 片，重叠 %d，畸形 %d",
		"net.attack.syn":        "SYN 洪泛迹象: SYN %d、SYN-ACK %d，峰值 %d/s，SYN 占 TCP %s",
		"net.attack.random_src": "源 IP 随机化/伪造: 仅出现 1 次且只发 SYN 的源 %d 个（共 %d 个 SYN 源，占 %s）",
		"net.attack.udp":        "UDP 洪泛迹象: 峰值 %d/s，占总包 %s",
		"net.attack.icmp":       "ICMP 洪泛迹象: 峰值 %d/s，占总包 %s",
		"net.attack.cc":         "CC 攻击迹象: HTTP 请求 %d 条，峰值 %d/s，Top 源 %s（%d 次），Top URI %s（%d 次）",
		"net.attack.cc_dist":    "分布式 CC: 同一 URI %s 被 %d 个不同源请求，共 %d 次",
		"net.attack.cc_single":  "单源高频请求: %s 共 %d 次，占全部请求 %s",
		"net.attack.loss":       "TCP 传输异常: 重传 %d（占数据段 %s），重复 ACK %d，seq 间隙 %d，零窗口 %d",
		"net.attack.trunc":      "抓包被截断: %d 个包的捕获长度小于线上长度，统计不完整",
		"net.attack.frag":       "分片异常: 重叠 %d 片、畸形 %d 片（泪滴类攻击特征）",
		"net.attack.capped":     "统计键数达到上限 %d，部分指标不完整",

		// ---- net 逐包详细视图（-V）----
		"net.flag.verbose":       "逐包详细视图，按 tshark -V 的协议树列出每个字段（自动开启 -l）",
		"net.det.frame_hdr":      "第 %d 帧: 线上 %d 字节 (%d 比特)，已捕获 %d 字节 (%d 比特)",
		"net.det.encap":          "封装类型",
		"net.det.arrival":        "到达时间",
		"net.det.epoch":          "时间戳",
		"net.det.since_ref":      "相对首帧",
		"net.det.seconds":        "秒",
		"net.det.frame_no":       "帧号",
		"net.det.frame_len":      "帧长度",
		"net.det.cap_len":        "捕获长度",
		"net.det.truncated":      "抓包被截断",
		"net.det.protocols":      "协议栈",
		"net.det.yes":            "是",
		"net.det.none":           "无",
		"net.det.set":            "置位",
		"net.det.notset":         "未置位",
		"net.det.info":           "摘要",
		"net.det.eth_hdr":        "以太网 II, 源: %s, 目的: %s",
		"net.det.dst":            "目的地址",
		"net.det.src":            "源地址",
		"net.det.vlan_idx":       "VLAN %d ID",
		"net.det.type":           "类型",
		"net.det.etype":          "%s (0x%04x)",
		"net.det.ipv4_hdr":       "IPv4, 源: %s, 目的: %s",
		"net.det.ipv6_hdr":       "IPv6, 源: %s, 目的: %s",
		"net.det.version":        "版本",
		"net.det.hdr_len":        "头部长度",
		"net.det.bytes":          "%d 字节 (%d)",
		"net.det.bytes_bits":     "%d 字节 (%d 比特)",
		"net.det.dsfield":        "区分服务字段",
		"net.det.total_len":      "总长度",
		"net.det.ident":          "标识",
		"net.det.flags":          "标志位",
		"net.det.df":             "不分片 (DF)",
		"net.det.mf":             "更多分片 (MF)",
		"net.det.frag_off":       "分片偏移",
		"net.det.frag_off_val":   "%d (%d 字节)",
		"net.det.ttl":            "生存时间",
		"net.det.hop_limit":      "跳数限制",
		"net.det.protocol":       "协议",
		"net.det.next_hdr":       "下一头部",
		"net.det.hdr_cksum":      "头部校验和",
		"net.det.src_addr":       "源地址",
		"net.det.dst_addr":       "目的地址",
		"net.det.tclass":         "流量类别",
		"net.det.flow_label":     "流标签",
		"net.det.payload_len":    "载荷长度",
		"net.det.tcp_hdr":        "TCP, 源端口: %d, 目的端口: %d, 序号: %d, 确认号: %d, 载荷: %d 字节",
		"net.det.udp_hdr":        "UDP, 源端口: %d, 目的端口: %d, 载荷: %d 字节",
		"net.det.icmp_hdr":       "%s, 类型: %d, 代码: %d",
		"net.det.icmp_type":      "%s (%d)",
		"net.det.src_port":       "源端口",
		"net.det.dst_port":       "目的端口",
		"net.det.seq":            "序号",
		"net.det.ack":            "确认号",
		"net.det.tcp_flags":      "标志位",
		"net.det.window":         "窗口大小",
		"net.det.checksum":       "校验和",
		"net.det.urgent_ptr":     "紧急指针",
		"net.det.length":         "长度",
		"net.det.service":        "服务",
		"net.det.code":           "代码",
		"net.det.icmp_id":        "标识符",
		"net.det.icmp_seq":       "序列号",
		"net.det.options":        "选项",
		"net.det.opt_kind":       "选项类型: %s",
		"net.det.flag.cwr":       "CWR",
		"net.det.flag.ece":       "ECE",
		"net.det.flag.urg":       "URG",
		"net.det.flag.ack":       "ACK",
		"net.det.flag.psh":       "PSH",
		"net.det.flag.rst":       "RST",
		"net.det.flag.syn":       "SYN",
		"net.det.flag.fin":       "FIN",
		"net.det.arp_hdr":        "ARP: %s",
		"net.det.hw_type":        "硬件类型",
		"net.det.proto_type":     "协议类型",
		"net.det.hw_size":        "硬件地址长度",
		"net.det.proto_size":     "协议地址长度",
		"net.det.arp_op":         "操作码",
		"net.det.arp_request":    "请求 (1)",
		"net.det.arp_reply":      "应答 (2)",
		"net.det.arp_other":      "其它",
		"net.det.arp_sender_mac": "发送方 MAC",
		"net.det.arp_sender_ip":  "发送方 IP",
		"net.det.arp_target_mac": "目标 MAC",
		"net.det.arp_target_ip":  "目标 IP",
		"net.det.http_host":      "Host",
		"net.det.http_cred":      "认证凭据",
		"net.det.http_pass":      "明文口令字段",
		"net.det.dns_name":       "查询名",
		"net.det.dns_ans":        "应答",
		"net.det.tls_sni":        "SNI",
		"net.det.frame_data":     "帧数据",

		// ---- net 交互式 TUI（-T） ----
		"net.flag.tui":                "交互式抓包浏览器：全屏包列表 + 协议树详情，可滚动/选中/实时过滤（需终端）",
		"net.tui.no":                  "编号",
		"net.tui.source":              "源",
		"net.tui.dest":                "目的",
		"net.tui.proto":               "协议",
		"net.tui.length":              "长度",
		"net.tui.info":                "信息",
		"net.tui.detail":              "协议树详情",
		"net.tui.detail_sel":          "（第 %d 帧，共 %d 个可见）",
		"net.tui.packets":             "个包",
		"net.tui.no_filter":           "（无过滤）",
		"net.tui.filter_prompt":       "过滤> ",
		"net.tui.filter_canceled":     "已取消过滤编辑",
		"net.tui.filter_cleared":      "已清除过滤条件",
		"net.tui.filter_hint_empty":   "直接回车清除过滤；输入表达式可过滤",
		"net.tui.filter_hint_ok":      "语法正确，回车应用",
		"net.tui.filter_ex_empty":     "例：tcp.port == 443 · ip.addr == 10.0.0.1 · frame.len > 1000 · http.host contains \"x\" · !(arp)",
		"net.tui.filter_ex_port":      "端口：tcp.port == 443 · src port 1024 · udp.port != 53",
		"net.tui.filter_ex_ip":        "地址：ip.addr == 10.0.0.1 · src host 192.168.1.1 · ip.dst != 8.8.8.8",
		"net.tui.filter_ex_len":       "长度：frame.len > 1000 · frame.len <= 1500 · tcp.payload_len >= 100",
		"net.tui.filter_ex_generic":   "例：tcp · tcp && port == 443 · (tcp || udp) && !arp · dns.qry.name contains \"example\"",
		"net.tui.filter_ex_ipfield":   "%s 接受 IP：%s == 10.0.0.1（或用 src host 10.0.0.1）",
		"net.tui.filter_ex_intfield":  "%s 接受数字：%s == 443 · %s > 100 · %s != 0",
		"net.tui.filter_ex_strfield":  "%s 接受字符串：%s contains \"x\" · %s == \"abc\"",
		"net.tui.filter_ex_boolfield": "%s 是布尔量：%s == 1（置位）或 == 0（未置位）",
		"net.tui.sug_none":            "提示：字段名 + 运算符 + 值，例如 tcp.port == 443；Tab 接受补全，? 查看全部字段",
		"net.tui.sug_field":           "字段：",
		"net.tui.sug_field_prefix":    "补全「%s」：",
		"net.tui.sug_no_field":        "没有以 %s 开头的字段，按 ? 查看全部可用字段",
		"net.tui.sug_operator":        "%s 可用运算符：%s",
		"net.tui.sug_value_generic":   "运算符后填写对应的值",
		"net.tui.sug_val_ip":          "%s 需要 IP 地址，例如 %s == 10.0.0.1",
		"net.tui.sug_val_int":         "%s 需要数字，例如 %s == 443，或 %s > 100",
		"net.tui.sug_val_str":         "%s 需要字符串（加引号），例如 %s contains \"x\"",
		"net.tui.sug_val_bool":        "%s 是布尔量，写 %s == 1 或 %s == 0",
		"net.tui.sug_val_float":       "%s 需要数字，例如 %s > 1.5",
		"net.tui.sug_logic":           "条件已完整，可继续写 && 或 || 串联，或直接回车应用",
		"net.tui.sug_tab":             "   （Tab 接受）",
		"net.tui.empty":               "过滤后没有匹配的包",
		"net.tui.no_match":            "没有匹配的包，按 c 清除过滤或 r 重新应用",
		"net.tui.key_move":            "移动",
		"net.tui.key_pane":            "面板",
		"net.tui.key_fold":            "折叠",
		"net.tui.key_filter":          "过滤",
		"net.tui.key_stats":           "统计",
		"net.tui.key_bytes":           "字节",
		"net.tui.key_help":            "帮助",
		"net.tui.key_quit":            "退出",
		"net.tui.key_enter":           "展开",
		"net.tui.key_fold_all":        "全部折叠",
		"net.tui.key_scroll":          "滚动",
		"net.tui.help_title":          "快捷键",
		"net.tui.help_move":           "上下移动选中包",
		"net.tui.help_fold":           "折叠 / 展开当前节点",
		"net.tui.help_fold_all":       "全部折叠 / 全部展开",
		"net.tui.help_pane":           "在包列表、协议树、字节面板间切换焦点",
		"net.tui.help_enter":          "展开或收起详情面板",
		"net.tui.help_filter":         "打开过滤输入（显示过滤器语法，如 tcp.port == 443）",
		"net.tui.help_history":        "过滤输入时翻阅历史表达式",
		"net.tui.help_esc":            "取消编辑；已有过滤时再按一次清除过滤",
		"net.tui.help_help":           "打开 / 关闭本帮助",
		"net.tui.help_stats":          "统计面板（协议 / 端点 / 会话分布）",
		"net.tui.help_clear":          "清除过滤，显示全部包",
		"net.tui.help_reapply":        "重新应用当前过滤",
		"net.tui.help_jump":           "跳到首包 / 末包",
		"net.tui.help_page":           "上下翻页",
		"net.tui.help_quit":           "退出",
		"net.tui.help_filter_fields":  "过滤可用字段：",
		"net.tui.filter_help":         "可用过滤字段",
		"net.tui.filter_help_hint":    "比如 ip.addr == 10.0.0.1 && tcp.port == 443；↑/↓ 调历史，Esc 取消，?q 退出本帮助",
		"net.tui.time":                "时间",
		"net.tui.bytes":               "字节",
		"net.tui.tree":                "协议树",
		"net.tui.stats":               "统计",
		"net.tui.pane_list":           "包列表",
		"net.tui.focus":               "当前面板",
		"net.tui.stat_proto":          "协议分布",
		"net.tui.stat_endpoint":       "端点分布",
		"net.tui.stat_convers":        "会话分布",
		"net.tui.stat_calculating":    "正在统计…",
		"net.tui.stat_none":           "没有可统计的数据",
		"net.tui.collapse_all":        "已全部折叠",
		"net.tui.expand_all":          "已全部展开",
		"net.tui.no_bytes":            "该帧没有原始字节",
		"net.tui.name":                "名称",
		"net.tui.stat_summary":        "共 %d 个包 / %s",
		"net.tui.percent":             "占比",
		"net.err.no_tty":              "交互式模式需要终端（stdin/stdout 均为 TTY）；请改用 -l 或 -V",
		"net.err.tui_output":          "-T 交互式模式占用终端，不能与 -o 同时使用",
		"net.err.frame_range":         "帧下标越界：%d",

		// ---- net 安全发现 ----
		"net.find.none":      "未发现明显的安全问题",
		"net.find.cred":      "捕获到明文凭据: %s",
		"net.find.field":     "HTTP 请求中的明文口令字段: %s",
		"net.find.arp":       "同一 IP 出现在多个 MAC 上，疑似 ARP 欺骗",
		"net.find.cleartext": "存在未加密的明文协议流量",

		// ==================== mem 模块 ====================
		"mem.group":   "内存取证",
		"mem.summary": "内存取证：分析活体进程或内存转储，还原程序行为并从内存中恢复文件",

		"mem.flag.input":    "分析目标：进程 PID、self（当前进程）或内存转储文件路径",
		"mem.flag.action":   "要执行的动作，逗号分隔可重复（info/maps/strings/behavior/carve/hash/entropy/dump/all）",
		"mem.flag.carvedir": "把恢复出来的文件写入该目录",
		"mem.flag.type":     "雕取的文件类型，逗号分隔（all 默认，或 png/jpg/zip/pdf/pe/sqlite…）",
		"mem.flag.filter":   "只保留包含该关键字（忽略大小写）的字符串与行为痕迹",
		"mem.flag.region":   "只分析指定区域：类型（image/heap/stack/mapped/anon）、all 或地址范围 0x1000-0x2000",
		"mem.flag.minsize":  "跳过小于该字节数的区域",
		"mem.flag.maxsize":  "跳过大于该字节数的区域（0 表示不限）",
		"mem.flag.minlen":   "字符串最小长度（默认 4）",
		"mem.flag.limit":    "每类结果最多输出多少条（默认 50）",
		"mem.flag.encoding": "字符串编码：ascii / utf16 / both（默认 both）",
		"mem.flag.addr":     "写入目标地址：0x1234、十进制，或 区域名+偏移（如 heap+0x40）",
		"mem.flag.data":     "要写入/替换的内容：\\xNN 字节序列、@文件路径，或普通 UTF-8 原文",
		"mem.flag.apply":    "真正执行写入；不加时只预览改动，不碰目标",
		"mem.flag.force":    "允许写入没有写权限的区域/目标（默认拒绝）",
		"mem.flag.backup":   "回滚记录文件路径（写入时自动生成备份，可用 -a restore 回滚）",
		"mem.flag.max":      "一次最多改写多少处（patch 时默认不限）",
		"mem.flag.out":      "把报告写入该文件（默认打印到 stdout）",
		"mem.flag.dump":     "把内存镜像导出到该文件（等价于 -a dump）",
		"mem.flag.json":     "输出 JSON 而非人读报告，便于 jq 等工具二次处理",
		"mem.flag.verbose":  "详细模式：列出全部区域（含未选中的）与已加载模块",
		"mem.flag.quiet":    "静默模式，不向 stderr 输出逐区域进度",
		"mem.flag.nonascii": "保留非 ASCII 字符串",
		"mem.flag.showall":  "不限制结果条数（输出可能很长）",

		"mem.usage": `gyhost mem - 内存取证：分析活体进程或内存转储文件

用法:
  gyhost mem -i <pid|self|转储文件> [-a 动作] [选项...]

参数（三个平台完全一致；底层按 Windows / Linux / macOS 分别编译）:

  -i, -input     分析目标
                    <pid>       正在运行的进程
                    self        当前进程
                    <文件路径>   内存转储文件（raw/dmp/bin，任意平台都能分析）
  -e, -program   分析指定程序，直接给 PID 或程序名，不用先查 PID
                  程序名匹配进程名 / 可执行文件名 / 命令行，命中多个则依次分析
  -l, -list      列出程序与子线程（值可省略）
                  -l            列出全部程序，并显示每个程序的子线程
                  -l <PID|程序名> 只显示该程序的子线程
  -a, -action    执行动作，逗号分隔可重复（默认 info,behavior）
  -o, -out       报告写入文件，stdout 保持干净
  -q, -quiet     不向 stderr 输出逐区域进度

  收敛分析范围
  -r, -region    只分析指定区域：image / heap / stack / mapped / anon
                  或地址范围，如 -r 0x7f0000000000-0x7f0000100000
  -s, -minsize   跳过小于该字节数的区域
  -S, -maxsize   跳过大于该字节数的区域
  -k, -filter    只保留包含该关键字的字符串与行为痕迹
  -L, -minlen    字符串最小长度
  -E, -encoding  字符串编码：ascii / utf16 / both
  -n, -limit     每类结果最多输出条数（默认 50）
  -X, -showall   不限制条数

  输出形式
  -j, -json      JSON 结构化输出，便于 jq 等工具处理
  -V, -verbose   详细模式（列出全部区域与已加载模块）

  内存中恢复文件
  -c, -carvedir  把恢复出来的文件写入该目录
  -t, -type      只雕取指定类型，逗号分隔（all 为全部）

  导出内存镜像
  -d, -dump      把内存镜像导出为 raw dump（同时生成 .index 索引）

在内存中操作目标程序（改写行为）
  -a write       在 --addr 指定的地址原位写入 -Y 的内容
  -a patch       把内存里 -k 指定的内容替换成 -Y 指定的内容
  -a restore     按备份记录回滚，把内存改回补丁前的样子
  --addr ADDR    目标地址：0x1234、十进制，或 区域名+偏移（如 heap+0x40）
  -Y DATA        写入/替换内容：\xNN 字节序列、@文件路径，或普通 UTF-8 原文
  --apply        真正执行写入（默认只预览，不碰目标）
  --force        允许写入无写权限的区域/目标（默认拒绝）
  --backup FILE  回滚记录文件（写入时自动生成，-a restore 时读取）
  --max N        一次最多改写多少处

动作 (-a):
  info      目标概览：进程信息、区域统计、类型分布、整体摘要
  maps      内存区域列表（地址、权限、类型、宿主文件）
  strings   字符串提取（ASCII 与 UTF-16LE）
  behavior  程序行为分析：URL/IP/域名/凭据/命令行/注入与持久化痕迹
  carve     从内存中恢复文件（按魔数雕取）
  hash      区域哈希（md5 / sha256）
  entropy   区域熵（判断明文 / 压缩 / 加密数据）
  dump      导出内存镜像为 raw dump
  write     在内存中按地址写入（需 --addr + -Y + --apply）
  patch     在内存中搜索替换（需 -k + -Y + --apply）
  restore   回滚到补丁前的原始内容（需 --backup + --apply）
  all       以上除 dump / write / patch / restore 外的全部
            （写类动作必须显式点名，不会被 all 顺带触发）

支持雕取的文件类型:
  png jpg gif pdf zip gzip bmp elf sqlite 7z rar dex tiff wav pe class lnk
  （-t 传 all 表示不限类型）

行为痕迹分类 (-a behavior):
  网络    url ip domain email port
  凭据    password private_key aws_key jwt basic_auth shadow
  主机    path_unix path_win registry env command
  取证    injection cred_dump persist anti_forensic mining ransom

示例:
  gyhost mem -l                                       # 列出全部程序与它们的子线程
  gyhost mem -l nginx                                 # 只看 nginx 这个程序的子线程
  gyhost mem -l 1234                                  # 只看 pid 1234 的子线程
  gyhost mem -e nginx                                 # 按程序名分析（等价于 -i <pid>）
  gyhost mem -e nginx -a info,behavior                # 按程序名做概览与行为分析
  gyhost mem -i self                                  # 分析当前进程
  gyhost mem -i 1234 -a info,maps                     # 看某进程的内存布局
  gyhost mem -i 1234 -a behavior -s 1048576           # 行为分析，跳过 1MB 以下区域
  gyhost mem -i 1234 -a carve -c ./carved -t png,zip  # 从内存里恢复 png/zip
  gyhost mem -i memdump.raw -a all -o report.txt      # 离线分析转储并写文件
  gyhost mem -i memdump.raw -a strings -k password    # 只看含 password 的串
  gyhost mem -i 1234 -a dump -d target.memdump        # 导出内存留证
  gyhost mem -i 1234 -a patch -k production -Y staging # 预览：把 production 改成 staging
  gyhost mem -i 1234 -a patch -k production -Y staging --apply   # 真的改写内存
  gyhost mem -i mem.bin -a write --addr heap+0x40 -Y '\x00\x01' --apply
  gyhost mem -i 1234 -a restore --backup mem-nginx-*.bak --apply  # 回滚
  gyhost mem -i memdump.raw -a info -j | jq .summary # JSON 接管道
  gyhost help mem`,

		// ---- mem 提示 ----
		"mem.info.opening":  "正在打开目标: %s",
		"mem.info.region":   "已扫描区域 %s  (%s)",
		"mem.info.selected": "%d 个（跳过 %d 个）",
		"mem.info.scanned":  "%s，完整 %d 个 / 中断 %d 个",
		"mem.info.saved":    "报告已写入: %s",
		"mem.info.dumped":   "内存镜像已导出: %s（%s，%d 个区域）",
		"mem.dump.summary":  "已导出 %d 个区域共 %s 到: %s",
		"mem.dump.index":    "区域索引: %s",

		// ---- mem 错误 ----
		"mem.err.missing_input": "缺少必需参数: -i <pid|self|转储文件>",
		"mem.err.bad_action":    "未知的 -a 动作: %s（可用: info/maps/strings/behavior/carve/hash/entropy/dump/all）",
		"mem.err.bad_target":    "无法识别的 -i 目标: %s",
		"mem.err.bad_region":    "无法识别的 -r 区域过滤: %s（可用: all/image/heap/stack/mapped/anon 或地址范围）",
		"mem.err.bad_minsize":   "-s 区域大小下限必须 >= 0（当前 %d）",
		"mem.err.bad_maxsize":   "-S 区域大小上限必须 >= 0（当前 %d）",
		"mem.err.bad_minlen":    "-L 字符串最小长度必须在 1~4096 之间（当前 %d）",
		"mem.err.bad_limit":     "-n 条数上限必须 >= 0（当前 %d）",
		"mem.err.size_range":    "-s(%d) 不能大于 -S(%d)",
		"mem.err.bad_encoding":  "未知的 -e 编码: %s（可用: ascii/utf16/both）",
		"mem.err.json_carve":    "-j 与 -c 不能同时使用（JSON 面向管道，恢复文件请用 -c 单独跑）",
		"mem.err.privilege":     "权限不足，无法读取 %s 上的目标进程内存: %s",
		"mem.err.unsupported":   "当前平台 (%s) 未实现活体内存读取；仍可用 -i <转储文件> 分析内存镜像",
		"mem.err.no_process":    "目标进程不存在: %s",
		"mem.err.gone":          "目标进程已退出或内存不可读: %s（%v）",
		"mem.err.open_target":   "打开目标失败: %s（%v）",
		"mem.err.open_file":     "打开内存转储文件失败: %s（%v）",
		"mem.err.regions":       "读取内存区域列表失败: %v",
		"mem.err.no_regions":    "目标没有任何可读内存区域",
		"mem.err.no_selected":   "过滤后没有可分析的区域，请放宽 -r / -s / -S",
		"mem.err.create_out":    "创建输出文件失败: %v",
		"mem.err.write_out":     "写入输出文件失败: %v",
		"mem.err.create_dir":    "创建恢复目录失败: %s（%v）",
		"mem.err.write_file":    "写入恢复文件失败: %s（%v）",

		// ---- mem 报告 ----
		"mem.sec.overview": "目标概览",
		"mem.sec.maps":     "内存区域",
		"mem.sec.entropy":  "区域熵",
		"mem.sec.hash":     "区域哈希",
		"mem.sec.behavior": "程序行为痕迹",
		"mem.sec.strings":  "字符串",
		"mem.sec.carve":    "内存中恢复的文件",

		"mem.kind.live":          "活体进程",
		"mem.kind.file":          "内存转储文件",
		"mem.kind.url":           "URL",
		"mem.kind.ip":            "IPv4 地址",
		"mem.kind.domain":        "域名",
		"mem.kind.email":         "邮箱",
		"mem.kind.port":          "端口",
		"mem.kind.password":      "口令/凭据",
		"mem.kind.private_key":   "私钥材料",
		"mem.kind.aws_key":       "云访问密钥",
		"mem.kind.jwt":           "JWT 令牌",
		"mem.kind.basic_auth":    "HTTP Basic 认证头",
		"mem.kind.shadow":        "shadow 口令行",
		"mem.kind.path_unix":     "Unix 路径",
		"mem.kind.path_win":      "Windows 路径",
		"mem.kind.registry":      "注册表键",
		"mem.kind.env":           "环境变量",
		"mem.kind.command":       "命令行",
		"mem.kind.injection":     "进程注入 API",
		"mem.kind.cred_dump":     "凭据窃取痕迹",
		"mem.kind.persist":       "持久化痕迹",
		"mem.kind.anti_forensic": "反取证痕迹",
		"mem.kind.mining":        "挖矿痕迹",
		"mem.kind.ransom":        "勒索痕迹",

		"mem.col.kind":     "目标类型",
		"mem.col.target":   "目标",
		"mem.col.pid":      "进程",
		"mem.col.ppid":     "父进程",
		"mem.col.proc":     "进程名",
		"mem.col.exe":      "可执行文件",
		"mem.col.arch":     "架构",
		"mem.col.user":     "用户",
		"mem.col.started":  "启动时间",
		"mem.col.vsize":    "虚拟内存",
		"mem.col.regions":  "内存区域",
		"mem.col.selected": "参与分析",
		"mem.col.exec":     "可执行区",
		"mem.col.scanned":  "已读取",
		"mem.col.total":    "整体摘要",
		"mem.col.start":    "起始地址",
		"mem.col.end":      "结束地址",
		"mem.col.size":     "大小",
		"mem.col.perm":     "权限",
		"mem.col.path":     "宿主文件",
		"mem.col.entropy":  "熵",
		"mem.col.class":    "分类",
		"mem.col.risk":     "风险",
		"mem.col.offset":   "偏移",
		"mem.col.value":    "内容",
		"mem.col.enc":      "编码",
		"mem.col.type":     "类型",
		"mem.col.score":    "置信度",
		"mem.col.saved":    "已保存",

		"mem.bykind":                   "按区域类型分布:",
		"mem.modules":                  "已加载模块（%d 个）:",
		"mem.more":                     "还有 %d 条未显示（用 -n 调整或 -X 显示全部）",
		"mem.none":                     "（无）",
		"mem.maps.header":              "%-16s %-16s %10s  %-4s %-6s %s",
		"mem.entropy.header":           "%8s %-7s %10s  %-6s %s",
		"mem.hash.header":              "%-16s %10s  %-6s %-32s %s",
		"mem.behavior.header":          "%-6s %-12s %-16s  %s",
		"mem.behavior.stats":           "分类统计:",
		"mem.behavior.count":           "个",
		"mem.behavior.none":            "未发现明显的行为痕迹",
		"mem.strings.header":           "%-16s  %-7s  %s",
		"mem.strings.none":             "没有提取到字符串",
		"mem.carve.header":             "%-8s %-16s %10s  %3s %-64s %s",
		"mem.carve.none":               "没有雕取到文件",
		"mem.carve.saved":              "已保存 %d 个文件到: %s",
		"mem.risk.0":                   "无害",
		"mem.risk.1":                   "信息",
		"mem.risk.2":                   "可疑",
		"mem.risk.3":                   "高危",
		"mem.sec.patch":                "内存改写",
		"mem.col.op":                   "动作",
		"mem.col.mode":                 "模式",
		"mem.col.hits":                 "命中",
		"mem.col.skipped":              "被拒",
		"mem.col.written":              "已写入",
		"mem.col.addr":                 "地址",
		"mem.col.before":               "改前",
		"mem.col.after":                "改后",
		"mem.col.status":               "状态",
		"mem.patch.header":             "%-16s  %-22s -> %-22s %s",
		"mem.patch.preview":            "预览（未写入）",
		"mem.patch.applied":            "已执行",
		"mem.patch.ok":                 "OK",
		"mem.patch.none":               "没有匹配到要改写的内容",
		"mem.patch.hint":               "以上仅为预览；确认无误后加 --apply 才会真正写入目标内存",
		"mem.info.backup_saved":        "已保存回滚记录（%d 条）: %s",
		"mem.warn.backup_failed":       "回滚记录保存失败: %s（%v）",
		"mem.warn.bad_record":          "地址 %#x 的备份记录无法解析，已跳过: %v",
		"mem.warn.restore_unreadable":  "地址 %#x 已不可读，无法回滚",
		"mem.warn.restore_failed":      "地址 %#x 回滚失败: %v",
		"mem.err.not_writable":         "目标不可写（%s 平台）：没有写权限；请用 root/管理员重试，或先 -d 导出后在镜像上操作",
		"mem.err.write_need_target":    "write/patch/restore 需要指定目标: -i <pid|self|转储文件> 或 -e <程序>",
		"mem.err.write_need_addr":      "-a write 需要 --addr 指定目标地址",
		"mem.err.write_need_data":      "需要用 -Y 指定要写入的内容",
		"mem.err.patch_need_data":      "需要用 -Y 指定替换成的内容",
		"mem.err.patch_need_needle":    "需要用 -k 指定要查找的内容（原始字节或原文）",
		"mem.err.bad_data":             "无法解析 -Y 的内容: %v",
		"mem.err.bad_addr":             "无法解析 --addr: %s",
		"mem.err.no_such_region":       "没有类型为 %s 的区域（用 -a maps 看有哪些）",
		"mem.err.addr_out_of_region":   "偏移 %#x 超出 %s 区域范围（%s）",
		"mem.err.bad_max":              "--max 必须 >= 0（当前 %d）",
		"mem.err.restore_need_backup":  "-a restore 需要 --backup <回滚记录文件>",
		"mem.err.no_backup":            "回滚记录文件里没有任何记录",
		"mem.err.restore_preview_only": "回滚只做了预览；加 --apply 才会真正写回",
		"mem.err.no_write_action":      "未指定写类动作（write / patch / restore）",
		"mem.err.target_conflict":      "-i 与 -e 不能同时使用（两个都指定了分析目标）",
		"mem.err.no_match":             "没有匹配的程序: %s（可用 -l 先查看程序列表）",
		"mem.err.list_processes":       "枚举 %s 上的进程失败: %v",
		"mem.err.threads_unsupported":  "当前平台 (%s) 无法枚举线程",
		"mem.info.matched":             "命中程序: pid %d (%s)",
		"mem.info.self_target":         "self (pid %d, %s)",
		"mem.info.proc_target":         "%s (pid %d)",
		"mem.info.multi_match":         "%s 匹配到 %d 个进程，将依次分析",
		"mem.info.all_procs":           "全部程序（%d 个）",
		"mem.info.only_proc":           "仅 %s（%d 个）",
		"mem.info.thread_fail":         "pid %d (%s) 的线程读取失败: %v",
		"mem.sec.procs":                "程序与线程",
		"mem.col.scope":                "范围",
		"mem.col.threads":              "线程数",
		"mem.col.tid":                  "线程ID",
		"mem.col.state":                "状态",
		"mem.col.name":                 "名称",
		"mem.col.cmd":                  "命令行",
		"mem.proc.header":              "%5s  %7s  %7s  %-7s %-12s %-20s %s",
		"mem.proc.none":                "没有匹配到程序",
		"mem.thread.title":             "各程序的子线程:",
		"mem.thread.header":            "%7s  %-11s %s",
		"mem.thread.of":                "pid %d (%s) 共 %d 个线程:",
		"mem.thread.none":              "pid %d (%s) 没有可列出的线程",
	},

	En: {
		// ==================== Banner ====================
		"app.title":    "gyhost - Go Language Local Analysis Tool",
		"app.author":   "Author: xiguayiqiua",
		"app.version":  "Tool Version: %s",
		"app.desc":     "Description: Local analysis toolkit focusing on offline network security analysis",
		"app.warning":  "Warning: Authorized testing only. Unauthorized use is strictly prohibited!",
		"app.get_help": `Run "./gyhost help" to get help`,

		// ==================== Root help ====================
		"help.usage":                   "Usage:",
		"help.commands":                "Available Modules:",
		"help.flags":                   "Flags:",
		"help.get_cmd_help":            `Use "gyhost help <module>" to get module help`,
		"help.usage_line1":             "  gyhost [help] [flags]",
		"help.usage_line2":             "  gyhost [command]",
		"root.err.unknown_module":      "unknown module: %s",
		"root.err.unknown_global_flag": "unknown global option: %s",
		"root.err.prefix":              "error: %v",

		// ==================== Global flags ====================
		"flag.help":      "show help",
		"flag.version":   "show version information",
		"flag.no_banner": "hide the startup banner",
		"flag.no_color":  "disable colored output",

		// ==================== Module contract ====================
		"mod.group.default": "Basic",
		"mod.err.nil":       "module: cannot register a nil module",
		"mod.err.empty":     "module: module name must not be empty",
		"mod.err.dup":       "module: module %q already registered",

		// ==================== pwdhash ====================
		"pwdhash.err.empty":       "pwdhash: empty hash",
		"pwdhash.err.unsupported": "pwdhash: unsupported hash format %q",
		"pwdhash.err.register":    "pwdhash: failed to register decoders",

		// ==================== shadow module ====================
		"shadow.group":        "Local Analysis",
		"shadow.summary":      "Offline password cracking for shadow files",
		"shadow.flag.input":   "path to the shadow file",
		"shadow.flag.dict":    "path to the password wordlist (mutually exclusive with -m)",
		"shadow.flag.mask":    "mask expression (hashcat style, e.g. ?l?l?d?d); mutually exclusive with -p",
		"shadow.flag.user":    "only crack the given users, comma-separated or repeated, e.g. -u root,alice (default: all)",
		"shadow.flag.threads": "number of worker threads",
		"shadow.flag.out":     "result output file",
		"shadow.flag.quiet":   "quiet mode, hide live progress",
		"shadow.flag.gpu":     "accelerate with a GPU (CUDA), falling back to CPU when unavailable (requires root/administrator)",
		"shadow.usage": `gyhost shadow - Offline password cracking for shadow files

Usage:
  gyhost shadow -i <shadow-file> (-p <wordlist> | -m <mask>) [options]

Options:
  -i, -input    path to a shadow file (e.g. /etc/shadow or a backup)
  -p, -pass     password wordlist, one candidate per line (mutually exclusive with -m)
  -m, -mask     mask expression, candidates generated on the fly (mutually exclusive with -p)
                hashcat style: ?l lower ?u upper ?d digit ?h/?H hex
                ?s special ?a all printable ?b every byte ?? literal '?'
                e.g. -m '?l?l?d?d', -m 'pass?d?d?d'
  -u, -user     only crack the given users, comma-separated or repeated, e.g. -u root,alice (default: all)
  -t, -threads  number of workers (default: number of CPUs)
  -o, -out      optional, write results as user:password
  -q, -quiet    quiet mode, hide the live progress line
  --gpu         accelerate with a GPU (CUDA), falls back to CPU (requires root/administrator)

Output:
  results/summary -> stdout (colored), live progress -> stderr (single refreshed line on TTY)
  progress shows: candidates consumed, checks performed, users & hash types being tried, speed, elapsed

Supported hashes:
  $1$ md5crypt, $5$/$6$ sha-crypt (with rounds), $2*$ bcrypt, $y$ yescrypt,
  $argon2*$, $pbkdf2-*$, $scrypt$

Examples:
  gyhost shadow -i /etc/shadow -p rockyou.txt
  gyhost shadow -i /etc/shadow -m '?d?d?d?d'          # brute force 4 digits
  gyhost shadow -i /etc/shadow -p rockyou.txt -u root,alice
  gyhost shadow -i shadow.bak -p pass.txt -u root -u alice -t 8 -o result.txt
  gyhost shadow -i /etc/shadow -p rockyou.txt 2>/dev/null   # results only
  gyhost help shadow`,

		// ---- shadow errors ----
		"shadow.err.missing_args":   "missing required options: -i <shadow-file>, plus either -p <wordlist> or -m <mask>",
		"shadow.err.mask_conflict":  "cannot use -p and -m at the same time, pick one",
		"shadow.err.mask":           "invalid mask expression",
		"shadow.err.threads":        "-t threads must be >= 1 (got %d)",
		"shadow.err.open_shadow":    "failed to open the shadow file",
		"shadow.err.open_dict":      "failed to open the wordlist",
		"shadow.err.bad_line":       "invalid line %d in shadow file: %q",
		"shadow.err.no_user":        "missing username on line %d of shadow file",
		"shadow.err.read":           "failed to read the shadow file",
		"shadow.err.empty_file":     "no entries found in shadow file %s",
		"shadow.err.no_targets":     "no cracker targets (%d entries, all locked or unsupported)",
		"shadow.err.user_not_found": "user(s) not found in the shadow file: %s",
		"shadow.err.create_out":     "failed to create the result file",
		"shadow.err.write_out":      "failed to write the result file",

		// ---- shadow skip reasons ----
		"shadow.skip.locked":      "locked / no password",
		"shadow.skip.unsupported": "unsupported hash (%s)",

		// ---- shadow GPU ----
		"shadow.gpu.enabled":       "[✓] GPU acceleration enabled: %s (%d MB)",
		"shadow.gpu.partial":       "[*] GPU handles %d targets, %d targets remain on CPU",
		"shadow.gpu.needs_root":    "[!] enabling the GPU requires root (administrator on Windows), falling back to CPU; re-run with sudo or as Administrator",
		"shadow.gpu.not_compiled":  "[!] built without CUDA support, falling back to CPU (rebuild with make to enable GPU)",
		"shadow.gpu.no_device":     "[!] no usable CUDA device found, falling back to CPU",
		"shadow.gpu.unsupported":   "[!] target hashes are not GPU-capable ($1$/$5$/$6$ only), falling back to CPU",
		"shadow.gpu.warmup":        "[*] Waking up the GPU and boosting its clocks (about %s)...",
		"shadow.gpu.runtime_error": "[!] GPU verification failed, falling back to CPU: %s",

		// ---- shadow report ----
		"shadow.mask.keyspace":     "[*] mask %s expands to %s candidates",
		"shadow.report.summary":    "[*] Targets %s | Skipped %s | Cracked %s",
		"shadow.report.stats":      "[*] Wordlist %s | Checks %s | Time %s | Speed %s/s",
		"shadow.report.stats_mask": "[*] Mask candidates %s | Checks %s | Time %s | Speed %s/s",
		"shadow.report.skip":       "[-] %s: skipped (%s)  %s",
		"shadow.report.pending":    "[!] Uncracked (%s): %s",
		"shadow.report.hint":       "[!] Try a larger wordlist or rule-based mutation",
		"shadow.report.all_done":   "[+] All targets cracked",
		"shadow.report.gpu":        "[*] GPU device: %s (%s MB)",

		// ---- shadow live progress ----
		"shadow.progress.head":      "[~] Progress %s | Wordlist %s | Checks %s |",
		"shadow.progress.head_mask": "[~] Progress %s | Mask %s | Checks %s |",
		"shadow.progress.cracked":   "%d/%d cracked",
		"shadow.progress.trying":    "Trying %s |",
		"shadow.progress.more":      " +%s more",
		"shadow.progress.finished":  " all cracked, finishing…",
		"shadow.progress.tail":      "%s | %s",
		"shadow.progress.rate":      "%s/s",

		// ---- shadow hit ----
		"shadow.hit.format": "%s %s  %s",

		// ==================== hashdump module ====================
		"hashdump.group":      "Local Analysis",
		"hashdump.summary":    "Extract crackable hashes from encrypted archives, documents and wireless captures",
		"hashdump.flag.input": "path to the archive/document/capture (repeatable; a directory scans its zip/7z/rar/pdf/cap files)",
		"hashdump.flag.out":   "write the extracted hashes to this file (default: stdout)",
		"hashdump.flag.quiet": "quiet mode, hide summary and notices on stderr",
		"hashdump.usage": `gyhost hashdump - Extract crackable hashes from encrypted archives, documents and wireless captures

Usage:
  gyhost hashdump -i [archive|document|capture] [options...]

Options:
  -i, -input    input path, repeatable; a directory scans by extension
                (zip/7z/rar, doc/docx/xls/xlsx/ppt/wps, pdf, cap/pcap/pcapng)
  -o, -out      optional, write the extracted hashes to this file (default: stdout)
  -q, -quiet    quiet mode, hide summary and notices on stderr

Output:
  hashes -> stdout (one hashcat hash per line, pipe friendly), summary -> stderr
  with -o the hashes go to the file and stdout stays clean

Supported formats:
  zip   ZipCrypto -> -m 17200 (deflate) / -m 17210 (stored); WinZip AES -> -m 13600
  7z    AES-256+SHA256 -> -m 11600 (including encrypted file names)
  rar   RAR5 -> -m 13000 (including encrypted headers -hp); RAR4/RAR3 not supported
  doc   encrypted Office/WPS documents: OOXML agile -> -m 9500 (SHA-1)
        / -m 9600 (SHA-512); OOXML standard -> -m 9400;
        Word/Excel 97-2003 -> -m 9700 (RC4+MD5) / -m 9800 (RC4+SHA1);
        output is byte-identical to john's office2john
        unencrypted documents, WPS private format and PPT/Access are reported
        with a specific skip reason
  cap   pcap/pcapng wireless capture -> -m 22000 (WPA/WPA2 PMKID and 4-way handshake)
        link types 802.11 / radiotap / Prism / AVS; the ESSID is taken from beacons,
        probe responses and (re)association requests; missing ESSID or an incomplete
        handshake is skipped
  pdf   encrypted PDF -> -m 10400 (RC4-40) / 10500 (RC4-128, AES-128)
        / 10600 (AES-256) / 10700 (AES-256 hardened KDF), picked from /Encrypt V/R

Notes:
  entries whose data exceeds the hashcat limit are skipped and reported on stderr

Examples:
  gyhost hashdump -i secret.zip > hashes.txt
  hashcat -m 17200 hashes.txt wordlist.txt
  gyhost hashdump -i secret.7z -o hashes.txt -q && hashcat -m 11600 hashes.txt wordlist.txt
  gyhost hashdump -i private.docx > office.hashes && hashcat -m 9600 office.hashes wordlist.txt
  gyhost hashdump -i wifite/wifi-01.cap > wpa.hc22000
  hashcat -m 22000 wpa.hc22000 wordlist.txt
  gyhost hashdump -i /path/to/dir 2>/dev/null | sort -u > all.txt
  gyhost help hashdump`,

		// ---- hashdump errors ----
		"hashdump.err.missing_args": "missing required option: -i [archive|document|capture]",
		"hashdump.err.open":         "cannot read %s: %v",
		"hashdump.err.no_archive":   "no input file to process",
		"hashdump.err.unrecognized": "unrecognized file (not a zip/7z/rar, Office document or wireless capture): %s",
		"hashdump.err.rar4":         "RAR4/RAR3 archives are not supported yet (known plaintext required): %s",
		"hashdump.err.bad_header":   "broken archive structure: %s",
		"hashdump.err.bad_capture":  "broken capture structure: %s",
		"hashdump.err.create_out":   "cannot create the output file: %v",
		"hashdump.err.write_out":    "cannot write the output file: %v",

		// ---- hashdump summary and notices ----
		"hashdump.info.archive": "%s (%s): extracted %d hash(es), hashcat -m %s",
		"hashdump.info.entry":   "    %s  (-m %d)",
		"hashdump.info.total":   "[*] %d hash(es) extracted",
		"hashdump.info.saved":   "[*] %d hash(es) extracted, written to %s",
		"hashdump.info.empty":   "[!] no crackable hash found in %s",
		"hashdump.info.header":  "(encrypted header/file names)",
		"hashdump.warn.skip":    "[-] %s: skipped %s (%s)",

		// ---- hashdump skip reasons ----
		"hashdump.skip.method":     "unsupported encryption/compression method %s",
		"hashdump.skip.codec":      "unsupported 7z algorithm %s",
		"hashdump.skip.large":      "data exceeds the hashcat limit (%d bytes)",
		"hashdump.skip.short":      "encrypted data too short",
		"hashdump.skip.no_check":   "password check value missing",
		"hashdump.skip.no_crc":     "CRC32 missing, cannot verify",
		"hashdump.skip.broken":     "invalid data offset or length",
		"hashdump.skip.no_ssid":    "no usable ESSID captured, cannot build the hash",
		"hashdump.skip.incomplete": "incomplete 4-way handshake, cannot build the hash",
		"hashdump.skip.linktype":   "unsupported link type %d (only 802.11/radiotap/Prism/AVS)",

		// ---- hashdump wireless capture ----
		"hashdump.wifi.capture":     "capture",
		"hashdump.wifi.entry.eapol": "handshake %s (%s/%s)",
		"hashdump.wifi.entry.pmkid": "PMKID %s (%s)",

		// ---- hashdump encrypted PDF ----
		"hashdump.pdf.skip.size":       "PDF is empty or too large (%d bytes), skipped",
		"hashdump.pdf.skip.no_encrypt": "PDF is not encrypted (no /Encrypt found), nothing to extract",
		"hashdump.pdf.skip.no_id":      "encryption dictionary has no /ID[0], no verifiable password hash to extract",
		"hashdump.pdf.skip.version":    "unsupported PDF encryption version (V=%d R=%d)",
		"hashdump.pdf.skip.broken":     "incomplete PDF encryption dictionary (V=%d R=%d)",

		// ---- hashdump Office documents ----
		"hashdump.office.skip.size":       "Office document is empty or too large (%d bytes), skipped",
		"hashdump.office.skip.ole":        "broken OLE compound document: %v",
		"hashdump.office.skip.broken":     "incomplete or corrupted encryption metadata",
		"hashdump.office.skip.external":   "external cryptographic provider is not supported",
		"hashdump.office.skip.flags":      "encryption flags do not match the encryption type, file may be corrupted",
		"hashdump.office.skip.hash_alg":   "unsupported hash algorithm %s",
		"hashdump.office.skip.cipher":     "unsupported cipher algorithm %s (AES only)",
		"hashdump.office.skip.access":     "encrypted Access databases are not supported yet",
		"hashdump.office.skip.ppt":        "encrypted PowerPoint documents are not supported yet",
		"hashdump.office.skip.no_streams": "no supported encryption data found in the OLE document",
		"hashdump.office.skip.xor":        "XOR obfuscation, not supported by hashcat",
		"hashdump.office.skip.wps":        "WPS private format document, hashcat has no matching mode",
		"hashdump.office.skip.no_encrypt": "document is not encrypted, nothing to extract",
		"hashdump.office.skip.doc_header": "unrecognized Word encryption header",
		"hashdump.office.skip.key_size":   "unsupported RC4 key size %d bits",

		// ==================== hashcat module ====================
		"hashcat.group":      "Local Analysis",
		"hashcat.summary":    "Identify the algorithm behind encrypted files and hashes, with the matching hashcat mode",
		"hashcat.flag.input": "path to the file/directory to analyze (repeatable; a directory scans its archives, documents, captures and hash lists)",
		"hashcat.flag.quiet": "quiet mode, hide skip reasons and the trailing hint",
		"hashcat.flag.list":  "list the algorithms GYhost can identify with their hashcat modes",
		"hashcat.usage": `gyhost hashcat - identify the algorithm behind encrypted files and hashes

Usage:
  gyhost hashcat -i [file...] [options]

Options:
  -i, -input    path to analyze, repeatable; a directory scans its
                zip/7z/rar/pdf/cap/pcap/pcapng and txt/hash/hashes files
  -q, -quiet    quiet mode, hide skip reasons and the trailing hint
  --list        only print the algorithm / hashcat mode reference table

Output:
  analysis -> stdout, one entry per item with the algorithm name and
  a ready-to-use -m mode number

What is recognized:
  containers  zip / 7z / rar / encrypted PDF / wireless capture
  hash lists  one hash per line; also shadow's user:hash:... and potfile's hash:password
  digests     MD5/NTLM, SHA-1, SHA-256, SHA-512 (32/40/64/128 hex chars)
  passwords   $1$ $apr1$ $5$ $6$ $2*$ $argon2*$ $scrypt$ $pbkdf2-sha256$ $y$
  documents   $office$ 2007/2010/2013/2016, $oldoffice$ 0/1/3/4

Notes:
  32 hex chars is ambiguous between MD5 and NTLM, so both modes are printed;
  yescrypt ($y$) has no native hashcat mode, only the algorithm name is shown

Examples:
  gyhost hashcat -i secret.zip              # which algorithm does this archive use
  gyhost hashcat -i hashes.txt              # identify every hash in the list
  gyhost hashcat -i /etc/shadow             # what password hashes are in this shadow
  gyhost hashcat -i /path/to/dir            # analyze a whole directory
  gyhost hashcat --list                     # reference table only
  gyhost help hashcat`,

		// ---- hashcat errors ----
		"hashcat.err.missing_args": "missing required option: -i [file...]",
		"hashcat.err.no_input":     "no input file to analyze",
		"hashcat.err.empty":        "no entry identified",
		"hashcat.err.unknown":      "unrecognized hash type",
		"hashcat.err.binary":       "not a text hash list and not a supported encrypted container (binary file)",

		// ---- hashcat output ----
		"hashcat.line":            "line %d",
		"hashcat.named":           "%s (line %d)",
		"hashcat.label.algo":      "Algorithm",
		"hashcat.label.mode":      "Mode",
		"hashcat.label.container": "Container",
		"hashcat.label.hint":      "Hint",
		"hashcat.hint.dump":       "entries live inside the file: export them with gyhost hashdump first, then feed hashcat",
		"hashcat.hint.crack":      "this file is already a hash list: feed it to hashcat or gyhost hashac directly",
		"hashcat.mode.none":       "no native mode",
		"hashcat.list.title":      "Algorithms identified by GYhost and their hashcat modes",

		// ---- hashcat categories ----
		"hashcat.kind.digest": "Raw digest",
		"hashcat.kind.crypt":  "Password hash (shadow/Unix)",
		"hashcat.kind.office": "MS Office document",
		"hashcat.kind.zip":    "ZIP archive",
		"hashcat.kind.7z":     "7z archive",
		"hashcat.kind.rar":    "RAR archive",
		"hashcat.kind.pdf":    "Encrypted PDF",
		"hashcat.kind.wifi":   "Wireless capture",

		// ---- hashcat algorithms ----
		"hashcat.algo.md5-ntlm":          "MD5 / NTLM (ambiguous 32-hex)",
		"hashcat.algo.sha1":              "SHA-1",
		"hashcat.algo.sha256":            "SHA-256",
		"hashcat.algo.sha512":            "SHA-512",
		"hashcat.algo.md5crypt":          "md5crypt ($1$)",
		"hashcat.algo.md5crypt-apr1":     "md5crypt-apr1 ($apr1$)",
		"hashcat.algo.sha256crypt":       "sha256crypt ($5$)",
		"hashcat.algo.sha512crypt":       "sha512crypt ($6$)",
		"hashcat.algo.bcrypt":            "bcrypt ($2*$)",
		"hashcat.algo.scrypt":            "scrypt ($scrypt$)",
		"hashcat.algo.argon2":            "Argon2 ($argon2*$)",
		"hashcat.algo.django-pbkdf2":     "Django PBKDF2-SHA256",
		"hashcat.algo.yescrypt":          "yescrypt ($y$)",
		"hashcat.algo.office-2007":       "MS Office 2007",
		"hashcat.algo.office-2010":       "MS Office 2010",
		"hashcat.algo.office-2013":       "MS Office 2013",
		"hashcat.algo.office-2016":       "MS Office 2016 (SheetProtection)",
		"hashcat.algo.office-2003-md5":   "MS Office <=2003 (MD5+RC4)",
		"hashcat.algo.office-2003-sha1":  "MS Office <=2003 (SHA1+RC4)",
		"hashcat.algo.zipcrypto-deflate": "ZipCrypto (deflate)",
		"hashcat.algo.zipcrypto-stored":  "ZipCrypto (stored)",
		"hashcat.algo.zip-aes128":        "WinZip AES-128",
		"hashcat.algo.zip-aes192":        "WinZip AES-192",
		"hashcat.algo.zip-aes256":        "WinZip AES-256",
		"hashcat.algo.7z-aes":            "7z AES-256",
		"hashcat.algo.rar5-aes":          "RAR5 AES-256",
		"hashcat.algo.pdf-rc4-40":        "PDF RC4-40",
		"hashcat.algo.pdf-rc4-128":       "PDF RC4-128",
		"hashcat.algo.pdf-aes-128":       "PDF AES-128",
		"hashcat.algo.pdf-aes-256":       "PDF AES-256",
		"hashcat.algo.pdf-aes-256-r6":    "PDF AES-256 (hardened KDF)",
		"hashcat.algo.wpa2-pmkid":        "WPA2 PMKID",
		"hashcat.algo.wpa2-eapol":        "WPA2 4-way handshake (EAPOL)",
		"hashcat.algo.unknown":           "unknown",

		// ==================== hashac module ====================
		"hashac.group":   "Local Analysis",
		"hashac.summary": "Enumerate plaintext collisions for common hashes (MD5/WPA2/RAR/ZIP/7z/PDF/Office)",
		"hashac.usage": `gyhost hashac - enumerate plaintext collisions for common hashes

Usage:
  gyhost hashac -i [hash file] (-p [wordlist] | -m [mask]) [options...]

Options:
  -i, -input    path to the hash file, one hash per line (blank lines and # comments ignored)
  -p, -pass     path to the wordlist, one candidate password per line (mutually exclusive with -m)
  -m, --mask    mask expression, candidates generated on the fly (mutually exclusive with -p)
                hashcat style: ?l lower ?u upper ?d digit ?h/?H hex
                ?s special ?a all printable ?b every byte ?? literal '?'
                e.g. -m '?l?l?d?d', -m 'pass?d?d?d'
  -o, -out      optional, write cracked hash:password pairs to this file
  -t, -threads  number of worker threads (default: CPU count)
  --mode        optional, force a hashcat mode number (0 = auto detect)
  -q, -quiet    quiet mode, hide the live progress line
  --gpu         use the GPU (CUDA) for the algorithms it supports, others fall back to CPU (requires root/administrator)

Supported types (auto detected; hashcat mode in parentheses):
  md5 / sha1 / sha256 / sha512   raw digests (32/40/64/128 hex chars)
  wpa2-pmkid / wpa2-eapol        WPA*01* / WPA*02* (-m 22000)
  rar5                           $rar5$... (-m 13000)
  zip-aes                        $zip2$... (-m 13600)
  zipcrypto                      $pkzip2$... (-m 17200/17210)
  7z                             $7z$... (-m 11600)
  pdf                            $pdf$... (-m 10400/10500/10600/10700)
                                 RC4/AES for V<=4 and AES-256 for V=5; tries user and owner passwords
  office-2007 / 2010 / 2013      $office$... (-m 9400/9500/9600)
                                 password verifier for encrypted docx/xlsx/pptx (incl. WPS-compatible saves)
  the $... forms can be produced by "gyhost hashdump" from encrypted archives, PDFs or Office documents

Output:
  hits and summary -> stdout, live progress and notices -> stderr (2>/dev/null keeps hits only)
  with -o the cracked pairs are written to the file (hash:password) and stdout keeps the summary

Examples:
  gyhost hashac -i hashes.txt -p wordlist.txt
  gyhost hashac -i hashes.txt -m '?d?d?d?d'            # brute force 4 digits
  gyhost hashac -i hashes.txt -m '?d?d?d?d?d?d?d?d' --gpu
  gyhost hashac -i hashes.txt -p wordlist.txt --gpu
  gyhost hashac -i hashes.txt -p wordlist.txt -o cracked.txt -q
  gyhost hashdump -i secret.rar -o hashes.txt && gyhost hashac -i hashes.txt -p wordlist.txt
  gyhost help hashac`,
		"hashac.flag.input":   "path to the hash file, one hash per line",
		"hashac.flag.dict":    "path to the wordlist, one candidate password per line (mutually exclusive with -m)",
		"hashac.flag.mask":    "mask expression (hashcat style, e.g. ?l?l?d?d); mutually exclusive with -p",
		"hashac.flag.out":     "write cracked hash:password pairs to this file (default: stdout only)",
		"hashac.flag.threads": "number of worker threads (default: CPU count)",
		"hashac.flag.mode":    "force a hashcat mode number (0 = auto detect; long option only, -m is the mask)",
		"hashac.flag.quiet":   "quiet mode, hide the live progress line",
		"hashac.flag.gpu":     "use the GPU (CUDA) for supported algorithms, others fall back to CPU (requires root/administrator)",

		// ---- hashac target types ----
		"hashac.algo.md5":            "MD5",
		"hashac.algo.sha1":           "SHA-1",
		"hashac.algo.sha256":         "SHA-256",
		"hashac.algo.sha512":         "SHA-512",
		"hashac.algo.wpa2-pmkid":     "WPA2-PMKID",
		"hashac.algo.wpa2-eapol":     "WPA2-EAPOL",
		"hashac.algo.rar5":           "RAR5",
		"hashac.algo.zip-aes":        "ZIP-AES",
		"hashac.algo.zipcrypto":      "ZIP-ZipCrypto",
		"hashac.algo.7z":             "7z-AES",
		"hashac.algo.pdf-rc4-40":     "PDF RC4-40",
		"hashac.algo.pdf-rc4-128":    "PDF RC4-128",
		"hashac.algo.pdf-aes-128":    "PDF AES-128",
		"hashac.algo.pdf-aes-256":    "PDF AES-256",
		"hashac.algo.pdf-aes-256-r6": "PDF AES-256 (hardened KDF)",
		"hashac.algo.office-2007":    "Office 2007",
		"hashac.algo.office-2010":    "Office 2010",
		"hashac.algo.office-2013":    "Office 2013",

		// ---- hashac errors ----
		"hashac.err.missing_args":  "missing required options: -i [hash file], plus either -p [wordlist] or -m [mask]",
		"hashac.err.mask_conflict": "cannot use -p and -m at the same time, pick one",
		"hashac.err.mask":          "invalid mask expression",
		"hashac.err.threads":       "thread count must be greater than 0: %d",
		"hashac.err.mode":          "unsupported hashcat mode number: %d",
		"hashac.err.pdf_version":   "unsupported PDF encryption version V=%d R=%d",
		"hashac.err.pdf_mode":      "this PDF hash maps V/R to -m %d, which conflicts with --mode %d",
		"hashac.err.office_year":   "unsupported Office encryption year %d (only 2007/2010/2013 are supported)",
		"hashac.err.office_mode":   "this Office hash maps to -m %d, which conflicts with --mode %d",
		"hashac.err.oldoffice":     "$oldoffice$ is not supported (-m 9700/9800, RC4 password verifiers from Word/Excel 97-2003)",
		"hashac.err.open_input":    "cannot read the hash file %s",
		"hashac.err.read_input":    "failed to read the hash file",
		"hashac.err.open_dict":     "failed to open the wordlist",
		"hashac.err.empty_hash":    "empty hash line",
		"hashac.err.unknown":       "unrecognized hash type: %s",
		"hashac.err.bad_syntax":    "invalid hash syntax: %s",
		"hashac.err.no_targets":    "no cracker targets (%d line(s) skipped)",
		"hashac.err.create_out":    "failed to create the result file",
		"hashac.err.write_out":     "failed to write the result file",

		// ---- hashac GPU ----
		"hashac.gpu.enabled":       "[✓] GPU acceleration enabled: %s (%d MB)",
		"hashac.gpu.partial":       "[*] GPU handles %d target(s), the remaining %d run on CPU",
		"hashac.gpu.needs_root":    "[!] enabling the GPU requires root (administrator on Windows), falling back to CPU; re-run with sudo or as Administrator",
		"hashac.gpu.not_compiled":  "[!] this binary was built without CUDA, falling back to CPU (rebuild with make to enable the GPU)",
		"hashac.gpu.no_device":     "[!] no usable CUDA device found, falling back to CPU",
		"hashac.gpu.unsupported":   "[!] target hash is not supported on the GPU, falling back to CPU",
		"hashac.gpu.note_r6":       "[*] the GPU kernel for -m 10700 (PDF R=6) is slower than the multi-threaded CPU, keeping it on CPU; set GYHOST_PDF_R6_GPU=1 to force the GPU",
		"hashac.gpu.note_7z":       "[*] this 7z entry uses LZMA/Deflate; the GPU kernel only handles the Copy coder, keeping it on CPU",
		"hashac.gpu.note_cipher":   "[*] this entry's ciphertext exceeds the GPU limit (%d bytes), keeping it on CPU",
		"hashac.gpu.warmup":        "[*] Waking up the GPU and boosting its clocks (about %s)...",
		"hashac.gpu.runtime_error": "[!] GPU verification failed, falling back to CPU: %s",

		// ---- hashac live progress ----
		"hashac.progress.head":      "[~] progress %s | wordlist %s | checks %s |",
		"hashac.progress.head_mask": "[~] progress %s | mask %s | checks %s |",
		"hashac.progress.cracked":   "%d/%d cracked",
		"hashac.progress.trying":    "trying %s |",
		"hashac.progress.more":      " +%s more",
		"hashac.progress.finished":  " all cracked, finishing…",
		"hashac.progress.tail":      "%s | %s",
		"hashac.progress.rate":      "%s/s",

		// ---- hashac hits and summary ----
		"hashac.hit.format":        "%s %s  %s %s",
		"hashac.mask.keyspace":     "[*] mask %s expands to %s candidates",
		"hashac.report.summary":    "[*] %s target(s) | %s skipped | %s cracked",
		"hashac.report.stats":      "[*] %s wordlist entries | %s checks | %s elapsed | %s checks/s",
		"hashac.report.stats_mask": "[*] %s mask candidates | %s checks | %s elapsed | %s checks/s",
		"hashac.report.gpu":        "[*] GPU device: %s (%s MB)",
		"hashac.report.skip":       "[-] skipped %s (%s)",
		"hashac.report.pending":    "[!] not cracked (%s): %s",
		"hashac.report.hint":       "[!] try a larger wordlist or targeted rules and run again",
		"hashac.report.all_done":   "[+] all targets cracked",

		// ==================== net module ====================
		"net.group":   "Network Analysis",
		"net.summary": "Offline analysis of pcap/cap captures: protocols, conversations, DNS/TLS/HTTP and cleartext findings",

		"net.flag.input":           "capture file path (pcap/pcapng/cap, repeatable; a directory scans for capture files)",
		"net.flag.out":             "write the report to this file (default: print to stdout)",
		"net.flag.list":            "list packets one by one (default: print the statistics report)",
		"net.flag.filter":          "filter expression applied to both report and list, e.g. -f \"tcp and port 443\"",
		"net.flag.top":             "maximum entries per statistics table (default 10)",
		"net.flag.limit":           "maximum packets to list in list mode (0 = no limit)",
		"net.flag.quiet":           "quiet mode, do not print notices to stderr",
		"net.flag.section":         "output only the given report sections, comma separated (io/proto/conv/endpoints/ports/dns/sni/http/findings/attack/all)",
		"net.flag.json":            "emit JSON instead of the human report, for jq and other tooling",
		"net.flag.time":            "time range filter: absolute 10:05:00-10:06:00, or seconds relative to first packet 30-90",
		"net.flag.interval":        "timeline bucket size in seconds, used with -z timeline (default 1)",
		"net.section.timeline":     "Traffic timeline",
		"net.tl.interval":          "bucket size",
		"net.tl.interval_desc":     "%.0f s",
		"net.tl.span":              "time span",
		"net.tl.span_desc":         "%s across %d buckets",
		"net.tl.avg":               "average rate",
		"net.tl.avg_desc":          "%.1f packets/s",
		"net.tl.peak":              "peak",
		"net.tl.peak_desc":         "at %.0fs, %d packets / %s",
		"net.tl.peak_peer":         "peak source",
		"net.tl.capped":            "timeline hit the %d bucket limit; the rest was not counted, use -I for a coarser bucket",
		"net.tl.rows":              "%d non-empty buckets, showing the first %d (adjust with --top)",
		"net.tl.col_t":             "time(s)",
		"net.tl.col_pkt":           "packets",
		"net.tl.col_bytes":         "bytes",
		"net.tl.col_proto":         "top protocol",
		"net.err.bad_section":      "unknown -z section: %s (available: io/timeline/proto/conv/endpoints/ports/dns/sni/http/findings/attack/follow/all)",
		"net.err.bad_follow":       "unrecognized -z follow argument: %s (format: ascii/raw/hex, optional stream index)",
		"net.err.time_range":       "unrecognized time range: %s (e.g. 10:05:00-10:06:00 or 30-90)",
		"net.err.time_range_order": "time range ends before it starts",
		"net.err.json_tui":         "-j and -T are mutually exclusive (JSON targets pipes; the TUI would be overwritten by it)",
		"net.err.list_section":     "-l and -z are mutually exclusive (-l is a per-packet stream with no sections)",
		"net.section.follow":       "TCP stream follow",
		"net.follow.stream":        "stream #%d/%d  %s",
		"net.follow.from":          "direction 0 (%s):",
		"net.follow.to":            "direction 1 (%s):",
		"net.follow.empty":         "(no payload)",
		"net.follow.truncated":     "this stream exceeded the reassembly limit; content is incomplete",
		"net.follow.gaps":          "reassembly found %d gaps; missing bytes are zero-filled",
		"net.follow.no_stream":     "no TCP stream to follow (needs TCP with payload)",
		"net.follow.no_index":      "stream index %d out of range (%d streams available)",
		"net.atk.capped":           "statistics hit a map limit; some metrics are incomplete",
		"net.flag.model":           "enable attack analysis models, comma separated (syn/udp/icmp/flood/cc/loss/frag/all), e.g. -m syn,cc",

		"net.usage": `gyhost net - offline traffic analysis of pcap/cap capture files

usage:
  gyhost net -i [capture] [options...]

options (grouped by purpose; each entry states only what it does --
         grammar is in the reference sections below):

  input and output
    -i, -input    capture file path; repeatable, a directory is scanned
    -o, -out      write the report to a file, keeping stdout clean
    -q, --quiet   suppress notices and warnings on stderr

  narrowing the scope
    -f, --filter  filter expression applied to both report and list
    -t, --time    time range filter
    -n, --limit   max packets listed in list mode (0 = unlimited)
    -I, --interval timeline bucket size in seconds, with -z timeline
    --top N       max rows per statistics table (default 10)

  choosing the output form (mutually exclusive; default is the report)
    -l, --list    per-packet list: no, time, endpoints, protocol, length, info
    -V, --verbose per-packet protocol tree in tshark -V style, with hexdump
    -T, --tui     interactive full-screen capture browser
    -j, --json    structured JSON output, for jq and other tooling

  enabling analysis models
    -m, --model   attack analysis models, see "attack models"

  trimming report sections
    -z, --section output only the given sections, see "report sections"

filter syntax (-f):
  shorthand
    space separated terms are ANDed, "or" for OR, "not" for negation
    terms       protocol name (tcp/udp/icmp/arp/dns/http/tls/ssh...)
                [src|dst] host IP      [src|dst] port PORT
                a bare number means port N
  display filter form (Wireshark style)
    expression  field OP value        OP: == != > < >= <= contains
    logic       && || ! and parentheses ()   a bare protocol name means "exists"
    fields      frame.*  ip.*  ipv6.*  tcp.*  udp.*  icmp.*  arp.*
                http.*  dns.*  tls.*  eth.*
    in the TUI, press / to get live hints while typing, ? to list all fields

time range (-t):
  absolute    10:05:00-10:06:00
  relative    30-90 seconds from the first packet (either end may be omitted)

report sections (-z):
  io          capture overview
  proto       protocol distribution
  conv        conversations
  endpoints   endpoints
  ports       ports
  dns         DNS queries
  sni         TLS SNI
  http        HTTP hosts and requests
  findings    security findings
  attack      attack analysis
  all         all of the above
  timeline    traffic over time in buckets, to spot bursts and quiet periods
  stream      follow,tcp,ascii|raw|hex[,<index>]
              reassembles out-of-order/retransmitted/segmented packets back
              into two byte streams, ordered by TCP sequence number
              ascii printable   raw escaped bytes   hex hexdump
  aliases     phs=proto   conv=flows   ep=endpoints   tls=sni   stream=follow

attack models (-m):
  syn    SYN flood, source IP randomization/spoofing
  udp    UDP flood
  icmp   ICMP flood
  flood  generic flood (syn + udp + icmp)
  cc     CC attack (HTTP layer rate / single source / distributed)
  loss   packet loss and TCP anomalies (retransmit, dup ACK, zero window, truncation)
  frag   IP fragmentation anomalies (overlap/malformed, teardrop style)
  all    all of the above (-m with no value is the same)

what gets analysed:
  capture overview, four-layer protocol distribution, top conversations /
  hosts / ports, DNS queries, TLS SNI, cleartext HTTP hosts and request URIs,
  and security findings (cleartext credentials, HTTP password fields,
  ARP conflicts, unencrypted cleartext protocols)
  with -m, per-model verdicts (hit/suspect/none), key metrics and evidence

output:
  report and list -> stdout, notices and warnings -> stderr
  with -o the report goes to a file (no color codes) and stdout stays empty
  for the full TUI key bindings and filter help, press ? inside the TUI

examples:
  basics
    gyhost net -i capture.pcap
    gyhost net -i capture.pcap --top 20

  filtering
    gyhost net -i capture.pcap -f "host 10.0.0.5"
    gyhost net -i capture.pcap -f "tcp.port == 443 && !http"
    gyhost net -i capture.pcap -t 30-90 -f "udp"

  per-packet inspection
    gyhost net -i capture.pcap -l -n 50
    gyhost net -i capture.pcap -V -n 5 -f "port 22"

  interactive
    gyhost net -i capture.pcap -T -f "tcp"

  scripting
    gyhost net -i capture.pcap -j | jq ".conversations | sort_by(-.packets) | .[0]"
    gyhost net -i capture.pcap -j -z http | jq ".http.credentials"
    gyhost net -i capture.pcap -z dns,http

  stream reassembly and timeline
    gyhost net -i capture.pcap -z "follow,tcp,ascii,0"
    gyhost net -i capture.pcap -z timeline
    gyhost net -i capture.pcap -z timeline -I 5

  attack analysis
    gyhost net -i capture.pcap -m all
    gyhost net -i capture.pcap -m syn,cc`,

		// ---- net errors ----
		"net.err.missing_args":          "missing required option: -i [capture file]",
		"net.err.no_input":              "no usable capture input (path missing, or the directory contains no capture files)",
		"net.err.bad_top":               "--top must be greater than 0: %d",
		"net.err.bad_limit":             "-n/--limit must not be negative: %d",
		"net.err.open":                  "cannot read %s: %v",
		"net.err.unrecognized":          "%s is not a supported capture container (pcap/pcapng only)",
		"net.err.bad_capture":           "failed to parse the capture: %v",
		"net.err.create_out":            "failed to create the report file: %v",
		"net.err.filter_missing":        "incomplete filter expression, missing argument after %s",
		"net.err.filter_ip":             "unrecognized IP address: %s",
		"net.err.filter_port":           "unrecognized port number: %s",
		"net.err.filter_token":          "unrecognized filter term: %s",
		"net.err.filter_dir":            "%s can only be combined with host or port",
		"net.err.filter_unknown_field":  "unknown field: %s (press \x1b[5m?\x1b[0m for available fields)",
		"net.err.filter_char":           "illegal character in filter: %s",
		"net.err.filter_unterminated":   "unterminated string in filter",
		"net.err.filter_unclosed_paren": "unclosed parenthesis in filter",
		"net.err.filter_number":         "not a valid number: %s",
		"net.err.filter_empty":          "empty filter expression",
		"net.err.bad_model":             "unknown analysis model: %s (available: %s)",

		// ---- net notices ----
		"net.info.saved": "report written to %s",

		// ---- net overview ----
		"net.label.format":          "Format",
		"net.label.linktype":        "Link type",
		"net.label.filter":          "Filter",
		"net.label.packets":         "Packets",
		"net.label.time":            "Time range",
		"net.label.bytes":           "Traffic",
		"net.label.models":          "Models",
		"net.label.peak":            "Peak rate",
		"net.packets.filtered":      "%d (after filter %d)",
		"net.time.desc":             "%s -> %s (%s)",
		"net.bytes.desc":            "captured %s, on the wire %s",
		"net.endian.le":             "little-endian",
		"net.endian.be":             "big-endian",
		"net.ts.sec":                "second timestamps",
		"net.ts.msec":               "millisecond timestamps",
		"net.ts.usec":               "microsecond timestamps",
		"net.ts.nsec":               "nanosecond timestamps",
		"net.format.ifaces":         "%d interfaces",
		"net.link.unknown":          "unknown link type (DLT %d)",
		"net.warn.unsupported_link": "unsupported link type %d, skipped %d frame(s)",
		"net.report.no_match":       "no packets matched the filter",

		// ---- net sections and table headers ----
		"net.section.protocols": "Protocol distribution",
		"net.section.flows":     "Top conversations (%d)",
		"net.section.endpoints": "Top hosts (%d)",
		"net.section.ports":     "Top ports (%d)",
		"net.section.dns":       "DNS queries",
		"net.section.sni":       "TLS SNI",
		"net.section.http":      "HTTP",
		"net.section.findings":  "Security findings",
		"net.section.attack":    "Attack analysis",
		"net.layer.l2":          "Link",
		"net.layer.l3":          "Network",
		"net.layer.l4":          "Transport",
		"net.layer.l7":          "Application",
		"net.subsection.hosts":  "Hosts",
		"net.subsection.uris":   "Request URIs",
		"net.head.layer":        "Layer",
		"net.head.proto":        "Proto",
		"net.head.packets":      "Pkts",
		"net.head.percent":      "%",
		"net.head.bytes":        "Bytes",
		"net.head.rank":         "#",
		"net.head.flow":         "Conversation",
		"net.head.host":         "Host",
		"net.head.ip":           "IP",
		"net.head.mac":          "MAC",
		"net.head.sent":         "Sent",
		"net.head.recv":         "Recv",
		"net.head.port":         "Port",
		"net.head.service":      "Service",
		"net.head.name":         "Name",
		"net.head.count":        "Count",
		"net.head.uri":          "URI",
		"net.head.idx":          "#",
		"net.head.time":         "Time",
		"net.head.endpoints":    "Endpoints",
		"net.head.len":          "Len",
		"net.head.info":         "Info",
		"net.head.model":        "Model",
		"net.head.verdict":      "Verdict",
		"net.head.metrics":      "Key metrics",

		// ---- net accounting ----
		"net.proto.unidentified": "unidentified",
		"net.proto.other":        "Other",
		"net.service.unknown":    "unregistered",
		"net.packets_fmt":        "%d packets",
		"net.dns.summary":        "%d queries, %d unique names, %d failed responses",
		"net.http.summary":       "%d cleartext HTTP request(s)",
		"net.list.summary":       "%d packets total, %d matched, %d listed",

		// ---- net per-packet summaries ----
		"net.info.beacon":       "beacon (SSID: %s)",
		"net.info.probe_req":    "probe request (SSID: %s)",
		"net.info.arp_req":      "who has %s? tell %s",
		"net.info.arp_rep":      "%s is at %s",
		"net.info.echo_req":     "echo request id=%d seq=%d",
		"net.info.echo_rep":     "echo reply id=%d seq=%d",
		"net.info.icmp_unreach": "destination unreachable (code=%d)",
		"net.info.icmp_ttl":     "time exceeded (code=%d)",
		"net.info.icmp":         "type=%d code=%d",
		"net.info.nd_ns":        "neighbor solicitation %s",
		"net.info.nd_na":        "neighbor advertisement %s",
		"net.info.nd_rs":        "router solicitation",
		"net.info.nd_ra":        "router advertisement",
		"net.info.ipv4_frag":    "IPv4 fragment offset=%d",
		"net.info.ipv6_frag":    "IPv6 fragment offset=%d",

		// ---- net attack analysis ----
		"net.verdict.hit":       "Detected",
		"net.verdict.suspect":   "Suspected",
		"net.verdict.miss":      "Not detected",
		"net.model.syn":         "SYN flood",
		"net.model.udp":         "UDP flood",
		"net.model.icmp":        "ICMP flood",
		"net.model.cc":          "CC attack",
		"net.model.loss":        "Packet loss / TCP anomalies",
		"net.model.frag":        "IP fragment anomalies",
		"net.metric.syn":        "SYNs %d (peak %d/s), SYN-ACKs %d, %d source IPs, %s of TCP",
		"net.metric.udp":        "UDP %d packets (peak %d/s), %s of all packets",
		"net.metric.icmp":       "ICMP %d packets (peak %d/s), %s of all packets",
		"net.metric.cc":         "HTTP requests %d (peak %d/s), top source %s x%d, top URI %s x%d",
		"net.metric.loss":       "retransmits %d (%s of data segments), dup ACKs %d, seq gaps %d, zero windows %d, truncated %d",
		"net.metric.frag":       "%d fragments, %d overlapping, %d malformed",
		"net.attack.syn":        "possible SYN flood: %d SYNs vs %d SYN-ACKs, peak %d/s, SYNs are %s of TCP",
		"net.attack.random_src": "randomized/spoofed sources: %d sources appear once and only send SYNs (%d SYN sources in total, %s)",
		"net.attack.udp":        "possible UDP flood: peak %d/s, %s of all packets",
		"net.attack.icmp":       "possible ICMP flood: peak %d/s, %s of all packets",
		"net.attack.cc":         "possible CC attack: %d HTTP requests, peak %d/s, top source %s (%d), top URI %s (%d)",
		"net.attack.cc_dist":    "distributed CC: URI %s requested by %d distinct sources, %d times",
		"net.attack.cc_single":  "single-source hammering: %s made %d requests, %s of all requests",
		"net.attack.loss":       "TCP anomalies: %d retransmits (%s of data segments), %d dup ACKs, %d seq gaps, %d zero windows",
		"net.attack.trunc":      "truncated capture: %d packets captured shorter than on the wire, statistics are incomplete",
		"net.attack.frag":       "fragment anomalies: %d overlapping, %d malformed fragments (teardrop-style)",
		"net.attack.capped":     "tracking key limit %d reached, some metrics are incomplete",

		// ---- net 逐包详细视图（-V）----
		"net.flag.verbose":       "per-packet detail view (protocol tree like tshark -V; implies -l)",
		"net.det.frame_hdr":      "Frame %d: %d bytes on wire (%d bits), %d bytes captured (%d bits)",
		"net.det.encap":          "Encapsulation type",
		"net.det.arrival":        "Arrival time",
		"net.det.epoch":          "Epoch time",
		"net.det.since_ref":      "Time since first frame",
		"net.det.seconds":        "seconds",
		"net.det.frame_no":       "Frame number",
		"net.det.frame_len":      "Frame length",
		"net.det.cap_len":        "Capture length",
		"net.det.truncated":      "Truncated",
		"net.det.protocols":      "Protocols in frame",
		"net.det.yes":            "Yes",
		"net.det.none":           "None",
		"net.det.set":            "Set",
		"net.det.notset":         "Not set",
		"net.det.info":           "Info",
		"net.det.eth_hdr":        "Ethernet II, Src: %s, Dst: %s",
		"net.det.dst":            "Destination",
		"net.det.src":            "Source",
		"net.det.vlan_idx":       "VLAN %d ID",
		"net.det.type":           "Type",
		"net.det.etype":          "%s (0x%04x)",
		"net.det.ipv4_hdr":       "Internet Protocol Version 4, Src: %s, Dst: %s",
		"net.det.ipv6_hdr":       "Internet Protocol Version 6, Src: %s, Dst: %s",
		"net.det.version":        "Version",
		"net.det.hdr_len":        "Header length",
		"net.det.bytes":          "%d bytes (%d)",
		"net.det.bytes_bits":     "%d bytes (%d bits)",
		"net.det.dsfield":        "Differentiated Services Field",
		"net.det.total_len":      "Total length",
		"net.det.ident":          "Identification",
		"net.det.flags":          "Flags",
		"net.det.df":             "Don't fragment (DF)",
		"net.det.mf":             "More fragments (MF)",
		"net.det.frag_off":       "Fragment offset",
		"net.det.frag_off_val":   "%d (%d bytes)",
		"net.det.ttl":            "Time to live",
		"net.det.hop_limit":      "Hop limit",
		"net.det.protocol":       "Protocol",
		"net.det.next_hdr":       "Next header",
		"net.det.hdr_cksum":      "Header checksum",
		"net.det.src_addr":       "Source address",
		"net.det.dst_addr":       "Destination address",
		"net.det.tclass":         "Traffic class",
		"net.det.flow_label":     "Flow label",
		"net.det.payload_len":    "Payload length",
		"net.det.tcp_hdr":        "Transmission Control Protocol, Src Port: %d, Dst Port: %d, Seq: %d, Ack: %d, Len: %d",
		"net.det.udp_hdr":        "User Datagram Protocol, Src Port: %d, Dst Port: %d, Len: %d",
		"net.det.icmp_hdr":       "%s, Type: %d, Code: %d",
		"net.det.icmp_type":      "%s (%d)",
		"net.det.src_port":       "Source port",
		"net.det.dst_port":       "Destination port",
		"net.det.seq":            "Sequence number",
		"net.det.ack":            "Acknowledgment number",
		"net.det.tcp_flags":      "Flags",
		"net.det.window":         "Window size",
		"net.det.checksum":       "Checksum",
		"net.det.urgent_ptr":     "Urgent pointer",
		"net.det.length":         "Length",
		"net.det.service":        "Service",
		"net.det.code":           "Code",
		"net.det.icmp_id":        "Identifier",
		"net.det.icmp_seq":       "Sequence number",
		"net.det.options":        "Options",
		"net.det.opt_kind":       "Option kind: %s",
		"net.det.flag.cwr":       "CWR",
		"net.det.flag.ece":       "ECE",
		"net.det.flag.urg":       "URG",
		"net.det.flag.ack":       "ACK",
		"net.det.flag.psh":       "PSH",
		"net.det.flag.rst":       "RST",
		"net.det.flag.syn":       "SYN",
		"net.det.flag.fin":       "FIN",
		"net.det.arp_hdr":        "Address Resolution Protocol: %s",
		"net.det.hw_type":        "Hardware type",
		"net.det.proto_type":     "Protocol type",
		"net.det.hw_size":        "Hardware size",
		"net.det.proto_size":     "Protocol size",
		"net.det.arp_op":         "Opcode",
		"net.det.arp_request":    "who has? (1)",
		"net.det.arp_reply":      "is at (2)",
		"net.det.arp_other":      "other",
		"net.det.arp_sender_mac": "Sender MAC address",
		"net.det.arp_sender_ip":  "Sender IP address",
		"net.det.arp_target_mac": "Target MAC address",
		"net.det.arp_target_ip":  "Target IP address",
		"net.det.http_host":      "Host",
		"net.det.http_cred":      "Authorization",
		"net.det.http_pass":      "Cleartext password field",
		"net.det.dns_name":       "Query name",
		"net.det.dns_ans":        "Answers",
		"net.det.tls_sni":        "SNI",
		"net.det.frame_data":     "Frame data",

		// ---- net interactive TUI (-T) ----
		"net.flag.tui":                "interactive packet browser: full-screen list + protocol tree, scroll/select/filter live (needs a terminal)",
		"net.tui.no":                  "No",
		"net.tui.source":              "Source",
		"net.tui.dest":                "Destination",
		"net.tui.proto":               "Proto",
		"net.tui.length":              "Length",
		"net.tui.info":                "Info",
		"net.tui.detail":              "Protocol tree",
		"net.tui.detail_sel":          "(frame %d, %d shown)",
		"net.tui.packets":             "packets",
		"net.tui.no_filter":           "(no filter)",
		"net.tui.filter_prompt":       "filter> ",
		"net.tui.filter_canceled":     "filter editing canceled",
		"net.tui.filter_cleared":      "filter cleared",
		"net.tui.filter_hint_empty":   "press Enter to clear the filter, or type an expression",
		"net.tui.filter_hint_ok":      "syntax OK, press Enter to apply",
		"net.tui.filter_ex_empty":     "e.g. tcp.port == 443 · ip.addr == 10.0.0.1 · frame.len > 1000 · http.host contains \"x\" · !(arp)",
		"net.tui.filter_ex_port":      "ports: tcp.port == 443 · src port 1024 · udp.port != 53",
		"net.tui.filter_ex_ip":        "addresses: ip.addr == 10.0.0.1 · src host 192.168.1.1 · ip.dst != 8.8.8.8",
		"net.tui.filter_ex_len":       "length: frame.len > 1000 · frame.len <= 1500 · tcp.payload_len >= 100",
		"net.tui.filter_ex_generic":   "e.g. tcp · tcp && port == 443 · (tcp || udp) && !arp · dns.qry.name contains \"example\"",
		"net.tui.filter_ex_ipfield":   "%s takes an IP: %s == 10.0.0.1 (or src host 10.0.0.1)",
		"net.tui.filter_ex_intfield":  "%s takes a number: %s == 443 · %s > 100 · %s != 0",
		"net.tui.filter_ex_strfield":  "%s takes a string: %s contains \"x\" · %s == \"abc\"",
		"net.tui.filter_ex_boolfield": "%s is a boolean: %s == 1 (set) or == 0 (not set)",
		"net.tui.sug_none":            "hint: field + operator + value, e.g. tcp.port == 443; Tab completes, ? lists all fields",
		"net.tui.sug_field":           "fields:",
		"net.tui.sug_field_prefix":    "complete \"%s\":",
		"net.tui.sug_no_field":        "no field starts with %s, press ? to list all",
		"net.tui.sug_operator":        "operators for %s: %s",
		"net.tui.sug_value_generic":   "type a value after the operator",
		"net.tui.sug_val_ip":          "%s needs an IP address, e.g. %s == 10.0.0.1",
		"net.tui.sug_val_int":         "%s needs a number, e.g. %s == 443, or %s > 100",
		"net.tui.sug_val_str":         "%s needs a quoted string, e.g. %s contains \"x\"",
		"net.tui.sug_val_bool":        "%s is a boolean: %s == 1 or %s == 0",
		"net.tui.sug_val_float":       "%s needs a number, e.g. %s > 1.5",
		"net.tui.sug_logic":           "condition complete; chain with && or ||, or press Enter to apply",
		"net.tui.sug_tab":             "   (Tab to accept)",
		"net.tui.empty":               "no packets match the filter",
		"net.tui.no_match":            "no packets match; press c to clear the filter or r to re-apply",
		"net.tui.key_move":            "move",
		"net.tui.key_pane":            "pane",
		"net.tui.key_fold":            "fold",
		"net.tui.key_filter":          "filter",
		"net.tui.key_stats":           "stats",
		"net.tui.key_bytes":           "bytes",
		"net.tui.key_help":            "help",
		"net.tui.key_quit":            "quit",
		"net.tui.key_enter":           "expand",
		"net.tui.key_fold_all":        "fold all",
		"net.tui.key_scroll":          "scroll",
		"net.tui.help_title":          "Keyboard shortcuts",
		"net.tui.help_move":           "move selection up/down",
		"net.tui.help_fold":           "collapse / expand current node",
		"net.tui.help_fold_all":       "collapse / expand all",
		"net.tui.help_pane":           "switch focus: list / tree / bytes",
		"net.tui.help_enter":          "show or hide the detail panes",
		"net.tui.help_filter":         "open filter input (e.g. tcp.port == 443)",
		"net.tui.help_history":        "browse filter history while typing",
		"net.tui.help_esc":            "cancel editing; press again to clear filter",
		"net.tui.help_help":           "open / close this help",
		"net.tui.help_stats":          "statistics panel (protocols / endpoints / conversations)",
		"net.tui.help_clear":          "clear filter, show all packets",
		"net.tui.help_reapply":        "re-apply the current filter",
		"net.tui.help_jump":           "jump to first / last packet",
		"net.tui.help_page":           "page up / down",
		"net.tui.help_quit":           "quit",
		"net.tui.help_filter_fields":  "Fields available in filters:",
		"net.tui.filter_help":         "Available filter fields",
		"net.tui.filter_help_hint":    "e.g. ip.addr == 10.0.0.1 && tcp.port == 443; up/down history, Esc cancel, ? close help",
		"net.tui.time":                "Time",
		"net.tui.bytes":               "Bytes",
		"net.tui.tree":                "Protocol tree",
		"net.tui.stats":               "Statistics",
		"net.tui.pane_list":           "Packet list",
		"net.tui.focus":               "focus",
		"net.tui.stat_proto":          "Protocol distribution",
		"net.tui.stat_endpoint":       "Endpoints",
		"net.tui.stat_convers":        "Conversations",
		"net.tui.stat_calculating":    "calculating…",
		"net.tui.stat_none":           "nothing to summarize",
		"net.tui.collapse_all":        "all collapsed",
		"net.tui.expand_all":          "all expanded",
		"net.tui.no_bytes":            "this frame has no raw bytes",
		"net.tui.name":                "Name",
		"net.tui.stat_summary":        "%d packets / %s",
		"net.tui.percent":             "%",
		"net.err.no_tty":              "interactive mode needs a terminal (stdin/stdout must be a TTY); use -l or -V instead",
		"net.err.tui_output":          "-T takes over the terminal and cannot be combined with -o",
		"net.err.frame_range":         "frame index out of range: %d",

		// ---- net security findings ----
		"net.find.none":      "no obvious security issues found",
		"net.find.cred":      "cleartext credential captured: %s",
		"net.find.field":     "cleartext password field in HTTP request: %s",
		"net.find.arp":       "same IP seen with multiple MACs, possible ARP spoofing",
		"net.find.cleartext": "unencrypted plaintext protocol traffic",

		// ==================== mem module ====================
		"mem.group":   "Memory Forensics",
		"mem.summary": "Memory forensics: analyze a live process or a memory dump, recover program behavior and carve files out of memory",

		"mem.flag.input":    "analysis target: process PID, self (current process), or path to a memory dump file",
		"mem.flag.action":   "actions to run, comma separated and repeatable (info/maps/strings/behavior/carve/hash/entropy/dump/all)",
		"mem.flag.carvedir": "write recovered files into this directory",
		"mem.flag.type":     "file types to carve, comma separated (all by default, or png/jpg/zip/pdf/pe/sqlite...)",
		"mem.flag.filter":   "only keep strings and behavior hits containing this keyword (case insensitive)",
		"mem.flag.region":   "only analyze these regions: type (image/heap/stack/mapped/anon), all, or an address range 0x1000-0x2000",
		"mem.flag.minsize":  "skip regions smaller than this many bytes",
		"mem.flag.maxsize":  "skip regions larger than this many bytes (0 = no limit)",
		"mem.flag.minlen":   "minimum string length (default 4)",
		"mem.flag.limit":    "maximum rows printed per section (default 50)",
		"mem.flag.encoding": "string encoding: ascii / utf16 / both (default both)",
		"mem.flag.addr":     "write target address: 0x1234, decimal, or region+offset (e.g. heap+0x40)",
		"mem.flag.data":     "content to write/replace: \\xNN byte sequence, @filepath, or plain UTF-8 text",
		"mem.flag.apply":    "actually perform the write; without it only a preview is computed and the target is untouched",
		"mem.flag.force":    "allow writing to regions/targets without write permission (denied by default)",
		"mem.flag.backup":   "rollback record file (a backup is written on every apply, replayable with -a restore)",
		"mem.flag.max":      "maximum number of replacements per run (unlimited for patch by default)",
		"mem.flag.out":      "write the report to this file (default: print to stdout)",
		"mem.flag.dump":     "export the memory image to this file (same as -a dump)",
		"mem.flag.json":     "emit JSON instead of the human report, for jq and other tooling",
		"mem.flag.verbose":  "verbose mode: list every region (including unselected ones) and loaded modules",
		"mem.flag.quiet":    "quiet mode, do not print per-region progress to stderr",
		"mem.flag.nonascii": "keep non-ASCII strings",
		"mem.flag.showall":  "do not limit the number of rows (output can be long)",

		"mem.usage": `gyhost mem - memory forensics on a live process or a memory dump file

Usage:
  gyhost mem -i <pid|self|dump-file> [-a action] [options...]

Flags (identical on every platform; the backend is compiled per OS):

  -i, -input     analysis target
                    <pid>       a running process
                    self        the current process
                    <file>      a memory dump file (raw/dmp/bin, analyzable anywhere)
  -e, -program   analyze the given program by PID or name, no PID lookup needed
                  matches the process name / executable name / command line;
                  when several match, each one is analyzed in turn
  -l, -list      list programs and their threads (value optional)
                  -l            every program, together with its threads
                  -l <PID|name> only the threads of that program
  -a, -action    actions to run, comma separated and repeatable (default info,behavior)
  -o, -out       write the report to a file, keeping stdout clean
  -q, -quiet     do not print per-region progress to stderr

  Narrow the scope
  -r, -region    only analyze the given regions: image / heap / stack / mapped / anon
                  or an address range, e.g. -r 0x7f0000000000-0x7f0000100000
  -s, -minsize   skip regions smaller than this many bytes
  -S, -maxsize   skip regions larger than this many bytes
  -k, -filter    only keep strings and hits containing this keyword
  -L, -minlen    minimum string length
  -E, -encoding  string encoding: ascii / utf16 / both
  -n, -limit     maximum rows per section (default 50)
  -X, -showall   do not limit rows

  Output format
  -j, -json      JSON output, ready for jq and other tooling
  -V, -verbose   verbose mode (all regions + loaded modules)

  Carve files out of memory
  -c, -carvedir  write recovered files into this directory
  -t, -type      only carve these types, comma separated (all = everything)

  Export a memory image
  -d, -dump      export the memory image as a raw dump (with a .index sidecar)

Operate on the target's memory (change its behavior)
  -a write       write -Y content at the address given by --addr
  -a patch       replace the -k content in memory with the -Y content
  -a restore     roll back, restoring the memory to its pre-patch content
  --addr ADDR    target address: 0x1234, decimal, or region+offset (e.g. heap+0x40)
  -Y DATA        content to write/replace: \xNN bytes, @filepath, or plain UTF-8 text
  --apply        really write (without it: preview only, target untouched)
  --force        allow writing to regions/targets without write permission (denied by default)
  --backup FILE  rollback record file (auto-written on apply, read by -a restore)
  --max N        maximum number of replacements per run

Actions (-a):
  info      target overview: process info, region stats, kind distribution, overall digests
  maps      memory region list (address, permission, kind, backing file)
  strings   string extraction (ASCII and UTF-16LE)
  behavior  program behavior: URL/IP/domain/credentials/commands/injection & persistence traces
  carve     recover files embedded in memory (by magic bytes)
  hash      per-region digests (md5 / sha256)
  entropy   per-region entropy (tells plaintext / compressed / encrypted apart)
  dump      export the memory image as a raw dump
  write     write into memory at an address (needs --addr + -Y + --apply)
  patch     search & replace inside memory (needs -k + -Y + --apply)
  restore   roll back to the pre-patch content (needs --backup + --apply)
  all       everything except dump / write / patch / restore
            (write actions must be named explicitly, "all" never triggers them)

Carvable file types:
  png jpg gif pdf zip gzip bmp elf sqlite 7z rar dex tiff wav pe class lnk
  (-t all means no type filter)

Behavior categories (-a behavior):
  network  url ip domain email port
  secrets  password private_key aws_key jwt basic_auth shadow
  host     path_unix path_win registry env command
  forensics injection cred_dump persist anti_forensic mining ransom

Examples:
  gyhost mem -l                                       # list every program and its threads
  gyhost mem -l nginx                                 # only the threads of the nginx program
  gyhost mem -l 1234                                  # only the threads of pid 1234
  gyhost mem -e nginx                                 # analyze by program name
  gyhost mem -e nginx -a info,behavior                # overview + behavior by name
  gyhost mem -i self                                  # analyze the current process
  gyhost mem -i 1234 -a info,maps                     # inspect a process memory map
  gyhost mem -i 1234 -a behavior -s 1048576           # behavior scan, skip regions < 1 MiB
  gyhost mem -i 1234 -a carve -c ./carved -t png,zip  # carve png/zip out of memory
  gyhost mem -i memdump.raw -a all -o report.txt      # offline analysis written to a file
  gyhost mem -i memdump.raw -a strings -k password    # only strings containing "password"
  gyhost mem -i 1234 -a dump -d target.memdump        # export memory as evidence
  gyhost mem -i 1234 -a patch -k production -Y staging # preview: production -> staging
  gyhost mem -i 1234 -a patch -k production -Y staging --apply   # really patch memory
  gyhost mem -i mem.bin -a write --addr heap+0x40 -Y '\x00\x01' --apply
  gyhost mem -i 1234 -a restore --backup mem-nginx-*.bak --apply  # roll back
  gyhost mem -i memdump.raw -a info -j | jq .summary # JSON into a pipeline
  gyhost help mem`,

		// ---- mem notices ----
		"mem.info.opening":  "opening target: %s",
		"mem.info.region":   "scanned region %s  (%s)",
		"mem.info.selected": "%d (skipped %d)",
		"mem.info.scanned":  "%s, complete %d / interrupted %d",
		"mem.info.saved":    "report written to: %s",
		"mem.info.dumped":   "memory image exported: %s (%s, %d regions)",
		"mem.dump.summary":  "exported %d regions, %s total to: %s",
		"mem.dump.index":    "region index: %s",

		// ---- mem errors ----
		"mem.err.missing_input": "missing required option: -i <pid|self|dump-file>",
		"mem.err.bad_action":    "unknown -a action: %s (available: info/maps/strings/behavior/carve/hash/entropy/dump/all)",
		"mem.err.bad_target":    "unrecognized -i target: %s",
		"mem.err.bad_region":    "unrecognized -r region filter: %s (use all/image/heap/stack/mapped/anon or an address range)",
		"mem.err.bad_minsize":   "-s minimum region size must be >= 0 (got %d)",
		"mem.err.bad_maxsize":   "-S maximum region size must be >= 0 (got %d)",
		"mem.err.bad_minlen":    "-L minimum string length must be within 1..4096 (got %d)",
		"mem.err.bad_limit":     "-n row limit must be >= 0 (got %d)",
		"mem.err.size_range":    "-s(%d) cannot be greater than -S(%d)",
		"mem.err.bad_encoding":  "unknown -e encoding: %s (available: ascii/utf16/both)",
		"mem.err.json_carve":    "-j cannot be combined with -c (JSON targets pipelines, run -c separately to save files)",
		"mem.err.privilege":     "insufficient privileges to read process memory on %s: %s",
		"mem.err.unsupported":   "live memory access is not implemented on this platform (%s); you can still analyze an image with -i <dump-file>",
		"mem.err.no_process":    "process not found: %s",
		"mem.err.gone":          "process exited or memory is not readable: %s (%v)",
		"mem.err.open_target":   "failed to open target: %s (%v)",
		"mem.err.open_file":     "failed to open memory dump file: %s (%v)",
		"mem.err.regions":       "failed to read the memory region list: %v",
		"mem.err.no_regions":    "the target has no readable memory regions",
		"mem.err.no_selected":   "no regions left after filtering, relax -r / -s / -S",
		"mem.err.create_out":    "failed to create the output file: %v",
		"mem.err.write_out":     "failed to write the output file: %v",
		"mem.err.create_dir":    "failed to create the recovery directory: %s (%v)",
		"mem.err.write_file":    "failed to write a recovered file: %s (%v)",

		// ---- mem report ----
		"mem.sec.overview": "Target Overview",
		"mem.sec.maps":     "Memory Regions",
		"mem.sec.entropy":  "Region Entropy",
		"mem.sec.hash":     "Region Digests",
		"mem.sec.behavior": "Program Behavior",
		"mem.sec.strings":  "Strings",
		"mem.sec.carve":    "Files Recovered From Memory",

		"mem.kind.live":          "live process",
		"mem.kind.file":          "memory dump file",
		"mem.kind.url":           "URL",
		"mem.kind.ip":            "IPv4 address",
		"mem.kind.domain":        "domain",
		"mem.kind.email":         "email",
		"mem.kind.port":          "port",
		"mem.kind.password":      "password / credential",
		"mem.kind.private_key":   "private key material",
		"mem.kind.aws_key":       "cloud access key",
		"mem.kind.jwt":           "JWT token",
		"mem.kind.basic_auth":    "HTTP Basic auth header",
		"mem.kind.shadow":        "shadow password line",
		"mem.kind.path_unix":     "Unix path",
		"mem.kind.path_win":      "Windows path",
		"mem.kind.registry":      "registry key",
		"mem.kind.env":           "environment variable",
		"mem.kind.command":       "command line",
		"mem.kind.injection":     "process injection API",
		"mem.kind.cred_dump":     "credential theft trace",
		"mem.kind.persist":       "persistence trace",
		"mem.kind.anti_forensic": "anti-forensics trace",
		"mem.kind.mining":        "crypto mining trace",
		"mem.kind.ransom":        "ransomware trace",

		"mem.col.kind":     "target kind",
		"mem.col.target":   "target",
		"mem.col.pid":      "process",
		"mem.col.ppid":     "ppid",
		"mem.col.proc":     "process name",
		"mem.col.exe":      "executable",
		"mem.col.arch":     "arch",
		"mem.col.user":     "user",
		"mem.col.started":  "start time",
		"mem.col.vsize":    "virtual memory",
		"mem.col.regions":  "regions",
		"mem.col.selected": "analyzed",
		"mem.col.exec":     "executable",
		"mem.col.scanned":  "read",
		"mem.col.total":    "overall digest",
		"mem.col.start":    "start address",
		"mem.col.end":      "end address",
		"mem.col.size":     "size",
		"mem.col.perm":     "perm",
		"mem.col.path":     "backing file",
		"mem.col.entropy":  "entropy",
		"mem.col.class":    "class",
		"mem.col.risk":     "risk",
		"mem.col.offset":   "offset",
		"mem.col.value":    "value",
		"mem.col.enc":      "enc",
		"mem.col.type":     "type",
		"mem.col.score":    "score",
		"mem.col.saved":    "saved",

		"mem.bykind":                   "by region kind:",
		"mem.modules":                  "loaded modules (%d):",
		"mem.more":                     "%d more rows not shown (use -n to adjust or -X for everything)",
		"mem.none":                     "(none)",
		"mem.maps.header":              "%-16s %-16s %10s  %-4s %-6s %s",
		"mem.entropy.header":           "%8s %-7s %10s  %-6s %s",
		"mem.hash.header":              "%-16s %10s  %-6s %-32s %s",
		"mem.behavior.header":          "%-6s %-12s %-16s  %s",
		"mem.behavior.stats":           "by category:",
		"mem.behavior.count":           "hits",
		"mem.behavior.none":            "no notable behavior traces found",
		"mem.strings.header":           "%-16s  %-7s  %s",
		"mem.strings.none":             "no strings extracted",
		"mem.carve.header":             "%-8s %-16s %10s  %3s %-64s %s",
		"mem.carve.none":               "no files carved",
		"mem.carve.saved":              "%d files saved to: %s",
		"mem.risk.0":                   "none",
		"mem.risk.1":                   "info",
		"mem.risk.2":                   "suspicious",
		"mem.risk.3":                   "high",
		"mem.sec.patch":                "Memory Patch",
		"mem.col.op":                   "op",
		"mem.col.mode":                 "mode",
		"mem.col.hits":                 "hits",
		"mem.col.skipped":              "refused",
		"mem.col.written":              "written",
		"mem.col.addr":                 "address",
		"mem.col.before":               "before",
		"mem.col.after":                "after",
		"mem.col.status":               "status",
		"mem.patch.header":             "%-16s  %-22s -> %-22s %s",
		"mem.patch.preview":            "PREVIEW (nothing written)",
		"mem.patch.applied":            "APPLIED",
		"mem.patch.ok":                 "OK",
		"mem.patch.none":               "nothing matched to patch",
		"mem.patch.hint":               "this is a preview only; add --apply to really write into the target memory",
		"mem.info.backup_saved":        "rollback records saved (%d): %s",
		"mem.warn.backup_failed":       "failed to save rollback records: %s (%v)",
		"mem.warn.bad_record":          "unparsable rollback record at %#x, skipped: %v",
		"mem.warn.restore_unreadable":  "address %#x is no longer readable, cannot roll back",
		"mem.warn.restore_failed":      "failed to roll back address %#x: %v",
		"mem.err.not_writable":         "target is not writable on %s: no write permission; retry as root/administrator, or export with -d and patch the image instead",
		"mem.err.write_need_target":    "write/patch/restore needs a target: -i <pid|self|dump-file> or -e <program>",
		"mem.err.write_need_addr":      "-a write needs --addr with the target address",
		"mem.err.write_need_data":      "use -Y to specify the content to write",
		"mem.err.patch_need_data":      "use -Y to specify the replacement content",
		"mem.err.patch_need_needle":    "use -k to specify the content to search for (raw bytes or text)",
		"mem.err.bad_data":             "cannot parse the -Y value: %v",
		"mem.err.bad_addr":             "cannot parse --addr: %s",
		"mem.err.no_such_region":       "no region of kind %s (run -a maps to see the available ones)",
		"mem.err.addr_out_of_region":   "offset %#x falls outside the %s region (%s)",
		"mem.err.bad_max":              "--max must be >= 0 (got %d)",
		"mem.err.restore_need_backup":  "-a restore needs --backup <rollback record file>",
		"mem.err.no_backup":            "the rollback record file contains no records",
		"mem.err.restore_preview_only": "rollback was only previewed; add --apply to really write it back",
		"mem.err.no_write_action":      "no write action given (write / patch / restore)",
		"mem.err.target_conflict":      "-i and -e cannot be combined (both specify an analysis target)",
		"mem.err.no_match":             "no program matched: %s (run -l to list programs first)",
		"mem.err.list_processes":       "failed to enumerate processes on %s: %v",
		"mem.err.threads_unsupported":  "thread enumeration is not available on this platform (%s)",
		"mem.info.matched":             "matched program: pid %d (%s)",
		"mem.info.self_target":         "self (pid %d, %s)",
		"mem.info.proc_target":         "%s (pid %d)",
		"mem.info.multi_match":         "%s matched %d processes, analyzing them one by one",
		"mem.info.all_procs":           "all programs (%d)",
		"mem.info.only_proc":           "only %s (%d)",
		"mem.info.thread_fail":         "failed to read threads of pid %d (%s): %v",
		"mem.sec.procs":                "Programs And Threads",
		"mem.col.scope":                "scope",
		"mem.col.threads":              "threads",
		"mem.col.tid":                  "TID",
		"mem.col.state":                "state",
		"mem.col.name":                 "name",
		"mem.col.cmd":                  "command line",
		"mem.proc.header":              "%5s  %7s  %7s  %-7s %-12s %s",
		"mem.proc.none":                "no program matched",
		"mem.thread.title":             "threads of each program:",
		"mem.thread.header":            "%7s  %-11s %s",
		"mem.thread.of":                "pid %d (%s), %d threads:",
		"mem.thread.none":              "pid %d (%s) has no listable thread",
	},
}
