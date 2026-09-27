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
		"hashac.summary": "枚举 MD5/WPA2/RAR/ZIP/7z/PDF 等常见哈希的明文碰撞",
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
  其中 $... 格式可由 gyhost hashdump 直接从加密压缩包或加密 PDF 提取

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

		// ---- hashac 错误 ----
		"hashac.err.missing_args":  "缺少必填参数: -i [哈希文件]，以及 -p [密码字典] 或 -m [掩码] 之一",
		"hashac.err.mask_conflict": "不能同时指定 -p 字典与 -m 掩码，二者只能选一个",
		"hashac.err.mask":          "掩码表达式非法",
		"hashac.err.threads":       "线程数必须大于 0: %d",
		"hashac.err.mode":          "不支持的 hashcat 模式号: %d",
		"hashac.err.pdf_version":   "不支持的 PDF 加密版本 V=%d R=%d",
		"hashac.err.pdf_mode":      "该 PDF 哈希的 V/R 对应 -m %d，与 --mode %d 不符",
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
		"hashac.summary": "Enumerate plaintext collisions for common hashes (MD5/WPA2/RAR/ZIP/7z/PDF)",
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
  the $... forms can be produced by "gyhost hashdump" from encrypted archives or PDFs

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

		// ---- hashac errors ----
		"hashac.err.missing_args":  "missing required options: -i [hash file], plus either -p [wordlist] or -m [mask]",
		"hashac.err.mask_conflict": "cannot use -p and -m at the same time, pick one",
		"hashac.err.mask":          "invalid mask expression",
		"hashac.err.threads":       "thread count must be greater than 0: %d",
		"hashac.err.mode":          "unsupported hashcat mode number: %d",
		"hashac.err.pdf_version":   "unsupported PDF encryption version V=%d R=%d",
		"hashac.err.pdf_mode":      "this PDF hash maps V/R to -m %d, which conflicts with --mode %d",
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
	},
}
