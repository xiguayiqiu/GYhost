# GYhost

GYhost 是一个**以本地为核心**的安全工具集，使用 Go 语言开发，专注于本地离线的安全分析能力。

> 定位：本地优先（local-first）。目标覆盖 hash 破解、pwn 测试、本地 fuzz 等本地安全场景，
> **当前仅落地了 hash 相关模块**，其余能力在规划中。

## 设计理念

- **本地优先**：所有分析在本地离线完成，不依赖在线服务，数据不出本机。
- **模块化**：核心是一个极简的模块注册与分发框架，新增能力 = 实现一个模块 + 注册一行。
- **GPU 可选**：检测到 CUDA 环境即自动启用 GPU 加速，否则回退纯 CPU，构建与运行都不会失败。使用 `--gpu` 需要 root（Windows 上为管理员）权限。
- **可管道**：结果与提示分流（结果走 stdout、进度与提示走 stderr），方便接入脚本与管道。

## 当前已实现的模块

> 以下均为 hash 方向的首批模块，**并非** GYhost 的核心能力全集，只是当前已落地的部分。

### shadow —— shadow 文件离线爆破

离线爆破 Linux/Unix `/etc/shadow` 中的密码哈希。

```bash
gyhost shadow -i /etc/shadow -p rockyou.txt
gyhost shadow -i /etc/shadow -m '?d?d?d?d'      # 掩码穷举，实时生成候选
```

- 支持哈希：`$1$` md5crypt、`$5$`/`$6$` sha-crypt（含 rounds）、`$2*$` bcrypt、`$y$` yescrypt、`$argon2*$`、`$pbkdf2-*$`、`$scrypt$`
- 多线程并发、可按用户过滤、支持 GPU 加速（`--gpu` 需 root/管理员）
- 候选来源二选一：`-p` 字典，或 `-m` 掩码（hashcat 风格表达式，见下）
- 可选将结果以 `user:password` 写入文件

### hashdump —— 加密压缩包 / 无线抓包哈希提取

从加密的 zip/7z/rar 压缩包，或 pcap/pcapng 无线抓包中提取可离线枚举的哈希，
输出 hashcat 可直接使用的格式。

```bash
gyhost hashdump -i secret.zip > hashes.txt
gyhost hashdump -i wifite/wifi-01.cap > wpa.hc22000
```

- **压缩包**：zip（ZipCrypto `-m 17200`/`17210`、WinZip AES `-m 13600`）、7z（`-m 11600`，含文件名加密）、rar（RAR5 `-m 13000`，含头加密 `-hp`）
- **无线抓包**（`-m 22000`，hc22000 格式，与 hcxtools 的 `hcxpcapngtool` 对齐）：
  - 抓包格式：pcap（含大小端与微秒/纳秒时间戳）、pcapng
  - 链路类型：802.11 / radiotap / Prism / AVS
  - 提取 PMKID（`WPA*01*`）与四次握手（`WPA*02*`），握手按 M2+M3 > M1+M2 > M3+M4 > M1+M4 择优配对
  - ESSID 取自 beacon / probe response / (re)association request；缺失 ESSID 或不完整握手会跳过并提示原因
- 支持目录扫描与批量输入；哈希走 stdout，可直接管道给 hashcat

```bash
# 提取无线握手并直接爆破
gyhost hashdump -i wifi-01.cap > wpa.hc22000
hashcat -m 22000 wpa.hc22000 wordlist.txt
# 也可以用 hashac 接着跑（无需 hashcat）
gyhost hashdump -i wifi-01.cap | gyhost hashac -i /dev/stdin -p wordlist.txt
```

### hashac —— 常见哈希明文碰撞

枚举常见哈希的明文碰撞，自动识别哈希类型。

```bash
gyhost hashac -i hashes.txt -p wordlist.txt
gyhost hashac -i hashes.txt -m '?l?l?d?d'       # 掩码穷举，实时生成候选
```

- 裸摘要：MD5 / SHA-1 / SHA-256 / SHA-512
- 复合格式：WPA2-PMKID/EAPOL（`-m 22000`）、RAR5（`-m 13000`）、ZIP-AES（`-m 13600`）、ZipCrypto（`-m 17200`/`17210`）、7z（`-m 11600`）
- 其中 `$...$` 格式可由 `hashdump` 直接从加密压缩包生成，两者可串联使用
- 候选来源二选一：`-p` 字典，或 `-m` 掩码（hashcat 风格表达式，见下）
- 支持 GPU 加速（`--gpu` 需 root/管理员）与并发

## 掩码（暴力枚举）

`shadow` 与 `hashac` 都支持用掩码实时生成候选，表达式沿用 hashcat：

- `?l` 小写字母、`?u` 大写字母、`?d` 数字
- `?h`/`?H` 十六进制小写/大写、`?s` 可见特殊字符（含空格）
- `?a` = `?l?u?d?s`（全部可见字符，95 个）、`?b` 全部 256 个字节
- `??` 表示字面量 `?`，其余字符按字面量处理
- 枚举顺序与 hashcat 一致：最右位变化最快

```bash
gyhost shadow -i /etc/shadow -m '?d?d?d?d'          # 4 位数字
gyhost shadow -i /etc/shadow -m '?u?l?l?l?d?d'      # Abcd12 形状
gyhost hashac -i hashes.txt -m 'pass?d?d?d'         # 字面量 + 数字
gyhost hashac -i hashes.txt -m '?a?a?a?a' --gpu     # 4 位全字符 + GPU
```

说明：

- 掩码与字典互斥：`-p` 和掩码只能给一个，两个都给或都不给都会报错
- 两个模块统一用 `-m` / `--mask` 表示掩码；`hashac` 的「强制 hashcat 模式号」改为只有长选项 `--mode`
- 启动时会提示掩码展开的候选总数；超大掩码（如 `?a` 超过 14 位）的计数会饱和显示为 `...18446744073709551615+`
- 掩码是流式枚举，没有上限；`?a?a?a?a?a?a` 这类巨大空间可随时 Ctrl-C 中断
- **`--gpu` 需要 root / 管理员权限**：非 root（Windows 上非管理员）时 `--gpu` 不会启用，会打印提示并回退 CPU 爆破。Linux/macOS/Termux 用 `sudo` 运行，Windows 需以管理员身份运行（UAC 提升）
- **`--gpu` 对快哈希帮助有限**：裸 MD5/SHA-1 这类单次计算极快的算法，瓶颈在每批 2048 个候选的显存分配与内核发射开销，实测与 CPU 基本持平；对 md5crypt、sha-crypt、RAR5、7z 等慢哈希才有明显加速（实测 `$1$` 约 2.7 倍）

## 构建

依赖：

- Go 1.27+
- CUDA Toolkit（可选，用于 GPU 加速）

```bash
make          # 自动检测：有 nvcc 则启用 GPU(CUDA)，否则回退纯 CPU
make cpu      # 强制纯 CPU 构建，二进制可在任意机器运行
make gpu      # 等同于 make
make cuda-lib # 只编译 CUDA 静态库 libgyhost_cuda.a
```

也可以直接用 go 命令：

```bash
go build -o gyhost .             # 纯 CPU
go build -tags cuda -o gyhost .  # 带 GPU（需先 make -C internal/cuda）
```

## 使用

```bash
./gyhost                 # 启动横幅 + 帮助
./gyhost help            # 查看帮助
./gyhost help shadow     # 查看模块帮助
./gyhost help hashdump
./gyhost help hashac
```

常用示例：

```bash
# shadow：基础爆破 / 指定用户 / 掩码 / GPU 加速 / 输出到文件
./gyhost shadow -i /etc/shadow -p rockyou.txt
./gyhost shadow -i /etc/shadow -p rockyou.txt -u root,alice
./gyhost shadow -i /etc/shadow -m '?d?d?d?d'            # 掩码穷举
sudo ./gyhost shadow -i /etc/shadow -p rockyou.txt --gpu -t 8   # GPU 需 root
./gyhost shadow -i shadow.bak -p pass.txt -o result.txt

# hashdump：提取哈希（可直接管道给 hashcat）
./gyhost hashdump -i secret.zip > hashes.txt
./gyhost hashdump -i secret.7z -o hashes.txt -q
./gyhost hashdump -i /path/to/dir 2>/dev/null | sort -u > all.txt

# hashac：碰撞（可接在 hashdump 之后）
./gyhost hashac -i hashes.txt -p wordlist.txt
./gyhost hashac -i hashes.txt -m '?l?l?l?l'              # 掩码穷举
sudo ./gyhost hashac -i hashes.txt -p wordlist.txt --gpu -o cracked.txt   # GPU 需 root
./gyhost hashdump -i secret.rar -o hashes.txt && ./gyhost hashac -i hashes.txt -p wordlist.txt
```

全局参数：`--help`、`--version`、`--no-banner`、`--no-color`。

## 项目结构

```
GYhost/
├── main.go          # 入口：注册模块并交给 CLI 分发
├── Makefile         # 构建/测试入口
├── internal/        # 核心框架（与具体模块无关）
│   ├── cli/         # CLI 根命令与横幅
│   ├── module/      # 模块契约与注册表
│   ├── cuda/        # CUDA GPU 加速
│   ├── pwdhash/     # 密码哈希解析/校验
│   ├── i18n/        # 国际化
│   └── utils/       # 输出配色等工具
└── modules/         # 功能模块（当前均为 hash 方向）
    ├── shadow/
    ├── hashdump/
    └── hashac/
```

## 扩展新模块

核心框架与具体功能解耦，新增能力只需两步：

1. 在 `modules/<name>/` 下实现 `module.Module` 接口（`Name` / `Summary` / `Group` / `Usage` / `Run`）。
2. 在 `main.go` 中加一行注册：

```go
registry.MustRegister(<name>.New())
```

## 国际化

界面语言由环境变量 `LANG` 决定，无需其它开关：

- `zh*` → 中文
- `en*` → 英文
- `C` / `POSIX` / 未设置 → 默认中文
- 其它语言 → 回退英文

```bash
LANG=zh_CN.UTF-8 ./gyhost   # 中文
LANG=en_US.UTF-8 ./gyhost   # 英文
```

## 测试

```bash
make test      # 单元测试（默认构建）
make test-gpu  # CUDA 构建下的测试（无 GPU 时自动跳过用例）
make vet       # 静态检查（CPU/CUDA 两种构建形态）
make fmt       # 列出未 gofmt 的文件（应为空）
```

## 免责声明

本工具仅供**授权范围内的安全测试与研究**使用。请勿用于任何未授权的用途。
 