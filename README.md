<p align="center">
  <img src="app.png" alt="GYhost" width="160">
</p>

# GYhost

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.27.1-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go 1.27.1">
  <img src="https://img.shields.io/badge/License-Apache--2.0-blue?style=flat-square" alt="License: Apache 2.0">
  <img src="https://img.shields.io/badge/CUDA-optional-76B900?style=flat-square&logo=nvidia&logoColor=white" alt="CUDA: optional">
  <img src="https://img.shields.io/badge/Platform-Windows_%7C_Linux_%7C_macOS_%7C_Termux-informational?style=flat-square" alt="Platforms: Windows / Linux / macOS / Termux">
</p>

GYhost 是一个**以本地为核心**的安全工具集，使用 Go 语言开发，专注于本地离线的安全分析能力。

> 定位：本地优先（local-first）。目标覆盖 hash 破解、pwn 测试、本地 fuzz 等本地安全场景，
> **当前仅落地了 hash 相关模块**，其余能力在规划中。

[GYscan](https://github.com/xiguayiqiu/GYscan)、[JYscan](https://github.com/xiguayiqiu/JYscan)、[GYhost](https://github.com/xiguayiqiu/GYhost) —— 其中 `GYhost` 是 GY 系列的本地分析工具。

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
  GPU 只覆盖 `$1$` md5crypt / `$5$` sha256crypt / `$6$` sha512crypt 三种算法；
  bcrypt、yescrypt、argon2、scrypt、pbkdf2 没有 CUDA 内核，仍走 CPU，混用时会打印提示
- 候选来源二选一：`-p` 字典，或 `-m` 掩码（hashcat 风格表达式，见下）
- 可选将结果以 `user:password` 写入文件

### hashdump —— 加密文件哈希提取

从加密的压缩包、加密文档或无线抓包中提取可离线枚举的哈希，输出 hashcat 可直接使用的格式。

```bash
gyhost hashdump -i secret.zip > hashes.txt
gyhost hashdump -i report.pdf > pdf.hashes
gyhost hashdump -i private.docx > office.hashes
gyhost hashdump -i wifite/wifi-01.cap > wpa.hc22000
```

- **压缩包**：zip（ZipCrypto `-m 17200`/`17210`、WinZip AES `-m 13600`）、7z（`-m 11600`，含文件名加密）、rar（RAR5 `-m 13000`，含头加密 `-hp`）
- **加密 Office 文档**（OLE 复合文档；WPS 以兼容格式保存的文档同样支持）：
  - OOXML agile 加密：`-m 9500`（SHA-1 / 2010）、`-m 9600`（SHA-512 / 2013+）
  - OOXML 标准加密（2007 CryptoAPI）：`-m 9400`
  - Word/Excel 97-2003：`$oldoffice$` → `-m 9700`（RC4+MD5）、`-m 9800`（RC4+SHA1）
  - 输出与 john 的 `office2john` 逐字节一致，且不带它的 `:::` 后缀，可直接管道给 hashcat；已用 hashcat v7.1.2 实测可破
  - 未加密文档、WPS 私有加密、PPT/Access 加密会明确说明跳过原因，不静默丢弃
- **加密 PDF**（按 `/Encrypt` 的 V/R 自动选模式）：
  - `-m 10400` V=1/R=2（RC4-40）、`-m 10500` V=2/R=3 与 V=4/R=4（RC4-128 / AES-128）
  - `-m 10600` V=5/R=5（AES-256）、`-m 10700` V=5/R=6（AES-256 强化 KDF）
  - 输出与 john 的 `pdf2john` 逐字节一致，已用 hashcat v7.1.2 实测可破
  - 四种模式（10400/10500/10600/10700）都有 CUDA 内核，`hashac --gpu` 可直接用显卡枚举
  - 目前 10400/10500/10600 默认走 GPU；10700（R=6 强化 KDF）的 GPU 内核虽已实现并有向量测试，
    但实测比多线程 CPU 慢（约 1.4 kH/s 对 10.7 kH/s），故仍走 CPU，换 T-table 版 AES 后再放开
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

### hashcat —— 算法识别与模式号

不破解，只回答一个问题：**这是什么算法？该用 hashcat 的 `-m` 几？**

```bash
gyhost hashcat -i secret.zip              # 这个压缩包用了什么算法
gyhost hashcat -i /etc/shadow             # shadow 里都是什么口令哈希
gyhost hashcat --list                     # 只看算法 / 模式对照表
```

- **加密容器**（复用 `hashdump` 的解析器）：zip（ZipCrypto `-m 17200`/`17210`、WinZip AES `-m 13600`）、7z（`-m 11600`）、RAR5（`-m 13000`）、加密 PDF（`-m 10400`/`10500`/`10600`/`10700`）、Office/WPS 文档（`-m 9400`/`9500`/`9600`/`9700`/`9800`/`25300`）、无线抓包（`-m 22000`）
- **哈希清单**（每行一条）：裸摘要 MD5/NTLM、SHA-1、SHA-256、SHA-512；口令哈希 `$1$`/`$apr1$`/`$5$`/`$6$`/`$2*$`/`$argon2*$`/`$scrypt$`/`$pbkdf2-sha256$`/`$y$`；Office 文档 `$office$`/`$oldoffice$`
- 兼容 shadow 的 `user:hash:...` 与 hashcat potfile 的 `hash:密码` 行，条目名直接取用户名（附行号）
- 每条输出「算法 / 模式 / 容器」三行，模式号可直接抄给 hashcat；结尾提示区分「容器需先 `hashdump` 导出」与「清单可直接使用」
- 既不是容器也不是文本的输入（二进制文件）整份判为一条「无法解析」，不会退回逐行猜哈希刷屏；未加密/不支持的文档同样给出具体原因
- 支持目录扫描（压缩包、文档、抓包与 `txt`/`hash`/`hashes` 清单）、`--list` 对照表与 `-q` 静默
- 32 位十六进制在 MD5 与 NTLM 之间天然歧义，两个模式号都会给出；yescrypt（`$y$`）在 hashcat 中没有原生模式，只给算法名
- 模式号已用本机 hashcat v7.1.2 的 `-hh` 输出逐条核对，含 Argon2 `-m 34000`、scrypt `-m 8900` 等 Generic KDF 模式

### hashac —— 常见哈希明文碰撞

枚举常见哈希的明文碰撞，自动识别哈希类型。

```bash
gyhost hashac -i hashes.txt -p wordlist.txt
gyhost hashac -i hashes.txt -m '?l?l?d?d'       # 掩码穷举，实时生成候选
```

- 裸摘要：MD5 / SHA-1 / SHA-256 / SHA-512
- 复合格式：WPA2-PMKID/EAPOL（`-m 22000`）、RAR5（`-m 13000`）、ZIP-AES（`-m 13600`）、ZipCrypto（`-m 17200`/`17210`）、7z（`-m 11600`）、加密 PDF（`-m 10400`/`10500`/`10600`/`10700`）、加密 Office 文档（`$office$` → `-m 9400` 标准加密 / `-m 9500` agile SHA-1 / `-m 9600` agile SHA-512）
  `$oldoffice$`（Word/Excel 97-2003，hashcat `-m 9700`/`9800`）暂不支持，遇到会明确报错而不是静默跳过
- WPA-Enterprise（WPE）与家用 WPA/WPA2 走同一条 hc22000 路径，抓包里的四次握手都按 `WPA*02*` 处理（个人版的 PMKID 走 `WPA*01*`）；
  John the Ripper 的 `$wpe$` / `wpa_pmkid+eapolv2` 私有格式未实现（hashcat 同样不支持）
- 其中 `$...$` 格式可由 `hashdump` 直接从加密压缩包生成，两者可串联使用
- 加密 PDF 的 `/U`（用户口令）与 `/O`（所有者口令）都会尝试——命中任一即可打开该 PDF；
  已用 hashcat v7.1.2 的 10400/10500/10600/10700 逐条实测对齐（注意 hashcat 只校验用户口令）
- 候选来源二选一：`-p` 字典，或 `-m` 掩码（hashcat 风格表达式，见下）
- 支持 GPU 加速（`--gpu` 需 root/管理员）与并发；加密 PDF 的 10400/10500/10600 走 CUDA 内核（10700 见上）
- 走 GPU 的类型：7z Copy 编码器、zip 的 ZipCrypto 与 WinZip AES、RAR5/RAR3、rar 之外的裸摘要、
  WPA2、PDF 10400/10500/10600、Office `$office$` 9400/9500/9600。留在 CPU 的目标会说明原因（如 7z 的 LZMA 条目需解压、
  密文超过 1 MiB）；`-m 10700` 默认留 CPU，`GYHOST_PDF_R6_GPU=1` 可强制用 GPU
- WPA2（`-m 22000`）的 PMKID 与 EAPOL 两种形态都走 GPU：EAPOL 帧要整帧下发，
  上限 64 KiB（hashcat 自己的 hc22000 解析只接受 256 字节以内的 EAPOL 字段，
  `hashdump` 从抓包转出来的行可能更长，这类目标以前会被 384 字节通用上限挡回 CPU）

### GPU 怎么跑满（shadow / hashac 通用）

`--gpu` 启动时先做两件事，否则速度会明显低于 hashcat：

- **唤醒显卡**：消费级显卡空载会停在低功耗档（P8，本机实测核心频率只有 210 MHz），
  NVIDIA 驱动只对「持续」的负载提频。所以爆破前会先用真实目标连续打满约 0.4 秒
  （stderr 提示「正在唤醒 GPU…」），让频率升到最高档再正式开跑；顺带完成内核加载。
- **多批流水线**：单 GPU 目标时最多 8 批同时在飞（`cuda.PipelineSlots()` 与 native 槽位对齐），
  批大小 131072。提交下一批用的是页锁定（pinned）内存，`cudaMemcpyAsync` 真正异步，
  主机准备下一批时 GPU 一直在算上一批——批与批之间不留空档，显卡才不会掉回低功耗档。
  多 GPU 目标退回逐目标同步路径。

两个模块都遵循同一条规则：**任何一批候选只要没能确认校验结果（GPU 出错、槽位被抢占），
就整批交给 CPU 复核**，宁可慢一点也不漏解。超长候选（超过 255 字节）本来就只能由 CPU 校验。

`internal/cuda` 的静态库默认用 `-arch=native` 编译：直接生成与本机 GPU 匹配的 cubin。
不给架构时只嵌入 PTX，驱动要在首次启动内核时现场 JIT 整个模块（本机实测接近一分钟，
表现为「--gpu 跑起来先卡住」）。交叉编译请显式指定，例如 `make cuda-lib ARCH=sm_86`。

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
./gyhost help hashcat
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
./gyhost hashdump -i private.docx > office.hashes         # 加密 Word/WPS 文档
./gyhost hashdump -i report.pdf > pdf.hashes              # 加密 PDF（用户/所有者口令都能破）
./gyhost hashdump -i /path/to/dir 2>/dev/null | sort -u > all.txt

# hashac：碰撞（可接在 hashdump 之后）
./gyhost hashac -i hashes.txt -p wordlist.txt
./gyhost hashac -i hashes.txt -m '?l?l?l?l'              # 掩码穷举
sudo ./gyhost hashac -i hashes.txt -p wordlist.txt --gpu -o cracked.txt   # GPU 需 root
./gyhost hashdump -i secret.rar -o hashes.txt && ./gyhost hashac -i hashes.txt -p wordlist.txt
./gyhost hashdump -i report.pdf | ./gyhost hashac -i /dev/stdin -p wordlist.txt   # 加密 PDF

# hashcat：识别算法并给出 -m 模式号
./gyhost hashcat -i secret.zip                    # 容器里是什么算法
./gyhost hashcat -i report.docx                   # 加密 Office/WPS 文档
./gyhost hashcat -i hashes.txt -i /etc/shadow     # 哈希清单 / shadow 逐行识别
./gyhost hashcat -i /path/to/dir                  # 批量分析整个目录
./gyhost hashcat --list                           # 算法 / 模式对照表
./gyhost hashcat -q -i hashes.txt                 # 静默：只看条目
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
    ├── hashcat/
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

## 许可证

本项目基于 [Apache License 2.0](LICENSE) 开源。

## 免责声明

本工具仅供**授权范围内的安全测试与研究**使用。请勿用于任何未授权的用途。
 
