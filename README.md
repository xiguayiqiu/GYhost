<p align="center">
  <img src="app.png" alt="GYhost" width="160">
</p>

# GYhost

> 更新日志见 [LOG.md](LOG.md)。

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.27.1-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go 1.27.1">
  <img src="https://img.shields.io/badge/License-Apache--2.0-blue?style=flat-square" alt="License: Apache 2.0">
  <img src="https://img.shields.io/badge/CUDA-optional-76B900?style=flat-square&logo=nvidia&logoColor=white" alt="CUDA: optional">
  <img src="https://img.shields.io/badge/Platform-Windows_%7C_Linux_%7C_macOS_%7C_Termux-informational?style=flat-square" alt="Platforms: Windows / Linux / macOS / Termux">
</p>

GYhost 是一个**以本地为核心**的安全工具集，使用 Go 语言开发，专注于本地离线的安全分析能力。

> 定位：本地优先（local-first）。目标覆盖 hash 破解、pwn 测试、本地 fuzz 等本地安全场景，
> **当前已落地 hash 方向（4 个模块）、网络抓包分析（`net`）、内存取证（`mem`）与进程分析（`proc`）四个方向**，其余能力在规划中。

[GYscan](https://github.com/xiguayiqiu/GYscan)、[JYscan](https://github.com/xiguayiqiu/JYscan)、[GYhost](https://github.com/xiguayiqiu/GYhost) —— 其中 `GYhost` 是 GY 系列的本地分析工具。

## 设计理念

- **本地优先**：所有分析在本地离线完成，不依赖在线服务，数据不出本机。
- **模块化**：核心是一个极简的模块注册与分发框架，新增能力 = 实现一个模块 + 注册一行。
- **GPU 可选**：检测到 CUDA 环境即自动启用 GPU 加速，否则回退纯 CPU，构建与运行都不会失败。使用 `--gpu` 需要 root（Windows 上为管理员）权限。
- **可管道**：结果与提示分流（结果走 stdout、进度与提示走 stderr），方便接入脚本与管道。

## 当前已实现的模块

> 以下模块**并非** GYhost 的核心能力全集，只是当前已落地的部分：hash 方向 4 个（shadow / hashdump / hashcat / hashac），
> 网络方向 1 个（net）、内存方向 1 个（mem）、进程方向 1 个（proc）；帮助信息里按「本地分析」「网络分析」「内存取证」「进程分析」四个分组展示。

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

### net —— pcap/cap 网络分析

离线分析 `pcap` / `pcapng` 抓包文件的网络流量（分组：网络分析）。只读本地文件，不发包、不联网。

- **输入**：`-i` 指定抓包（可重复；给目录时按扩展名 `.pcap`/`.cap`/`.pcapng`/`.dmp` 扫描）
- **容器**：pcap（大小端、微秒/纳秒时间戳）与 pcapng（多 section/接口、`if_tsresol`/`if_tsoffset`），
  读取逻辑在 `internal/pcap`，`hashdump` 的无线抓包提取同样复用它（输出与重构前一致）
- **解码**：Ethernet（含 VLAN/QinQ）、Linux SLL/SLL2、Raw IP、Null/Loopback、PPP、
  802.11（radiotap/Prism/AVS）、FDDI；IPv4/IPv6（扩展头）/ARP/MPLS/PPPoE；TCP/UDP/ICMP/ICMPv6，
  以及 GRE/ESP/AH/OSPF/SCTP 等其它网络协议
- **报告**：抓包概览（格式/链路类型/包数/时间范围/流量）→ 四层协议分布（链路/网络/传输/应用）
  → 会话 TOP → 主机 TOP → 端口 TOP（服务端口按流推断：TCP 以 SYN 方向为准，否则首包目的端口）
  → DNS 查询 → TLS SNI → 明文 HTTP 主机与请求 URI → 安全发现；指定 `-m` 时最前面多一段攻击分析
- **`-m` 攻击分析**：启用一个或多个分析模型（逗号分隔、可重复），逐模型给出
  「命中 / 疑似 / 未命中」判定、关键指标与命中迹象：
  - `syn`　SYN 洪泛（峰值、SYN:SYN-ACK 失衡、SYN 占比）与源 IP 随机化/伪造
    （只出现 1 次且只发 SYN 的源占比）
  - `udp` / `icmp`　洪泛（单秒峰值 + 占总包比例双判据，速率线刻意取高以避开 VoIP/视频）
  - `flood`　通用洪泛（= `syn`+`udp`+`icmp`）
  - `cc`　CC 攻击（HTTP 请求速率、单源高频、同一 URI 被大量源请求的分布式形态）
  - `loss`　流量丢包与 TCP 传输异常（重传、seq 间隙、连续 3 个重复 ACK、零窗口、抓包截断）
  - `frag`　IP 分片异常（重叠/畸形分片，泪滴类）
  - `all`　以上全部（`-m` 留空等价于 `all`）
  阈值集中在 `modules/net/attack.go` 顶部常量；统计单遍完成、不保存包内容，
  超大抓包只按「源 IP 数 / 流数 / 时长」占内存（键数触顶时报告会提示指标不完整）
- **安全发现**：FTP/POP3/IMAP/SMTP 的明文凭据（`USER`+`PASS` 同会话配对、`AUTH PLAIN`）、
  HTTP `Authorization`（Basic/Digest）与表单/查询串里的口令字段、ARP 同 IP 多 MAC（疑似欺骗）、
  未加密的明文协议流量（Telnet/FTP/SMTP/MySQL/VNC 等端口）。
  凭据类一行一条；条目较多的（ARP 冲突、明文端口）渲染成「标题 + 缩进明细表」，
  按 IP / 端口号升序排列，端口与包数右对齐
- **应用层识别**：先看载荷（HTTP/TLS/DTLS/SSH），再退回端口映射；列表的「信息」列会给出
  DNS 查询/应答、文本协议首行、DHCP 消息类型、`ClientHello SNI=...` 这类摘要
- **`-l` 逐包列表**：序号 / 相对首包时间 / 端点 / 协议 / 长度 / 摘要，流式输出不占内存
- **`-V` 逐包详细视图**（对齐 `tshark -V`）：按协议树逐层展开每个包的字段明细
  - Frame：封装类型、到达时间/时间戳/相对首帧、线上与捕获长度（截断时明确提示）、协议栈
  - 以太网：源/目的 MAC、802.1Q/QinQ 的 VLAN ID、EtherType（带名称）
  - IPv4：版本、头长、DSCP/ECN、总长度、Identification、DF/MF 标志位、分片偏移、TTL、
    协议号、头部校验和、源/目的地址；IPv6：流量类别、流标签、载荷长度、下一头部、跳数限制
  - TCP：端口、序号/确认号、头长、8 个标志位逐位置位情况、窗口、校验和、紧急指针，
    并逐条解析选项（MSS / Window Scale / SACK / Timestamps 等取值）
  - UDP：端口、长度、校验和、端口对应服务名；ICMP/ICMPv6：类型（带名称）、代码、校验和、标识符、序列号
  - ARP：硬件/协议类型与长度、操作码、收发双方 MAC 与 IP
  - 应用层：HTTP 的 Host 与明文凭据/口令字段、DNS 查询名与应答、TLS SNI
  - 末尾附整帧原始字节的 hexdump（16 字节一行，偏移 + 十六进制 + ASCII）
  - 单独给 `-V` 会自动开启 `-l`；可与 `-f`、`-n`、`-m` 组合使用
  - 详细字段只在 `-V` 时填充，报告模式仍走原有的轻量路径（性能不受影响）
- **`-T` 交互式抓包浏览器**（对齐图形化 tshark/Wireshark）：接管终端的全屏三栏界面
  - 上方是包列表（编号 / 源 / 目的 / 协议 / 长度 / 信息），可滚动并高亮选中项
  - 下方是选中包的协议树详情（复用 `-V` 的渲染），用分隔线与列表隔开
  - 顶部状态栏显示文件、容器格式、当前过滤表达式与「可见 / 总数」
  - 底部状态栏显示按键提示；过滤输入时就地显示表达式
  - 按键：`↑↓` 或 `j/k` 移动、空格/PgUp/PgDn 翻页、`g/G` 首尾、`Enter` 展开/收起详情、
    `/` 输入过滤表达式（沿用 `-f` 的语法）、`↑`/`↓` 翻阅过滤历史、`?` 查看可用字段、
    `c` 清除过滤、`r` 重新应用、`q`/`Ctrl-C` 退出
  - 过滤输入时 `Esc` 取消编辑；已有过滤时再按一次 `Esc` 清除过滤
  - 使用备用屏幕缓冲区，退出后完整还原终端；进入/退出都会正确恢复光标与回显
  - 需要 stdin/stdout 都是终端；管道、重定向或 CI 环境会给出明确提示并建议改用 `-l`/`-V`
  - 只为每帧保留几十字节的索引（偏移 + 时间戳），选中某帧时才按偏移从文件重读，
    因此内存占用与包数成正比而与文件大小无关；460 万帧的抓包约占 160 MiB
- **`-f` 过滤**：同时作用于统计、列表与交互界面。支持两套语法：

  **显示过滤器**（Wireshark 风格，推荐）：

  ```
  字段            运算符              值
  tcp.port    ==  !=  >  <  >=  <=     80  1024  "text"  10.0.0.1
  ```

  ```bash
  ./gyhost net -i capture.pcap -f "ip.addr == 10.0.0.1 && tcp.port == 443"
  ./gyhost net -i capture.pcap -f "frame.len > 1000 || http.host contains \"example\""
  ./gyhost net -i capture.pcap -f "!(arp || icmp) && tcp.flags.syn == 1"
  ./gyhost net -i capture.pcap -f "(tcp || udp) && port 53"
  ```

  - 逻辑：`&&`（也可写 `and`）、`||`（`or`）、`!`（`not`）、括号分组；空白分隔的多个条件等价于 `&&`
  - 字符串比较用 `contains`（大小写不敏感），字符串需引号
  - 裸写协议名等价于存在性判断（`tcp` ≡ `tcp == 1`）
  - 常用字段：`frame.*`（number/len/cap_len/time/protocols）、`ip.*`（src/dst/addr/ttl/len/id/flags.df/mf）、
    `ipv6.*`、`tcp.*`（port/srcport/dstport/seq/ack/window_size_value/flags/flags.syn…）、
    `udp.*`、`icmp.*`、`arp.*`、`http.*`（host/request.method/request.uri/user_agent/response.code）、
    `tls.sni`、`dns.*`、`eth.*`
  - 在 TUI 里按 `?` 可查看全部字段与说明；`/` 打开过滤输入后会显示**实时提示框**：
    边输入边补全字段名（`Tab` 接受）、提示可用运算符、说明该填什么类型的值，
    并实时校验语法，不用先背语法再猜哪里写错

  **简写语法**（历史写法，继续有效）：

  ```bash
  ./gyhost net -i capture.pcap -f "tcp and port 443"
  ./gyhost net -i capture.pcap -f "src host 192.168.1.1 or dst port 53"
  ./gyhost net -i capture.pcap -f "not host 10.0.0.1"
  ```

  - 条件为协议名、`[src|dst] host IP`、`[src|dst] port N`（纯数字等价 `port N`）
  - 两种语法对同一串文本的理解可能不同（`port 443` 在简写里是关键字），因此**简写优先解析**，
    只有它无法表达的写法才交给显示过滤器
  - 未知字段、括号未闭合、端口越界等都会给出明确错误，并保留原有过滤不变
- **纯 CLI 复杂分析**（不依赖图形界面，可直接进管道与脚本）：
  - `-z` 章节选择：只输出报告的某几段，便于 `grep`/`awk` 二次处理
    （`io`/`proto`/`conv`/`endpoints`/`ports`/`dns`/`sni`/`http`/`findings`/`attack`/`timeline`/`all`）
  - `-z timeline` 流量时间线：按时间桶给出包数、流量与主要协议，能直接看出突发与静默
    （配 `-I N` 调整分桶粒度，秒）。JSON 里则是 `timeline.buckets[]`，含每桶的协议构成
  - `-z follow,tcp,ascii|raw|hex[,<序号>]`：TCP 会话重组与追踪。按 TCP 序号把
    乱序、重传、分段的报文拼回两个方向的字节流，从而看到完整对话内容
    （HTTP 请求体、SMTP 会话、传输的文件等）。缺号处填 0 并给出提示，
    超出内存上限时明确标注"内容不完整"，不会给出看似完整实则截断的结果
  - `-j` JSON 输出：结构化数据，可 `jq` 任意切片、排序、聚合
  - `-t` 时间范围：绝对时刻（`10:05:00-10:06:00`）或相对首帧的秒数（`30-90`），
    先按时间切开再在其中做别的分析
  - 三者可组合，例如：
    `./gyhost net -i c.pcap -t 30-90 -f "tcp.port == 443" -j -z conv | jq '.conversations[0]'`
    `./gyhost net -i c.pcap -z timeline -I 5`  # 5 秒一桶看流量起伏
- **输出分流**：报告/列表走 stdout、提示与告警走 stderr；`-o` 写入文件（自动去掉 ANSI 颜色码），
  `-q` 静默提示
- **大文件性能**：单遍扫描、常数级内存，40 万帧（38 MiB）约 0.3 s。
  为此做了几处针对性优化，均不改变输出内容：
  - 报告模式不生成列表摘要（`-l` 才需要），省掉每帧的字符串格式化
  - MAC 只在真正用到时（ARP 冲突检测、802.11 无 IP 帧）才渲染成字符串
  - 会话查找先比对"上一帧所属会话"，命中就不拼 map 键；未命中在复用缓冲区里拼键，
    map 查找本身不分配
  - 帧缓冲与 `pkt` 结构体逐帧复用，HTTP 头逐行扫描字节切片（不复制整段头部）

```bash
./gyhost net -i capture.pcap                          # 分析报告
./gyhost net -i capture.pcap --top 20                 # 各表只显示前 20 条
./gyhost net -i capture.pcap -m all                   # 附带全部攻击分析（洪泛/CC/丢包/分片）
./gyhost net -i capture.pcap -m syn,cc                # 只看 SYN 洪泛与 CC 攻击
./gyhost net -i capture.pcap -m loss -f "host 10.0.0.5" # 该主机的重传与丢包迹象
./gyhost net -i capture.pcap -f "host 10.0.0.5"       # 只统计该主机
./gyhost net -i capture.pcap -l -f "tcp and port 443" # 逐包列出 TLS 流量
./gyhost net -i capture.pcap -l -n 100                # 只列前 100 个包
./gyhost net -i capture.pcap -V -n 5                 # 逐包详细视图（协议树 + hexdump）
./gyhost net -i capture.pcap -V -f "host 10.0.0.5"   # 某个包的完整字段明细
./gyhost net -i capture.pcap -T                      # 交互式抓包浏览器（全屏）
./gyhost net -i capture.pcap -T -f "tcp and 443"     # 交互式 + 预设过滤
./gyhost net -i ./captures -o report.txt              # 批量分析目录并写入文件
```

### mem —— 内存取证

分析**活体进程**或**内存转储文件**（分组：内存取证）。四个用途：内存分析、内存中分析程序行为、从内存中恢复文件、导出内存镜像。全程只读，不修改目标进程。

```bash
gyhost mem -l                                       # 列出全部程序与它们的子线程
gyhost mem -l nginx                                 # 只看 nginx 这个程序的子线程
gyhost mem -l 1234                                  # 只看 pid 1234 的子线程
gyhost mem -e nginx                                 # 按程序名分析（等价于 -i <pid>）
gyhost mem -i self                                  # 分析当前进程
gyhost mem -i 1234 -a info,maps                     # 看某进程的内存布局
gyhost mem -i 1234 -a behavior -s 1048576           # 行为分析，跳过 1MB 以下区域
gyhost mem -i 1234 -a carve -c ./carved -t png,zip  # 从内存里恢复 png/zip
gyhost mem -i memdump.raw -a all -o report.txt      # 离线分析转储并写文件
gyhost mem -i memdump.raw -a strings -k password    # 只看含 password 的串
gyhost mem -i 1234 -a dump -d target.memdump        # 导出内存留证
```

- **目标**：`-i` 接进程 PID、`self`（当前进程）或内存转储文件路径。转储文件在**任意平台**都能分析，
  因此「别处采的镜像」可以拿回本机反复分析。
- **`-e` 按程序名分析**：`-e <PID|程序名>` 直接分析指定程序，不必先查 PID。
  程序名会依次匹配**进程名 / 可执行文件名 / 命令行首项**，命中多个时逐个出报告。
  例：`gyhost mem -e nginx -a behavior`。
- **`-l` 列出程序与子线程**：
  - `gyhost mem -l` —— 列出**全部程序**，并逐个显示它们的**子线程**（TID、状态、线程名）
  - `gyhost mem -l <PID|程序名>` —— **只**显示该程序的子线程
  - 线程数多的程序排在前面；`-n` 控制条数（`-X` 不限），`-j` 可输出 JSON
  - 三个平台的线程模型不同（Linux 的 task、Windows 的 Thread、macOS 的 thread port），
    但都被归一成同一份 `TID / 状态 / 名称` 输出，脚本可以无差别处理
- **动作**（`-a`，逗号分隔、可重复，默认 `info,behavior`）：
  - `info`　目标概览：进程信息、区域统计、类型分布、整体摘要
  - `maps`　内存区域列表（地址、权限、类型、宿主文件）
  - `strings`　字符串提取（ASCII 与 UTF-16LE）
  - `behavior`　程序行为分析（见下）
  - `carve`　从内存中恢复文件
  - `hash`　区域哈希（md5 / sha256）
  - `entropy`　区域熵（区分明文 / 压缩 / 加密数据）
  - `dump`　导出内存镜像为 raw dump（附 `.index` 区域索引）
  - `all`　以上除 `dump` 外的全部
- **收敛范围**：`-r` 只看某类区域（`image`/`heap`/`stack`/`mapped`/`anon`）或地址范围，
  `-s`/`-S` 按区域大小过滤，`-k` 按关键字过滤字符串与痕迹，`-L` 字符串最小长度，
  `-n` 每类结果的条数上限（`-X` 不限），`-V` 详细模式。
- **程序行为分析**（`-a behavior`）从内存字符串里还原程序在做什么，痕迹分四组：
  - 网络　`url` `ip` `domain` `email` `port`
  - 凭据　`password` `private_key` `aws_key` `jwt` `basic_auth` `shadow`
  - 主机　`path_unix` `path_win` `registry` `env` `command`
  - 取证　`injection`（注入 API）`cred_dump`（凭据窃取）`persist`（持久化）
    `anti_forensic`（反取证）`mining`（挖矿）`ransom`（勒索）
  
  每条痕迹带风险等级（无害/信息/可疑/高危），报告里高危优先展示，便于先看要害。
- **内存中恢复文件**（`-a carve -c <目录>`）：按魔数雕取 18 种格式
  （`png` `jpg` `gif` `pdf` `zip` `gzip` `bmp` `elf` `sqlite` `7z` `rar` `dex`
  `tiff` `wav` `pe` `class` `lnk`），`-t` 可只雕指定类型。文件名形如
  `0007_png_00000040.png`，序号对应报告行、偏移对应虚拟地址，便于回溯核对。
- **雕取的准确率**：先按魔数命中，再用头部长度字段（PNG/zip/PE/ELF/sqlite…）或尾标记
  （`IEND`/`%%EOF`/EOCD…）推导真实长度，并给出置信度；置信度过低的（等于「只能按固定窗口截断」）
  直接丢弃，避免噪声淹没报告。魔数过短的格式（`BM`/`RIFF`/`MZ`）另加格式自洽性校验。
- **在内存中操作目标程序**：不只扫描，还能**改写**目标内存，从而在运行期改变它的行为
  （改配置、改开关、改参数）。三个动作：
  ```bash
  gyhost mem -i 1234 -a patch -k production -Y staging          # 预览（默认不写）
  gyhost mem -i 1234 -a patch -k production -Y staging --apply  # 真正写入目标内存
  gyhost mem -i mem.bin -a write --addr heap+0x40 -Y '\x00\x01' --apply
  gyhost mem -i 1234 -a restore --backup 'mem-*.bak' --apply    # 一键回滚
  ```
  - `--addr` 支持 `0x1234`、十进制，或 **`区域名+偏移`**（如 `heap+0x40`）
  - `-Y` 支持 `\xNN` 字节序列、`@文件`，或普通 UTF-8 原文
  - `--max N` 限制单次改写次数，`--force` 才允许写无写权限的区域
- **写操作的安全设计**（避免手滑改坏目标）：
  1. **默认只预览**：不加 `--apply` 只计算不写，逐条给出 before/after
  2. **先备份再写**：每次 `--apply` 自动生成回滚记录，`-a restore` 可还原
  3. **不越权**：只写本来就读得到的内存，缺权限明确报错而不是硬来
  4. **默认不碰只读区域**：需要 `--force` 才写
  5. **`-a all` 不含写动作**：`write`/`patch`/`restore` 必须显式点名
- **在镜像上操作**：`-i <转储文件>` 同样可 `patch`/`restore`——先 `-d` 导出，
  在副本上试补丁，验证好了再决定是否对活体进程下手。转储文件是只读权限时会被明确拒绝。
- **输出**：结果走 stdout、逐区域进度走 stderr（`-q` 静默），`-j` 输出 JSON 便于接 `jq`，
  `-o` 写入文件。

**跨平台设计**：三个平台的内存管理模型完全不同，因此「怎么读内存」按平台分文件编译，
但**命令行参数与上层逻辑完全一致**，同一份报告在 Windows / Linux / macOS 上可直接对照阅读：

| 平台 | 进程列表 | 内存布局 | 内存内容 | 内存写入 | 子线程枚举 | 权限要求 |
| --- | --- | --- | --- | --- | --- | --- |
| Windows | `CreateToolhelp32Snapshot` | `VirtualQueryEx` | `ReadProcessMemory` | `WriteProcessMemory` | `TH32CS_SNAPTHREAD` | 管理员（SeDebugPrivilege） |
| Linux / Termux | `/proc/<pid>/*` | `/proc/<pid>/maps` | `/proc/<pid>/mem` | 同左（`O_RDWR`） | `/proc/<pid>/task/<tid>` | root（操作自己无需权限） |
| macOS | `proc_listallpids` | `mach_vm_region` | `mach_vm_read_overwrite` | `mach_vm_write` | `task_threads` | root 或同用户 + 开发者模式 |

写入权限拿不到时**自动退回只读**，只读取证路径不受影响；报告里会明确说明哪些命中被拒、为什么。

对应代码分布：

```
modules/mem/
├── os_linux.go    //go:build linux || android  → 选 os/linux
├── os_windows.go  //go:build windows            → 选 os/windows
├── os_darwin.go   //go:build darwin             → 选 os/darwin
├── os_other.go    其余平台                       → 选 os/unsupported（降级）
└── os/{linux,windows,darwin,unsupported}/        各平台实现，共用同一个内部契约
```

平台内部分析算法（字符串、熵、哈希、文件雕取、行为规则）全部与操作系统无关，放在
`internal/mem`，可被其它模块复用。未实现的平台会明确提示，但仍可用 `-i <转储文件>` 分析镜像。

### proc —— 进程分析（Linux / macOS）

分析**进程本身**：列表、父子树、命令行、环境变量、打开的文件、资源占用（分组：进程分析）。只读，不修改任何进程。

> 该模块只在 Linux（不含 Android/Termux）与 macOS 上编译，Windows 与 Termux 产物中
> 没有 `proc` 子命令。详见下方「平台覆盖与能力边界」。

```bash
gyhost proc                                          # 进程列表（按线程数排序）
gyhost proc -t rss -n 20                             # 按常驻内存排序看前 20
gyhost proc -k nginx -a detail                       # 叫 nginx 的进程详情
gyhost proc -i 1234 -a thread                        # 某进程的线程
gyhost proc -u root -a user                          # root 用户的进程统计
gyhost proc -P 1 -a tree                             # 以 pid 1 为根看进程树
gyhost proc --min-threads 50 -X                      # 只看线程数 ≥ 50 的进程
```

与 `mem` 的分工：**mem 看的是内存**（区域、字符串、熵、雕取、改写），**proc 看的是进程**（命令行、环境变量、打开的文件、父子关系、资源占用）。

- **动作**（`-a`，逗号分隔可重复，默认 `list`）：
  - `list`　进程列表：pid/ppid/状态/用户/线程/fd/常驻内存/虚拟内存/命令行
  - `tree`　父子关系树，按 PPID 分层（孤儿进程当根，父子环会被截断，不会死循环）
  - `user`　按用户聚合统计
  - `thread`　线程列表（需 `-i`）
  - `detail`　单进程详情（需 `-i`）：命令行、环境变量、打开的文件、加载的映像、内存映射摘要
  - `all`　`list` + `tree` + `user`（`thread`/`detail` 依赖 `-i`，不会被 `all` 顺带触发）
- **收敛范围**：`-k` 关键字、`-u` 用户、`-P` 父进程、`-t` 排序（`threads`/`pid`/`name`/`user`/`rss`/`vsize`/`fds`/`start`）、
  `--min-threads` 线程数下限、`--min-rss` 内存下限、`-K` 排除内核线程（默认开）、`-n` 条数、`-X` 不限、`-V` 完整命令行、`-j` JSON。
- **从 `/proc` 恢复文件**（`-r`，Linux 专有）：两段式——先扫出清单，再按编号/关键字指定恢复：
  ```bash
  gyhost proc -i 1234 -r                    # 扫描：列出候选清单（带编号）
  gyhost proc -i 1234 -r 1                  # 恢复第 1 项
  gyhost proc -i 1234 -r 1,3 -O ./evidence  # 恢复多项并指定输出目录
  gyhost proc -i 1234 -r all -O ./evidence  # 恢复全部可恢复项
  ```
  扫描范围是 `/proc/<pid>` 下的四个入口：
  - `exe`　正在执行的可执行文件
  - `cwd` / `root`　工作目录、根目录（只列出，目录不作为文件恢复）
  - `fd/<n>`　**打开的文件描述符——取证价值最高的一类**：文件即使已从磁盘删除，
    只要进程还持有 fd，inode 就还在，内容照样能通过 `/proc/<pid>/fd/<n>` 取回
  - `map_files/`　内存映射的文件（需 root；只保留已删除的，因为磁盘上还在的没恢复价值）

  已删除的条目**排在清单最前并带「已删除」标记**，一眼就能看到；不可恢复的条目也会
  留在清单里并注明原因（而不是悄悄消失），避免「没列出来 = 不存在」的误判。
  恢复出的文件保留**原始文件名**，便于与证据对照。
- **生效的过滤条件会在概览里回显**，避免「为什么少了进程」查不出来。
- 同分时按 PID 稳定排序，保证多次运行输出可逐行比对。

**平台覆盖与能力边界**：

| 平台 | 进程表 | 命令行 | 环境变量 | 打开的文件 | 内存映射 |
| --- | --- | --- | --- | --- | --- |
| Linux | `/proc` | ✅ 完整 | ✅ | ✅ 路径 + 数量 | ✅ |
| macOS | `libproc` | ✅ 完整 | ⚠️ 他人进程需 root | ⚠️ 数量（他人进程不给路径） | ⚠️ 仅主映像 |
| Windows / Termux | — | — | — | — | — |

> **Windows 与 Termux 的产物里没有 `proc` 子命令**（不是「有命令但报不支持」）：
> 包级构建约束是 `(linux && !android) || darwin`，这两个平台根本不编入该模块，
> 相应地也不会带上它约 9 KB 的中英文案。原因：Windows 的进程模型是 WMI/CIM，
> 与 procfs 无关；Android 7+ 起限制访问其它应用的 `/proc`，Termux 上根本拿不到
> 有用的进程表，`mem` 模块不受影响。
> 注意约束里必须显式写 `!android`——`GOOS=android` 会同时满足 `linux` 这个
> 构建标签，只写 `linux` 的话 Termux 构建仍会把本包编进去。

> macOS 没有完整 procfs，且受 SIP 与权限模型限制：他人进程的环境变量与 fd 路径取不到，
> 报告里会标注「不可用」而不是给一个空值让你误判成「没有」。这些数据需要 root。
> `-r` 从 `/proc` 恢复文件同理是 Linux 专有，macOS 上会明确提示不支持。

**跨平台设计**：与 `mem` 同一套路——参数与上层逻辑在所有平台一致，只有「怎么取进程数据」按平台分文件编译：

```
internal/proc/            进程数据模型 + 与 OS 无关的分析（匹配/排序/过滤/建树/按用户聚合）
internal/maclite/         macOS libSystem 的无 cgo 绑定（mem 与 proc 共用，避免重复写易错的汇编桩）
modules/proc/
├── os_linux.go    //go:build linux || android  → 选 os/linux
├── os_darwin.go   //go:build darwin             → 选 os/darwin
├── os_other.go    其余平台                       → 选 os/unsupported（明确降级）
└── os/{linux,darwin,unsupported}/              各平台实现，共用同一个 Backend 契约
```

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
表现为「--gpu 跑起来先卡住」）。交叉编译请显式指定，例如
`cmake -S . -B build -DGYHOST_GPU=ON -DGYHOST_CUDA_ARCH=86`。

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

> **构建系统已从 Makefile 迁移到 CMake**，仓库中不再有 `Makefile`。
> 如果你之前用 `make` 构建，现在改用下面的 CMake 命令；完整对照见
> [从 make 迁移](#从-make-迁移)。需要 CMake 3.24+。

依赖：

- Go 1.27+
- CMake 3.24+（构建入口）
- CUDA Toolkit（可选，用于 GPU 加速）

```bash
cmake -S . -B build && cmake --build build   # 自动：找到 nvcc 就启用 GPU(CUDA)
cmake -S . -B build -DGYHOST_GPU=OFF         # 强制纯 CPU，二进制可在任意机器运行
```

可用选项：

| 选项 | 默认 | 说明 |
| --- | --- | --- |
| `GYHOST_GPU` | `AUTO` | `AUTO` 自动探测 nvcc；`ON` 强制启用（缺 nvcc 直接报错）；`OFF` 纯 CPU |
| `GYHOST_CUDA_ARCH` | `native` | CUDA 目标架构，如 `native` / `86` / `80` |
| `GYHOST_BUILD_TESTS` | `ON` | 是否注册 CTest 测试 |

其它命令：

```bash
cmake --build build --target gyhost-help  # 本项目的完整用法说明
cmake -P cmake/GYhostHelp.cmake           # 同上，无需先 configure
cmake --build build --target gyhost-cpu  # 强制纯 CPU
cmake --build build --target cuda-lib    # 只编译 CUDA 静态库 libgyhost_cuda.a
```

> 查看帮助请用上面两条。`cmake help` 无效——CMake 会把 `help` 当成源码目录路径，
> 报 `The source directory ".../help" does not exist`；`cmake --help` 显示的是 CMake
> 自身的用法，不是本项目的。目标名也不能叫 `help`，那是 CMake 的保留名。

### 从 make 迁移

旧 Makefile 的每个目标都有 CMake 对应实现，行为一致：

| 旧命令 | 新命令 |
| --- | --- |
| `make` / `make build` / `make gpu` | `cmake -S . -B build && cmake --build build` |
| `make cpu` | `cmake -S . -B build -DGYHOST_GPU=OFF`，或 `--target gyhost-cpu` |
| `make cuda-lib` | `cmake --build build --target cuda-lib` |
| `make test` | `ctest --test-dir build`，或 `--target test` |
| `make test-gpu` | `ctest --test-dir build -R go-test-gpu`（需启用 CUDA） |
| `make vet` | `cmake --build build --target vet` |
| `make fmt` | `cmake --build build --target fmt` |
| `make clean` | `./clean.sh` |
| `make help` | `cmake -P cmake/GYhostHelp.cmake` |
| `make -C internal/cuda ARCH=sm_86` | `cmake -S . -B build -DGYHOST_CUDA_ARCH=86` |

多平台交叉编译仍用 `./build.sh`（内部也已全部改为调用 CMake）。

> 迁移背景与遇到的 CMake 陷阱见 [`LOG.md`](LOG.md) 的 `[0.1.3]`
> 「变更 → 构建系统从 Makefile 迁移到 CMake」。

### 清理

一条命令清光所有 CMake 与 `go build` 产物，只留源码和构建脚本：

```bash
./clean.sh          # 构建产物 + CMake 缓存（保留 dist/ 发布产物）
./clean.sh --all    # 连 dist/、build-dist/、build-cuda/ 一并清
./clean.sh --dist   # 只清发布产物与交叉编译目录
```

清理范围：构建目录（`build/`、`build-*/`）、`go build` 产物、CUDA 静态库与中间文件、CMake 缓存
（`CMakeCache.txt`、`CMakeFiles/`、`cmake_install.cmake`、`CTestTestfile.cmake`）、
in-source 配置残留、构建日志。也可从 CMake 调用：`cmake --build build --target gyhost-distclean`。

只想局部清理时：

| 命令 | 清理范围 |
| --- | --- |
| `cmake --build build --target gyhost-clean` | `go build` 产物（构建目录内的二进制） |
| `cmake --build build --target clean` | 仅 CMake 自身的中间文件，**不删** go build 的二进制 |
| `rm -rf build && cmake -S . -B build` | 整个构建目录（含 `CMakeCache.txt`），彻底重来 |
| `cmake -S . -B build --fresh` | 重置缓存但保留目录 |
| `./build.sh clean` | `dist/`、`build-dist/`、`build-cuda/`、构建日志、CUDA 静态库 |

> 生成器的 `clean` 删不掉本项目的二进制：产物出自 `add_custom_target` + `go build`，
> 不像 `add_executable` 那样自动登记输出。要删二进制得用 `gyhost-clean` 或 `clean.sh`。
> 同理，`clean` 与 `help` 都是 CMake 保留目标名，不能直接用作 `add_custom_target` 的名字。

CUDA 静态库落在 `internal/cuda/`（cgo 按源码目录做 `-L` 链接，不能放构建目录），需单独删：

```bash
rm -f internal/cuda/libgyhost_cuda.a   # clean.sh 与 build.sh clean 都已包含
```

> **关于 `Makefile`**：构建系统已从手写 Makefile 迁移到 CMake，仓库里不再有 Makefile。
> 但若有人误做 in-source 配置（`cmake .` 不带 `-B`），CMake 会在根目录和 `internal/cuda/`
> 生成同名 `Makefile`（首行是 `CMAKE generated file: DO NOT EDIT!`），看起来像没删干净的源码。
> `clean.sh` 按首行判定只删这种生成物；`.gitignore` 也已按路径忽略这两个文件。

也可以直接用 go 命令：

```bash
go build -o gyhost .             # 纯 CPU
go build -tags cuda -o gyhost .  # 带 GPU（需先 cmake --build build --target cuda-lib）
```

> 多平台交叉编译（Windows / Linux / macOS / Termux 发布产物）仍用 `build.sh`，
> 它按 `GOOS/GOARCH` 出包，不走 CMake。

## 使用

```bash
./gyhost                 # 启动横幅 + 帮助
./gyhost help            # 查看帮助
./gyhost help shadow     # 查看模块帮助
./gyhost help hashdump
./gyhost help hashcat
./gyhost help hashac
./gyhost help net
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

# net：离线分析 pcap/cap 抓包（报告走 stdout、提示走 stderr）
./gyhost net -i capture.pcap                       # 协议 / 会话 / DNS / TLS / HTTP / 安全发现
./gyhost net -i capture.pcap --top 20              # 各表只显示前 20 条
./gyhost net -i capture.pcap -m all                # 附带攻击分析（洪泛 / CC / 丢包 / 分片）
./gyhost net -i capture.pcap -m syn,cc             # 只跑 SYN 洪泛与 CC 攻击两个模型
./gyhost net -i capture.pcap -f "host 10.0.0.5"    # 只统计该主机
./gyhost net -i capture.pcap -l -f "tcp and 443"    # 逐包列出（纯数字等价 port 443）
./gyhost net -i capture.pcap -l -n 100             # 只列前 100 个包
./gyhost net -i capture.pcap -V -n 5              # 逐包详细视图（tshark -V 风格协议树）
./gyhost net -i capture.pcap -V -m all -n 3       # 详细视图 + 末尾的攻击分析结论
./gyhost net -i capture.pcap -T                   # 交互式抓包浏览器（全屏三栏）
./gyhost net -i capture.pcap -T -f "tcp and 443"  # 交互式 + 预设过滤
./gyhost net -i ./captures -o report.txt           # 批量分析目录并写入文件

# mem：内存取证（结果走 stdout、提示走 stderr）
./gyhost mem -l                                     # 列出全部程序与它们的子线程
./gyhost mem -l nginx                               # 只看某个程序的子线程
./gyhost mem -e nginx                               # 按程序名分析内存
./gyhost mem -i 1234 -a info,maps                    # 某进程的内存布局
./gyhost mem -i 1234 -a behavior -s 1048576          # 行为分析（跳过 1MB 以下区域）
./gyhost mem -i 1234 -a carve -c ./carved -t png,zip # 从内存里恢复 png/zip
./gyhost mem -i 1234 -a dump -d target.memdump       # 导出内存镜像留证
./gyhost mem -i 1234 -a patch -k production -Y staging          # 预览内存改写
./gyhost mem -i 1234 -a patch -k production -Y staging --apply  # 真正改写目标内存
./gyhost mem -i mem.bin -a restore --backup 'mem-*.bak' --apply # 回滚内存改写
./gyhost mem -i memdump.raw -a all -o report.txt     # 离线分析转储并写文件
./gyhost mem -i memdump.raw -a strings -k password   # 只看含 password 的串
```

全局参数：`--help`、`--version`、`--no-banner`、`--no-color`。

## 项目结构

```
GYhost/
├── main.go          # 入口：注册模块并交给 CLI 分发
├── CMakeLists.txt    # 构建/测试入口（驱动 go build）
├── cmake/           # GYhostHelp.cmake：项目用法说明（--target gyhost-help / -P 脚本）
├── internal/        # 核心框架（与具体模块无关）
│   ├── cli/         # CLI 根命令与横幅
│   ├── module/      # 模块契约与注册表
│   ├── cuda/        # CUDA GPU 加速
│   ├── pcap/        # pcap/pcapng 容器读取（net 与 hashdump 的无线抓包共用）
│   ├── mem/         # 内存分析内核（区域/字符串/熵/雕取/行为规则/补丁，跨平台）
│   ├── proc/        # 进程分析内核（进程模型/匹配/排序/过滤/进程树/文件恢复，跨平台）
│   ├── cliflag/     # 「值可省略」的 flag 参数支持（mem -l / proc -r 共用）
│   ├── maclite/     # macOS libSystem 无 cgo 绑定（mem 与 proc 共用）
│   ├── pwdhash/     # 密码哈希解析/校验
│   ├── platformmods/ # 平台受限模块的注册（proc.go / proc_off.go 按构建标签二选一）
│   ├── i18n/        # 国际化
│   └── utils/       # 输出配色等工具
└── modules/         # 功能模块
    ├── shadow/      # 本地分析：shadow 爆破
    ├── hashdump/    # 本地分析：加密文件哈希提取
    ├── hashcat/     # 本地分析：算法识别与模式号
    ├── hashac/      # 本地分析：常见哈希明文碰撞
    ├── net/         # 网络分析：pcap/cap 离线流量分析与 -m 攻击分析
    ├── mem/         # 内存取证：内存分析 / 行为分析 / 内存中恢复文件
    │   └── os/      # 各平台内存访问实现（编译时只编目标系统）
    └── proc/        # 进程分析：进程列表 / 父子树 / 详情 / 线程
        └── os/      # 各平台进程采集实现（Linux / macOS / 降级）
```

## 扩展新模块

核心框架与具体功能解耦，新增能力只需两步：

1. 在 `modules/<name>/` 下实现 `module.Module` 接口（`Name` / `Summary` / `Group` / `Usage` / `Run`）。
2. 在 `main.go` 中加一行注册：

```go
registry.MustRegister(<name>.New())
```

若该模块只在部分平台存在（如 `proc` 仅 Linux/macOS），不能直接在 `main.go` 里 import——
Go 不支持对导入做条件编译，Windows / Termux 会报 `build constraints exclude all Go files`。
这种模块要放进 `internal/platformmods/`，由 `proc.go`（有该模块的平台）与 `proc_off.go`（空实现）
按构建标签二选一，`main.go` 统一调 `platformmods.Register(registry)`。

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
ctest --test-dir build                # 单元测试（CUDA 配置下会自动多跑一份 -tags cuda）
cmake --build build --target test     # 同上
cmake --build build --target vet      # 静态检查（CPU/CUDA 两种构建形态）
cmake --build build --target fmt      # 列出未 gofmt 的文件（应为空）
```

## 许可证

本项目基于 [Apache License 2.0](LICENSE) 开源。

## 免责声明

本工具仅供**授权范围内的安全测试与研究**使用。请勿用于任何未授权的用途。
 
