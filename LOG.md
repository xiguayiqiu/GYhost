# 更新日志

本文件记录 GYhost 每个版本的变化。只列用户可感知的变化与影响使用/构建的决策，
实现细节请看代码与提交历史。版本号见 `internal/cli/root.go` 的 `const Version`。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

---

## [0.1.3] — 2026-09-29

本版本新增三个方向：**网络抓包分析（`net`）**、**内存取证（`mem`）**、**进程分析（`proc`）**，
并把原来散在各模块里的公共能力下沉到 `internal/`。

### 新增

- **`net` —— 离线分析 pcap/cap 抓包**：协议/会话统计、DNS、TLS、HTTP 解析与明文安全发现。
- **`mem` —— 内存取证**：分析活体进程或内存转储，跨平台支持扫描、字符串、熵、哈希、文件雕取、
  行为分析；提供 `write`/`patch`/`restore` 内存操作（默认预览，写入前自动备份，可回滚）。
- **`proc` —— 进程分析（Linux / macOS）**：进程列表、父子树、命令行、环境变量、打开的文件、资源占用，
  支持过滤/排序、JSON 输出。
- **`proc -r` 从 `/proc` 恢复文件（Linux 专有）**：两段式恢复——先扫出带编号的候选清单，
  再按编号/关键字/`all` 指定恢复，并可用 `-O/--outdir` 指定输出目录。扫描覆盖
  `exe`、`fd`、`cwd`/`root`、`map_files`；重点是「已从磁盘删除但仍被进程持有」的文件。
- 新增内部库以复用跨模块能力：`internal/mem`、`internal/proc`、`internal/pcap`、
  `internal/cliflag`（值可省略的 flag，供 `mem -l` / `proc -r` 共用）、`internal/maclite`
  （macOS libSystem 的无 cgo 绑定，供 `mem` 与 `proc` 共用）。

### 变更

- **构建系统从 Makefile 迁移到 CMake**（原 `Makefile` 与 `internal/cuda/Makefile` 已删除）：
  - 入口 `cmake -S . -B build && cmake --build build`；版本号仍从 `internal/cli/root.go` 提取，
    与 `build.sh` 共用同一来源，不会漂移。
  - 开关 `GYHOST_GPU`（`AUTO`/`ON`/`OFF`）、`GYHOST_CUDA_ARCH`、`GYHOST_BUILD_TESTS`。
  - 目标：`gyhost`、`gyhost-cpu`、`cuda-lib`、`vet`、`fmt`、`test`。
  - 单元测试接入 CTest：`ctest --test-dir build`；启用 CUDA 时自动多注册一份 `-tags cuda`。
  - `build.sh`（多平台交叉编译）已完全改为调用 CMake：每个目标走
    `cmake -S . -B build-dist/<goos>-<goarch> -DGYHOST_TARGET_OS=... -DGYHOST_TARGET_ARCH=...
    -DGYHOST_OUTPUT=... -DGYHOST_TRIMPATH=ON` 再 `cmake --build --target release`，
    脚本不再直接调用 `go build`——「交叉编译用什么参数」只在 CMakeLists.txt 里定义一处。
    GPU 目标复用 `build-cuda/` 以避免重复编译 `cuda.cu`。
  - 迁移中修掉两个 CMake 陷阱：`option()` 只能存 BOOL，三态值需用 `CACHE STRING`，
    否则 `AUTO` 会被落成 `OFF`、明明装了 nvcc 却静默走 CPU 分支；CUDA 静态库必须落在
    `internal/cuda/`（cgo 的 `-L${SRCDIR}` 要求），已用 `ARCHIVE_OUTPUT_DIRECTORY` 指定。
  - 手写 `Makefile` 与 `internal/cuda/Makefile` 已全部删除，仓库里不再有 Makefile。
    其 11 个目标（`all`/`build`/`gpu`/`cpu`/`cuda-lib`/`test`/`test-gpu`/`vet`/`fmt`/`clean`/`help`）
    均有 CMake 对应实现，无任何脚本调用 `make`；`ARCH=sm_86` → `-DGYHOST_CUDA_ARCH=86`，
    `EXTRA_NVCCFLAGS` → `-DGYHOST_CUDA_FLAGS`。`internal/cuda` 两个 Go 文件里
    指向 `make -C internal/cuda` 的注释同步改为 CMake 命令。
    注意 in-source 配置（`cmake .` 不带 `-B`）会在同名路径生成 Makefile，看起来像没删干净，
    `.gitignore` 已按完整路径忽略，`clean.sh` 按首行判定只清这种生成物。
  - 新增 `clean.sh`：一条命令清光所有 CMake 与 `go build` 产物（构建目录、CUDA 静态库、
    CMake 缓存、in-source 残留、日志），`--all` 连 `dist/` 发布产物一并清。
    也可从 CMake 调用 `--target gyhost-distclean`。
  - 新增 `cmake/GYhostHelp.cmake` 与 `--target gyhost-help`，输出本项目自己的用法说明
    （构建目标、`-D` 选项、交叉编译示例、清理方式）；`cmake -P cmake/GYhostHelp.cmake`
    可在 configure 之前查看。
  - 修掉生成器的 `clean` 删不掉本项目二进制的问题：本工程产物出自 `add_custom_target` +
    `go build`，不像 `add_executable` 自动登记输出，故补 `--target gyhost-clean` 显式删除
    （实测加 `BYPRODUCTS` 无效，Makefile 与 Ninja 两种生成器的 clean 都不删自定义目标的 byproduct）。
- **`proc` 模块只在 Linux（不含 Android/Termux）与 macOS 上编译**：Windows 走 WMI/CIM、
  Termux 的 `/proc` 受限，这两个平台的产物里没有 `proc` 子命令（不是「有命令但报不支持」），
  也不带上它约 9 KB 的中英文案。原因见下「修复」。
- 平台相关的模块注册从 `main.go` 拆到 `internal/platformmods/`（`proc.go` / `proc_off.go`
  按构建标签二选一），以便不同平台注册不同模块。放子包而不是留在根目录的
  `package main`，是为了让 `main.go` 只剩一次普通导入调用，平台分支集中在自己的包里。
- `internal/i18n` 中 `proc.*` 文案拆到带构建标签的 `proc.go` / `proc_off.go`，
  无该模块的平台不编译这些文案。
- README 大幅扩充：补齐 `net`/`mem`/`proc` 三个方向的用法、平台能力边界与目录结构说明。
- `build.sh` 注释补充 Termux/Windows 产物不含 `proc` 的说明。

### 修复

- **`proc` 的构建约束必须显式写 `!android`**：`GOOS=android` 会同时满足 `linux` 标签，
  只写 `linux` 会让 Termux 构建误把 `proc` 编进去。
- 修正 `proc` 在 Windows 构建下会因找不到包而失败的问题（模块注册改为按平台分文件）。
- `proc` 恢复清单表头缺少 `proc.col.path` 文案定义，会直接显示成键名 `"proc.col.path"`。
- 英文文案表里 `proc.col.size` 被误填为中文「大小」。
- 恢复扫描的统计行误用「进程总数」作标签，改为「扫描结果」（该行是文件候选统计，不是进程数）。

### 新增测试

- `modules/proc/i18n_keys_test.go`：校验「源码引用的每个 `proc.*` 键在中文/英文表中都有定义」，
  且英文文案不混入中文——防止上面那类不会编译报错、只在界面静默出错的问题再次发生。

### 已知限制

- `proc` 的 macOS 行为仅做了交叉编译与 vet 验证，尚未在真实 macOS 硬件上跑通。
- Linux `map_files` 恢复需要 `CAP_SYS_ADMIN`/root，未对真实已删除映射实测。
- 跨进程 `mem` 写入仅在 `self` 与可写 dump 文件上验证过；受环境 ptrace 策略限制，未对其它进程写入。
- 恢复出的文件重名时可能相互覆盖（碰撞映射尚未传递到后端 `Recover`）。
- `-r` 的关键字匹配为子串匹配，尚不是文档中示例那样的 glob 语义。

### 构建

- 构建入口已换成 CMake，**不再提供 Makefile**。最小命令：

  ```bash
  cmake -S . -B build && cmake --build build   # 自动探测 nvcc，装了就带 GPU
  cmake -S . -B build -DGYHOST_GPU=OFF         # 强制纯 CPU
  ```

  完整用法见 `cmake -P cmake/GYhostHelp.cmake` 或 `--target gyhost-help`。
- 交叉编译目标不变：Windows(amd64/arm64)、Linux(amd64/arm64)、macOS(amd64/arm64)、Termux(android/arm64)，
  用 `./build.sh`（内部已全部改为调用 CMake）。

---

## [0.1.2]

- 上一版本（提交 `d74adc9`）。具体变化未单独记录。

## [0.1.1]

- 上一版本（提交 `bffe1a8`）。具体变化未单独记录。

[0.1.3]: https://github.com/xiguayiqiu/GYhost/releases/tag/v0.1.3
[0.1.2]: https://github.com/xiguayiqiu/GYhost/releases/tag/v0.1.2
[0.1.1]: https://github.com/xiguayiqiu/GYhost/releases/tag/v0.1.1
