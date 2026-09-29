# ---------------------------------------------------------------------------
# GYhostHelp.cmake —— 打印本项目的 CMake 用法说明
#
# 两处调用，文本只此一份：
#   1. `cmake --build <dir> --target gyhost-help`  （由根 CMakeLists.txt 注册）
#   2. `cmake -P cmake/GYhostHelp.cmake`          （无需先 configure，任何时候可用）
#
# 不用 `add_custom_target(help)`：CMake 把 "help" 列为保留目标名，那样写会直接
# configure 失败（The target name "help" is reserved ...）。故目标名用 gyhost-help，
# 与生成器自带的 `help` 目标（列出 all/clean/test 等构建目标）共存而不冲突。
#
# 注意 `cmake help` 不是有效命令：CMake 会把 help 当成 <path-to-source>，
# 报 "The source directory ".../help" does not exist"。本项目的帮助请用上面两种方式。
# ---------------------------------------------------------------------------

# 用法
message(STATUS "")
message(STATUS "  GYhost —— CMake 构建入口")
message(STATUS "")
message(STATUS "  本工程是纯 Go 项目，CMake 不编译 Go 代码，只负责编排：")
message(STATUS "  探测 nvcc 决定是否编 internal/cuda 的 CUDA 静态库，再调用")
message(STATUS "  go build / go test / go vet / gofmt。")
message(STATUS "")

# 快速上手
message(STATUS "  【快速上手】")
message(STATUS "    cmake -S . -B build && cmake --build build    # 自动探测 nvcc，装了就带 GPU")
message(STATUS "    cmake -S . -B build -DGYHOST_GPU=OFF          # 强制纯 CPU，产物可在任意机器运行")
message(STATUS "    cmake --build build --target gyhost-help     # 显示本帮助")
message(STATUS "")

# 构建目标
message(STATUS "  【构建目标】用 cmake --build <构建目录> --target <名字>")
message(STATUS "    gyhost        出主二进制（默认目标，= all）")
message(STATUS "    release       同上，build.sh 使用的入口")
message(STATUS "    gyhost-cpu    强制纯 CPU（CGO_ENABLED=0），不依赖 GPU 目标")
message(STATUS "    cuda-lib      只编 internal/cuda/libgyhost_cuda.a，不出二进制")
message(STATUS "    test          单元测试（等价于 go test ./...）")
message(STATUS "    vet           go vet（CPU 与 cuda 两种构建形态都查）")
message(STATUS "    fmt           gofmt -l，应无输出")
message(STATUS "    gyhost-clean  删除 go build 产物（构建目录内的二进制）")
message(STATUS "    clean         只清 CMake 自己的中间文件，不删 go build 的二进制")
message(STATUS "")
message(STATUS "    查看生成器自带的全部目标：cmake --build <构建目录> --target help")
message(STATUS "")

# 清理
message(STATUS "  【清理】三种粒度，按需要选")
message(STATUS "    1) 只删二进制（最快，下次构建会重跑 go build）")
message(STATUS "       cmake --build build --target gyhost-clean")
message(STATUS "")
message(STATUS "    2) 删 CMake 中间文件 + 二进制")
message(STATUS "       cmake --build build --target clean")
message(STATUS "       cmake --build build --target gyhost-clean")
message(STATUS "")
message(STATUS "    3) 彻底重来：整个删掉构建目录（含 CMakeCache.txt）后重新 configure")
message(STATUS "       rm -rf build && cmake -S . -B build")
message(STATUS "       只想重置缓存而保留目录：cmake -S . -B build --fresh")
message(STATUS "")
message(STATUS "    发布产物与交叉编译目录：./build.sh clean")
message(STATUS "    （清 dist/、build-dist/、build-cuda/、构建日志、CUDA 静态库）")
message(STATUS "")
message(STATUS "  【彻底清理】推荐用脚本，一条命令清光所有 CMake 与 go build 产物：")
message(STATUS "    ./clean.sh          # 构建产物 + CMake 缓存（保留 dist/）")
message(STATUS "    ./clean.sh --all    # 连 dist/ 发布产物、build-dist/ 一并清")
message(STATUS "    ./clean.sh --dist   # 只清发布产物与交叉编译目录")
message(STATUS "")
message(STATUS "    注意：CUDA 静态库落在 internal/cuda/（cgo 按源码目录做 -L 链接，")
message(STATUS "    不能放构建目录），需单独删：")
message(STATUS "      rm -f internal/cuda/libgyhost_cuda.a")
message(STATUS "")
message(STATUS "    两个 clean 目标名都不能用裸名：`clean` 与 `help` 都是 CMake 保留名，")
message(STATUS "    add_custom_target(clean ...) 会直接 configure 失败。")
message(STATUS "")

# 配置选项
message(STATUS "  【配置选项】用 -D 传入，格式 -D<变量>=<值>")
message(STATUS "    GYHOST_GPU            默认 AUTO。GPU 开关，三态：")
message(STATUS "                           AUTO  自动探测 nvcc，找到就启用")
message(STATUS "                           ON    强制启用，缺 nvcc 直接报错")
message(STATUS "                           OFF   纯 CPU")
message(STATUS "                           （三态而非 option()：option() 只能存 BOOL，")
message(STATUS "                             会把 \"AUTO\" 落成 OFF，装了 CUDA 也静默走 CPU）")
message(STATUS "    GYHOST_CUDA_ARCH      默认 native。目标架构，如 native / 86 / 80")
message(STATUS "                           默认 native 是刻意的：不指定时 nvcc 只嵌 PTX，")
message(STATUS "                           驱动首次启动内核要现场 JIT（实测近一分钟）")
message(STATUS "    GYHOST_BUILD_TESTS    默认 ON。是否注册 CTest 测试")
message(STATUS "    GYHOST_TARGET_OS      默认空。交叉编译目标 GOOS，留空为本机")
message(STATUS "    GYHOST_TARGET_ARCH    默认空。交叉编译目标 GOARCH，留空为本机")
message(STATUS "    GYHOST_OUTPUT         默认空。go build -o 的输出路径")
message(STATUS "    GYHOST_TRIMPATH       默认 OFF。go build -trimpath，发布产物去掉本机路径")
message(STATUS "")

# 交叉编译
message(STATUS "  【交叉编译】单目标，产出发布用的 .exe 等")
message(STATUS "    cmake -S . -B build-x \\")
message(STATUS "          -DGYHOST_TARGET_OS=windows -DGYHOST_TARGET_ARCH=amd64 \\")
message(STATUS "          -DGYHOST_OUTPUT=dist/gyhost.exe -DGYHOST_TRIMPATH=ON \\")
message(STATUS "          -DGYHOST_BUILD_TESTS=OFF")
message(STATUS "    cmake --build build-x --target release")
message(STATUS "")
message(STATUS "    多平台出包直接用脚本（内部也是调 CMake）：")
message(STATUS "      ./build.sh              # 全部目标")
message(STATUS "      ./build.sh nogpu        # 只出无 GPU 版（可全平台交叉编译）")
message(STATUS "      ./build.sh gpu          # 只出带 GPU 版（仅本机 OS/ARCH）")
message(STATUS "      ./build.sh nogpu arm64  # 按架构过滤")
message(STATUS "      ./build.sh --help       # 脚本说明")
message(STATUS "")

# 测试
message(STATUS "  【测试】")
message(STATUS "    ctest --test-dir build                  # 跑全部已注册测试")
message(STATUS "    ctest --test-dir build -N               # 只列出测试名")
message(STATUS "    ctest --test-dir build --output-on-failure")
message(STATUS "    已注册：go-test（CGO_ENABLED=0），装了 nvcc 时另有 go-test-gpu")
message(STATUS "")

# 注意
message(STATUS "  【注意】")
message(STATUS "    * cmake help 无效：CMake 会把 help 当成源码目录路径。")
message(STATUS "      cmake --help 显示的是 CMake 自身用法，不是本项目。")
message(STATUS "    * 多平台产物名与构建流程见 ./build.sh --help。")
message(STATUS "")
