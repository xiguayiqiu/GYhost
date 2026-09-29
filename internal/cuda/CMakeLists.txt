cmake_minimum_required(VERSION 3.24)

# ---------------------------------------------------------------------------
# internal/cuda/CMakeLists.txt —— 编译 GYhost 公共 CUDA 静态库
#
# 产出 libgyhost_cuda.a，供 `go build -tags cuda` 通过 cgo 链接。
# 生成后无需额外步骤，根目录的 gyhost 目标会自动依赖这里。
#
# 架构默认 native：直接生成与本机 GPU 匹配的 cubin。
# 不指定时 nvcc 只嵌入 PTX，驱动必须在首次启动内核时现场 JIT 整个模块
# （本机实测接近一分钟，表现为「--gpu 跑起来先卡住」），对爆破工具很致命。
# 交叉编译请显式指定，例如 cmake -DGYHOST_CUDA_ARCH=sm_86。
# ---------------------------------------------------------------------------

project(gyhost_cuda LANGUAGES CUDA)

# 与 internal/cuda/cuda_cgo.go 里的 -O2 -Xcompiler -fPIC -lineinfo 保持一致
set(GYHOST_CUDA_FLAGS "-lineinfo" CACHE STRING "追加传给 nvcc 的额外参数")
set(GYHOST_CUDA_ARCH "native" CACHE STRING "目标架构，如 native / 86 / 86-real / 80")

add_library(gyhost_cuda STATIC cuda.cu)

set_target_properties(gyhost_cuda PROPERTIES
  OUTPUT_NAME gyhost_cuda
  # cgo 侧是 -L${SRCDIR} -lgyhost_cuda，SRCDIR 即本源码目录。
  # 静态库必须落在这里；放到构建目录（CMake 默认）会导致链接时找不到。
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  CUDA_ARCHITECTURES "${GYHOST_CUDA_ARCH}"
  POSITION_INDEPENDENT_CODE ON
)

target_compile_options(gyhost_cuda PRIVATE
  $<$<COMPILE_LANGUAGE:CUDA>:${GYHOST_CUDA_FLAGS}>
)

# 供根目录拼接依赖：名字存在才 add_dependencies，避免 CPU 构建报错。
set(_gyhost_gpu_deps gyhost_cuda PARENT_SCOPE)

message(STATUS "  CUDA 架构   : ${GYHOST_CUDA_ARCH}")
message(STATUS "  静态库      : ${CMAKE_CURRENT_SOURCE_DIR}/libgyhost_cuda.a")