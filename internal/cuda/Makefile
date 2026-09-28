# internal/cuda/Makefile — 编译 GYhost 公共 CUDA 静态库
#
# 用法:
#   make            生成 libgyhost_cuda.a
#   make ARCH=sm_86 指定目标架构（交叉编译时用）
#   make clean      清理中间产物
#
# 生成后即可: go build -tags cuda
#
# 架构默认值是 native：直接生成与本机 GPU 匹配的 cubin。
# 不给 -arch 时 nvcc 只嵌入 PTX，驱动必须在首次启动内核时现场 JIT 整个模块
#（本机实测接近一分钟，表现为「--gpu 跑起来先卡住」），对爆破工具来说很致命。
# 交叉编译请显式指定，例如 make ARCH=sm_86。

NVCC      ?= nvcc
AR        ?= ar
TARGET    := libgyhost_cuda.a
NVCCFLAGS ?= -O2 -Xcompiler -fPIC -lineinfo

ARCH ?= native
NVCCFLAGS += -arch=$(ARCH)
NVCCFLAGS += $(EXTRA_NVCCFLAGS)

.PHONY: all clean

all: $(TARGET)

cuda.o: cuda.cu cuda.h
	$(NVCC) $(NVCCFLAGS) -c cuda.cu -o $@

$(TARGET): cuda.o
	$(AR) rcs $@ $^

clean:
	rm -f cuda.o $(TARGET)
