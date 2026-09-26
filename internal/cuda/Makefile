# internal/cuda/Makefile — 编译 GYhost 公共 CUDA 静态库
#
# 用法:
#   make            生成 libgyhost_cuda.a
#   make ARCH=sm_86 指定目标架构（不指定则由 nvcc 选择默认架构并附带 PTX）
#   make clean      清理中间产物
#
# 生成后即可: go build -tags cuda

NVCC      ?= nvcc
AR        ?= ar
TARGET    := libgyhost_cuda.a
NVCCFLAGS ?= -O2 -Xcompiler -fPIC -lineinfo

ifneq ($(strip $(ARCH)),)
NVCCFLAGS += -arch=$(ARCH)
endif
NVCCFLAGS += $(EXTRA_NVCCFLAGS)

.PHONY: all clean

all: $(TARGET)

cuda.o: cuda.cu cuda.h
	$(NVCC) $(NVCCFLAGS) -c cuda.cu -o $@

$(TARGET): cuda.o
	$(AR) rcs $@ $^

clean:
	rm -f cuda.o $(TARGET)
