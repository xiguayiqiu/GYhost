# GYhost 根 Makefile — 常用构建/测试入口
#
# 用法:
#   make            默认构建：检测到 nvcc 就自动编译 CUDA 静态库并带上 -tags cuda（GPU 加速），
#                   没有 nvcc 则回退为纯 CPU 构建，不会失败
#   make cpu        强制纯 CPU 构建（不依赖 CUDA，二进制可在任意机器上运行）
#   make gpu        = make（兼容旧命令）
#   make cuda-lib   只编译 internal/cuda 的静态库 libgyhost_cuda.a
#   make test       单元测试（默认构建）
#   make test-gpu   单元测试（-tags cuda，需要先有 libgyhost_cuda.a；无 GPU 时自动跳过用例）
#   make vet        go vet（两种构建形态都检查）
#   make fmt        列出未 gofmt 的文件（应为空）
#   make clean      清理产物
#
# 直接用 go 命令也可以:
#   go build -o gyhost .             # 纯 CPU
#   go build -tags cuda -o gyhost .  # 带 GPU（先 make -C internal/cuda）

BIN      := gyhost
CUDA_DIR := internal/cuda

.PHONY: all build gpu cpu cuda-lib test test-gpu vet fmt clean help

all: build

## build: 默认构建 —— 有 nvcc 就启用 GPU (CUDA)，否则回退纯 CPU
build:
	@if command -v nvcc >/dev/null 2>&1; then \
		echo "[*] 检测到 nvcc，启用 GPU (CUDA) 加速构建"; \
		$(MAKE) -C $(CUDA_DIR) && go build -tags cuda -o $(BIN) . ; \
	else \
		echo "[!] 未找到 nvcc，回退为纯 CPU 构建（安装 CUDA Toolkit 后再 make 即可启用 GPU）"; \
		go build -o $(BIN) . ; \
	fi

## gpu: build 的别名（兼容旧命令）
gpu: build

## cpu: 纯 CPU 构建，二进制不依赖 CUDA，可在任意机器上运行
cpu:
	go build -o $(BIN) .

## cuda-lib: 编译 internal/cuda 的 CUDA 静态库 libgyhost_cuda.a
cuda-lib:
	$(MAKE) -C $(CUDA_DIR)

## test: 单元测试（默认构建）
test:
	go test ./...

## test-gpu: 单元测试（CUDA 构建，验证 GPU 路径）
test-gpu:
	go test -tags cuda ./...

## vet: 静态检查（两种构建形态）
vet:
	go vet ./...
	go vet -tags cuda ./...

## fmt: 列出未 gofmt 的文件（应为空）
fmt:
	gofmt -l .

clean:
	rm -f $(BIN)
	$(MAKE) -C $(CUDA_DIR) clean

help:
	@grep -E '^## ' Makefile | sed 's/^## //'
