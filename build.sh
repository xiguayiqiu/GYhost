#!/usr/bin/env bash
#
# GYhost 多平台构建脚本 —— 与 CMakeLists.txt 配套的一键发布构建
#
# 用法:
#   ./build.sh                  # 构建全部可构建目标（无 GPU 全平台 + 本机可编的 GPU）
#   ./build.sh nogpu            # 只构建无 GPU 版本
#   ./build.sh gpu              # 只构建带 GPU 版本
#   ./build.sh clean            # 清理 dist/、CMake 构建目录与 CUDA 中间产物
#
# 实现说明: 每个目标都走 CMake（见 CMakeLists.txt）配置+构建，脚本只决定编哪些。
#   * 无 GPU 目标: 每目标一个 build-dist/<goos>-<goarch>/ 目录
#   * GPU 目标   : 复用 build-cuda/，避免重复编译 cuda.cu
#   * 构建日志   : build-dist/<目标>.log 与 build-cuda.log，失败时查看
#
# 可选架构过滤（第 2 个参数，按产物标签匹配）:
#   ./build.sh nogpu amd64      # 仅 windows/linux/macos 的 amd64
#   ./build.sh nogpu arm64      # 仅 windows/linux/macos 的 arm64
#   ./build.sh nogpu aarch64    # 仅 Termux (android/arm64)
#   ./build.sh nogpu linux      # 仅 linux 平台
#
# 产物: dist/gyhost-v<版本>-<平台>-<架构>[-gpu][.exe]
#
# 平台与架构覆盖:
#   无 GPU : Windows(amd64/arm64)、Linux(amd64/arm64)、macOS(amd64/arm64)、Termux(aarch64)
#   带 GPU : Windows(amd64)、Linux(amd64/arm64)
#
# 说明:
#   * 无 GPU 版本是纯 Go 静态构建（CGO_ENABLED=0），可任意交叉编译，运行不依赖 CUDA。
#   * 带 GPU 版本依赖 nvcc 与 CUDA 静态库 libgyhost_cuda.a，二者都绑定平台，
#     因此只能在“与本机 OS/ARCH 一致”的目标上构建：无法从 Linux 交叉编译出
#     Windows 或 arm64 的 CUDA 版本（脚本会跳过并给出提示）。
#     要出这些产物，请在对应平台（Windows 需装 CUDA Toolkit + MinGW/MSYS2）上运行本脚本。
#   * Termux 目标为 android/arm64，纯 Go 静态二进制可直接在 Termux 中运行；
#     如需 cgo DNS 解析，需改用 Android NDK 交叉编译（本脚本默认走纯 Go 解析器）。
#   * Termux 与 Windows 产物不含 proc 模块（约束见 modules/proc）：
#     Android 的 /proc 受限、Windows 走 WMI，都用不上进程分析。
#     这两个目标下 gyhost proc 会提示未知模块——本就没有此功能。
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

BIN="gyhost"
DIST="${DIST:-$ROOT/dist}"
CUDA_DIR="internal/cuda"

# ---------------------------------------------------------------- 颜色输出
if [ -t 1 ]; then
	C_INFO=$'\033[34m'; C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_RST=$'\033[0m'
else
	C_INFO=; C_OK=; C_WARN=; C_ERR=; C_RST=
fi
info() { printf '%s[*]%s %s\n' "$C_INFO" "$C_RST" "$*"; }
ok()   { printf '%s[✓]%s %s\n' "$C_OK"   "$C_RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_WARN" "$C_RST" "$*"; }
err()  { printf '%s[✗]%s %s\n' "$C_ERR"  "$C_RST" "$*" >&2; }

# usage 打印文件头部的注释块（跳过 shebang 与紧随的空注释行）
usage() {
	awk 'NR>2 && /^#/ { sub(/^# ?/, ""); print; next } NR>2 { exit }' "$0"
}

# ---------------------------------------------------------------- 版本号
# 从 internal/cli/root.go 的 const Version = "x.y.z" 提取
VERSION="$(sed -n 's/^[[:space:]]*const[[:space:]]*Version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
	internal/cli/root.go 2>/dev/null | head -n1)"
VERSION="${VERSION:-0.0.0}"

HOST_OS="$(go env GOOS)"
HOST_ARCH="$(go env GOARCH)"

# ---------------------------------------------------------------- 目标矩阵
# 每项格式: 标签:GOOS:GOARCH
NOGPU_TARGETS=(
	"windows-amd64:windows:amd64"
	"windows-arm64:windows:arm64"
	"linux-amd64:linux:amd64"
	"linux-arm64:linux:arm64"
	"macos-amd64:darwin:amd64"
	"macos-arm64:darwin:arm64"
	"termux-aarch64:android:arm64"
)

GPU_TARGETS=(
	"windows-amd64:windows:amd64"
	"linux-amd64:linux:amd64"
	"linux-arm64:linux:arm64"
)

MODE="${1:-all}"
FILTER="${2:-}"
BUILT=0
FAILED=0
CUDA_LIB_READY=0

# ---------------------------------------------------------------- 工具函数
# match_filter 按产物标签做子串匹配；FILTER 为空则全部匹配。
match_filter() {
	[ -z "$FILTER" ] && return 0
	case "$1" in
		*"$FILTER"*) return 0 ;;
	esac
	return 1
}

# build_one 标签 GOOS GOARCH 是否GPU(0/1)
#
# 每个目标走一次独立的 CMake 配置+构建，产物直接落到 dist/。
# 「交叉编译用什么参数」完全由 CMakeLists.txt 定义（GYHOST_TARGET_OS/ARCH、
# GYHOST_OUTPUT、GYHOST_TRIMPATH），脚本只负责决定「编哪些目标」，
# 两边不会各自维护一套参数而漂移。
build_one() {
	local label="$1" goos="$2" goarch="$3" gpu="$4"
	local ext="" suffix="" gmode="OFF"
	[ "$goos" = "windows" ] && ext=".exe"
	[ "$gpu" = "1" ] && { suffix="-gpu"; gmode="ON"; }

	local out="$DIST/${BIN}-v${VERSION}-${label}${suffix}${ext}"
	# 每个目标一个构建目录：GOOS/GOARCH 是 CMake 缓存变量，
	# 复用同一个目录会在目标切换时沿用上次的值。
	#
	# GPU 目标例外：CUDA 静态库始终是本机目标，且已在 build-cuda 里编过一遍。
	# 若这里再用一个新目录，CMake 会把 129KB 的 cuda.cu 重编一次（纯浪费）。
	# 所以 GPU 目标直接复用 build-cuda，让 CMake 的增量判断跳过重编。
	local bdir log
	if [ "$gpu" = "1" ]; then
		bdir="${ROOT}/build-cuda"
	else
		bdir="${ROOT}/build-dist/${goos}-${goarch}"
	fi
	log="$bdir.log"

	# 目标路径的父目录必须先建：shell 的 `> "$log"` 不会自动创建目录，
	# 而 cmake -B 自己创建的是构建目录，日志写在它外面。
	mkdir -p "$(dirname "$out")" "$(dirname "$log")"

	info "构建 ${label}${suffix}  (GOOS=${goos} GOARCH=${goarch} GPU=${gmode})"

	if ! cmake -S "$ROOT" -B "$bdir" \
		-DGYHOST_GPU="$gmode" \
		-DGYHOST_BUILD_TESTS=OFF \
		-DGYHOST_TARGET_OS="$goos" \
		-DGYHOST_TARGET_ARCH="$goarch" \
		-DGYHOST_OUTPUT="$out" \
		-DGYHOST_TRIMPATH=ON > "$log" 2>&1
	then
		err "CMake 配置失败: ${label}${suffix}（详见 ${bdir}.log）"
		FAILED=$((FAILED + 1))
		return
	fi

	if cmake --build "$bdir" --target release >> "$log" 2>&1; then
		ok "$(basename "$out")  $(du -h "$out" | cut -f1)"
		BUILT=$((BUILT + 1))
	else
		err "构建失败: ${label}${suffix}（详见 ${bdir}.log）"
		FAILED=$((FAILED + 1))
	fi
}

# ensure_cuda_lib 按需编译一次 CUDA 静态库
#
# 走 CMake 而非 make（构建系统已从 Makefile 迁移到 CMakeLists.txt）。
# 用一个独立的构建目录，与用户自己的 cmake -B build 互不干扰。
ensure_cuda_lib() {
	[ "$CUDA_LIB_READY" = "1" ] && return 0
	command -v nvcc >/dev/null 2>&1 || { warn "未找到 nvcc，无法构建 CUDA 静态库"; return 1; }
	command -v cmake >/dev/null 2>&1 || { warn "未找到 cmake，无法构建 CUDA 静态库"; return 1; }
	local bdir="${ROOT}/build-cuda"
	info "编译 CUDA 静态库: cmake --build ${bdir} --target gyhost_cuda"
	cmake -S "${ROOT}" -B "${bdir}" -DGYHOST_GPU=ON \
		-DGYHOST_BUILD_TESTS=OFF \
		-DGYHOST_CUDA_ARCH="${GYHOST_CUDA_ARCH:-native}" >/dev/null 2>&1 \
		|| { err "CMake 配置失败"; return 1; }
	cmake --build "${bdir}" --target gyhost_cuda \
		|| { err "CUDA 静态库编译失败"; return 1; }
	CUDA_LIB_READY=1
}

# ---------------------------------------------------------------- 构建流程
run_nogpu() {
	info "== 无 GPU 版本（纯 Go 静态构建，可全平台交叉编译） =="
	local t label goos goarch
	for t in "${NOGPU_TARGETS[@]}"; do
		IFS=: read -r label goos goarch <<<"$t"
		match_filter "$label" || continue
		build_one "$label" "$goos" "$goarch" 0
	done
}

run_gpu() {
	info "== 带 GPU 版本（CUDA，仅本机 ${HOST_OS}/${HOST_ARCH} 可编） =="
	local t label goos goarch attempted=0
	for t in "${GPU_TARGETS[@]}"; do
		IFS=: read -r label goos goarch <<<"$t"
		match_filter "$label" || continue
		if [ "$goos" != "$HOST_OS" ] || [ "$goarch" != "$HOST_ARCH" ]; then
			warn "跳过 GPU ${label}: CUDA 静态库与工具链绑定平台，需在 ${goos}/${goarch} 上运行本脚本"
			continue
		fi
		attempted=1
		ensure_cuda_lib || { warn "跳过 GPU ${label}"; continue; }
		build_one "$label" "$goos" "$goarch" 1
	done
	[ "$attempted" = "1" ] || warn "没有与本机匹配的 GPU 目标，已全部跳过"
}

clean() {
	rm -rf "$DIST"
	# CMake 构建目录：每个交叉目标一个，外加本机 GPU 库目录。
	rm -rf "${ROOT}/build-dist" "${ROOT}/build-cuda"
	# 构建日志（每个目标一个，写在构建目录旁边）
	rm -f "${ROOT}"/*.log
	# CUDA 静态库落在 internal/cuda（cgo 的 -L${SRCDIR} 要求），需单独删。
	rm -f "${CUDA_DIR}/cuda.o" "${CUDA_DIR}/libgyhost_cuda.a"
	ok "已清理 ${DIST}、CMake 构建目录与 CUDA 中间产物"
}

# ---------------------------------------------------------------- 入口
case "$MODE" in
	clean) clean; exit 0 ;;
	all | nogpu | gpu) ;;
	-h | --help | help) usage; exit 0 ;;
	*) err "未知模式: $MODE"; echo; usage; exit 2 ;;
esac

mkdir -p "$DIST"

command -v cmake >/dev/null 2>&1 || { err "未找到 cmake，请先安装 CMake 3.24+"; exit 1; }

info "GYhost v${VERSION}  主机: ${HOST_OS}/${HOST_ARCH}  产物目录: ${DIST}"
[ -n "$FILTER" ] && info "架构过滤: ${FILTER}"

case "$MODE" in
	all) run_nogpu; echo; run_gpu ;;
	nogpu) run_nogpu ;;
	gpu) run_gpu ;;
esac

echo
if [ "$FAILED" -eq 0 ]; then
	ok "构建完成: 成功 ${BUILT} 个目标"
	exit 0
fi
warn "构建完成: 成功 ${BUILT} 个，失败 ${FAILED} 个"
exit 1
