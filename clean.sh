#!/usr/bin/env bash
#
# GYhost 彻底清理 —— 删除全部 CMake 与 go build 产物，只留源码和构建脚本
#
# 用法:
#   ./clean.sh            # 清构建产物与 CMake 缓存（保留 dist/ 发布产物）
#   ./clean.sh --all      # 连 dist/ 发布产物、build-dist/、build-cuda/ 一起清
#   ./clean.sh --dist     # 只清 dist/ 与交叉编译目录
#
# 清理范围:
#   * 构建目录          build/、build-*/、build-dist/、build-cuda/、Testing/
#   * 发布产物          dist/（--all 或 --dist 才清）
#   * go build 产物     根目录 gyhost、gyhost-cpu、gyhost.exe，internal/cuda/*.a、*.o
#   * CMake 缓存        CMakeCache.txt、CMakeFiles/、cmake_install.cmake、
#                       CTestTestfile.cmake、compile_commands.json
#   * 构建日志          *.log
#
# 保留: *.go、*.cu、*.h、go.mod/go.sum、CMakeLists.txt、cmake/、build.sh、clean.sh、
#       本文件、README.md、LOG.md、LICENSE、.gitignore
#
# 关于 Makefile 的特别说明:
#   本项目的手写 Makefile 已随构建系统迁移到 CMake 一并删除，源码树里不应再有它。
#   但若有人误做 in-source 配置（cmake . 不带 -B），CMake 会在根目录和 internal/cuda/
#   生成同名 Makefile（首行 "CMAKE generated file: DO NOT EDIT!"），看起来像是
#   「没删干净的源码」。因此这里仍按首行判定、只删 CMake 生成的那种；
#   万一将来引入了别的手写 Makefile，也不会被误删。
#
# 环境变量:
#   GYHOST_KEEP_BUILD_DIR  指定一个构建目录使其免于删除。CMake 的 gyhost-distclean
#                         目标会自动传入，因为它的工作目录就在该构建目录里，
#                         删掉会导致外层 shell 报 getcwd 失败。手工运行无需设置。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [ -t 1 ]; then
	C_INFO=$'\033[34m'; C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_RST=$'\033[0m'
else
	C_INFO=; C_OK=; C_WARN=; C_RST=;
fi
info() { printf '%s[*]%s %s\n' "$C_INFO" "$C_RST" "$*"; }
ok()   { printf '%s[✓]%s %s\n' "$C_OK" "$C_RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_WARN" "$C_RST" "$*" >&2; }

REMOVED=0
SKIPPED=0

# remove_path 删除文件或目录，存在才删，删完计数
remove_path() {
	local p="$1"
	[ -e "$p" ] || return 0
	rm -rf "$p"
	printf '    删 %s\n' "$p"
	REMOVED=$((REMOVED + 1))
}

# remove_cmake_generated 只删首行声明自己是 CMake 产物的 Makefile，
# 即 in-source 配置的残留。手写版（首行是注释）会被跳过，避免误删源码。
remove_cmake_generated() {
	local f="$1"
	[ -f "$f" ] || return 0
	if head -n 1 "$f" | grep -q 'CMAKE generated file'; then
		rm -f "$f"
		printf '    删 %s (CMake 生成)\n' "$f"
		REMOVED=$((REMOVED + 1))
	else
		printf '    留 %s (非 CMake 生成，疑似手写)\n' "$f"
		SKIPPED=$((SKIPPED + 1))
	fi
}

# 保留项：本次正在运行的构建目录。
# 通过 `cmake --build build --target gyhost-distclean` 触发时，CMake 的工作目录就是
# build/，把它删掉会让外层 shell 报 getcwd 失败、后续命令无法执行。
# 手工跑 ./clean.sh 时 KEEP_BUILD_DIR 为空，build/ 照常删除。
KEEP_BUILD_DIR="${GYHOST_KEEP_BUILD_DIR:-}"

# ---------------------------------------------------------------- 构建目录
clean_build_dirs() {
	info "== 构建目录 =="
	local d abs
	for d in build build-* build-dist build-cuda; do
		# build-* 会匹配到 build.sh，必须排除
		case "$(basename "$d")" in
			build.sh) continue ;;
		esac
		abs="${ROOT}/${d}"
		if [ -n "$KEEP_BUILD_DIR" ] && [ "$abs" = "$KEEP_BUILD_DIR" ]; then
			printf '    留 %s (当前构建目录，经 CMake 调用时保留)\n' "$d"
			SKIPPED=$((SKIPPED + 1))
			continue
		fi
		remove_path "$d"
	done
}

# ---------------------------------------------------------------- 发布产物
clean_dist() {
	info "== 发布产物 =="
	remove_path dist
}

# ---------------------------------------------------------------- go build 产物
clean_go_outputs() {
	info "== go build 产物 =="
	remove_path gyhost
	remove_path gyhost-cpu
	remove_path gyhost.exe
	remove_path gyhost-cpu.exe
	# 根目录可能散落其它 go build 输出
	local f
	for f in *.test; do remove_path "$f"; done
}

# ---------------------------------------------------------------- CUDA 产物
# 静态库必须落在 internal/cuda/（cgo 按源码目录做 -L 链接，不能放构建目录），
# 所以它不在 build/ 下，需单独清。
clean_cuda() {
	info "== CUDA 产物（internal/cuda/，cgo 链接要求落在此处）=="
	remove_path internal/cuda/libgyhost_cuda.a
	remove_path internal/cuda/cuda.o
	remove_path internal/cuda/CMakeFiles
	remove_path internal/cuda/cmake_install.cmake
	remove_path internal/cuda/CTestTestfile.cmake
	# in-source 配置可能在这里留下 CMake 生成的 Makefile
	remove_cmake_generated internal/cuda/Makefile
}

# ---------------------------------------------------------------- CMake 缓存
# 根目录这一组只在「有人误做 in-source 配置」（cmake . 不带 -B）时才会出现。
# CMakeCache.txt 里的 CMAKE_CACHEFILE_DIR 等于源码目录即为这种残留。
clean_cmake_cache() {
	info "== CMake 缓存（in-source 配置残留）=="
	if [ -f CMakeCache.txt ] && grep -q "^CMAKE_CACHEFILE_DIR:INTERNAL=${ROOT}$" CMakeCache.txt; then
		info "  CMakeCache.txt 的 CMAKE_CACHEFILE_DIR 就是源码目录，确认是 in-source 残留"
	fi
	remove_path CMakeCache.txt
	remove_path CMakeFiles
	remove_path cmake_install.cmake
	remove_path CTestTestfile.cmake
	remove_path compile_commands.json
	remove_path Testing
	remove_cmake_generated Makefile
}

# ---------------------------------------------------------------- 日志
clean_logs() {
	info "== 构建日志 =="
	local f
	for f in *.log; do remove_path "$f"; done
}

# ---------------------------------------------------------------- 入口
MODE="${1:-normal}"
case "$MODE" in
--dist)
	clean_dist
	clean_build_dirs
	ok "已清理发布产物与交叉编译目录"
	exit 0
	;;
--all | -a)
	clean_build_dirs
	clean_dist
	clean_go_outputs
	clean_cuda
	clean_cmake_cache
	clean_logs
	ok "已彻底清理：只剩源码与构建脚本"
	exit 0
	;;
-h | --help | help)
	awk 'NR>2 && /^#/ { sub(/^ ?# ?/, ""); print; next } NR>2 { exit }' "$0"
	exit 0
	;;
normal | "")
	clean_build_dirs
	clean_go_outputs
	clean_cuda
	clean_cmake_cache
	clean_logs
	ok "已清理构建产物（dist/ 保留，需要一并清请用 ./clean.sh --all）"
	;;
*)
	printf '未知参数: %s\n\n' "$MODE" >&2
	awk 'NR>2 && /^#/ { sub(/^ ?# ?/, ""); print; next } NR>2 { exit }' "$0" >&2
	exit 2
	;;
esac

printf '\n'
info "删除 ${REMOVED} 项"
[ "$SKIPPED" -gt 0 ] && info "跳过 ${SKIPPED} 项（同名但非 CMake 产物，已保留）"
exit 0
