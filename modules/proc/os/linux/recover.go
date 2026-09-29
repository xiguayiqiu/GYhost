//go:build linux && !android

package linux

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gyhost/internal/proc"
)

// maxRecoverSize 是单个恢复件的体积上限。
//
// /proc/<pid>/exe 与 map_files 指向的可能是几百 MB 的镜像/内存映射，
// 一股脑复制既慢又占盘；超过上限就只列不恢复。
const maxRecoverSize = 512 << 20 // 512 MiB

// Scan 枚举 /proc/<pid> 下所有可恢复的文件。
//
// 四个来源：
//
//	/proc/<pid>/exe              正在执行的可执行文件
//	/proc/<pid>/cwd              工作目录
//	/proc/<pid>/root             根目录（chroot 场景）
//	/proc/<pid>/fd/<n>           打开的文件（已删除的也在内）
//	/proc/<pid>/map_files/<..>   内存映射的文件
func (b *Backend) Scan(pid int) ([]proc.FileRef, error) {
	if _, err := os.Stat(procPath(strconv.Itoa(pid))); err != nil {
		return nil, fmt.Errorf("%w: pid %d", proc.ErrNoProcess, pid)
	}
	var refs []proc.FileRef
	refs = append(refs, scanLink(pid, proc.FileExe, "exe"))
	refs = append(refs, scanLink(pid, proc.FileCwd, "cwd"))
	refs = append(refs, scanLink(pid, proc.FileRoot, "root"))
	refs = append(refs, scanFDs(pid)...)
	refs = append(refs, scanMaps(pid)...)

	// 编号要在过滤/排序之后才固定，保证「看到的编号」=「-r 能指定的编号」
	for i := range refs {
		refs[i].Index = i + 1
	}
	// 已删除的排前面：那是取证最想先看的东西
	sort.SliceStable(refs, func(i, j int) bool {
		if refs[i].Deleted != refs[j].Deleted {
			return refs[i].Deleted
		}
		return refs[i].Index < refs[j].Index
	})
	for i := range refs {
		refs[i].Index = i + 1
	}
	return refs, nil
}

// scanLink 扫一个软链接型入口（exe / cwd / root）。
func scanLink(pid int, kind proc.FileKind, name string) proc.FileRef {
	ref := proc.FileRef{Kind: kind, Size: -1, Target: ""}
	target, err := os.Readlink(procPath(strconv.Itoa(pid), name))
	if err != nil {
		ref.Reason = errText(err)
		return ref
	}
	ref.Link = target
	ref.Target = target
	ref.Deleted = strings.HasSuffix(target, " (deleted)")
	if ref.Deleted {
		ref.Target = strings.TrimSuffix(target, " (deleted)")
	}
	fillStat(&ref, name, pid)
	return ref
}

// scanFDs 扫 /proc/<pid>/fd/。
func scanFDs(pid int) []proc.FileRef {
	dir := procPath(strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []proc.FileRef{{Kind: proc.FileFD, Size: -1, Reason: errText(err)}}
	}
	var out []proc.FileRef
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		ref := proc.FileRef{Kind: proc.FileFD, FD: fd, Size: -1}
		link, err := os.Readlink(filepath.Join(dir, e.Name()))
		if err != nil {
			ref.Reason = errText(err)
			out = append(out, ref)
			continue
		}
		ref.Link = link
		ref.Target = link
		// 套接字/管道/事件fd/anon inode 不是文件，跳过但保留原因说明
		if isSpecial(link) {
			ref.Reason = "not a regular file"
			out = append(out, ref)
			continue
		}
		ref.Deleted = strings.HasSuffix(link, " (deleted)")
		if ref.Deleted {
			ref.Target = strings.TrimSuffix(link, " (deleted)")
		}
		fillStat(&ref, "fd/"+e.Name(), pid)
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FD < out[j].FD })
	return out
}

// scanMaps 扫 /proc/<pid>/map_files/。
//
// 两条现实约束决定了这里怎么判「可恢复」：
//
//  1. map_files 的项是虚拟地址区间（start-end），是文件的**一个片段**，
//     不是整个文件；照着复制拿到的只是那一段。
//  2. 打开 map_files 里的项需要 CAP_SYS_ADMIN（root），普通用户会拿到 EPERM。
//
// 因此：映射到**磁盘上仍存在**的文件没有恢复价值（文件本来就能直接访问），
// 只保留「已删除但仍被映射」的条目——那才是取证要的东西。
func scanMaps(pid int) []proc.FileRef {
	dir := procPath(strconv.Itoa(pid), "map_files")
	entries, err := os.ReadDir(dir)
	if err != nil {
		// map_files 需要 CAP_SYS_ADMIN，拿不到是常态而不是错误
		return []proc.FileRef{{Kind: proc.FileMap, Size: -1, Reason: errText(err)}}
	}
	var out []proc.FileRef
	seen := map[string]int{} // 同一路径的其它区间计数
	for _, e := range entries {
		ref := proc.FileRef{Kind: proc.FileMap, Size: -1}
		link, err := os.Readlink(filepath.Join(dir, e.Name()))
		if err != nil {
			ref.Reason = errText(err)
			out = append(out, ref)
			continue
		}
		ref.Link = link
		ref.Target = link
		ref.Deleted = strings.HasSuffix(link, " (deleted)")
		if ref.Deleted {
			ref.Target = strings.TrimSuffix(link, " (deleted)")
		}
		seen[ref.Target]++
		if n := seen[ref.Target]; n > 1 {
			// 同一文件被分成多个区间映射，只留第一个，避免重复恢复同一份内容
			ref.Recoverable = false
			ref.Reason = fmt.Sprintf("duplicate mapping segment (#%d of the same file)", n)
		} else if !ref.Deleted {
			ref.Recoverable = false
			ref.Reason = "memory-mapped, file still exists on disk"
		} else {
			ref.Recoverable = true
		}
		out = append(out, ref)
	}
	return out
}

// fillStat 补充存在性、类型、大小与时间。
func fillStat(ref *proc.FileRef, procName string, pid int) {
	// 优先按真实路径 stat；已删除的文件 stat 会失败，
	// 那时退回 stat /proc/<pid>/<procName> 拿到仍在的 inode 信息。
	st, err := os.Stat(ref.Target)
	if err != nil {
		if st2, err2 := os.Stat(procPath(strconv.Itoa(pid), procName)); err2 == nil {
			st, err = st2, nil
			ref.Exists = false
			ref.Deleted = true
			ref.Target = strings.TrimSuffix(ref.Link, " (deleted)")
		} else {
			ref.Reason = errText(err)
			return
		}
	} else {
		ref.Exists = true
	}
	ref.IsDir = st.IsDir()
	if !st.IsDir() {
		ref.Size = st.Size()
	}
	ref.ModTime = st.ModTime().Format("2006-01-02 15:04:05")

	switch {
	case ref.IsDir:
		ref.Recoverable = false
		ref.Reason = "directory, cannot be copied as a file"
	case ref.Size > maxRecoverSize:
		ref.Recoverable = false
		ref.Reason = fmt.Sprintf("file is %s, over the %s limit", humanBytes(uint64(ref.Size)), humanBytes(maxRecoverSize))
	default:
		// 注意不能用 "!ref.Recoverable" 当条件：它此时恒为 false，
		// 判反了会把所有普通文件都标成不可恢复。
		ref.Recoverable = true
	}
}

// isSpecial 判断软链接目标是不是非文件对象。
func isSpecial(link string) bool {
	for _, prefix := range []string{"socket:[", "pipe:[", "anon_inode:[", "memfd:", "/dev/"} {
		if strings.HasPrefix(link, prefix) {
			return true
		}
	}
	return false
}

// Recover 把文件恢复成 destDir 下的普通文件。
func (b *Backend) Recover(pid int, ref proc.FileRef, destDir string) (string, int64, error) {
	// 数据源永远是 /proc 里的那个入口，而不是磁盘上的路径：
	// 这正是能恢复「已删除但仍被进程持有」的文件的关键。
	var src string
	switch ref.Kind {
	case proc.FileExe:
		src = procPath(strconv.Itoa(pid), "exe")
	case proc.FileFD:
		src = procPath(strconv.Itoa(pid), "fd", strconv.Itoa(ref.FD))
	case proc.FileMap:
		src = procPath(strconv.Itoa(pid), "map_files", mapRange(pid, ref))
	case proc.FileCwd, proc.FileRoot:
		return "", 0, fmt.Errorf("cannot recover a directory as a file")
	default:
		return "", 0, fmt.Errorf("unsupported source: %s", ref.Kind)
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", 0, err
	}
	out := filepath.Join(destDir, proc.RecoverName(ref, map[string]bool{}))
	in, err := os.Open(src)
	if err != nil {
		return "", 0, err
	}
	defer in.Close()
	f, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return "", 0, err
	}
	n, cerr := io.Copy(f, in)
	closeErr := f.Close()
	if cerr != nil {
		os.Remove(out)
		return "", 0, cerr
	}
	if closeErr != nil {
		os.Remove(out)
		return "", 0, closeErr
	}
	return out, n, nil
}

// mapRange 找回 map_files 下的区间名。
//
// map_files 的项名是虚拟地址区间 "start-end"，而 FileRef.Link 存的是目标路径，
// 所以要反查一次目录才能对上号。
func mapRange(pid int, ref proc.FileRef) string {
	dir := procPath(strconv.Itoa(pid), "map_files")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		link, err := os.Readlink(dir + "/" + e.Name())
		if err != nil {
			continue
		}
		if strings.TrimSuffix(link, " (deleted)") == ref.Target {
			return e.Name()
		}
	}
	return ""
}

// errText 把错误压成一行可读文案。
func errText(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	// procfs 的错误很长，只取最有信息量的尾部
	if i := strings.LastIndex(s, ": "); i >= 0 && i+2 < len(s) {
		return s[i+2:]
	}
	return s
}

// humanBytes 把字节数渲染成可读形式。
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}
