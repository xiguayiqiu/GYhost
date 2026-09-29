package mem

import (
	"io"
	"os"
)

// FileTarget 把一个内存转储文件（raw dump / dmp / bin / 任意二进制）当作内存镜像。
//
// 三个平台的 live 读取能力不同，但转储文件在任意平台都能分析：
// 整个文件被视作一段从 0 开始的匿名可读区域，虚拟地址即文件偏移。
type FileTarget struct {
	f        *os.File
	size     uint64
	info     ProcessInfo
	writable bool
}

// NewFileTarget 打开一个内存转储文件。
func NewFileTarget(path string) (*FileTarget, error) {
	// 优先以可写方式打开：这样才能在镜像副本上试验补丁。
	// 只读打开时所有读能力照常，Writable() 返回 false。
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	writable := err == nil
	if !writable {
		if f, err = os.Open(path); err != nil {
			return nil, err
		}
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	t := &FileTarget{
		f:        f,
		size:     uint64(st.Size()),
		writable: writable,
		info: ProcessInfo{
			Arch:        "file",
			Exe:         path,
			TotalMemory: uint64(st.Size()),
		},
	}
	return t, nil
}

// Kind 返回 "file"。
func (t *FileTarget) Kind() string { return "file" }

// Info 返回目标信息（PID 为 0，Exe 为文件路径）。
func (t *FileTarget) Info() ProcessInfo { return t.info }

// Regions 返回唯一一段区域，覆盖整个文件。
func (t *FileTarget) Regions() ([]Region, error) {
	return []Region{{
		Start: 0,
		End:   t.size,
		Perm:  "rw-p",
		Path:  t.info.Exe,
		Kind:  RegionMapped,
	}}, nil
}

// ReadAt 从文件偏移 addr（即虚拟地址）读取。
func (t *FileTarget) ReadAt(addr uint64, p []byte) (int, error) {
	if addr >= t.size {
		return 0, io.EOF
	}
	if max := t.size - addr; uint64(len(p)) > max {
		p = p[:max]
	}
	return t.f.ReadAt(p, int64(addr))
}

// Close 关闭文件。
func (t *FileTarget) Close() error { return t.f.Close() }

// Writable 报告转储文件是否以可写方式打开。
func (t *FileTarget) Writable() bool { return t.writable }

// WriteAt 在转储文件里原位改写数据。
//
// 这让「先导出、再离线试验补丁」成为可能：不必对活体进程下手，
// 就能在镜像副本上验证改动效果。
func (t *FileTarget) WriteAt(addr uint64, p []byte) (int, error) {
	if !t.writable {
		return 0, ErrNotWritable
	}
	if addr >= t.size {
		return 0, io.EOF
	}
	if max := t.size - addr; uint64(len(p)) > max {
		p = p[:max]
	}
	return t.f.WriteAt(p, int64(addr))
}
