// 内存导出（-a dump / -d）：把目标里选中的区域原样写成 raw dump 文件。
//
// 用途：取证留证、把活体进程转成可离线复核的镜像，
// 以及把其它平台采到的 dump 拿到本平台上重复分析。
package mem

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"gyhost/internal/i18n"
	memcore "gyhost/internal/mem"
)

// dumpRecordSize 是索引项大小：起始地址 + 长度。
const dumpRecordSize = 16

// runDump 导出内存镜像并写出索引文件。
func runDump(tgt memcore.Target, regions []memcore.Region, dest io.Writer,
	notice func(NoticeLevel, string), opt options) error {

	path := opt.dump
	if path == "" {
		path = defaultDumpName(tgt.Info())
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("%s", i18n.Tf("mem.err.create_out", err))
	}
	defer f.Close()

	// 索引文件记录每段区域在 dump 里的偏移与虚拟地址，便于回溯
	idx, err := os.Create(path + ".index")
	if err != nil {
		return fmt.Errorf("%s", i18n.Tf("mem.err.create_out", err))
	}
	defer idx.Close()

	var written uint64
	for _, r := range regions {
		start := written
		for addr := r.Start; addr < r.End; {
			n := r.End - addr
			if n > readChunkSize {
				n = readChunkSize
			}
			buf := make([]byte, n)
			got, err := tgt.ReadAt(addr, buf)
			if got > 0 {
				if _, werr := f.Write(buf[:got]); werr != nil {
					return fmt.Errorf("%s", i18n.Tf("mem.err.write_out", werr))
				}
				written += uint64(got)
			}
			if err != nil {
				break
			}
			addr += n
		}
		// 记录：虚拟起始地址、dump 内偏移、长度
		var rec [dumpRecordSize]byte
		binary.LittleEndian.PutUint64(rec[0:8], r.Start)
		binary.LittleEndian.PutUint64(rec[8:16], written-start)
		if _, werr := idx.Write(rec[:]); werr != nil {
			return fmt.Errorf("%s", i18n.Tf("mem.err.write_out", werr))
		}
		notice(NoticeInfo, i18n.Tf("mem.info.region", r.String(), humanBytes(int64(written-start))))
	}

	notice(NoticeOK, i18n.Tf("mem.info.dumped", path, humanBytes(int64(written)), len(regions)))
	if opt.quiet {
		return nil
	}
	fmt.Fprintf(dest, "%s\n", i18n.Tf("mem.dump.summary", path, humanBytes(int64(written)), len(regions)))
	fmt.Fprintf(dest, "%s\n", i18n.Tf("mem.dump.index", path+".index"))
	return nil
}

// defaultDumpName 按目标生成默认导出文件名。
func defaultDumpName(info memcore.ProcessInfo) string {
	if info.Exe != "" {
		return baseName(info.Exe) + ".memdump"
	}
	return fmt.Sprintf("pid%d.memdump", info.PID)
}

// baseName 取路径最后一段（不依赖 path/filepath，跨平台一致）。
func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}
