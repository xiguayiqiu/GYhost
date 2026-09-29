//go:build darwin

package maclite

import "unsafe"

// ptr 把 Go 切片的首地址转成 uintptr。
//
// 这里必须用 unsafe.SliceData 而非 &buf[0]：后者在空切片上会 panic，
// 而本包的绑定函数大量使用“空/零长度”调用（先探测再分配）。
func ptr[T any](b []T) uintptr {
	if len(b) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(unsafe.SliceData(b)))
}
