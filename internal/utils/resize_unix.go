//go:build unix

package utils

import (
	"os"
	"os/signal"
	"syscall"
)

// NotifyResize 订阅终端尺寸变化（SIGWINCH）。
//
// 返回一个 channel：每次窗口尺寸变化时收到通知，由调用方在主循环里执行
// 实际的重新布局。信号处理函数里不能安全地做 ioctl 或写终端，所以只做
// "通知"这件事。stop 用于取消订阅，调用方应 defer 它。
func NotifyResize() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGWINCH)
	go func() {
		for range sig {
			// 合并短时间内的连续变化（拖动窗口会来一串信号），
			// 缓冲区为 1 时多余的信号自然被丢弃
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}()
	return ch, func() { signal.Stop(sig); close(sig) }
}
