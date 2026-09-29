//go:build !unix

package utils

import "time"

// NotifyResize 在本平台没有 SIGWINCH，退化为定时通知。
//
// 交互式界面在本平台本就不可用（见 SetRaw），这个实现只是让代码能编译通过。
func NotifyResize() (<-chan struct{}, func()) {
	ch := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				select {
				case ch <- struct{}{}:
				default:
				}
			case <-stop:
				return
			}
		}
	}()
	return ch, func() { close(stop) }
}
