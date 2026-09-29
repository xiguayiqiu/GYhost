//go:build !unix

package utils

import (
	"errors"
	"os"
	"time"
)

// ErrRawUnsupported 表示当前平台或输入不是终端，无法进入 raw 模式。
var ErrRawUnsupported = errors.New("raw mode unsupported")

// SetRaw 在本平台不支持 raw 模式（调用方应据此回退到非交互输出）。
func SetRaw(f *os.File) (restore func(), err error) { return nil, ErrRawUnsupported }

// IsTerminalFD 判断输入是否为终端；本平台无法探测，保守返回 false。
func IsTerminalFD(f *os.File) bool { return false }

// waitReadable 在本平台没有可用的等待机制，保守返回"可读"。
//
// 调用方只在解析 ESC 序列时用到它；本平台的 raw 模式本就不可用，
// 交互式界面不会真正跑到这里。
func waitReadable(f *os.File, timeout time.Duration) bool { return true }
