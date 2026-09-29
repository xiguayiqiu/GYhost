//go:build (android || !linux) && !darwin

package platformmods

import "gyhost/internal/module"

// Register 在本平台不注册任何模块。
//
// 对应 proc.go：proc 只在 Linux（不含 Android/Termux）与 macOS 上存在，
// 这里必须提供同名同签名的实现，否则这些平台会缺符号（undefined: Register）。
// 二者必须同时提供。
func Register(r *module.Registry) {}
