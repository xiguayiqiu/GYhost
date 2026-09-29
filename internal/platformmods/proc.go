//go:build (linux && !android) || darwin

// Package platformmods 负责「只在部分平台存在」的模块的注册。
//
// 为什么需要这个包：Go 无法对导入做条件编译，main.go 只要 import 了
// modules/proc，Windows / Termux 构建就会因 build constraints exclude all
// Go files 而失败。而 proc 只在 Linux（不含 Android/Termux）与 macOS 上存在。
//
// 做法是把注册拆成两个同包文件，由构建标签二选一：
//   - proc.go     平台有 proc，注册之
//   - proc_off.go 平台没有 proc，空实现
//
// 效果：这两个平台执行 `gyhost proc` 得到「未知模块」，与该平台本就没有
// 此功能一致（不是「有命令但报不支持」）。
//
// 新增平台受限模块时，在这里加一行 + 配套的 _off.go 即可。
package platformmods

import (
	"gyhost/internal/module"
	"gyhost/modules/proc"
)

// Register 注册「只在部分平台存在」的模块。
func Register(r *module.Registry) {
	r.MustRegister(proc.New())
}
