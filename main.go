// GYhost 是模块化的主机安全工具集。
//
// 入口只做一件事：注册功能模块并交给 CLI 根命令分发。
// 新增模块 = 实现 module.Module + 在这里加一行注册。
package main

import (
	"os"

	"gyhost/internal/cli"
	"gyhost/internal/module"
	"gyhost/internal/platformmods"
	"gyhost/modules/hashac"
	"gyhost/modules/hashcat"
	"gyhost/modules/hashdump"
	"gyhost/modules/mem"
	"gyhost/modules/net"
	"gyhost/modules/shadow"
)

func main() {
	registry := module.NewRegistry()

	// ---- 在此注册全部功能模块 ----
	registry.MustRegister(shadow.New())
	registry.MustRegister(hashdump.New())
	registry.MustRegister(hashcat.New())
	registry.MustRegister(hashac.New())
	registry.MustRegister(net.New())
	registry.MustRegister(mem.New())

	// 平台相关的模块（当前只有 proc）由 internal/platformmods 按构建标签注册，
	// 那个包内部拆成 proc.go / proc_off.go 两个同签名实现。
	platformmods.Register(registry)

	// registry.MustRegister(<新模块>.New())

	os.Exit(cli.New(registry).Run(os.Args[1:]))
}
