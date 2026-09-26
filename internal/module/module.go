// Package module 定义了 GYhost 的功能模块接口与模块注册表。
//
// 所有功能都以“模块”为单位实现：一个模块 = 一个命令。
// 新增功能时只需实现 Module 接口并在 main 中注册，CLI 层无需改动。
package module

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"gyhost/internal/i18n"
)

// Module 是 GYhost 的最小功能单元。
type Module interface {
	// Name 模块名，用作命令行的第一个参数，例如 "shadow"。全局唯一。
	Name() string
	// Summary 一句话功能描述，用于根帮助信息中的列表。
	Summary() string
	// Usage 该模块的用法说明（含示例），在 `gyhost help <name>` 时展示。
	Usage() string
	// Run 执行模块，args 为模块名之后的原始参数。
	Run(args []string) error
}

// Registry 模块注册表，负责模块的登记与查找。
type Registry struct {
	mods  map[string]Module
	order []string
}

// DefaultGroup 模块未声明分组时使用的默认分组名（已国际化）。
func DefaultGroup() string { return i18n.T("mod.group.default") }

// Grouper 是 Module 的可选扩展接口：实现它可声明模块在帮助信息中的分组。
type Grouper interface {
	// Group 返回分组名，例如 "本地分析"（应返回 i18n.T 的结果）。
	Group() string
}

// GroupOf 返回模块所属分组；未实现 Grouper 或分组为空时返回 DefaultGroup。
func GroupOf(m Module) string {
	if g, ok := m.(Grouper); ok {
		if name := strings.TrimSpace(g.Group()); name != "" {
			return name
		}
	}
	return DefaultGroup()
}

// NewRegistry 创建一个空的模块注册表。
func NewRegistry() *Registry {
	return &Registry{mods: map[string]Module{}}
}

// Register 注册一个模块；模块名不能为空且不能重复。
func (r *Registry) Register(m Module) error {
	if m == nil {
		return errors.New(i18n.T("mod.err.nil"))
	}
	name := strings.TrimSpace(m.Name())
	if name == "" {
		return errors.New(i18n.T("mod.err.empty"))
	}
	if _, ok := r.mods[name]; ok {
		return fmt.Errorf(i18n.T("mod.err.dup"), name)
	}
	r.mods[name] = m
	r.order = append(r.order, name)
	return nil
}

// MustRegister 与 Register 相同，但注册失败时直接 panic（用于 main 中的静态注册）。
func (r *Registry) MustRegister(m Module) {
	if err := r.Register(m); err != nil {
		panic(err)
	}
}

// Get 按名称查找模块。
func (r *Registry) Get(name string) (Module, bool) {
	m, ok := r.mods[name]
	return m, ok
}

// Names 返回全部模块名，按注册顺序排列。
func (r *Registry) Names() []string {
	names := make([]string, len(r.order))
	copy(names, r.order)
	return names
}

// SortedNames 返回全部模块名，按字典序排列（用于帮助信息）。
func (r *Registry) SortedNames() []string {
	names := r.Names()
	sort.Strings(names)
	return names
}
