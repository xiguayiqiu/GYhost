package shadow

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"gyhost/internal/i18n"
)

// Entry 是 shadow 文件中的一条账户记录。
type Entry struct {
	User string // 用户名
	Hash string // 密码哈希（第二个字段）
	Line int    // 所在行号（从 1 开始）
}

// lockedHash 表示该账户无可用哈希（锁定、禁用或密码为空），无需爆破。
// 常见形式: ""（空密码）、"*"、"!"、"!!"、"!$6$..."（被锁定的历史哈希）、"x"。
func (e Entry) lockedHash() bool {
	h := strings.TrimSpace(e.Hash)
	if h == "" || h == "x" {
		return true
	}
	return strings.HasPrefix(h, "!") || strings.HasPrefix(h, "*")
}

// filterUsers 只保留 users 中指定的账户记录（保持文件原有顺序）。
// 返回保留的记录，以及在文件里没找到的用户名（按 users 的给定顺序，已去重）。
func filterUsers(entries []Entry, users []string) (kept []Entry, missing []string) {
	want := make(map[string]struct{}, len(users))
	for _, u := range users {
		want[u] = struct{}{}
	}

	found := make(map[string]struct{}, len(users))
	for _, e := range entries {
		if _, ok := want[e.User]; ok {
			kept = append(kept, e)
			found[e.User] = struct{}{}
		}
	}
	reported := make(map[string]struct{}, len(users))
	for _, u := range users {
		if _, ok := found[u]; ok {
			continue
		}
		if _, ok := reported[u]; ok {
			continue
		}
		reported[u] = struct{}{}
		missing = append(missing, u)
	}
	return kept, missing
}

// Parse 读取并解析 shadow 文件，返回全部账户记录。
//
// shadow 每行格式（字段以 ":" 分隔）:
//
//	username:password:lastchanged:min:max:warn:inactive:expire:reserved
func Parse(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("shadow.err.open_shadow"), err)
	}
	defer f.Close()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimRight(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			return nil, errors.New(i18n.Tf("shadow.err.bad_line", lineNo, line))
		}

		user := strings.TrimSpace(fields[0])
		if user == "" {
			return nil, errors.New(i18n.Tf("shadow.err.no_user", lineNo))
		}

		entries = append(entries, Entry{
			User: user,
			Hash: fields[1],
			Line: lineNo,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("shadow.err.read"), err)
	}
	if len(entries) == 0 {
		return nil, errors.New(i18n.Tf("shadow.err.empty_file", path))
	}
	return entries, nil
}
