package hashcat

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gyhost/internal/i18n"
	"gyhost/internal/module"
	"gyhost/internal/utils"
	"gyhost/modules/hashdump"
)

// Module hashcat 模块。
type Module struct{}

// New 创建 hashcat 模块。
func New() module.Module { return &Module{} }

// Name 模块名。
func (m *Module) Name() string { return "hashcat" }

// Summary 模块简介（已国际化）。
func (m *Module) Summary() string { return i18n.T("hashcat.summary") }

// Group 模块在帮助信息中的分组（已国际化）。
func (m *Module) Group() string { return i18n.T("hashcat.group") }

// Usage 模块用法说明（已国际化）。
func (m *Module) Usage() string {
	return strings.TrimSpace(i18n.T("hashcat.usage"))
}

// entry 是一条算法分析结果。
type entry struct {
	name  string // 条目名（文件内条目、用户名或"第 N 行"；无则空）
	kind  string // 分类：容器类型（zip/7z/...）或 "hash"（哈希清单条目）
	algo  string // 算法（i18n key 后缀，见 hashcat.algo.*）
	modes []int  // 对应 hashcat 模式号（可能有多个候选；空表示无原生模式）
}

// report 是单个输入的完整分析结果。
type report struct {
	path    string
	entries []entry
	skips   []hashdump.Skip
	// hashList 为 true 表示输入按"哈希清单"而非"加密容器"解析，
	// 两者的后续动作不同：容器要先 hashdump 导出，清单可直接交给 hashcat
	hashList bool
}

// Run 解析参数并执行算法分析。
func (m *Module) Run(args []string) error {
	fs := flag.NewFlagSet("gyhost hashcat", flag.ContinueOnError)
	fs.SetOutput(new(strings.Builder)) // 由本模块自行输出提示，避免重复打印

	var (
		inputs inputList
		quiet  bool
		list   bool
	)
	fs.Var(&inputs, "i", i18n.T("hashcat.flag.input"))
	fs.Var(&inputs, "input", i18n.T("hashcat.flag.input"))
	fs.BoolVar(&quiet, "q", false, i18n.T("hashcat.flag.quiet"))
	fs.BoolVar(&quiet, "quiet", false, i18n.T("hashcat.flag.quiet"))
	fs.BoolVar(&list, "list", false, i18n.T("hashcat.flag.list"))
	fs.Usage = func() { fmt.Println(m.Usage()) }

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Println(m.Usage())
			return nil
		}
		return err
	}

	if list {
		printCatalog(os.Stdout)
		return nil
	}
	if len(inputs) == 0 {
		fmt.Println(m.Usage())
		return errors.New(i18n.T("hashcat.err.missing_args"))
	}

	paths, err := resolveInputs(inputs)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New(i18n.T("hashcat.err.no_input"))
	}

	for _, p := range paths {
		rep := analyze(p)
		printReport(os.Stdout, rep, quiet)
	}
	return nil
}

// analyze 分析单个输入。
//
// 先按加密容器解析（复用 hashdump 的解析器）；若它不是可识别的容器，
// 再退回按"哈希清单"逐行识别算法类型。
func analyze(path string) *report {
	if res, err := hashdump.Extract(path); err == nil {
		rep := &report{path: path, skips: res.Skipped}
		for _, e := range res.Entries {
			rep.entries = append(rep.entries, entry{
				name:  entryName(e),
				kind:  e.Kind,
				algo:  algoOf(e.Hash, e.Kind, e.Mode),
				modes: []int{e.Mode},
			})
		}
		if len(rep.entries) == 0 && len(rep.skips) == 0 {
			rep.skips = append(rep.skips, hashdump.Skip{
				Name: filepath.Base(path), Reason: i18n.T("hashcat.err.empty"),
			})
		}
		return rep
	}

	// 不是加密容器：二进制文件按行扫描只会刷屏，先判定形态再分析
	if !isTextFile(path) {
		rep := &report{path: path}
		rep.skips = append(rep.skips, hashdump.Skip{
			Name: filepath.Base(path), Reason: i18n.T("hashcat.err.binary"),
		})
		return rep
	}

	// 是文本：按哈希清单识别
	rep := analyzeHashList(path)
	rep.hashList = true
	return rep
}

// isTextFile 判断文件是否看起来是文本（可按行分析的哈希清单）。
//
// 判据：前 4 KiB 内没有 NUL，且控制字符占比不超过一成。
// 读取失败时不拦，交给后续流程给出具体的读取错误。
func isTextFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return true
	}
	defer f.Close()

	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	if n == 0 {
		return true
	}
	ctrl := 0
	for _, b := range buf[:n] {
		if b == 0 {
			return false
		}
		if b < 0x09 || (b > 0x0d && b < 0x20) {
			ctrl++
		}
	}
	return ctrl*10 <= n
}

// entryName 取条目名：容器内的条目用条目名，单文件型（PDF/抓包）用文件名。
func entryName(e hashdump.Entry) string {
	if e.Name != "" {
		return e.Name
	}
	return filepath.Base(e.Archive)
}

// analyzeHashList 把输入当作"每行一条哈希"的清单，逐行识别类型。
//
// 兼容三种常见行形态：整行就是一条哈希；shadow 的 user:hash:... ；
// hashcat potfile 的 hash:password。后两者取其中的哈希字段，并优先用
// 前缀字段（用户名）当条目名。
func analyzeHashList(path string) *report {
	rep := &report{path: path}
	f, err := os.Open(path)
	if err != nil {
		rep.skips = append(rep.skips, hashdump.Skip{
			Name: filepath.Base(path), Reason: i18n.Tf("hashdump.err.open", path, err),
		})
		return rep
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		label := i18n.Tf("hashcat.line", line)
		name, algo, modes, ok := splitLineHash(s)
		if !ok {
			rep.skips = append(rep.skips, hashdump.Skip{
				Name: label, Reason: i18n.T("hashcat.err.unknown"),
			})
			continue
		}
		if name == "" {
			name = label
		} else {
			// 影子文件里同一用户可能有多条记录，补上行号便于定位
			name = i18n.Tf("hashcat.named", name, line)
		}
		rep.entries = append(rep.entries, entry{
			name:  name,
			kind:  "hash",
			algo:  algo,
			modes: modes,
		})
	}
	if err := sc.Err(); err != nil {
		rep.skips = append(rep.skips, hashdump.Skip{
			Name: filepath.Base(path), Reason: i18n.Tf("hashdump.err.open", path, err),
		})
	}
	if len(rep.entries) == 0 && len(rep.skips) == 0 {
		rep.skips = append(rep.skips, hashdump.Skip{
			Name: filepath.Base(path), Reason: i18n.T("hashcat.err.empty"),
		})
	}
	return rep
}

// splitLineHash 从一行文本里挑出可识别的哈希并给出算法与模式号。
//
// 整行可识别时原样解析；否则按冒号切开逐段找，命中段之前的首段若是个
// 普通字段（用户名之类），就当作条目名返回。找不到时返回 ok=false。
func splitLineHash(s string) (name, algo string, modes []int, ok bool) {
	if a, m, hit := identifyHash(s); hit {
		return "", a, m, true
	}
	if !strings.Contains(s, ":") {
		return "", "", nil, false
	}
	fields := strings.Split(s, ":")
	for i, f := range fields {
		if a, m, hit := identifyHash(f); hit {
			if i > 0 && isPlainField(fields[0]) {
				name = fields[0]
			}
			return name, a, m, true
		}
	}
	return "", "", nil, false
}

// isPlainField 判断首段是否适合作条目名（非空、不含 $ 与空白）。
func isPlainField(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	return !strings.ContainsAny(s, "$ \t")
}

// identifyHash 按前缀/长度识别一条哈希的类型。
//
// 返回算法 key 与候选 hashcat 模式号。32 位十六进制在 MD5 与 NTLM 之间
// 天然有歧义，两者都返回；yescrypt 在 hashcat 7.x 无原生模式，只返回算法名。
func identifyHash(h string) (string, []int, bool) {
	switch {
	case strings.HasPrefix(h, "WPA*01*"):
		return "wpa2-pmkid", []int{22000}, true
	case strings.HasPrefix(h, "WPA*02*"):
		return "wpa2-eapol", []int{22000}, true
	case strings.HasPrefix(h, "$rar5$"):
		return "rar5-aes", []int{13000}, true
	case strings.HasPrefix(h, "$zip2$"):
		switch zipAESStrength(h) {
		case 1:
			return "zip-aes128", []int{13600}, true
		case 2:
			return "zip-aes192", []int{13600}, true
		default:
			return "zip-aes256", []int{13600}, true
		}
	case strings.HasPrefix(h, "$pkzip2$"):
		f := strings.Split(h, "*")
		if len(f) > 9 && f[9] == "0" {
			return "zipcrypto-stored", []int{17210}, true
		}
		return "zipcrypto-deflate", []int{17200}, true
	case strings.HasPrefix(h, "$7z$"):
		return "7z-aes", []int{11600}, true
	case strings.HasPrefix(h, "$pdf$"):
		v, r, ok := pdfVR(h)
		if !ok {
			return "", nil, false
		}
		switch {
		case v == 1:
			return "pdf-rc4-40", []int{10400}, true
		case v == 5 && r == 6:
			return "pdf-aes-256-r6", []int{10700}, true
		case v == 5:
			return "pdf-aes-256", []int{10600}, true
		case v >= 4 && r >= 4:
			return "pdf-aes-128", []int{10500}, true
		default:
			return "pdf-rc4-128", []int{10500}, true
		}
	case strings.HasPrefix(h, "$office$2016$"):
		// Office 2016+ 的表格保护口令，格式用 $ 分隔而非 *
		return "office-2016", []int{25300}, true
	case strings.HasPrefix(h, "$office$"):
		// $office$*<年份>*... ：前缀与年份之间有分隔符，年份在第 1 段
		f := strings.Split(h, "*")
		if len(f) < 2 {
			return "", nil, false
		}
		switch f[1] {
		case "2007":
			return "office-2007", []int{9400}, true
		case "2010":
			return "office-2010", []int{9500}, true
		case "2013":
			return "office-2013", []int{9600}, true
		}
		return "", nil, false
	case strings.HasPrefix(h, "$oldoffice$"):
		// $oldoffice$<类型>*... ：类型粘在前缀后面，即第 0 段的末尾
		v := strings.TrimPrefix(h, "$oldoffice$")
		if len(v) < 2 || v[1] != '*' {
			return "", nil, false
		}
		switch v[0] {
		case '0', '1':
			return "office-2003-md5", []int{9700}, true
		case '3', '4':
			return "office-2003-sha1", []int{9800}, true
		}
		return "", nil, false
	// ---- Unix/shadow 口令哈希（常见于 /etc/shadow、john/hashcat potfile）----
	case strings.HasPrefix(h, "$apr1$"):
		return "md5crypt-apr1", []int{1600}, true
	case strings.HasPrefix(h, "$1$"):
		return "md5crypt", []int{500}, true
	case strings.HasPrefix(h, "$5$"):
		return "sha256crypt", []int{7400}, true
	case strings.HasPrefix(h, "$6$"):
		return "sha512crypt", []int{1800}, true
	case isBcryptPrefix(h):
		return "bcrypt", []int{3200}, true
	case strings.HasPrefix(h, "$argon2i$"), strings.HasPrefix(h, "$argon2d$"),
		strings.HasPrefix(h, "$argon2id$"):
		return "argon2", []int{34000}, true
	case strings.HasPrefix(h, "$scrypt$"):
		return "scrypt", []int{8900}, true
	case strings.HasPrefix(h, "$pbkdf2-sha256$"):
		return "django-pbkdf2", []int{10000}, true
	case strings.HasPrefix(h, "$y$"):
		// hashcat 7.x 没有 yescrypt 原生模式（需 Python 插件），只给算法名
		return "yescrypt", nil, true
	}

	if !isHex(h) {
		return "", nil, false
	}
	switch len(h) {
	case 32:
		// 裸 MD5 与 NTLM 同为 32 位十六进制，无法区分
		return "md5-ntlm", []int{0, 1000}, true
	case 40:
		return "sha1", []int{100}, true
	case 64:
		return "sha256", []int{1400}, true
	case 128:
		return "sha512", []int{1700}, true
	}
	return "", nil, false
}

// isBcryptPrefix 判断是否为 bcrypt 的 $2*$ 家族前缀（$2$/$2a$/$2b$/$2x$/$2y$）。
func isBcryptPrefix(s string) bool {
	for _, p := range []string{"$2$", "$2a$", "$2b$", "$2x$", "$2y$"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// isHex 判断是否全为十六进制字符。
func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// 输出
// ---------------------------------------------------------------------------

// printReport 输出单个输入的算法分析结果。
//
// quiet 只抑制跳过原因与结尾提示，条目本身始终输出。
func printReport(w io.Writer, rep *report, quiet bool) {
	utils.Plainf(w, "%s %s", utils.Info("[*]"), utils.Bold("%s", rep.path))
	for _, e := range rep.entries {
		label := e.name
		if label == "" {
			label = filepath.Base(rep.path)
		}
		utils.Plainf(w, "    %s", utils.Bold("%s", label))
		utils.Plainf(w, "      %s %s",
			utils.Dim("%s", utils.PadRight(i18n.T("hashcat.label.algo"), 10)),
			i18n.T("hashcat.algo."+e.algo))
		utils.Plainf(w, "      %s %s",
			utils.Dim("%s", utils.PadRight(i18n.T("hashcat.label.mode"), 10)),
			modeText(e.modes))
		if e.kind != "" && e.kind != "hash" {
			utils.Plainf(w, "      %s %s",
				utils.Dim("%s", utils.PadRight(i18n.T("hashcat.label.container"), 10)),
				i18n.T("hashcat.kind."+e.kind))
		}
	}
	if !quiet {
		base := filepath.Base(rep.path)
		for _, s := range rep.skips {
			if s.Name != "" && s.Name != base {
				utils.Warnf(w, "%s %s: %s", utils.Warn("[-]"), s.Name, s.Reason)
				continue
			}
			utils.Warnf(w, "%s %s", utils.Warn("[-]"), s.Reason)
		}
	}
	// 结尾提示按输入形态区分：容器要先导出，清单可直接用
	if len(rep.entries) > 0 && !quiet {
		key := "hashcat.hint.dump"
		if rep.hashList {
			key = "hashcat.hint.crack"
		}
		utils.Plainf(w, "      %s %s",
			utils.Dim("%s", utils.PadRight(i18n.T("hashcat.label.hint"), 10)),
			i18n.T(key))
	}
}

// modeText 把模式号列表渲染成 "-m 0 / -m 1000"；
// 没有原生模式时（如 yescrypt）返回占位说明。
func modeText(modes []int) string {
	if len(modes) == 0 {
		return utils.Warn("%s", i18n.T("hashcat.mode.none"))
	}
	parts := make([]string, 0, len(modes))
	for _, m := range modes {
		parts = append(parts, fmt.Sprintf("-m %d", m))
	}
	return utils.Success("%s", strings.Join(parts, " / "))
}

// printCatalog 输出 GYhost 支持的格式与对应 hashcat 模式（--list）。
func printCatalog(w io.Writer) {
	utils.Titlef(w, "%s", i18n.T("hashcat.list.title"))
	for _, g := range catalog {
		utils.Plainf(w, "")
		utils.Infof(w, "  %s", i18n.T("hashcat.kind."+g.kind))
		for _, row := range g.rows {
			var cell string
			if row.modes == "" {
				cell = utils.Warn("%s", i18n.T("hashcat.mode.none"))
			} else {
				cell = utils.Success("%s", row.modes)
			}
			utils.Plainf(w, "    %s %s",
				utils.PadRight(i18n.T("hashcat.algo."+row.algo), 34), cell)
		}
	}
}

// catalog 是 --list 展示的支持矩阵（与 identifyHash 的识别范围一致）。
// modes 为空串表示该算法在 hashcat 中没有原生模式，打印时用 hashcat.mode.none。
var catalog = []struct {
	kind string
	rows []struct{ algo, modes string }
}{
	{kindDigest, []struct{ algo, modes string }{
		{"md5-ntlm", "-m 0 / -m 1000"},
		{"sha1", "-m 100"},
		{"sha256", "-m 1400"},
		{"sha512", "-m 1700"},
	}},
	{kindCrypt, []struct{ algo, modes string }{
		{"md5crypt", "-m 500"},
		{"md5crypt-apr1", "-m 1600"},
		{"sha256crypt", "-m 7400"},
		{"sha512crypt", "-m 1800"},
		{"bcrypt", "-m 3200"},
		{"scrypt", "-m 8900"},
		{"argon2", "-m 34000"},
		{"django-pbkdf2", "-m 10000"},
		{"yescrypt", ""},
	}},
	{kindOffice, []struct{ algo, modes string }{
		{"office-2007", "-m 9400"},
		{"office-2010", "-m 9500"},
		{"office-2013", "-m 9600"},
		{"office-2016", "-m 25300"},
		{"office-2003-md5", "-m 9700"},
		{"office-2003-sha1", "-m 9800"},
	}},
	{kindZip, []struct{ algo, modes string }{
		{"zipcrypto-deflate", "-m 17200"},
		{"zipcrypto-stored", "-m 17210"},
		{"zip-aes128", "-m 13600"},
		{"zip-aes192", "-m 13600"},
		{"zip-aes256", "-m 13600"},
	}},
	{kind7z, []struct{ algo, modes string }{
		{"7z-aes", "-m 11600"},
	}},
	{kindRar, []struct{ algo, modes string }{
		{"rar5-aes", "-m 13000"},
	}},
	{kindPDF, []struct{ algo, modes string }{
		{"pdf-rc4-40", "-m 10400"},
		{"pdf-rc4-128", "-m 10500"},
		{"pdf-aes-128", "-m 10500"},
		{"pdf-aes-256", "-m 10600"},
		{"pdf-aes-256-r6", "-m 10700"},
	}},
	{kindWifi, []struct{ algo, modes string }{
		{"wpa2-pmkid", "-m 22000"},
		{"wpa2-eapol", "-m 22000"},
	}},
}

// ---------------------------------------------------------------------------
// 输入解析
// ---------------------------------------------------------------------------

// inputList 是 -i 参数的取值类型：支持逗号分隔与重复指定，并自动去重。
type inputList []string

// String 实现 flag.Value，用于回显当前取值。
func (l *inputList) String() string { return strings.Join(*l, ",") }

// Set 追加一个参数值（内部按逗号拆分）。
func (l *inputList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		dup := false
		for _, e := range *l {
			if e == name {
				dup = true
				break
			}
		}
		if !dup {
			*l = append(*l, name)
		}
	}
	return nil
}

// scanExt 是目录扫描时接受的文件扩展名。
var scanExt = map[string]bool{
	".zip": true, ".zipx": true, ".7z": true, ".7za": true, ".rar": true,
	".pdf": true, ".cap": true, ".pcap": true, ".pcapng": true,
	// Office / WPS 文档（加密时同样是可提取口令哈希的容器）
	".doc": true, ".docx": true, ".docm": true,
	".xls": true, ".xlsx": true, ".xlsm": true,
	".ppt": true, ".pptx": true, ".pps": true, ".ppsx": true,
	".wps": true, ".et": true, ".dps": true,
	// 哈希清单常见后缀
	".txt": true, ".hash": true, ".hashes": true,
}

// resolveInputs 展开输入列表：文件原样保留，目录按扩展名扫描；按出现顺序去重。
func resolveInputs(inputs []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range inputs {
		st, err := os.Stat(p)
		if err != nil {
			return nil, errors.New(i18n.Tf("hashdump.err.open", p, err))
		}
		if !st.IsDir() {
			add(p)
			continue
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, errors.New(i18n.Tf("hashdump.err.open", p, err))
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if scanExt[strings.ToLower(filepath.Ext(e.Name()))] {
				add(filepath.Join(p, e.Name()))
			}
		}
	}
	return out, nil
}
