// Package hashcat 实现 GYhost 的算法分析模块：
// 识别文件或哈希使用了什么加密算法/哈希类型，并给出对应的 hashcat 模式号。
//
// 与相邻模块的分工：
//
//	hashdump  导出可离线枚举的原始哈希（面向管道，喂给破解器）
//	hashcat   分析这些哈希属于什么算法、该用哪个 -m（面向人看）
//	hashac    拿字典去枚举这些哈希的明文
//	shadow    专门破解 shadow 文件
//
// 用法: gyhost hashcat -i [文件...]
package hashcat

import (
	"strconv"
	"strings"
)

// 分类（前 5 个与 hashdump 的 Result.Kind 一致；后 3 个只用于 --list 分组，
// 对应"哈希清单"里能识别出的裸摘要、Unix 口令哈希与 Office 文档）。
const (
	kindZip    = "zip"
	kind7z     = "7z"
	kindRar    = "rar"
	kindPDF    = "pdf"
	kindWifi   = "wifi"
	kindDigest = "digest"
	kindCrypt  = "crypt"
	kindOffice = "office"
)

// algoOf 给出条目对应算法的 i18n key 后缀。
//
// hashcat 模式号本身已能区分绝大多数算法，但有几处共用同一模式号，
// 需要再看哈希串才能细分：
//   - PDF -m 10500 同时覆盖 RC4-128 与 AES-128，靠 $pdf$ 的 V/R 区分
//   - WPA -m 22000 同时覆盖 PMKID 与四次握手，靠 WPA*01*/WPA*02* 区分
//   - WinZip AES 的密钥长度写在 $zip2$ 里（128/192/256）
func algoOf(hash, kind string, mode int) string {
	switch mode {
	case 17200:
		return "zipcrypto-deflate"
	case 17210:
		return "zipcrypto-stored"
	case 13600:
		switch zipAESStrength(hash) {
		case 1:
			return "zip-aes128"
		case 2:
			return "zip-aes192"
		default:
			return "zip-aes256"
		}
	case 11600:
		return "7z-aes"
	case 13000:
		return "rar5-aes"
	case 10400:
		return "pdf-rc4-40"
	case 10500:
		if v, r, ok := pdfVR(hash); ok && v >= 4 && r >= 4 {
			return "pdf-aes-128"
		}
		return "pdf-rc4-128"
	case 10600:
		return "pdf-aes-256"
	case 10700:
		return "pdf-aes-256-r6"
	case 22000:
		if strings.HasPrefix(hash, "WPA*01*") {
			return "wpa2-pmkid"
		}
		return "wpa2-eapol"
	case 9400:
		return "office-2007"
	case 9500:
		return "office-2010"
	case 9600:
		return "office-2013"
	case 25300:
		return "office-2016"
	case 9700:
		return "office-2003-md5"
	case 9800:
		return "office-2003-sha1"
	}
	// 兜底：按容器给个笼统的名字
	switch kind {
	case kindZip:
		return "zipcrypto-deflate"
	case kind7z:
		return "7z-aes"
	case kindRar:
		return "rar5-aes"
	case kindPDF:
		return "pdf-rc4-128"
	case kindWifi:
		return "wpa2-eapol"
	}
	return "unknown"
}

// zipAESStrength 从 $zip2$*0*<strength>*... 里取 AES 强度（1/2/3）。
func zipAESStrength(hash string) int {
	f := strings.Split(hash, "*")
	if len(f) < 3 || f[0] != "$zip2$" {
		return 0
	}
	n, err := strconv.Atoi(f[2])
	if err != nil {
		return 0
	}
	return n
}

// pdfVR 从 $pdf$<V>*<R>*... 里取加密版本 V 与修订号 R。
//
// 注意 $pdf$ 与 V 之间没有分隔符，所以 V 粘在第 0 段上（"$pdf$1"），
// R 才是第 1 段——直接比 f[0] 是否等于 "$pdf$" 会永远匹配不上。
func pdfVR(hash string) (int, int, bool) {
	f := strings.Split(hash, "*")
	if len(f) < 2 || !strings.HasPrefix(f[0], "$pdf$") {
		return 0, 0, false
	}
	v, err1 := strconv.Atoi(strings.TrimPrefix(f[0], "$pdf$"))
	r, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return v, r, true
}
