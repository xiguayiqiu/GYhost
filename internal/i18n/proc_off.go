//go:build (android || !linux) && !darwin

package i18n

// procMessages 在本平台为空：proc 模块不存在（Windows 走 WMI，
// Android/Termux 的 /proc 受限），文案也就没必要进二进制。
// 对应 proc.go，二者必须同时提供。
var procMessages map[Lang]map[string]string
