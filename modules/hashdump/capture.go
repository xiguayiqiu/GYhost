// 抓包容器接入：把 pcap/pcapng 交给 internal/pcap 读取，逐帧喂给 802.11 收集器。
//
// 容器解析（字节序、时间戳、pcapng 块）统一放在 internal/pcap，
// 这里只保留无线抓包关心的部分：链路类型与帧分发。
//
// 支持范围：
//   - pcap（libpcap，含大小端与微秒/纳秒时间戳精度）
//   - pcapng（Section Header / Interface Description / Enhanced & Simple Packet 块）
//   - 链路类型 802.11(105) / radiotap(127) / Prism(119) / AVS(163)
package hashdump

import (
	"errors"
	"io"

	"gyhost/internal/i18n"
	"gyhost/internal/pcap"
)

// 链路类型（pcap 的 network 字段 / pcapng 的 IDB linktype）。
const (
	linkTypeIEEE80211    = 105
	linkTypePrism        = 119
	linkTypeRadiotap     = 127
	linkTypeIEEE80211AVS = 163
)

// isPCAPMagic 判断是否为 pcap 文件（兼容两种字节序与两种时间戳精度）。
func isPCAPMagic(m []byte) bool { return pcap.IsPCAP(m) }

// isPCAPNGMagic 判断是否为 pcapng 文件（魔数为字节回文，与字节序无关）。
func isPCAPNGMagic(m []byte) bool { return pcap.IsPCAPNG(m) }

// extractCapture 解析 pcap/pcapng 抓包并提取 WPA/WPA2 哈希。
func extractCapture(f io.ReaderAt, size int64, path string) (*Result, error) {
	c := newCollector(path)

	err := pcap.Read(f, size, func(rec pcap.Record) error {
		c.feed(rec.LinkType, rec.Data)
		return nil
	})
	if err != nil {
		if errors.Is(err, pcap.ErrNotCapture) {
			return nil, errors.New(i18n.Tf("hashdump.err.unrecognized", path))
		}
		return nil, errors.New(i18n.Tf("hashdump.err.bad_capture", err))
	}
	return c.result(), nil
}
