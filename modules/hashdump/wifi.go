// 802.11 / EAPOL 解析：把抓包中的无线帧还原为 hashcat -m 22000（hc22000）哈希行。
//
// 实现对照 hcxtools 的 hcxpcapngtool：
//   - ESSID 取自 beacon / probe response / (re)association request；
//   - PMKID 取自 EAPOL M1 的 key data（RSN PMKID KDE）与 (re)association request 的 RSN IE；
//   - 四次握手按 (AP, STA) 聚合，再按 hcxpcapngtool 的优先级挑一对消息生成哈希行。
//
// 输出行形如：
//
//	WPA*02*MIC*AP*STA*ESSID*ANONCE*EAPOL*MESSAGEPAIR
//	WPA*01*PMKID*AP*STA*ESSID***
package hashdump

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"gyhost/internal/i18n"
)

// 802.11 帧类型与子类型（只保留本模块用到的取值）。
const (
	dot11TypeMgmt = 0
	dot11TypeData = 2

	dot11SubAssocReq   = 0
	dot11SubReassocReq = 2
	dot11SubProbeResp  = 5
	dot11SubBeacon     = 8
)

// 802.11 信息元素（IE）编号。
const (
	ieSSID = 0
	ieRSN  = 48
)

// EAPOL / LLC 相关常量。
const (
	etherTypeEAPOL = 0x888e
	eapolTypeKey   = 3
)

// EAPOL-Key 帧内的固定偏移（相对 EAPOL 帧起始）。
const (
	eapolKeyNonceOff   = 17 // key nonce（AP 侧 ANonce 或 STA 侧 SNonce）
	eapolKeyNonceLen   = 32
	eapolMICOff        = 81 // key MIC
	eapolMICLen        = 16
	eapolKeyDataLenOff = 97 // key data length
	eapolKeyDataOff    = 99 // key data
	eapolKeyMinLen     = eapolMICOff + eapolMICLen
)

// modeWPA2 是 WPA/WPA2 PMKID 与四次握手对应的 hashcat 模式号。
const modeWPA2 = 22000

// 四次握手的消息对编码（hc22000 的 MESSAGEPAIR 字段低 3 位）。
const (
	mpM1M2 = 0 // M1+M2，EAPOL 取 M2（challenge，ANONCE 来自 M1）
	mpM1M4 = 1 // M1+M4，EAPOL 取 M4（需 M4 携带非零 client nonce）
	mpM2M3 = 2 // M2+M3，EAPOL 取 M2（authorized，ANONCE 来自 M3）
	mpM3M4 = 5 // M3+M4，EAPOL 取 M4（需 M4 携带非零 client nonce）
	// mpNC 是 MESSAGEPAIR 的 bit7：置位表示可用 nonce 纠错。
	mpNC = 0x80
)

// eapolMsg 是一条 EAPOL-Key 消息中哈希行需要的字段。
type eapolMsg struct {
	number int    // 消息序号 1..4
	mic    []byte // 16 字节 MIC
	nonce  []byte // 32 字节 key nonce
	frame  []byte // 完整 EAPOL 帧，MIC 字段已置零
}

// handshake 是某个 (AP, STA) 上收集到的四次握手消息（下标 1..4）。
type handshake struct {
	ap, sta []byte
	msg     [5]*eapolMsg
}

// pmkidRec 是一条待输出的 PMKID。
type pmkidRec struct {
	ap, sta []byte
	pmkid   []byte
}

// collector 汇总单个抓包文件中的全部候选素材。
type collector struct {
	path  string
	order []*handshake
	index map[string]*handshake
	ssids map[string][]byte

	pmkids    []pmkidRec
	pmkidSeen map[string]bool

	badLinks map[uint32]bool
}

// newCollector 创建收集器。
func newCollector(path string) *collector {
	return &collector{
		path:      path,
		index:     map[string]*handshake{},
		ssids:     map[string][]byte{},
		pmkidSeen: map[string]bool{},
		badLinks:  map[uint32]bool{},
	}
}

// ---------------------------------------------------------------------------
// 帧分发
// ---------------------------------------------------------------------------

// feed 处理一条链路层帧。
func (c *collector) feed(linkType uint32, pkt []byte) {
	dot11, ok := stripLinkHeader(linkType, pkt)
	if !ok {
		c.badLinks[linkType] = true
		return
	}
	c.parseDot11(dot11)
}

// stripLinkHeader 剥掉链路层封装，返回 802.11 帧。
func stripLinkHeader(linkType uint32, pkt []byte) ([]byte, bool) {
	switch linkType {
	case linkTypeIEEE80211:
		return pkt, true
	case linkTypeRadiotap:
		// radiotap 头长度位于偏移 2（小端 u16）
		if len(pkt) < 4 {
			return nil, false
		}
		n := int(binary.LittleEndian.Uint16(pkt[2:4]))
		if n < 8 || n > len(pkt) {
			return nil, false
		}
		return pkt[n:], true
	case linkTypePrism, linkTypeIEEE80211AVS:
		// Prism / AVS 头长度位于偏移 4（小端 u32）
		if len(pkt) < 8 {
			return nil, false
		}
		n := int(binary.LittleEndian.Uint32(pkt[4:8]))
		if n < 8 || n > len(pkt) {
			return nil, false
		}
		return pkt[n:], true
	}
	return nil, false
}

// parseDot11 按帧类型分发。
func (c *collector) parseDot11(b []byte) {
	if len(b) < 24 {
		return
	}
	fc := binary.LittleEndian.Uint16(b[0:2])
	switch (fc >> 2) & 3 {
	case dot11TypeMgmt:
		c.parseMgmt(fc, b)
	case dot11TypeData:
		c.parseData(fc, b)
	}
}

// parseMgmt 处理管理帧，收集 ESSID 与 PMKID。
func (c *collector) parseMgmt(fc uint16, b []byte) {
	sub := (fc >> 4) & 0x0f
	body := b[24:]

	switch sub {
	case dot11SubBeacon, dot11SubProbeResp:
		// 帧体: timestamp(8) + beacon interval(2) + capability(2) + IEs
		if len(body) < 12 {
			return
		}
		c.setSSID(b[16:22], ieValue(body[12:], ieSSID))

	case dot11SubAssocReq, dot11SubReassocReq:
		// (Re)Association Request 在 Order 位置位时带 HT Control 字段。
		if fc&0x8000 != 0 {
			if len(body) < 4 {
				return
			}
			body = body[4:]
		}
		// 帧体: capability(2) + listen interval(2) [+ current AP(6)] + IEs
		off := 4
		if sub == dot11SubReassocReq {
			off += 6
		}
		if len(body) < off {
			return
		}
		ies := body[off:]
		// Association Request 的 BSSID 是 addr1，STA 是 addr2。
		c.setSSID(b[4:10], ieValue(ies, ieSSID))
		if rsn := ieValue(ies, ieRSN); rsn != nil {
			for _, p := range rsnPMKIDs(rsn) {
				c.addPMKID(mac(b[4:10]), mac(b[10:16]), p)
			}
		}
	}
}

// parseData 处理数据帧：剥掉 MAC 头与 LLC/SNAP 后交给 EAPOL 解析。
func (c *collector) parseData(fc uint16, b []byte) {
	toDS := (fc >> 8) & 1
	fromDS := (fc >> 9) & 1
	if toDS == fromDS {
		return // IBSS / WDS：无法确定 AP 与 STA 的角色
	}

	var ap, sta []byte
	if fromDS == 1 {
		ap, sta = b[10:16], b[4:10] // addr2 = BSSID，addr1 = 目的 STA
	} else {
		ap, sta = b[4:10], b[10:16] // addr1 = BSSID，addr2 = 源 STA
	}

	h := dot11DataHeaderLen(fc)
	if len(b) < h+8 {
		return
	}
	llc := b[h:]
	// LLC/SNAP: AA AA 03 00 00 00 <ethertype>
	if llc[0] != 0xaa || llc[1] != 0xaa || llc[2] != 0x03 ||
		llc[3] != 0x00 || llc[4] != 0x00 || llc[5] != 0x00 {
		return
	}
	if binary.BigEndian.Uint16(llc[6:8]) != etherTypeEAPOL {
		return
	}
	c.addEAPOL(mac(ap), mac(sta), llc[8:])
}

// dot11DataHeaderLen 返回数据帧 MAC 头的长度。
func dot11DataHeaderLen(fc uint16) int {
	n := 24
	if fc&0x0300 == 0x0300 { // toDS 与 fromDS 同时置位 → 含 addr4
		n += 6
	}
	if (fc>>4)&0x08 != 0 { // QoS 子类型
		n += 2
	}
	if fc&0x8000 != 0 { // Order → HT Control
		n += 4
	}
	return n
}

// ---------------------------------------------------------------------------
// EAPOL-Key
// ---------------------------------------------------------------------------

// addEAPOL 解析一条 EAPOL 帧并归入对应的 (AP, STA) 握手。
func (c *collector) addEAPOL(ap, sta, b []byte) {
	m := parseEAPOLKey(b)
	if m == nil {
		return
	}
	hs := c.handshakeFor(ap, sta)
	if hs.msg[m.number] == nil {
		hs.msg[m.number] = m
	}
	// M1 的 key data 里可能带 PMKID KDE。
	if m.number == 1 {
		if p := keyDataPMKID(m.frame); p != nil {
			c.addPMKID(ap, sta, p)
		}
	}
}

// parseEAPOLKey 解析 EAPOL-Key 帧；非 EAPOL-Key 或字段不全时返回 nil。
func parseEAPOLKey(b []byte) *eapolMsg {
	if len(b) < 4 || b[1] != eapolTypeKey {
		return nil
	}
	total := 4 + int(binary.BigEndian.Uint16(b[2:4]))
	if total > len(b) {
		total = len(b) // 抓包被 snaplen 截断，按实际长度处理
	}
	if total < eapolKeyMinLen {
		return nil
	}

	frame := append([]byte(nil), b[:total]...)
	mic := append([]byte(nil), frame[eapolMICOff:eapolMICOff+eapolMICLen]...)
	keyInfo := binary.BigEndian.Uint16(frame[5:7])
	number := eapolMsgNumber(keyInfo)
	if number == 0 {
		return nil
	}
	// M2/M3/M4 的 MIC 位应当置位且 MIC 非零；M1 无 MIC。
	if (keyInfo>>8)&1 == 1 && isZero(mic) {
		return nil
	}
	// 哈希行中的 EAPOL 帧必须把 MIC 字段置零。
	for i := eapolMICOff; i < eapolMICOff+eapolMICLen; i++ {
		frame[i] = 0
	}
	return &eapolMsg{
		number: number,
		mic:    mic,
		nonce:  append([]byte(nil), frame[eapolKeyNonceOff:eapolKeyNonceOff+eapolKeyNonceLen]...),
		frame:  frame,
	}
}

// eapolMsgNumber 由 key information 判定消息序号（1..4），无法判定返回 0。
//
// ACK / MIC / Secure 三个标志位足以区分四条消息：
//
//	M1: ACK=1 MIC=0         M3: ACK=1 MIC=1
//	M2: ACK=0 MIC=1 Sec=0   M4: ACK=0 MIC=1 Sec=1
func eapolMsgNumber(keyInfo uint16) int {
	ack := (keyInfo >> 7) & 1
	mic := (keyInfo >> 8) & 1
	secure := (keyInfo >> 9) & 1
	switch {
	case ack == 1 && mic == 0:
		return 1
	case ack == 1 && mic == 1:
		return 3
	case ack == 0 && mic == 1 && secure == 0:
		return 2
	case ack == 0 && mic == 1 && secure == 1:
		return 4
	}
	return 0
}

// keyDataPMKID 从 EAPOL-Key 的 key data 中取出 RSN PMKID KDE。
//
// KDE 形如: dd <len> 00 0f ac 04 <16 字节 PMKID>
func keyDataPMKID(frame []byte) []byte {
	if len(frame) < eapolKeyDataOff+2 {
		return nil
	}
	kdLen := int(binary.BigEndian.Uint16(frame[eapolKeyDataLenOff : eapolKeyDataLenOff+2]))
	if kdLen == 0 || eapolKeyDataOff+kdLen > len(frame) {
		return nil
	}
	kd := frame[eapolKeyDataOff : eapolKeyDataOff+kdLen]
	for i := 0; i+2 <= len(kd); {
		id := kd[i]
		ln := int(kd[i+1])
		if i+2+ln > len(kd) {
			return nil
		}
		body := kd[i+2 : i+2+ln]
		if id == 0xdd && ln == 20 &&
			body[0] == 0x00 && body[1] == 0x0f && body[2] == 0xac && body[3] == 0x04 {
			return append([]byte(nil), body[4:20]...)
		}
		i += 2 + ln
	}
	return nil
}

// rsnPMKIDs 解析 RSN IE 中的 PMKID 列表。
//
// 布局: version(2) group(4) pairwiseCnt(2)+.. akmCnt(2)+.. caps(2) pmkidCnt(2)+16*n
func rsnPMKIDs(rsn []byte) [][]byte {
	r := newReader(rsn)
	r.u16()                  // version
	r.skip(4)                // group cipher suite
	r.skip(int(r.u16()) * 4) // pairwise cipher suites
	r.skip(int(r.u16()) * 4) // AKM suites
	r.skip(2)                // RSN capabilities
	n := int(r.u16())
	if r.err != nil || n <= 0 {
		return nil
	}
	var out [][]byte
	for i := 0; i < n && r.err == nil; i++ {
		p := r.take(16)
		if r.err != nil {
			break
		}
		out = append(out, append([]byte(nil), p...))
	}
	return out
}

// ---------------------------------------------------------------------------
// 收集
// ---------------------------------------------------------------------------

// handshakeFor 取出或新建 (AP, STA) 对应的握手（保持首次出现顺序）。
func (c *collector) handshakeFor(ap, sta []byte) *handshake {
	k := hexKey(ap) + hexKey(sta)
	if hs, ok := c.index[k]; ok {
		return hs
	}
	hs := &handshake{ap: ap, sta: sta}
	c.index[k] = hs
	c.order = append(c.order, hs)
	return hs
}

// setSSID 记录 BSSID 的 ESSID（只记第一个可用的，忽略后续 ESSID 变更）。
func (c *collector) setSSID(bssid, ssid []byte) {
	if !usableSSID(ssid) {
		return
	}
	k := hexKey(bssid)
	if _, ok := c.ssids[k]; !ok {
		c.ssids[k] = append([]byte(nil), ssid...)
	}
}

// addPMKID 记录一条 PMKID（按 AP/STA/PMKID 去重）。
func (c *collector) addPMKID(ap, sta, pmkid []byte) {
	if len(pmkid) != 16 || isZero(pmkid) {
		return
	}
	k := hexKey(ap) + hexKey(sta) + hexKey(pmkid)
	if c.pmkidSeen[k] {
		return
	}
	c.pmkidSeen[k] = true
	c.pmkids = append(c.pmkids, pmkidRec{ap: ap, sta: sta, pmkid: pmkid})
}

// ---------------------------------------------------------------------------
// 输出
// ---------------------------------------------------------------------------

// build 生成 hashcat -m 22000 的 EAPOL 哈希行。
//
// 优先级与 hcxpcapngtool 一致：M2+M3（authorized）> M1+M2（challenge）
// > M3+M4 > M1+M4（后两者要求 M4 携带非零的 client nonce）。EAPOL 一律取
// 携带 MIC 的那一条（M2 或 M4），ANONCE 取 AP 侧（M1 或 M3）。
func (h *handshake) build(ssid []byte) (string, bool) {
	var (
		msg    *eapolMsg
		anonce []byte
		pair   int
	)
	switch {
	case h.msg[2] != nil && h.msg[3] != nil:
		msg, anonce, pair = h.msg[2], h.msg[3].nonce, mpM2M3
	case h.msg[1] != nil && h.msg[2] != nil:
		msg, anonce, pair = h.msg[2], h.msg[1].nonce, mpM1M2
	case h.msg[3] != nil && h.msg[4] != nil && !isZero(h.msg[4].nonce):
		msg, anonce, pair = h.msg[4], h.msg[3].nonce, mpM3M4
	case h.msg[1] != nil && h.msg[4] != nil && !isZero(h.msg[4].nonce):
		msg, anonce, pair = h.msg[4], h.msg[1].nonce, mpM1M4
	default:
		return "", false
	}
	if isZero(anonce) {
		return "", false
	}
	// 抓到 M1 说明可用 nonce 纠错，置 bit7（hcxpcapngtool 同样处理）。
	if h.msg[1] != nil {
		pair |= mpNC
	}
	return fmt.Sprintf("WPA*02*%s*%s*%s*%s*%s*%s*%02x",
		hexLower(msg.mic),
		hexLower(h.ap),
		hexLower(h.sta),
		hexLower(ssid),
		hexLower(anonce),
		hexLower(msg.frame),
		pair,
	), true
}

// result 汇总提取结果。
func (c *collector) result() *Result {
	res := &Result{Path: c.path, Kind: "wifi"}

	for _, p := range c.pmkids {
		ssid := c.ssids[hexKey(p.ap)]
		if !usableSSID(ssid) {
			res.addSkip(hexLower(p.ap), i18n.T("hashdump.skip.no_ssid"))
			continue
		}
		line := fmt.Sprintf("WPA*01*%s*%s*%s*%s***",
			hexLower(p.pmkid), hexLower(p.ap), hexLower(p.sta), hexLower(ssid))
		res.addEntry(i18n.Tf("hashdump.wifi.entry.pmkid", ssidText(ssid), hexLower(p.ap)), modeWPA2, line)
	}

	for _, hs := range c.order {
		label := hexLower(hs.ap) + "/" + hexLower(hs.sta)
		ssid := c.ssids[hexKey(hs.ap)]
		if !usableSSID(ssid) {
			res.addSkip(label, i18n.T("hashdump.skip.no_ssid"))
			continue
		}
		line, ok := hs.build(ssid)
		if !ok {
			res.addSkip(label, i18n.T("hashdump.skip.incomplete"))
			continue
		}
		res.addEntry(i18n.Tf("hashdump.wifi.entry.eapol", ssidText(ssid), hexLower(hs.ap), hexLower(hs.sta)), modeWPA2, line)
	}

	// 整包都是不支持的链路类型时给出解释，避免"0 个哈希"无从排查。
	if len(res.Entries) == 0 {
		for lt := range c.badLinks {
			res.addSkip(i18n.T("hashdump.wifi.capture"), i18n.Tf("hashdump.skip.linktype", lt))
		}
	}
	return res
}

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

// mac 复制一个 MAC 地址。
func mac(b []byte) []byte { return append([]byte(nil), b...) }

// hexKey 把字节串转成可作 map 键的十六进制串。
func hexKey(b []byte) string { return hex.EncodeToString(b) }

// isZero 判断字节串是否全为 0（空串视为 true）。
func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// usableSSID 判断 ESSID 是否可用于生成哈希（隐藏/全零/超长一律不可用）。
func usableSSID(s []byte) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for _, b := range s {
		if b != 0 {
			return true
		}
	}
	return false
}

// ssidText 把 ESSID 渲染成可读文本：可打印 ASCII 原样显示，否则退化为十六进制。
func ssidText(ssid []byte) string {
	for _, b := range ssid {
		if b < 0x20 || b > 0x7e {
			return hexLower(ssid)
		}
	}
	return string(ssid)
}

// ieValue 返回第一个 tag 匹配的 IE 值；没有匹配返回 nil。
func ieValue(ies []byte, tag byte) []byte {
	for i := 0; i+2 <= len(ies); {
		id := ies[i]
		ln := int(ies[i+1])
		if i+2+ln > len(ies) {
			return nil
		}
		if id == tag {
			return ies[i+2 : i+2+ln]
		}
		i += 2 + ln
	}
	return nil
}
