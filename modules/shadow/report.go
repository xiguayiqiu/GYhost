package shadow

import (
	"fmt"
	"io"
	"strings"

	"gyhost/internal/i18n"
	"gyhost/internal/utils"
)

// printReport 输出彩色的爆破统计与未破解目标（文案已国际化）。
//
// 配色约定：
//   - 分隔线/标题：青色粗体
//   - 统计信息 [*]：蓝色粗体，关键数字按语义着色（已破=绿、跳过=黄、耗时=暗色）
//   - 跳过账户 [-]：黄色粗体，用户名白粗体，哈希暗色
//   - 未破解 [!]：红色粗体
//   - 全部命中 [+]：绿色粗体
func printReport(w io.Writer, r *Report) {
	utils.Titlef(w, "%s", strings.Repeat("-", 60))
	utils.Infof(w, i18n.T("shadow.report.summary"),
		utils.Success("%d", r.Targets),
		utils.Warn("%d", len(r.Skipped)),
		utils.Success("%d", r.Cracked()))
	statsKey := "shadow.report.stats"
	if r.Masked {
		statsKey = "shadow.report.stats_mask"
	}
	utils.Infof(w, i18n.T(statsKey),
		utils.Title("%d", r.WordlistLen),
		utils.Title("%d", r.Attempts),
		utils.Dim("%s", fmt.Sprintf("%.2fs", r.Duration.Seconds())),
		utils.Success("%.0f", r.Speed()))
	if r.GPU != "" {
		utils.Infof(w, i18n.T("shadow.report.gpu"),
			utils.Success("%s", r.GPU),
			utils.Title("%d", r.GPUMemMB))
	}

	for _, s := range r.Skipped {
		// s.Reason 在分拣阶段已按当前语言生成，这里直接使用
		utils.Warnf(w, i18n.T("shadow.report.skip"),
			utils.Bold("%s", s.User),
			s.Reason,
			utils.Dim("%s", s.Hash))
	}

	if len(r.Pending) > 0 {
		utils.Errorf(w, i18n.T("shadow.report.pending"),
			utils.Error("%d", len(r.Pending)),
			utils.Warn("%s", strings.Join(r.Pending, ", ")))
		utils.Warnf(w, "%s", i18n.T("shadow.report.hint"))
	} else if r.Cracked() > 0 {
		utils.Successf(w, "%s", i18n.T("shadow.report.all_done"))
	}
}
