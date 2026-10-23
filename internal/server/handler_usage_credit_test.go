package server

import (
	"math"
	"testing"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
	"github.com/misakano7545/workbuddy2api-panel/internal/pool"
)

// 移植上游 PR #104：计费字段合法性闸门（流式/聚合/解析层同口径）。

func TestUsageCreditTotalRequiresValidExplicitCreditAndTokens(t *testing.T) {
	tests := []struct {
		name  string
		usage map[string]any
		want  bool
	}{
		{name: "confirmed free", usage: map[string]any{"credit": float64(0), "total_tokens": float64(10)}, want: true},
		{name: "paid", usage: map[string]any{"credit": float64(0.1), "total_tokens": float64(10)}, want: true},
		{name: "missing credit", usage: map[string]any{"total_tokens": float64(10)}},
		{name: "negative credit", usage: map[string]any{"credit": float64(-0.1), "total_tokens": float64(10)}},
		{name: "nan credit", usage: map[string]any{"credit": math.NaN(), "total_tokens": float64(10)}},
		{name: "infinite credit", usage: map[string]any{"credit": math.Inf(1), "total_tokens": float64(10)}},
		{name: "string credit", usage: map[string]any{"credit": "0", "total_tokens": float64(10)}},
		{name: "missing total", usage: map[string]any{"credit": float64(0)}},
		{name: "zero total", usage: map[string]any{"credit": float64(0), "total_tokens": float64(0)}},
		{name: "negative total", usage: map[string]any{"credit": float64(0), "total_tokens": float64(-1)}},
		{name: "fractional total", usage: map[string]any{"credit": float64(0), "total_tokens": float64(1.5)}},
		{name: "infinite total", usage: map[string]any{"credit": float64(0), "total_tokens": math.Inf(1)}},
		{name: "out of range total", usage: map[string]any{"credit": float64(0), "total_tokens": math.Exp2(63)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credit, total, ok := usageCreditTotal(map[string]any{"usage": tt.usage})
			if ok != tt.want {
				t.Fatalf("usageCreditTotal ok=%v, want %v (credit=%v total=%d)", ok, tt.want, credit, total)
			}
			if ok && (credit < 0 || total <= 0) {
				t.Fatalf("accepted invalid cost fields: credit=%v total=%d", credit, total)
			}
		})
	}
}

// TestUsageTotalTokensInt64BoundaryRejected 2^63 必须拒绝：值域闸门必须在「转换前」，
// 转换后的 round-trip 校验在边界上是失效的。
//
// 钉住的是一类「校验看着对、边界上必失效」的坑，不是编造的极端输入：
//   - float64 尾数只有 52 位，MaxInt64 = 2^63-1 不可精确表示，float64(math.MaxInt64)
//     会舍入回 2^63（下面第一条断言就是这条 spec 级事实，与平台无关）；
//   - 越界 float64 → int 转换是实现定义的（amd64/arm64 上饱和到 MaxInt64）；
//   - 于是旧实现「先 int(total) 再比 float64(parsed) != total」在 total = 2^63 上
//     恒等成立（饱和成 MaxInt64，MaxInt64 又舍回 2^63），越界值被当成合法 token 数
//     放行，usage.credit=0 + total_tokens=2^63 直接通过计费闸门。
//
// 闸门放在转换之前后，只接受严格小于 2^63 的整数：该区间的 float64 整数值都能
// 精确落进 int64，转换无实现定义行为。
func TestUsageTotalTokensInt64BoundaryRejected(t *testing.T) {
	limit := math.Exp2(63) // 2^63

	// spec 级陷阱：2^63 这个 float64 值恰好就是 float64(MaxInt64)（尾数不够，向上舍入）。
	if float64(math.MaxInt64) != limit {
		t.Fatalf("float64(MaxInt64)=%.17g 应等于 2^63=%.17g；若不成立说明 round-trip 校验在边界侥幸可用，需重新评估本用例的前提",
			float64(math.MaxInt64), limit)
	}

	if got, ok := parseUsageTotalTokens(limit); ok {
		t.Fatalf("2^63 越界必须拒绝，got total=%d ok=true（round-trip 校验在边界失效）", got)
	}
	if got, ok := parseUsageTotalTokens(math.Nextafter(limit, math.Inf(1))); ok {
		t.Fatalf("超过 2^63 的值必须拒绝，got total=%d ok=true", got)
	}
	// 阈值内侧最近的可表示整数必须照旧接受：闸门不能误伤合法的大计数
	// （本仓构建目标全为 64 位，int 即 int64）。
	inside := math.Nextafter(limit, 0) // 2^63-1024：小于 2^63 的最大 float64 整数值
	if got, ok := parseUsageTotalTokens(inside); !ok || float64(got) != inside {
		t.Fatalf("2^63 以内最大的 float64 整数应接受，got total=%d ok=%v want %.17g", got, ok, inside)
	}

	// 聚合入口（handler）：与测试表里的 out of range total 同一路径，这里再钉一次确切语义。
	if _, _, ok := usageCreditTotal(map[string]any{"usage": map[string]any{
		"credit": float64(0), "total_tokens": limit,
	}}); ok {
		t.Fatal("usageCreditTotal 必须拒绝 total_tokens=2^63（否则天量 token 会计进成本账本）")
	}

	// 流式入口（logging.go 共用 parseUsageTotalTokens，JSON 数字直接解成 float64）：
	// 越界 total 帧判「未知」并覆盖先前帧，不得采信。
	reader := &chatStatsReader{}
	reader.parseSSELine(`data: {"usage":{"credit":0,"total_tokens":9223372036854775808}}`)
	if total, ok := reader.TotalTokens(); ok {
		t.Fatalf("流式越界 total 必须判未知，got total=%d", total)
	}
}

// TestUsageCreditTotalMissingCreditDoesNotCreateFreeModelObservation 缺 credit 字段
// 不能被当成「确认免费」写进成本账本（否则保底/分层被脏免费证据污染）。
func TestUsageCreditTotalMissingCreditDoesNotCreateFreeModelObservation(t *testing.T) {
	p := pool.New("")
	defer p.Close()
	p.SetCostExploreInterval(0)
	p.SetCreditFloor(100)
	p.SetModelRateOf(func(realm, model string) string {
		if realm == "global" && model == "deepseek-v4.1-flash" {
			return "0.03"
		}
		return ""
	})

	oldGlobal := auth.GlobalEnabled()
	auth.SetGlobalEnabled(true)
	t.Cleanup(func() { auth.SetGlobalEnabled(oldGlobal) })
	p.Add(&auth.Auth{UID: "poor", Domain: "www.workbuddy.ai"})
	p.SetCredits("poor", 99, 0)

	credit, total, known := usageCreditTotal(map[string]any{"usage": map[string]any{
		"prompt_tokens": float64(900), "completion_tokens": float64(100), "total_tokens": float64(1000),
	}})
	if known {
		p.NoteModelCost("poor", "deepseek-v4.1-flash", credit, total)
	}
	status, ok := p.Status("poor")
	if !ok || len(status.ModelCosts) != 0 {
		t.Fatalf("missing credit must not create a free observation: status=%+v ok=%v", status, ok)
	}
	if got := p.PickExcludingForRealm(nil, "deepseek-v4.1-flash", "global"); got != nil {
		t.Fatalf("catalog-paid model below credit floor must remain blocked, got %v", got.UID)
	}
}

// TestUsageCreditTotalAcceptsAndRecordsConfirmedZero 显式 0 是合法的「确认免费」：
// 记入账本后该模型在保底线以下仍可用（tier 0 证据）。
func TestUsageCreditTotalAcceptsAndRecordsConfirmedZero(t *testing.T) {
	p := pool.New("")
	defer p.Close()
	p.SetCostExploreInterval(0)
	p.SetCreditFloor(100)
	p.SetModelRateOf(func(realm, model string) string { return "0.03" })
	p.Add(&auth.Auth{UID: "poor"})
	p.SetCredits("poor", 99, 0)

	credit, total, known := usageCreditTotal(map[string]any{"usage": map[string]any{
		"credit": float64(0), "total_tokens": float64(1000),
	}})
	if !known || credit != 0 || total != 1000 {
		t.Fatalf("explicit zero is a valid free observation, got credit=%v total=%d known=%v", credit, total, known)
	}
	p.NoteModelCost("poor", "free-model", credit, total)
	if got := p.PickExcludingForRealm(nil, "free-model", ""); got == nil || got.UID != "poor" {
		t.Fatalf("confirmed zero-cost model should remain usable below floor, got %v", got)
	}
}

// TestStreamUsageCreditRejectsNegativeAndInvalidTotal 流式解析层：显式 0 保留；
// 负 credit / 小数 total 一律判「未知」（且覆盖先前帧值）。
func TestStreamUsageCreditRejectsNegativeAndInvalidTotal(t *testing.T) {
	reader := &chatStatsReader{}
	reader.parseSSELine(`data: {"usage":{"credit":0,"total_tokens":20.0}}`)
	if credit, ok := reader.Credit(); !ok || credit != 0 {
		t.Fatalf("explicit stream credit zero should be retained, got credit=%v ok=%v", credit, ok)
	}
	if total, ok := reader.TotalTokens(); !ok || total != 20 {
		t.Fatalf("positive integer stream total should be retained, got total=%d ok=%v", total, ok)
	}

	reader.parseSSELine(`data: {"usage":{"credit":-0.1,"total_tokens":20}}`)
	if credit, ok := reader.Credit(); ok {
		t.Fatalf("negative stream credit must be unknown, got credit=%v", credit)
	}
	reader.parseSSELine(`data: {"usage":{"credit":0,"total_tokens":1.5}}`)
	if total, ok := reader.TotalTokens(); ok {
		t.Fatalf("fractional stream total must be unknown, got total=%d", total)
	}
}
