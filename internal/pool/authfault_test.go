package pool

// 类型化认证故障（auth_fault / needs_relogin）与「重登录成功后的窄口径恢复」。
//
// 本文件防的回归（issue #215 复盘里最贵的几个）：
//   - 认证失效账号只能靠「解冻」恢复：Revive 会把管理员暂停、模型级冷却、熔断、
//     连败降权一起清空——一次重登录等于把运维手工积累的状态全抹掉。
//     新口径必须只清认证故障域（ClearAuthFault），其余原样保留；
//   - 非认证原因的禁用（管理员手点 / 上游 11140 风控）被误判成「需重登」，
//     面板给出重登入口，甚至 ClearAuthFault 把这类禁用也解掉；
//   - 重登录「删号重建」：账号池指针、历史统计（success/err）、优先级/份额/冷却态脱节，
//     磁盘上多出一个凭证文件；
//   - auth_fault 不持久化：重启后面板只剩一个没有来由的 disabled 账号。
//
// 只断言语义（经 Status / AuthByUID / List / state.json 观察），不钉死内部实现。

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
)

// entryView 直接读 entry 的惩罚域原始字段（Status 不透出全部维度，如 modelCooldowns 数量）。
type entryView struct {
	paused         bool
	until          time.Time
	softStreak     int
	modelCooldowns int
	breakerUntil   time.Time
	degradeUntil   time.Time
	credits        int64
	creditsTotal   int64
	sessionDead    int
	authFault      AuthFault
}

func viewOf(t *testing.T, p *Pool, uid string) entryView {
	t.Helper()
	p.mu.RLock()
	defer p.mu.RUnlock()
	e, ok := p.byUID[uid]
	if !ok {
		t.Fatalf("账号 %s 不在池内", uid)
	}
	return entryView{
		paused:         e.paused,
		until:          e.until,
		softStreak:     e.softStreak,
		modelCooldowns: len(e.modelCooldowns),
		breakerUntil:   e.breakerUntil,
		degradeUntil:   e.degradeUntil,
		credits:        e.credits,
		creditsTotal:   e.creditsTotal,
		sessionDead:    e.sessionDeadFails,
		authFault:      e.authFault,
	}
}

// TestDisableAuthMarksNeedsRelogin DisableAuth = 禁用 + 类型化认证故障标记：
// Status 必须同时给出 needs_relogin=true 与正确的 auth_fault（面板据此显示重登按钮）。
func TestDisableAuthMarksNeedsRelogin(t *testing.T) {
	cases := []struct {
		name  string
		fault AuthFault
		// JSON 里的字面值：前端按这个值判定「重登」文案，不可漂移。
		wantJSON string
	}{
		{"业务 12153", AuthFaultSessionDead, "session_dead"},
		{"网关 401", AuthFaultGateway401, "gateway_401"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := New("")
			p.Add(&auth.Auth{UID: "u1", AccessToken: "at"})
			if !p.DisableAuth("u1", "12153 session dead", c.fault) {
				t.Fatal("DisableAuth 应返回 true（账号存在）")
			}
			st, ok := p.Status("u1")
			if !ok {
				t.Fatal("no status")
			}
			if !st.Disabled {
				t.Fatalf("应 disabled: %+v", st)
			}
			if st.AuthFault != string(c.fault) {
				t.Errorf("auth_fault=%q want %q", st.AuthFault, string(c.fault))
			}
			if !st.NeedsRelogin {
				t.Error("needs_relogin 应为 true（disabled && authFault 非空）")
			}
			if st.AuthFaultAt.IsZero() {
				t.Error("auth_fault_at 应记录打标时刻")
			}
			if got := p.AuthFaultOf("u1"); got != c.fault {
				t.Errorf("AuthFaultOf=%q want %q", got, c.fault)
			}
			// 面板契约：JSON 字段名与取值固定（前端直接读）。
			raw, err := json.Marshal(st)
			if err != nil {
				t.Fatalf("marshal status: %v", err)
			}
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("unmarshal status: %v", err)
			}
			if doc["auth_fault"] != c.wantJSON {
				t.Errorf("JSON auth_fault=%v want %q", doc["auth_fault"], c.wantJSON)
			}
			if doc["needs_relogin"] != true {
				t.Errorf("JSON needs_relogin=%v want true", doc["needs_relogin"])
			}
		})
	}
	// 不存在的 uid 不 panic、返回 false；AuthFaultOf 返回无故障。
	p := New("")
	if p.DisableAuth("nope", "x", AuthFaultSessionDead) {
		t.Error("不存在的 uid 应返回 false")
	}
	if got := p.AuthFaultOf("nope"); got != AuthFaultNone {
		t.Errorf("AuthFaultOf(不存在)=%q want 空", got)
	}
}

// TestNonAuthDisableClearsAuthFault 非认证原因的禁用（管理员手点、上游 11140 风控）
// 必须清掉上一次的认证标记：否则面板会在一个「被管理员禁用」的账号上显示「需重登」，
// 且 ClearAuthFault 会误把这禁用解掉。
func TestNonAuthDisableClearsAuthFault(t *testing.T) {
	p := New("")
	p.Add(&auth.Auth{UID: "u1", AccessToken: "at"})
	p.DisableAuth("u1", "12153 session dead", AuthFaultSessionDead)
	if st, _ := p.Status("u1"); !st.NeedsRelogin {
		t.Fatal("precondition: 应处于需重登态")
	}

	p.Disable("u1", "account restricted by upstream (11140 request illegal)")

	st, _ := p.Status("u1")
	if !st.Disabled {
		t.Fatal("非认证禁用仍然要禁用")
	}
	if st.NeedsRelogin || st.AuthFault != "" {
		t.Errorf("非认证禁用必须清认证标记: needs_relogin=%v auth_fault=%q", st.NeedsRelogin, st.AuthFault)
	}
	if st.AuthFaultAt.IsZero() == false {
		t.Error("auth_fault_at 应归零")
	}
	// 既然不是认证故障，ClearAuthFault 不得解除它。
	if p.ClearAuthFault("u1") {
		t.Error("无认证故障时 ClearAuthFault 应返回 false（no-op）")
	}
	if st2, _ := p.Status("u1"); !st2.Disabled {
		t.Error("ClearAuthFault 不得解除管理员/风控的禁用")
	}
}

// TestClearAuthFaultOnlyClearsAuthDomain 重登录成功的恢复口径：只清认证故障域，
// 其余惩罚/观测状态一律保留。若退化成 Revive（解冻），下面每一项都会被清空。
func TestClearAuthFaultOnlyClearsAuthDomain(t *testing.T) {
	p := New("")
	p.Add(&auth.Auth{UID: "u1", AccessToken: "at"})
	p.DisableAuth("u1", "12153 session dead", AuthFaultSessionDead)
	// 认证失效期间照常发生的其它状态（运维暂停、限流冷却、熔断、连败降权、余额快照）：
	// 它们各有权威恢复证据，与「凭据换了新的」无关，重登录无权替运维清零。
	if !p.Pause("u1") {
		t.Fatal("precondition: Pause")
	}
	p.SetCredits("u1", 777, 2000)
	p.CooldownSoftRate("u1", time.Minute, time.Time{}, "429 rate limit") // until + softStreak=1
	// 6004 模型级独立冷却（resetAt 非零 → 进 modelCooldowns 台账）。
	p.CooldownSoftForModel("u1", time.Minute, time.Now().Add(5*time.Minute), "glm-test", "6004")
	p.SetBreaker(1, time.Hour, time.Hour)
	p.NoteError("u1") // 触发熔断
	p.SetDegrade(1, time.Hour, time.Hour)
	p.NoteFailures("u1") // 触发连败降权

	before := viewOf(t, p, "u1")
	if !before.paused || before.until.IsZero() || before.softStreak == 0 ||
		before.modelCooldowns == 0 || before.breakerUntil.IsZero() || before.degradeUntil.IsZero() {
		t.Fatalf("precondition: 惩罚域未全部置位: %+v", before)
	}
	if before.authFault != AuthFaultSessionDead {
		t.Fatalf("precondition: authFault=%q", before.authFault)
	}

	if !p.ClearAuthFault("u1") {
		t.Fatal("ClearAuthFault 应返回 true（确有认证故障被清除）")
	}

	st, _ := p.Status("u1")
	if st.Disabled {
		t.Error("认证禁用应被解除")
	}
	if st.NeedsRelogin || st.AuthFault != "" {
		t.Errorf("认证标记应清除: needs_relogin=%v auth_fault=%q", st.NeedsRelogin, st.AuthFault)
	}
	if got := p.AuthFaultOf("u1"); got != AuthFaultNone {
		t.Errorf("AuthFaultOf=%q want 空", got)
	}

	after := viewOf(t, p, "u1")
	if !after.paused {
		t.Error("管理员暂停选号不得被 ClearAuthFault 清掉")
	}
	if after.until != before.until || after.softStreak != before.softStreak {
		t.Errorf("软限流冷却域被改动: until %v→%v softStreak %d→%d",
			before.until, after.until, before.softStreak, after.softStreak)
	}
	if after.modelCooldowns != before.modelCooldowns {
		t.Errorf("模型级冷却台账被改动: %d→%d", before.modelCooldowns, after.modelCooldowns)
	}
	if after.breakerUntil != before.breakerUntil {
		t.Errorf("熔断截止被改动: %v→%v", before.breakerUntil, after.breakerUntil)
	}
	if after.degradeUntil != before.degradeUntil {
		t.Errorf("连败降权截止被改动: %v→%v", before.degradeUntil, after.degradeUntil)
	}
	if after.credits != 777 || after.creditsTotal != 2000 {
		t.Errorf("余额快照被改动: credits=%d total=%d", after.credits, after.creditsTotal)
	}
	// 连续 12153 计数作废（账号已被证明活着）。
	if after.sessionDead != 0 {
		t.Errorf("session_dead_fails=%d want 0", after.sessionDead)
	}
	// 冷却/降权仍在 → 账号不该立刻回到选号池（恢复凭据 ≠ 恢复可用性）。
	if p.Pick() != nil {
		t.Error("仍处于冷却/降权/暂停的账号不应被选中")
	}
}

// TestClearAuthFaultKeepsNonAuthDisable 非认证原因的 disabled 不会被解除：
// authFault 是「这次禁用是不是认证造成的」唯一判据。
func TestClearAuthFaultKeepsNonAuthDisable(t *testing.T) {
	p := New("")
	p.Add(&auth.Auth{UID: "u1", AccessToken: "at"})
	p.Disable("u1", "manual disable by admin")
	// 阈值内的网关 401 只累计计数、不打故障标记（未判死）。
	p.NoteSessionDeadWith("u1", "401 invalid token (re-login required)")
	if got := viewOf(t, p, "u1").sessionDead; got == 0 {
		t.Fatal("precondition: 应累计一次 session dead 计数")
	}

	if !p.ClearAuthFault("u1") {
		t.Fatal("有连续计数时 ClearAuthFault 应返回 true")
	}
	if v := viewOf(t, p, "u1"); v.sessionDead != 0 {
		t.Errorf("session_dead_fails=%d want 0", v.sessionDead)
	}
	st, _ := p.Status("u1")
	if !st.Disabled {
		t.Error("非认证原因的禁用不得被解除")
	}
	if st.DisabledReason != "manual disable by admin" {
		t.Errorf("禁用原因被改动: %q", st.DisabledReason)
	}
	if p.ClearAuthFault("u1") {
		t.Error("第二次 ClearAuthFault 应为 no-op（false）")
	}
}

// TestReplaceCredentialsKeepsPoolIdentityAndStats 原位替换凭据的全部「不许变」：
// 同一个 *auth.Auth 指针、账号条目数、历史统计、优先级/份额/余额/冷却态。
// 一旦退化成「删号重建」，运维会看到账号的优先级与统计凭空消失，事后无法复盘。
func TestReplaceCredentialsKeepsPoolIdentityAndStats(t *testing.T) {
	dir := t.TempDir()
	old := &auth.Auth{
		AccessToken:  "at-old",
		RefreshToken: "rt-old",
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		Domain:       "copilot.tencent.com",
		UID:          "u1",
		Nickname:     "Old",
		FilePath:     filepath.Join(dir, "workbuddy-u1.json"),
	}
	if err := old.SaveAtomic(); err != nil {
		t.Fatalf("precondition: save old credentials: %v", err)
	}

	p := New("")
	p.Add(old)
	dirtyState := func() {
		p.SetCredits("u1", 1234, 5000)
		p.NoteSuccess("u1") // successCount=1
		p.NoteError("u1")   // errTotal=1
		p.SetAccountPriority(map[string]int{"u1": 7})
		p.SetAccountShare(map[string]float64{"u1": 0.25})
		p.CooldownSoftRate("u1", time.Minute, time.Time{}, "429 rate limit")
	}
	dirtyState()
	p.DisableAuth("u1", "12153 session dead", AuthFaultSessionDead)

	ptrBefore := p.AuthByUID("u1")
	stBefore, _ := p.Status("u1")
	listBefore := len(p.List())
	if stBefore.SuccessCount == 0 || stBefore.ErrTotal == 0 || stBefore.Priority != 7 || stBefore.Share != 0.25 {
		t.Fatalf("precondition: 统计/偏好未置位: %+v", stBefore)
	}
	// 重新登录只换凭据：冷却态（429 冷却）应原样保留，不该被顺手清掉。
	viewBefore := viewOf(t, p, "u1")

	src := &auth.Auth{
		AccessToken:  "at-new",
		RefreshToken: "rt-new",
		ExpiresAt:    time.Now().Add(2 * time.Hour).Unix(),
		Domain:       "copilot.tencent.com",
		UID:          "u1",
		Nickname:     "New",
		FilePath:     old.FilePath,
	}
	if _, err := p.ReplaceCredentials("u1", src); err != nil {
		t.Fatalf("ReplaceCredentials: %v", err)
	}

	if got := p.AuthByUID("u1"); got != ptrBefore {
		t.Error("*auth.Auth 指针身份必须不变（handler/scheduler 手里在途的指针仍要有效）")
	}
	if got := len(p.List()); got != listBefore {
		t.Errorf("账号数 %d→%d（重登录绝不新增账号）", listBefore, got)
	}
	stAfter, _ := p.Status("u1")
	if stAfter.SuccessCount != stBefore.SuccessCount || stAfter.ErrTotal != stBefore.ErrTotal {
		t.Errorf("历史统计被重置: success %d→%d err %d→%d",
			stBefore.SuccessCount, stAfter.SuccessCount, stBefore.ErrTotal, stAfter.ErrTotal)
	}
	if stAfter.Priority != 7 || stAfter.Share != 0.25 {
		t.Errorf("优先级/份额被重置: priority=%d share=%v", stAfter.Priority, stAfter.Share)
	}
	if stAfter.Credits != 1234 || stAfter.CreditsTotal != 5000 {
		t.Errorf("余额快照被重置: credits=%d total=%d", stAfter.Credits, stAfter.CreditsTotal)
	}
	viewAfter := viewOf(t, p, "u1")
	if viewAfter.until != viewBefore.until || viewAfter.softStreak != viewBefore.softStreak {
		t.Errorf("冷却态被改动: until %v→%v softStreak %d→%d",
			viewBefore.until, viewAfter.until, viewBefore.softStreak, viewAfter.softStreak)
	}
	// 认证禁用与故障标记被解除（账号已恢复），凭据已换新。
	if stAfter.Disabled || stAfter.NeedsRelogin || stAfter.AuthFault != "" {
		t.Errorf("重登后应恢复: disabled=%v needs_relogin=%v auth_fault=%q",
			stAfter.Disabled, stAfter.NeedsRelogin, stAfter.AuthFault)
	}
	if got := ptrBefore.AccessTokenValue(); got != "at-new" {
		t.Errorf("池内凭据未换新: accessToken=%q want at-new", got)
	}
	// 磁盘：原文件被换新，且没有第二个凭证文件。
	raw, err := os.ReadFile(old.FilePath)
	if err != nil {
		t.Fatalf("read credentials: %v", err)
	}
	parsed, err := auth.Parse(raw)
	if err != nil {
		t.Fatalf("parse credentials: %v", err)
	}
	if parsed.AccessToken != "at-new" || parsed.RefreshToken != "rt-new" {
		t.Errorf("磁盘凭据未换新: %q/%q", parsed.AccessToken, parsed.RefreshToken)
	}
	if parsed.DeviceToken != "" && old.DeviceToken == "" {
		t.Errorf("不应凭空出现 device_token: %q", parsed.DeviceToken)
	}
}

// TestReplaceCredentialsUnknownUID 按 uid 操作的运维入口要能区分「账号不存在」。
func TestReplaceCredentialsUnknownUID(t *testing.T) {
	p := New("")
	p.Add(&auth.Auth{UID: "u1", AccessToken: "at"})
	_, err := p.ReplaceCredentials("nope", &auth.Auth{AccessToken: "at-new", UID: "nope"})
	if !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("err=%v want ErrAccountNotFound", err)
	}
	if _, err := p.ReplaceCredentials("u1", nil); err == nil {
		t.Fatal("nil src 应报错")
	}
	// 池内账号不受影响。
	if got := p.AuthByUID("u1").AccessTokenValue(); got != "at" {
		t.Errorf("失败调用不得改动池内凭据: %q", got)
	}
}

// TestReplaceCredentialsFailureKeepsAccountState 替换失败（身份不符/空 token/写盘失败）
// 时账号状态与旧凭证必须原样：这是「接口不许返回假成功」在池层的最后一道保证。
func TestReplaceCredentialsFailureKeepsAccountState(t *testing.T) {
	setup := func(t *testing.T) (*Pool, *auth.Auth) {
		t.Helper()
		dir := t.TempDir()
		a := &auth.Auth{
			AccessToken:  "at-old",
			RefreshToken: "rt-old",
			ExpiresAt:    time.Now().Add(time.Hour).Unix(),
			Domain:       "copilot.tencent.com",
			UID:          "u1",
			FilePath:     filepath.Join(dir, "workbuddy-u1.json"),
		}
		if err := a.SaveAtomic(); err != nil {
			t.Fatalf("save: %v", err)
		}
		p := New("")
		p.Add(a)
		p.DisableAuth("u1", "12153 session dead", AuthFaultSessionDead)
		return p, a
	}

	t.Run("UID 不一致", func(t *testing.T) {
		p, a := setup(t)
		fileBefore, _ := os.ReadFile(a.FilePath)
		_, err := p.ReplaceCredentials("u1", &auth.Auth{AccessToken: "at-evil", UID: "other"})
		if err == nil {
			t.Fatal("UID 不一致必须报错（不得串号覆盖）")
		}
		st, _ := p.Status("u1")
		if !st.Disabled || !st.NeedsRelogin || st.AuthFault != string(AuthFaultSessionDead) {
			t.Errorf("失败后账号状态必须原样保留: %+v", st)
		}
		if got := a.AccessTokenValue(); got != "at-old" {
			t.Errorf("内存凭据被改动: %q", got)
		}
		fileAfter, _ := os.ReadFile(a.FilePath)
		if string(fileAfter) != string(fileBefore) {
			t.Error("磁盘凭据被改动")
		}
	})

	t.Run("空 accessToken", func(t *testing.T) {
		p, a := setup(t)
		fileBefore, _ := os.ReadFile(a.FilePath)
		if _, err := p.ReplaceCredentials("u1", &auth.Auth{AccessToken: " ", UID: "u1"}); err == nil {
			t.Fatal("空 accessToken 必须报错")
		}
		if st, _ := p.Status("u1"); !st.NeedsRelogin {
			t.Errorf("失败后仍需重登: %+v", st)
		}
		fileAfter, _ := os.ReadFile(a.FilePath)
		if string(fileAfter) != string(fileBefore) {
			t.Error("磁盘凭据被改动")
		}
	})

	t.Run("写盘失败", func(t *testing.T) {
		p, a := setup(t)
		// 目标目录被移除 → 原子写盘失败（真实部署里 auths 卷掉线的形态）。
		a.FilePath = filepath.Join(t.TempDir(), "unmounted", "workbuddy-u1.json")
		_, err := p.ReplaceCredentials("u1", &auth.Auth{
			AccessToken: "at-new", UID: "u1", FilePath: a.FilePath,
		})
		if err == nil {
			t.Fatal("写盘失败必须如实报错（不许假成功）")
		}
		st, _ := p.Status("u1")
		if !st.Disabled || !st.NeedsRelogin {
			t.Errorf("写盘失败后账号状态必须原样（仍是需重登）: %+v", st)
		}
		if got := a.AccessTokenValue(); got != "at-old" {
			t.Errorf("写盘失败后内存凭据被改动: %q", got)
		}
		if got := a.Epoch(); got != 0 {
			t.Errorf("写盘失败后代次不得推进: %d", got)
		}
	})
}

// TestAuthFaultStateRoundTrip auth_fault 随 state.json 持久化并在重启后恢复：
// 否则重启后面板只剩一个没有来由的 disabled 账号，运维无从判断该重登还是该查风控。
// 同时验证向后兼容：旧 state.json 没有 auth_fault 键 → 零值 = 无故障。
func TestAuthFaultStateRoundTrip(t *testing.T) {
	t.Run("新键持久化并恢复", func(t *testing.T) {
		dir := t.TempDir()
		fp := filepath.Join(dir, "state.json")
		p := New(fp)
		p.Add(&auth.Auth{UID: "u1", AccessToken: "at"})
		p.DisableAuth("u1", "12153 session dead", AuthFaultSessionDead)
		p.Flush()

		p2 := New(fp)
		p2.Add(&auth.Auth{UID: "u1", AccessToken: "at"})
		st, ok := p2.Status("u1")
		if !ok {
			t.Fatal("重启后账号应恢复")
		}
		if st.AuthFault != string(AuthFaultSessionDead) {
			t.Errorf("auth_fault=%q want session_dead（未持久化/未恢复）", st.AuthFault)
		}
		if !st.Disabled || !st.NeedsRelogin {
			t.Errorf("disabled=%v needs_relogin=%v want true/true", st.Disabled, st.NeedsRelogin)
		}
		if st.AuthFaultAt.IsZero() {
			t.Error("auth_fault_at 应随状态恢复")
		}
		// 重启后仍能走窄口径恢复（面板点重登成功 → 账号回池）。
		if !p2.ClearAuthFault("u1") {
			t.Error("恢复后 ClearAuthFault 应返回 true")
		}
		if st2, _ := p2.Status("u1"); st2.Disabled || st2.NeedsRelogin {
			t.Errorf("恢复后应解除: %+v", st2)
		}
	})

	t.Run("旧 state.json 无该键可正常加载", func(t *testing.T) {
		dir := t.TempDir()
		fp := filepath.Join(dir, "state.json")
		legacy := `{"accounts":{"u1":{"disabled":true,"reason":"manual disable by admin"}}}`
		if err := os.WriteFile(fp, []byte(legacy), 0o600); err != nil {
			t.Fatalf("write legacy state: %v", err)
		}
		p := New(fp)
		p.Add(&auth.Auth{UID: "u1", AccessToken: "at"})
		st, ok := p.Status("u1")
		if !ok {
			t.Fatal("旧 state.json 应能正常加载出账号")
		}
		if !st.Disabled || st.DisabledReason != "manual disable by admin" {
			t.Errorf("旧字段应保留: %+v", st)
		}
		if st.AuthFault != "" || st.NeedsRelogin {
			t.Errorf("旧文件缺 auth_fault 必须视为无故障: auth_fault=%q needs_relogin=%v",
				st.AuthFault, st.NeedsRelogin)
		}
	})
}

// TestAuthFaultNormalize 脏值（手改 state.json / 未来新枚举）归一化为「无故障」，
// 而非让前端拿一个不认识的字符串去猜按钮。
func TestAuthFaultNormalize(t *testing.T) {
	if got := NormalizeAuthFault("bogus"); got != AuthFaultNone {
		t.Errorf("未知值应归一化为空，得到 %q", got)
	}
	for _, f := range []AuthFault{AuthFaultNone, AuthFaultSessionDead, AuthFaultGateway401} {
		if !f.Valid() {
			t.Errorf("%q 应为合法枚举", f)
		}
	}
}
