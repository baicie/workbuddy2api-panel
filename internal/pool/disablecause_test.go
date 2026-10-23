package pool

// 合并前审查：**禁用成因优先级**。本文件钉住四类状态互不冒充：
//
//	管理员主动禁用（admin） / 上游风控禁用（upstream） / 认证故障禁用（auth） / 暂停选号（paused）
//
// 必须成立的结论（任一失败都会让运维丢状态或有安全网失效）：
//   - 已被管理员/上游禁用的账号，随后收到历史在途请求的 401，**不得**改写禁用原因，
//     不得被标成「需重新登录」，也不得让重登录把它解禁；
//   - 认证禁用可以被重登录窄口径恢复，但恢复时**不得**顺手清掉暂停选号等管理员状态；
//   - 存量 state.json（无 disabled_cause）一律按「不可自动恢复」处理，需人工解冻。
//
// 判据只看类型化字段（DisabledCause），不解析 reason 文本。

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
)

// newDiskAuth 造一个带可写 FilePath 的账号（ReplaceCredentials 会真的写盘，
// 没有 FilePath 会被 auth.AdoptCredentials 拒绝——那是正确的防御，不是测试不便）。
func newDiskAuth(t *testing.T, uid string) *auth.Auth {
	t.Helper()
	a := &auth.Auth{
		UID:          uid,
		AccessToken:  "at-old",
		RefreshToken: "rt-old",
		Domain:       "copilot.tencent.com",
		FilePath:     filepath.Join(t.TempDir(), "workbuddy-"+uid+".json"),
	}
	if err := a.SaveAtomic(); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	return a
}

// causeOf 读账号当前禁用成因与禁用文案。
func causeOf(t *testing.T, p *Pool, uid string) (cause DisableCause, reason string, disabled bool) {
	t.Helper()
	p.mu.RLock()
	defer p.mu.RUnlock()
	e, ok := p.byUID[uid]
	if !ok {
		t.Fatalf("账号 %s 不在池内", uid)
	}
	return e.disabledCause, e.reason, e.disabled
}

// TestAdminDisableSurvivesAuthFault 管理员禁用 + 历史在途请求 401：
// 原因不被覆盖、不标需重登、重登录也不解禁。
func TestAdminDisableSurvivesAuthFault(t *testing.T) {
	p := New("")
	defer p.Close()
	p.Add(newDiskAuth(t, "u1"))

	const adminReason = "manual disable (panel)"
	if !p.DisableWithCause("u1", DisableCauseAdmin, adminReason) {
		t.Fatal("首次管理员禁用应成功")
	}

	// 在途请求回来判死（12153 一次即禁的路径）。
	if p.DisableAuth("u1", "12153 session dead", AuthFaultSessionDead) {
		t.Fatal("已因管理员禁用，认证故障不得再落一次禁用（会覆盖原因）")
	}
	// 连续阈值路径同理。
	for i := 0; i < SessionDeadThreshold(); i++ {
		if p.NoteSessionDeadFault("u1", AuthFaultSessionDead, "12153 session dead") {
			t.Fatal("已因管理员禁用，连续判死达阈也不得覆盖")
		}
	}

	cause, reason, disabled := causeOf(t, p, "u1")
	if !disabled || cause != DisableCauseAdmin {
		t.Errorf("disabled=%v cause=%q want true/admin（管理员禁用被认证故障改写）", disabled, cause)
	}
	if reason != adminReason {
		t.Errorf("reason=%q want %q（管理员禁用原因被覆盖）", reason, adminReason)
	}
	st, _ := p.Status("u1")
	if st.NeedsRelogin {
		t.Error("管理员禁用不得显示成「需重新登录」")
	}
	if st.AuthFault != "" {
		t.Errorf("auth_fault=%q：管理员禁用期间不得记认证故障（会伪装成认证失效）", st.AuthFault)
	}

	// 重登录成功也不得解禁。
	rep, err := p.ReplaceCredentials("u1", &auth.Auth{UID: "u1", AccessToken: "at-new", RefreshToken: "rt-new"})
	if err != nil {
		t.Fatalf("ReplaceCredentials: %v", err)
	}
	if rep.Recovered {
		t.Error("重登录不得解除管理员禁用")
	}
	if !rep.Disabled || rep.InRotation() {
		t.Errorf("重登录后仍应禁用且不在选号：disabled=%v in_rotation=%v", rep.Disabled, rep.InRotation())
	}
	if cause, reason, _ := causeOf(t, p, "u1"); cause != DisableCauseAdmin || reason != adminReason {
		t.Errorf("重登录后 cause=%q reason=%q 必须保持管理员原状", cause, reason)
	}
	// 但凭证确实换新了（接口要如实拆开这两件事）。
	if got := p.AuthByUID("u1").AccessTokenValue(); got != "at-new" {
		t.Errorf("凭据应已换新，得到 %q", got)
	}
}

// TestUpstreamDisableSurvivesAuthFault 上游风控（11140）与认证失效分离：
// 风控封禁换凭据也解不开，不得被 401 改写成「需重登」。
func TestUpstreamDisableSurvivesAuthFault(t *testing.T) {
	p := New("")
	defer p.Close()
	p.Add(newDiskAuth(t, "u1"))

	if !p.DisableWithCause("u1", DisableCauseUpstream, "account restricted by upstream (11140)") {
		t.Fatal("上游风控禁用应成功")
	}
	if p.DisableAuth("u1", "12153 session dead", AuthFaultSessionDead) {
		t.Fatal("风控禁用不得被认证故障覆盖")
	}
	cause, reason, _ := causeOf(t, p, "u1")
	if cause != DisableCauseUpstream || reason != "account restricted by upstream (11140)" {
		t.Errorf("cause=%q reason=%q 应保持上游风控原状", cause, reason)
	}
	if st, _ := p.Status("u1"); st.NeedsRelogin {
		t.Error("风控封禁不得显示成需重新登录")
	}
	rep, err := p.ReplaceCredentials("u1", &auth.Auth{UID: "u1", AccessToken: "at2"})
	if err != nil {
		t.Fatalf("ReplaceCredentials: %v", err)
	}
	if rep.Recovered || !rep.Disabled {
		t.Errorf("风控封禁不应被重登录解除：recovered=%v disabled=%v", rep.Recovered, rep.Disabled)
	}
}

// TestAdminDisableUpgradesAuthDisable 先认证禁用、后管理员禁用：管理员是更强成因，
// 应升级并清掉认证标记（此后要靠人工解冻）。
func TestAdminDisableUpgradesAuthDisable(t *testing.T) {
	p := New("")
	defer p.Close()
	p.Add(newDiskAuth(t, "u1"))

	if !p.DisableAuth("u1", "12153 session dead", AuthFaultSessionDead) {
		t.Fatal("认证禁用应成功")
	}
	if st, _ := p.Status("u1"); !st.NeedsRelogin {
		t.Fatal("认证禁用应标为需重登")
	}
	if !p.DisableWithCause("u1", DisableCauseAdmin, "manual disable (panel)") {
		t.Fatal("管理员禁用应能升级认证禁用")
	}
	cause, reason, _ := causeOf(t, p, "u1")
	if cause != DisableCauseAdmin || reason != "manual disable (panel)" {
		t.Errorf("cause=%q reason=%q want admin", cause, reason)
	}
	st, _ := p.Status("u1")
	if st.NeedsRelogin {
		t.Error("升级为管理员禁用后不得再显示需重登")
	}
	if st.AuthFault != "" {
		t.Errorf("升级后应清掉认证标记，得到 %q", st.AuthFault)
	}
	if p.ClearAuthFault("u1") {
		t.Error("管理员禁用不应被 ClearAuthFault 清除")
	}
	if _, _, disabled := causeOf(t, p, "u1"); !disabled {
		t.Error("管理员禁用必须保留")
	}
}

// TestClearAuthFaultKeepsPaused 认证恢复只清认证域：管理员「暂停选号」必须保留。
// （暂停与禁用正交：暂停号照常签到/保活，只是不接流量，重登录不该替运维改成接流量。）
func TestClearAuthFaultKeepsPaused(t *testing.T) {
	p := New("")
	defer p.Close()
	p.Add(newDiskAuth(t, "u1"))

	if !p.DisableAuth("u1", "12153 session dead", AuthFaultSessionDead) {
		t.Fatal("认证禁用应成功")
	}
	if !p.Pause("u1") {
		t.Fatal("暂停选号应成功")
	}

	// 用重登录恢复（内部走 ClearAuthFault）。
	rep, err := p.ReplaceCredentials("u1", &auth.Auth{UID: "u1", AccessToken: "at-new"})
	if err != nil {
		t.Fatalf("ReplaceCredentials: %v", err)
	}
	if !rep.Recovered {
		t.Fatal("认证禁用应被恢复")
	}
	if !rep.Paused {
		t.Error("暂停选号不得被重登录清除")
	}
	if rep.InRotation() {
		t.Error("仍在暂停选号的账号不得显示为「已回到选号」")
	}
	st, _ := p.Status("u1")
	if st.Disabled || !st.Paused {
		t.Errorf("disabled=%v paused=%v want false/true", st.Disabled, st.Paused)
	}
}

// TestLegacyDisabledWithoutCauseIsNotAutoRecoverable 存量 state.json（只有 disabled+reason，
// 没有 disabled_cause）无从判断成因，必须按「不可自动恢复」处理：
// 不标需重登、重登录不解禁、只有人工解冻才恢复。
func TestLegacyDisabledWithoutCauseIsNotAutoRecoverable(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "state.json")
	legacy := `{"accounts":{"u1":{"disabled":true,"reason":"manual disable by admin"}}}`
	if err := os.WriteFile(fp, []byte(legacy), 0o600); err != nil {
		t.Fatalf("write legacy state: %v", err)
	}
	p := New(fp)
	defer p.Close()
	p.Add(newDiskAuth(t, "u1"))

	cause, reason, disabled := causeOf(t, p, "u1")
	if !disabled || cause != DisableCauseUnknown || reason != "manual disable by admin" {
		t.Fatalf("存量禁用应还原为 unknown 且保留原因，得到 disabled=%v cause=%q reason=%q",
			disabled, cause, reason)
	}
	if st, _ := p.Status("u1"); st.NeedsRelogin {
		t.Error("来路不明的禁用不得显示成需重新登录")
	}
	if p.ClearAuthFault("u1") {
		t.Error("ClearAuthFault 不得清除来路不明的禁用")
	}
	rep, err := p.ReplaceCredentials("u1", &auth.Auth{UID: "u1", AccessToken: "at-new"})
	if err != nil {
		t.Fatalf("ReplaceCredentials: %v", err)
	}
	if rep.Recovered || !rep.Disabled {
		t.Errorf("unknown 成因不得被重登录解除：recovered=%v disabled=%v", rep.Recovered, rep.Disabled)
	}
	// 人工解冻才是它的恢复路径。
	if !p.Revive("u1") {
		t.Fatal("Revive 应成功")
	}
	if _, cause, _ := func() (bool, DisableCause, string) {
		p.mu.RLock()
		defer p.mu.RUnlock()
		e := p.byUID["u1"]
		return e.disabled, e.disabledCause, e.reason
	}(); cause != DisableCauseNone {
		t.Errorf("Revive 后成因应清空，得到 %q", cause)
	}
}

// TestDisableCausePersistsAcrossRestart 成因跨重启保留（否则重启后管理员禁用会被
// 当成认证禁用 → 面板给出重登入口 → 重登录把它解掉）。
func TestDisableCausePersistsAcrossRestart(t *testing.T) {
	cases := []struct {
		name  string
		apply func(p *Pool, uid string)
		want  DisableCause
	}{
		{"admin", func(p *Pool, uid string) { p.DisableWithCause(uid, DisableCauseAdmin, "manual disable (panel)") }, DisableCauseAdmin},
		{"upstream", func(p *Pool, uid string) { p.DisableWithCause(uid, DisableCauseUpstream, "11140") }, DisableCauseUpstream},
		{"auth", func(p *Pool, uid string) { p.DisableAuth(uid, "12153 session dead", AuthFaultSessionDead) }, DisableCauseAuth},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			fp := filepath.Join(dir, "state.json")
			p := New(fp)
			p.Add(newDiskAuth(t, "u1"))
			c.apply(p, "u1")
			p.Flush()
			p.Close()

			p2 := New(fp)
			defer p2.Close()
			p2.Add(&auth.Auth{UID: "u1", AccessToken: "at"})
			cause, _, disabled := causeOf(t, p2, "u1")
			if !disabled || cause != c.want {
				t.Fatalf("重启后 disabled=%v cause=%q want true/%q", disabled, cause, c.want)
			}
			st, _ := p2.Status("u1")
			if wantRelogin := c.want == DisableCauseAuth; st.NeedsRelogin != wantRelogin {
				t.Errorf("needs_relogin=%v want %v", st.NeedsRelogin, wantRelogin)
			}
		})
	}
}
