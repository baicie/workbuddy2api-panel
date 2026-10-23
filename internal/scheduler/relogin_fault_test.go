package scheduler

// 余额探测 401 的类型化认证故障语义（balance_401.go + pool.AuthFault*）。
//
// 背景（issue #215）：余额刷新是池内唯一的分钟级健康观测量，但此前拿到 401 只写一行
// 日志、不碰池状态，上游批量注销会话后面板一直显示「可用」。也不能把 401 直接当
// session dead 计罚——401 有两种成因（会话被注销 / 降级 token），必须用 refresh 求证。
//
// 本文件防的回归：
//   - 401 且 refresh 成功（降级 token）却打了认证故障标记/禁用：好号被误杀；
//   - 401 且 refresh 回 12153 达阈后只置 disabled、不带类型化标记：面板给不出「重新登录」
//     入口，运维只能盲目点「解冻」（还会把管理员暂停等状态一起清掉）；
//   - 429/402/5xx 被误算成认证故障：它们各有既有的冷却/熔断路径，重复计罚会雪崩；
//   - 重登录后不清 401 求证的退避窗口：下一次余额探测被旧窗口跳过（最长 30 分钟），
//     面板表现为「重登没生效」。

import (
	"net/http"
	"testing"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
	"github.com/misakano7545/workbuddy2api-panel/internal/pool"
	"github.com/misakano7545/workbuddy2api-panel/internal/upstream"
)

// TestBalance401RefreshOKLeavesNoAuthFault Billing 401 但 refresh 成功（降级 token）：
// 会话仍活 → 不禁用、不打认证故障、已累计的 session dead 计数清零。
func TestBalance401RefreshOKLeavesNoAuthFault(t *testing.T) {
	f := &healFake{} // refresh 端点回新 token
	srv := f.server(t)
	a := &auth.Auth{UID: "u1", AccessToken: "at-old", RefreshToken: "rt-1", ExpiresAt: 1}
	s := healScheduler(t, srv.URL, a)

	// 先累计到阈值前的 2 次连续 12153：refresh 成功必须把它清零。
	s.cfg.Pool.NoteSessionDead("u1")
	s.cfg.Pool.NoteSessionDead("u1")
	if st, _ := s.cfg.Pool.Status("u1"); st.SessionDeadFails != 2 {
		t.Fatalf("precondition: session_dead_fails=%d want 2", st.SessionDeadFails)
	}

	s.RunBalanceRefreshNow()

	st, _ := s.cfg.Pool.Status("u1")
	if st.Disabled {
		t.Errorf("refresh 成功说明会话仍活，不该禁用: %+v", st)
	}
	if st.AuthFault != "" || st.NeedsRelogin {
		t.Errorf("降级 token 不是认证故障: auth_fault=%q needs_relogin=%v", st.AuthFault, st.NeedsRelogin)
	}
	if st.SessionDeadFails != 0 {
		t.Errorf("session_dead_fails=%d want 0（refresh 成功即清计数）", st.SessionDeadFails)
	}
	if got := a.AccessTokenValue(); got != "at-new" {
		t.Errorf("accessToken=%q want at-new（求证顺手换新 token）", got)
	}
	if f.refresh != 1 {
		t.Errorf("refresh 调用=%d want 1", f.refresh)
	}
}

// TestBalance401SessionDeadThresholdMarksAuthFault 连续 12153 达阈：禁用**并且**
// 打上 session_dead 标记（面板据此显示「需要重新登录」而不是无来由的 disabled）。
func TestBalance401SessionDeadThresholdMarksAuthFault(t *testing.T) {
	f := &healFake{sessionDie: true} // refresh 端点回 12153
	srv := f.server(t)
	a := &auth.Auth{UID: "u1", AccessToken: "at-old", RefreshToken: "rt-1", ExpiresAt: 1}
	s := healScheduler(t, srv.URL, a)

	threshold := pool.SessionDeadThreshold()
	if threshold < 2 {
		t.Fatalf("阈值=%d，用例依赖「阈值前不禁用」", threshold)
	}
	// 阈值前：只累计计数，不禁用、不打标记（一次抖动不该把号打光）。
	for i := 1; i < threshold; i++ {
		s.RunBalanceRefreshNow()
		st, _ := s.cfg.Pool.Status("u1")
		if st.Disabled {
			t.Fatalf("第 %d 次 12153 就禁用了（阈值 %d）: %+v", i, threshold, st)
		}
		if st.AuthFault != "" || st.NeedsRelogin {
			t.Fatalf("未达阈不该打认证标记: %+v", st)
		}
		if st.SessionDeadFails != i {
			t.Fatalf("第 %d 次后 session_dead_fails=%d", i, st.SessionDeadFails)
		}
	}
	// 达阈：禁用 + session_dead 标记 + 计数清零。
	s.RunBalanceRefreshNow()
	st, _ := s.cfg.Pool.Status("u1")
	if !st.Disabled {
		t.Fatalf("连续 %d 次 12153 应禁用: %+v", threshold, st)
	}
	if st.AuthFault != string(pool.AuthFaultSessionDead) {
		t.Errorf("auth_fault=%q want %q（面板要靠它给重登入口）", st.AuthFault, pool.AuthFaultSessionDead)
	}
	if !st.NeedsRelogin {
		t.Error("needs_relogin 应为 true")
	}
	if st.SessionDeadFails != 0 {
		t.Errorf("达阈禁用时计数应清零（不会残留到下一次误判）: %d", st.SessionDeadFails)
	}
	if got := s.cfg.Pool.AuthFaultOf("u1"); got != pool.AuthFaultSessionDead {
		t.Errorf("AuthFaultOf=%q want session_dead", got)
	}
	if f.refresh != threshold {
		t.Errorf("refresh 调用=%d want %d（真死号不轮换 RT，每轮都必须求证）", f.refresh, threshold)
	}
}

// TestBalanceNonAuthErrorsProduceNoAuthFault 429/402/5xx/传输层失败都不属于认证故障域：
// 不 refresh 求证、不打标记、不禁用（它们各有既有惩罚路径，重复计罚会雪崩）。
func TestBalanceNonAuthErrorsProduceNoAuthFault(t *testing.T) {
	f := &healFake{}
	srv := f.server(t)
	a := &auth.Auth{UID: "u1", AccessToken: "at-old", RefreshToken: "rt-1", ExpiresAt: 1}
	s := healScheduler(t, srv.URL, a)

	errs := []error{
		&upstream.Error{Kind: upstream.ErrSoftRate, Status: http.StatusTooManyRequests, Msg: "429 rate limit"},
		&upstream.Error{Kind: upstream.ErrHardCredit, Status: http.StatusPaymentRequired, Msg: "insufficient credits"},
		&upstream.Error{Kind: upstream.ErrServer, Status: http.StatusBadGateway, Msg: "bad gateway"},
		&upstream.Error{Kind: upstream.ErrClient, Status: http.StatusBadRequest, Msg: "bad request"},
	}
	for _, err := range errs {
		s.noteBalanceAuthFailure(a, "u1", err)
	}
	st, _ := s.cfg.Pool.Status("u1")
	if st.Disabled || st.AuthFault != "" || st.NeedsRelogin {
		t.Errorf("非 401 不得产生认证故障: %+v", st)
	}
	if st.SessionDeadFails != 0 {
		t.Errorf("session_dead_fails=%d want 0", st.SessionDeadFails)
	}
	if f.refresh != 0 {
		t.Errorf("非 401 不该触发 refresh 求证，实际调用 %d 次", f.refresh)
	}
}

// TestClearAuthHealResets401Backoff 重登录成功后必须清掉 401 求证的退避记录：
// 否则新凭据的第一次余额探测被旧窗口跳过（最长 30 分钟），运维误以为重登没生效。
func TestClearAuthHealResets401Backoff(t *testing.T) {
	f := &healFake{} // 探测恒 401、refresh 恒成功
	srv := f.server(t)
	a := &auth.Auth{UID: "u1", AccessToken: "at-old", RefreshToken: "rt-1", ExpiresAt: 1}
	s := healScheduler(t, srv.URL, a)

	s.RunBalanceRefreshNow() // 第一次：401 → refresh 求证成功 → 记退避
	if f.refresh != 1 {
		t.Fatalf("第一轮 refresh=%d want 1", f.refresh)
	}
	s.RunBalanceRefreshNow() // 退避窗口内：跳过 refresh（保护上游 RT 不被反复轮换）
	if f.refresh != 1 {
		t.Fatalf("退避窗口内 refresh=%d want 1（每轮刷新=一天 288 次 RT 轮换）", f.refresh)
	}

	s.ClearAuthHeal("u1")    // 重新登录成功：清退避
	s.RunBalanceRefreshNow() // 下一轮必须重新求证
	if f.refresh != 2 {
		t.Fatalf("ClearAuthHeal 后 refresh=%d want 2（重登后首轮余额探测不能被旧窗口挡住）", f.refresh)
	}
	// 幂等：清一个没有记录的 uid 不该 panic，也不该顺手放行本号的退避
	// （上传一轮刚 refresh 成功、退避已重建，所以这里仍是跳过）。
	s.ClearAuthHeal("ghost")
	s.RunBalanceRefreshNow()
	if f.refresh != 2 {
		t.Fatalf("无记录 uid 的 ClearAuthHeal 不应影响本号退避: refresh=%d want 2", f.refresh)
	}
}
