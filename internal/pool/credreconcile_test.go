package pool

// 合并前审查：**双文件持久化一致性**（auths/*.json 与 state.json 是两个文件、两次写）。
//
// 现实会出现的失败窗口（本文件逐个复现）：
//
//	① 新凭证落盘成功（auth 文件 fsync）；
//	② 内存凭证更新成功；
//	③ 认证故障状态清理（内存里 disabled/auth_fault 已清）；
//	④ state.json 写入失败（磁盘满 / 只读 / bind-mount 抖动）；
//	⑤ 进程重启 —— 此时 state.json 仍是「disabled + auth 成因」，而 auth 文件里
//	   已经是全新授权凭据。
//
// 必须成立：重启后**不能**重新陷入不可恢复的认证禁用（否则用户反复点重登，每次都
// 「成功」却永远是禁用）；也不能因此错误清除管理员禁用；也不能回滚成已废弃的旧 token。
//
// 机制：凭证代次（auth 文件 auth.epoch ↔ state.json auth_epoch）是唯一能跨重启证明
// 「凭证比 state 记录的新」的证据（见 reconcileCredEpochLocked）。判据只看代次，
// 不解析 reason 文本。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
)

// seedPool 建一个「已落盘 + 已认证禁用」的池与它的 state.json 路径。
func seedPool(t *testing.T, stateDir string) (*Pool, *auth.Auth, string) {
	t.Helper()
	fp := filepath.Join(stateDir, "state.json")
	p := New(fp)
	a := newDiskAuth(t, "u1")
	p.Add(a)
	if !p.DisableAuth("u1", "12153 session dead", AuthFaultSessionDead) {
		t.Fatal("seed: 认证禁用应成功")
	}
	p.Flush()
	return p, a, fp
}

// readStateAccounts 读 state.json 里某账号的持久化记录（断言落盘结果用）。
func readStateAccounts(t *testing.T, fp string) map[string]stateAccount {
	t.Helper()
	raw, err := os.ReadFile(fp)
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	var sf stateFile
	if err := json.Unmarshal(raw, &sf); err != nil {
		t.Fatalf("parse state.json: %v", err)
	}
	return sf.Accounts
}

// TestReplaceCredentialsReportsStagedResult 正常路径：换凭据必须如实回报
// 「已解认证禁用」「状态已落盘」「代次已写进 auth 文件」。
func TestReplaceCredentialsReportsStagedResult(t *testing.T) {
	stateDir := t.TempDir()
	p, a, fp := seedPool(t, stateDir)
	defer p.Close()

	rep, err := p.ReplaceCredentials("u1", &auth.Auth{
		UID: "u1", AccessToken: "at-new", RefreshToken: "rt-new", Domain: "copilot.tencent.com",
	})
	if err != nil {
		t.Fatalf("ReplaceCredentials: %v", err)
	}
	if !rep.Recovered {
		t.Error("认证禁用应被恢复")
	}
	if !rep.StatePersisted {
		t.Error("正常路径 state.json 应已落盘（StatePersisted=true）")
	}
	if rep.Disabled || rep.Paused || rep.Cooling || !rep.InRotation() {
		t.Errorf("恢复后应回到选号：disabled=%v paused=%v cooling=%v", rep.Disabled, rep.Paused, rep.Cooling)
	}
	if rep.Epoch != 1 {
		t.Errorf("Epoch=%d want 1", rep.Epoch)
	}
	// auth 文件里的代次必须与内存一致（重启对账的前提）。
	onDisk, err := auth.Parse(readFileT(t, a.FilePath))
	if err != nil {
		t.Fatalf("parse auth: %v", err)
	}
	if onDisk.Epoch() != 1 {
		t.Errorf("auth 文件 epoch=%d want 1（代次没落盘，重启无法对账）", onDisk.Epoch())
	}
	// state.json 记录同一个代次。
	accts := readStateAccounts(t, fp)
	if got := accts["u1"].AuthEpoch; got != 1 {
		t.Errorf("state.json auth_epoch=%d want 1", got)
	}
	if accts["u1"].Disabled {
		t.Error("state.json 里不应再是 disabled")
	}
}

// readFileT 读文件内容（nil 判定的错误直接 Fatal）。
func readFileT(t *testing.T, fp string) []byte {
	t.Helper()
	raw, err := os.ReadFile(fp)
	if err != nil {
		t.Fatalf("read %s: %v", fp, err)
	}
	return raw
}

// TestRestartRecoversAuthDisableAfterStateWriteFailure 核心场景：凭据换新成功但
// state.json 写失败 → 重启后必须自动按「重新授权口径」窄口径恢复，而不是重新卡在
// 不可恢复的认证禁用。
func TestRestartRecoversAuthDisableAfterStateWriteFailure(t *testing.T) {
	stateDir := t.TempDir()
	p, a, fp := seedPool(t, stateDir)

	// ④ 让 state.json 写入失败：目录改成不可写（文件本身仍可读）。
	if err := os.Chmod(stateDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	rep, err := p.ReplaceCredentials("u1", &auth.Auth{
		UID: "u1", AccessToken: "at-restart", RefreshToken: "rt-restart", Domain: "copilot.tencent.com",
	})
	if err != nil {
		t.Fatalf("ReplaceCredentials: %v", err)
	}
	if rep.StatePersisted {
		t.Fatal("state 目录不可写时 StatePersisted 必须为 false（不允许报含糊成功）")
	}
	if !rep.Recovered {
		t.Error("运行态仍应完成认证恢复（只是没落盘）")
	}
	// 抓取「写失败那一刻」的陈旧 state.json（重启后看到的就是它）。
	stale := readFileT(t, fp)
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatalf("chmod restore: %v", err)
	}
	p.Close()

	// 断言这份 state.json 确实陈旧：仍是 disabled + 认证成因 + auth_epoch 为 0。
	var sf stateFile
	if err := json.Unmarshal(stale, &sf); err != nil {
		t.Fatalf("parse stale state: %v", err)
	}
	if got := sf.Accounts["u1"]; !got.Disabled || got.DisabledCause != DisableCauseAuth || got.AuthEpoch != 0 {
		t.Fatalf("前提不成立：stale disabled=%v cause=%q epoch=%d", got.Disabled, got.DisabledCause, got.AuthEpoch)
	}

	// ⑤ 重启：把陈旧 state.json 放到全新的目录，并用 LoadDir 读回 auth 文件（含代次）。
	restartDir := t.TempDir()
	fp2 := filepath.Join(restartDir, "state.json")
	if err := os.WriteFile(fp2, stale, 0o600); err != nil {
		t.Fatalf("write stale: %v", err)
	}
	auths, err := auth.LoadDir(filepath.Dir(a.FilePath))
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(auths) != 1 || auths[0].Epoch() != 1 {
		t.Fatalf("auth 文件应读回代次 1，得到 %d 个账号", len(auths))
	}

	p2 := New(fp2)
	defer p2.Close()
	p2.SyncToDir(auths) // 与生产启动路径一致：LoadDir → New → SyncToDir

	st, ok := p2.Status("u1")
	if !ok {
		t.Fatal("重启后账号应在池内")
	}
	if st.Disabled {
		t.Error("重启对账失败：仍停在认证禁用（用户会永远卡在需重登）")
	}
	if st.NeedsRelogin {
		t.Error("重启对账失败：仍显示需重新登录")
	}
	if st.AuthFault != "" {
		t.Errorf("重启对账应清掉陈旧 auth_fault，得到 %q", st.AuthFault)
	}
	// 自愈要把结果写回，否则每次启动都要重新对账一遍。
	p2.Flush()
	accts := readStateAccounts(t, fp2)
	if accts["u1"].Disabled {
		t.Error("对账结果未落盘：state.json 仍是 disabled")
	}
	if accts["u1"].AuthEpoch != 1 {
		t.Errorf("state.json auth_epoch=%d want 1", accts["u1"].AuthEpoch)
	}
	// 凭证不得回滚成旧 token（state.json 从不存 token，这条是防未来改动踩坑）。
	fromDisk := string(readFileT(t, a.FilePath))
	if !strings.Contains(fromDisk, "at-restart") {
		t.Error("auth 文件应保持新授权凭证")
	}
}

// TestRestartReconcileKeepsAdminDisable 同一重启窗口，但禁用成因是管理员：
// 对账必须**不动**它（代次领先只证明凭据换了，不代表管理员撤销了禁用）。
func TestRestartReconcileKeepsAdminDisable(t *testing.T) {
	restartDir := t.TempDir()
	fp := filepath.Join(restartDir, "state.json")
	// 陈旧 state.json：管理员禁用 + auth_epoch=0
	stale := `{"accounts":{"u1":{"disabled":true,"disabled_cause":"admin","reason":"manual disable (panel)","auth_epoch":0}}}`
	if err := os.WriteFile(fp, []byte(stale), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	// auth 文件代次=1（= 期间发生过一次重新授权，但管理员禁用仍然有效）。
	a := newDiskAuth(t, "u1")
	if err := a.AdoptCredentials(&auth.Auth{UID: "u1", AccessToken: "at-relogin", RefreshToken: "rt-relogin"}); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if a.Epoch() != 1 {
		t.Fatalf("前提：代次应为 1，得到 %d", a.Epoch())
	}
	auths, err := auth.LoadDir(filepath.Dir(a.FilePath))
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	p := New(fp)
	defer p.Close()
	p.SyncToDir(auths)

	cause, reason, disabled := causeOf(t, p, "u1")
	if !disabled || cause != DisableCauseAdmin || reason != "manual disable (panel)" {
		t.Fatalf("重启对账不得清除管理员禁用：disabled=%v cause=%q reason=%q", disabled, cause, reason)
	}
	if st, _ := p.Status("u1"); st.NeedsRelogin {
		t.Error("管理员禁用不得因凭证代次领先而被标成需重登")
	}
	// 代次仍要对齐（否则每次启动都重复对账 + 重复告警）。
	p.Flush()
	if got := readStateAccounts(t, fp)["u1"].AuthEpoch; got != 1 {
		t.Errorf("auth_epoch=%d want 1（代次应对齐并落盘）", got)
	}
}

// TestReconcileClearsStaleAuthFaultWhenNotDisabled state.json 里有 auth_fault 但账号
// 并未禁用（历史遗留/手工改坏），凭证代次领先时只清标记，不动禁用状态（本来也没禁用）。
func TestReconcileClearsStaleAuthFaultWhenNotDisabled(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "state.json")
	stale := `{"accounts":{"u1":{"disabled":false,"auth_fault":"session_dead","session_dead_fails":2,"auth_epoch":0}}}`
	if err := os.WriteFile(fp, []byte(stale), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	a := newDiskAuth(t, "u1")
	if err := a.AdoptCredentials(&auth.Auth{UID: "u1", AccessToken: "at-new"}); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	auths, err := auth.LoadDir(filepath.Dir(a.FilePath))
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	p := New(fp)
	defer p.Close()
	p.SyncToDir(auths)

	st, _ := p.Status("u1")
	if st.AuthFault != "" {
		t.Errorf("陈旧 auth_fault 应被清除，得到 %q", st.AuthFault)
	}
	if st.SessionDeadFails != 0 {
		t.Errorf("陈旧 session_dead_fails 应清零，得到 %d", st.SessionDeadFails)
	}
	if st.Disabled {
		t.Error("本用例账号本就未禁用，对账不得把它变成禁用")
	}
}

// TestReconcileToleratesCredentialRollback 反向异常：state.json 记录的代次比 auth 文件
// 高（凭证被从备份回滚/手工替换）。不得崩、不得改禁用状态，只以文件为准并告警。
func TestReconcileToleratesCredentialRollback(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "state.json")
	stale := `{"accounts":{"u1":{"disabled":true,"disabled_cause":"auth","reason":"12153 session dead","auth_epoch":7}}}`
	if err := os.WriteFile(fp, []byte(stale), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	a := newDiskAuth(t, "u1") // 文件代次 0（从备份恢复的旧凭证）
	p := New(fp)
	defer p.Close()
	p.SyncToDir([]*auth.Auth{a})

	// 行为契约：不回滚到旧 token（state 不存 token，天然满足），也不因"代次落后"解禁。
	cause, _, disabled := causeOf(t, p, "u1")
	if !disabled || cause != DisableCauseAuth {
		t.Errorf("代次落后时不得擅自改动禁用状态：disabled=%v cause=%q", disabled, cause)
	}
	// 代次以文件为准，避免每次启动重复告警。
	p.Flush()
	if got := readStateAccounts(t, fp)["u1"].AuthEpoch; got != 0 {
		t.Errorf("auth_epoch=%d want 0（以文件为准）", got)
	}
}
