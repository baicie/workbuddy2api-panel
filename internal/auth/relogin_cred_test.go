package auth

// 401 失效账号「原位重新登录」的凭据替换事务（auth.AdoptCredentials）。
//
// 本文件防的回归：
//   - 重登录把账号身份写串（把 A 的 token 写进 B 的凭证文件）——靠 UID 校验拒写；
//   - 重登录抹掉设备风控 token（DeviceToken 空时被新凭据覆盖成空）——重登只换
//     OAuth 凭据，桌面端设备 token 仍属同一台机器；
//   - 重登录另起一个凭证文件（FilePath 被重新拼成 workbuddy-<uid>.json）——同名 UID
//     在多 realm/手工改名场景下会留下两个文件，重启时 LoadDir 读回两份凭证；
//   - 写盘失败却已经把内存字段换掉（内存新、磁盘旧）——重启后凭据回退，运维看到
//     「刚重登完又 401」；
//   - 代次（credEpoch）不递增 —— 在途 refresh 会用旧世界的结果覆盖刚写入的新授权
//     （见 relogin_epoch_test.go）。

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// credSnapshot AdoptCredentials 事务应守住的全部字段快照（可比较，用于「完全未变」断言）。
type credSnapshot struct {
	accessToken  string
	refreshToken string
	expiresAt    int64
	domain       string
	realm        string
	uid          string
	enterpriseID string
	nickname     string
	deviceToken  string
	filePath     string
	epoch        uint64
}

// snapshotOf 锁内读全字段（测试自身不并发，但保持与生产读法同锁，-race 下无噪声）。
func snapshotOf(a *Auth) credSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	return credSnapshot{
		accessToken:  a.AccessToken,
		refreshToken: a.RefreshToken,
		expiresAt:    a.ExpiresAt,
		domain:       a.Domain,
		realm:        a.realm,
		uid:          a.UID,
		enterpriseID: a.EnterpriseID,
		nickname:     a.Nickname,
		deviceToken:  a.DeviceToken,
		filePath:     a.FilePath,
		epoch:        a.credEpoch,
	}
}

// newCredAuth 造一个已落盘的「旧账号」：uin+设备 token+realm 都有值，
// 以便验证重登录后哪些字段该换、哪些必须保留。
func newCredAuth(t *testing.T, dir, uid string) *Auth {
	t.Helper()
	a := &Auth{
		AccessToken:  "at-old-" + uid,
		RefreshToken: "rt-old-" + uid,
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		Domain:       "copilot.tencent.com",
		realm:        "cn",
		UID:          uid,
		EnterpriseID: "ent-old",
		Nickname:     "Old Nick",
		DeviceToken:  "dev-token-1",
		FilePath:     filepath.Join(dir, "workbuddy-"+uid+".json"),
	}
	if err := a.SaveAtomic(); err != nil {
		t.Fatalf("precondition: save old credentials: %v", err)
	}
	return a
}

// newReloginCred 造一个「重新登录刚拿到」的新凭据：只有 OAuth 域字段，
// DeviceToken/FilePath/realm 都空（panel 的 finishRelogin 也是这样构造的）。
func newReloginCred(uid string) *Auth {
	return &Auth{
		AccessToken:  "at-new-" + uid,
		RefreshToken: "rt-new-" + uid,
		ExpiresAt:    time.Now().Add(2 * time.Hour).Unix(),
		Domain:       "copilot.tencent.com",
		UID:          uid,
		EnterpriseID: "ent-new",
		Nickname:     "New Nick",
	}
}

func readFileBytes(t *testing.T, fp string) []byte {
	t.Helper()
	raw, err := os.ReadFile(fp)
	if err != nil {
		t.Fatalf("read %s: %v", fp, err)
	}
	return raw
}

// TestAdoptCredentialsReplacesInPlace 成功路径：换 OAuth 凭据、保留账号身份相关项
// （FilePath/DeviceToken/realm）、代次 +1、磁盘文件同步换成新 token。
//
// 若这里退化成「新增一个 *Auth」或「重拼 FilePath」，重登录就会变成新增账号：
// 账号池里的历史统计、优先级/份额、冷却态全部脱节，且磁盘上多出一个凭证文件。
func TestAdoptCredentialsReplacesInPlace(t *testing.T) {
	dir := t.TempDir()
	old := newCredAuth(t, dir, "u1")
	oldPath := old.FilePath
	oldEpoch := old.Epoch()

	src := newReloginCred("u1")
	if err := old.AdoptCredentials(src); err != nil {
		t.Fatalf("AdoptCredentials: %v", err)
	}

	got := snapshotOf(old)
	if got.accessToken != src.AccessToken || got.refreshToken != src.RefreshToken {
		t.Errorf("凭据未换新: at=%q rt=%q", got.accessToken, got.refreshToken)
	}
	if got.expiresAt != src.ExpiresAt || got.domain != src.Domain {
		t.Errorf("过期时间/域未换新: exp=%d domain=%q", got.expiresAt, got.domain)
	}
	if got.enterpriseID != "ent-new" || got.nickname != "New Nick" {
		t.Errorf("身份展示字段未换新: ent=%q nick=%q", got.enterpriseID, got.nickname)
	}
	if got.uid != "u1" {
		t.Errorf("uid 不该变: %q", got.uid)
	}
	// 保留项：FilePath 不重拼（绝不产生第二个凭证文件）。
	if got.filePath != oldPath {
		t.Errorf("FilePath=%q want %q（必须沿用原账号文件）", got.filePath, oldPath)
	}
	// 保留项：src 未携带 DeviceToken 时沿用旧值（重登不该抹掉设备风控 token）。
	if got.deviceToken != "dev-token-1" {
		t.Errorf("DeviceToken=%q want dev-token-1（src 为空时保留旧值）", got.deviceToken)
	}
	// 保留项：src 未携带 realm 时沿用旧值。
	if got.realm != "cn" {
		t.Errorf("realm=%q want cn（src 为空时保留旧值）", got.realm)
	}
	if got.epoch != oldEpoch+1 {
		t.Errorf("credEpoch=%d want %d（整体替换必须依次递增，供在途 refresh 判旧）", got.epoch, oldEpoch+1)
	}

	// 磁盘：同一个文件、内容已是新 token、保留 device_token 与 realm。
	parsed, err := Parse(readFileBytes(t, oldPath))
	if err != nil {
		t.Fatalf("parse saved credentials: %v", err)
	}
	if parsed.AccessToken != src.AccessToken || parsed.RefreshToken != src.RefreshToken {
		t.Errorf("磁盘 token 未换新: at=%q rt=%q", parsed.AccessToken, parsed.RefreshToken)
	}
	if parsed.DeviceToken != "dev-token-1" {
		t.Errorf("磁盘 device_token=%q want dev-token-1", parsed.DeviceToken)
	}
	if r := parsed.RealmStored(); r != "cn" {
		t.Errorf("磁盘 realm=%q want cn", r)
	}
	if parsed.UID != "u1" || parsed.Nickname != "New Nick" {
		t.Errorf("磁盘身份=%q/%q want u1/New Nick", parsed.UID, parsed.Nickname)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") && e.Name() != filepath.Base(oldPath) {
			t.Errorf("同目录出现第二个凭证文件 %q（重登必须原位替换，不得新增账号）", e.Name())
		}
	}

	// src 是共享对象时不该被本方法改写。
	if src.AccessToken != "at-new-u1" || src.FilePath != "" {
		t.Errorf("src 被意外改写: at=%q path=%q", src.AccessToken, src.FilePath)
	}
}

// TestAdoptCredentialsRejectsUIDMismatch 身份安全闸：目标账号 UID 非空时，
// 新凭据 UID 必须一致。这是「登录 A 账号却把凭据写进 B 账号文件」的唯一防线。
// 拒绝时任何字段（含 FilePath/DeviceToken/代次）与磁盘内容都必须原样。
func TestAdoptCredentialsRejectsUIDMismatch(t *testing.T) {
	dir := t.TempDir()
	a := newCredAuth(t, dir, "u1")
	before := snapshotOf(a)
	fileBefore := readFileBytes(t, a.FilePath)

	src := newReloginCred("attacker-uid")
	err := a.AdoptCredentials(src)
	if err == nil {
		t.Fatal("UID 不一致必须拒绝覆盖（否则两个账号会持有对方 token）")
	}
	if !strings.Contains(err.Error(), "uid mismatch") {
		t.Errorf("错误应明确是 uid 不匹配，得到 %v", err)
	}
	if after := snapshotOf(a); after != before {
		t.Errorf("拒绝覆盖时字段必须完全未变:\nbefore=%+v\nafter =%+v", before, after)
	}
	if !bytes.Equal(readFileBytes(t, a.FilePath), fileBefore) {
		t.Error("拒绝覆盖时磁盘凭证必须完全未变")
	}
}

// TestAdoptCredentialsRejectsEmptyAccessToken 空 accessToken 拒写：空凭据落盘会让
// 账号在重启后变成「有文件、无 token」的死档，且 SaveAtomic 的同类防御也依赖它。
func TestAdoptCredentialsRejectsEmptyAccessToken(t *testing.T) {
	dir := t.TempDir()
	a := newCredAuth(t, dir, "u1")
	before := snapshotOf(a)
	fileBefore := readFileBytes(t, a.FilePath)

	src := newReloginCred("u1")
	src.AccessToken = "   "
	if err := a.AdoptCredentials(src); err == nil {
		t.Fatal("空 accessToken 必须拒写")
	}
	if after := snapshotOf(a); after != before {
		t.Errorf("拒写时字段必须完全未变:\nbefore=%+v\nafter =%+v", before, after)
	}
	if !bytes.Equal(readFileBytes(t, a.FilePath), fileBefore) {
		t.Error("拒写时磁盘凭证必须完全未变")
	}
}

// TestAdoptCredentialsWriteFailureLeavesStateIntact 写盘失败的事务性：先落盘、
// 成功后改内存。失败时**旧文件与内存字段全部保留**，接口必须如实报错（不许假成功）。
//
// 两种失败注入：
//   - 目标目录不存在（真实部署里 data/auths 卷没挂上的形态）；
//   - 备份文件位置被占（.bak 是同目录下的目录，rename 必然失败）——
//     这一种能保留「旧文件已经存在且内容有效」的前提，从而验证旧凭证没被改写。
func TestAdoptCredentialsWriteFailureLeavesStateIntact(t *testing.T) {
	t.Run("父目录不存在", func(t *testing.T) {
		dir := t.TempDir()
		a := newCredAuth(t, dir, "u1")
		a.FilePath = filepath.Join(dir, "not-mounted", "workbuddy-u1.json")
		before := snapshotOf(a)

		if err := a.AdoptCredentials(newReloginCred("u1")); err == nil {
			t.Fatal("写盘失败必须返回错误（接口不许假成功）")
		}
		if after := snapshotOf(a); after != before {
			t.Errorf("写盘失败时字段必须完全未变（内存新、磁盘旧是最危险的中间态）:\nbefore=%+v\nafter =%+v", before, after)
		}
	})

	t.Run("备份位置被占用时旧文件保留", func(t *testing.T) {
		dir := t.TempDir()
		a := newCredAuth(t, dir, "u1")
		before := snapshotOf(a)
		fileBefore := readFileBytes(t, a.FilePath)

		// 让 safefile 的 .bak 重命名必然失败：同名位置放一个非空目录。
		bakDir := a.FilePath + ".bak"
		if err := os.Mkdir(bakDir, 0o755); err != nil {
			t.Fatalf("mkdir bak dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(bakDir, "occupied"), []byte("x"), 0o600); err != nil {
			t.Fatalf("populate bak dir: %v", err)
		}

		if err := a.AdoptCredentials(newReloginCred("u1")); err == nil {
			t.Fatal("写盘失败必须返回错误")
		}
		if after := snapshotOf(a); after != before {
			t.Errorf("写盘失败时字段必须完全未变:\nbefore=%+v\nafter =%+v", before, after)
		}
		if !bytes.Equal(readFileBytes(t, a.FilePath), fileBefore) {
			t.Error("写盘失败时旧凭证文件必须原样保留（不得被截断/覆盖）")
		}
	})
}

// TestAdoptCredentialsSelfRejected 同一对象自我替换会自锁；明确报错比死锁好排查。
func TestAdoptCredentialsSelfRejected(t *testing.T) {
	dir := t.TempDir()
	a := newCredAuth(t, dir, "u1")
	if err := a.AdoptCredentials(a); err == nil {
		t.Fatal("src==a 必须拒绝（sync.Mutex 不可重入）")
	}
	if err := a.AdoptCredentials(nil); err == nil {
		t.Fatal("nil src 必须拒绝")
	}
}

// TestSaveAtomicFormatUnchanged SaveAtomic 重构（saveAtomicLocked/writeLocked）后的
// 格式回归：插件 OAuth 输出形态不变 —— 嵌套 auth + account + 按需顶层 device_token。
// 格式漂移会让桌面端插件读不到凭证，或让 LoadDir 的解析路径整体走偏。
func TestSaveAtomicFormatUnchanged(t *testing.T) {
	t.Run("带 device_token", func(t *testing.T) {
		dir := t.TempDir()
		a := newCredAuth(t, dir, "u1")
		raw := readFileBytes(t, a.FilePath)

		var top map[string]json.RawMessage
		if err := json.Unmarshal(raw, &top); err != nil {
			t.Fatalf("saved doc 不是 JSON: %v", err)
		}
		var authObj map[string]any
		if err := json.Unmarshal(top["auth"], &authObj); err != nil {
			t.Fatalf("缺少/损坏 auth 对象（嵌套形态被破坏）: %v", err)
		}
		for _, k := range []string{"accessToken", "refreshToken", "expiresAt", "domain", "realm"} {
			if _, ok := authObj[k]; !ok {
				t.Errorf("auth.%s 缺失（格式列必须完整）", k)
			}
		}
		var acctObj map[string]any
		if err := json.Unmarshal(top["account"], &acctObj); err != nil {
			t.Fatalf("缺少/损坏 account 对象: %v", err)
		}
		for _, k := range []string{"uid", "enterpriseId", "nickname"} {
			if _, ok := acctObj[k]; !ok {
				t.Errorf("account.%s 缺失", k)
			}
		}
		var dev string
		if err := json.Unmarshal(top["device_token"], &dev); err != nil || dev != "dev-token-1" {
			t.Errorf("顶层 device_token=%q err=%v want dev-token-1", dev, err)
		}
	})

	t.Run("无 device_token 不写空键", func(t *testing.T) {
		dir := t.TempDir()
		a := &Auth{
			AccessToken: "at-plain",
			ExpiresAt:   time.Now().Unix(),
			Domain:      "copilot.tencent.com",
			UID:         "u2",
			FilePath:    filepath.Join(dir, "workbuddy-u2.json"),
		}
		if err := a.SaveAtomic(); err != nil {
			t.Fatalf("SaveAtomic: %v", err)
		}
		var top map[string]any
		if err := json.Unmarshal(readFileBytes(t, a.FilePath), &top); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if _, ok := top["device_token"]; ok {
			t.Error("DeviceToken 为空时不得写入空 device_token 键（会污染无该字段的旧文件）")
		}
	})

	t.Run("空 accessToken 拒写", func(t *testing.T) {
		dir := t.TempDir()
		a := &Auth{UID: "u3", FilePath: filepath.Join(dir, "workbuddy-u3.json")}
		if err := a.SaveAtomic(); err == nil {
			t.Fatal("空 accessToken 必须拒写（避免误用空凭证覆盖有效文件）")
		}
		if _, err := os.Stat(a.FilePath); !os.IsNotExist(err) {
			t.Errorf("拒写后不应产生文件: err=%v", err)
		}
	})
}
