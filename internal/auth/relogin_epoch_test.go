package auth_test

// P0 竞态：在途 refresh 不得覆盖「刚完成重新登录」的新授权凭据。
//
// 场景（生产真会发生）：keepalive/请求路径拿着旧 refreshToken 发出刷新请求（HTTP 在锁外，
// 最长 30s）；这期间运维在面板点了「重新登录」，AdoptCredentials 把新 token 落盘、代次 +1。
// 刷新请求随后返回旧世界的结果——如果照写，新授权刚写好的凭证文件被覆盖回旧 token，
// 用户看到的现象是「重登成功但账号又坏了」，而凭证文件里躺着早已失效的旧 token。
//
// 这就是 auth.credEpoch + upstream.applyRefresh 代次校验要守住的东西。本文件用外部测试包
// （auth_test）实测真实的 upstream.RefreshToken 调用链，而不是自己模拟 applyRefresh。
//
// 两种旧世界结果都必须丢弃：
//   - 成功结果（旧 RT 换来的新 token）：写回 = 覆盖刚落的盘；
//   - 失败结果（旧 RT 回 12153）：照判 = 把刚恢复的账号再判一次死（误杀）。
// 两种都必须返回 nil（= 本次刷新不算失败），调用方才不会禁用/冷却账号。

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
	"github.com/misakano7545/workbuddy2api-panel/internal/upstream"
)

// rtFunc 把函数适配成 http.RoundTripper（不联网、不依赖 httptest 端口）。
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func rtJSON(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// refreshBlockingClient 造一个「refresh 请求进入后阻塞，直到 release 关闭」的上游：
// 用阻塞窗口复现「刷新在途时用户完成重新登录」的时间顺序。
func refreshBlockingClient(t *testing.T, entered chan struct{}, release <-chan struct{}, status int, body string) (*upstream.Client, *int32) {
	t.Helper()
	var calls int32
	var once sync.Once
	c := &upstream.Client{
		HTTP: &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
			if !strings.HasSuffix(r.URL.Path, "/v2/plugin/auth/token/refresh") {
				return nil, fmt.Errorf("unexpected upstream path: %s", r.URL.Path)
			}
			calls++
			once.Do(func() { close(entered) })
			<-release
			return rtJSON(status, body), nil
		})},
		ChatBaseCN:    "https://chat.example",
		BillingBaseCN: "https://billing.example",
	}
	return c, &calls
}

// reloginAuth 造一个已落盘的旧账号（CN 域，有 RT 可刷新）。
func reloginAuth(t *testing.T, dir, uid string) *auth.Auth {
	t.Helper()
	a := &auth.Auth{
		AccessToken:  "at-old-world",
		RefreshToken: "rt-old-world",
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		Domain:       "copilot.tencent.com",
		UID:          uid,
		Nickname:     "Old",
		FilePath:     filepath.Join(dir, "workbuddy-"+uid+".json"),
	}
	if err := a.SaveAtomic(); err != nil {
		t.Fatalf("precondition: save old credentials: %v", err)
	}
	return a
}

// adoptedCred 造「重新登录刚拿到的新授权」（panel.finishRelogin 同形）。
func adoptedCred(uid, filePath string) *auth.Auth {
	return &auth.Auth{
		AccessToken:  "at-relogin-new",
		RefreshToken: "rt-relogin-new",
		ExpiresAt:    time.Now().Add(2 * time.Hour).Unix(),
		Domain:       "copilot.tencent.com",
		UID:          uid,
		Nickname:     "New",
		FilePath:     filePath,
	}
}

func readCred(t *testing.T, fp string) *auth.Auth {
	t.Helper()
	raw, err := os.ReadFile(fp)
	if err != nil {
		t.Fatalf("read credentials: %v", err)
	}
	parsed, err := auth.Parse(raw)
	if err != nil {
		t.Fatalf("parse credentials: %v", err)
	}
	return parsed
}

// TestInflightRefreshSuccessDoesNotOverwriteRelogin stale 刷新成功结果必须被丢弃：
// 内存与磁盘都保持重新登录写入的新 token，且 RefreshToken 返回 nil（不报错）。
func TestInflightRefreshSuccessDoesNotOverwriteRelogin(t *testing.T) {
	dir := t.TempDir()
	a := reloginAuth(t, dir, "u1")

	entered := make(chan struct{})
	release := make(chan struct{})
	c, calls := refreshBlockingClient(t, entered, release, http.StatusOK,
		`{"code":0,"msg":"ok","data":{"accessToken":"at-stale-world","refreshToken":"rt-stale-world","expiresIn":3600}}`)

	errCh := make(chan error, 1)
	go func() { errCh <- c.RefreshToken(a) }()
	<-entered // refresh 已发出、正拿旧 RT 等上游

	// 用户在这期间完成重新登录：新授权落盘 + 代次 +1。
	if err := a.AdoptCredentials(adoptedCred("u1", a.FilePath)); err != nil {
		t.Fatalf("AdoptCredentials: %v", err)
	}
	close(release)

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("旧世界的刷新结果必须被静默丢弃（返回 nil），得到错误: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("refresh 未在放行后返回（测试装置失效）")
	}
	if got := *calls; got != 1 {
		t.Fatalf("refresh 上游调用=%d want 1（装置未真正打到上游）", got)
	}

	// 内存：新授权优先。
	if got := a.AccessTokenValue(); got != "at-relogin-new" {
		t.Errorf("内存 accessToken=%q want at-relogin-new（stale 刷新结果不得覆盖新授权）", got)
	}
	if got := a.RefreshTokenValue(); got != "rt-relogin-new" {
		t.Errorf("内存 refreshToken=%q want rt-relogin-new", got)
	}
	// 磁盘：仍是新授权（这是重登最终生效的唯一凭据来源）。
	parsed := readCred(t, a.FilePath)
	if parsed.AccessToken != "at-relogin-new" || parsed.RefreshToken != "rt-relogin-new" {
		t.Errorf("磁盘 token=%q/%q want at-relogin-new/rt-relogin-new（旧世界结果覆盖了新凭证文件）",
			parsed.AccessToken, parsed.RefreshToken)
	}
	raw, _ := os.ReadFile(a.FilePath)
	if strings.Contains(string(raw), "at-stale-world") || strings.Contains(string(raw), "rt-stale-world") {
		t.Error("磁盘凭证文件出现了旧世界的 token（重新登录等于白做）")
	}
	if got := a.Epoch(); got != 1 {
		t.Errorf("credEpoch=%d want 1", got)
	}
}

// TestInflightRefreshFailureDoesNotKillRelogin stale 刷新失败（12153）同样必须丢弃：
// 否则刚重登恢复的账号会立刻被计一次 session dead（阈值 3 次就再次禁用）。
func TestInflightRefreshFailureDoesNotKillRelogin(t *testing.T) {
	dir := t.TempDir()
	a := reloginAuth(t, dir, "u1")

	entered := make(chan struct{})
	release := make(chan struct{})
	c, _ := refreshBlockingClient(t, entered, release, http.StatusUnauthorized,
		`{"code":12153,"msg":"Offline user session not found"}`)

	errCh := make(chan error, 1)
	go func() { errCh <- c.RefreshToken(a) }()
	<-entered

	if err := a.AdoptCredentials(adoptedCred("u1", a.FilePath)); err != nil {
		t.Fatalf("AdoptCredentials: %v", err)
	}
	close(release)

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("旧凭据的失败结论必须作废（返回 nil），否则刚重登的账号会被再判死: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("refresh 未在放行后返回")
	}
	if got := a.AccessTokenValue(); got != "at-relogin-new" {
		t.Errorf("accessToken=%q want at-relogin-new", got)
	}
	parsed := readCred(t, a.FilePath)
	if parsed.AccessToken != "at-relogin-new" || parsed.RefreshToken != "rt-relogin-new" {
		t.Errorf("磁盘 token 被改动: %q/%q", parsed.AccessToken, parsed.RefreshToken)
	}
}

// TestInflightRefreshAppliesWithoutRelogin 对照组：没有重新登录时，在途刷新的结果必须
// 照常写回。没有它，上面两条测试即使因为「装置根本没放行」也会假绿。
func TestInflightRefreshAppliesWithoutRelogin(t *testing.T) {
	dir := t.TempDir()
	a := reloginAuth(t, dir, "u1")

	entered := make(chan struct{})
	release := make(chan struct{})
	c, calls := refreshBlockingClient(t, entered, release, http.StatusOK,
		`{"code":0,"msg":"ok","data":{"accessToken":"at-fresh-world","refreshToken":"rt-fresh-world","expiresIn":3600}}`)

	errCh := make(chan error, 1)
	go func() { errCh <- c.RefreshToken(a) }()
	<-entered
	close(release)

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("refresh 未在放行后返回")
	}
	if got := *calls; got != 1 {
		t.Fatalf("refresh 上游调用=%d want 1", got)
	}
	if got := a.AccessTokenValue(); got != "at-fresh-world" {
		t.Errorf("无重登录时刷新结果应写回，accessToken=%q want at-fresh-world", got)
	}
	if got := a.RefreshTokenValue(); got != "rt-fresh-world" {
		t.Errorf("refreshToken=%q want rt-fresh-world", got)
	}
}

// TestRefreshSnapshotIsConsistent 代次与 token 必须一次读齐：
// 若 RefreshSnapshot 分开读，读代次与读 token 之间插入一次整体替换，
// upstream 的代次校验就会失效（拿旧代次配新 token → 合法刷新被丢弃，反之覆盖新凭证）。
func TestRefreshSnapshotIsConsistent(t *testing.T) {
	dir := t.TempDir()
	a := reloginAuth(t, dir, "u1")

	epoch, at, rt := a.RefreshSnapshot()
	if epoch != 0 || at != "at-old-world" || rt != "rt-old-world" {
		t.Fatalf("初始快照=%d/%q/%q", epoch, at, rt)
	}
	if err := a.AdoptCredentials(adoptedCred("u1", a.FilePath)); err != nil {
		t.Fatalf("AdoptCredentials: %v", err)
	}
	epoch, at, rt = a.RefreshSnapshot()
	if epoch != 1 || at != "at-relogin-new" || rt != "rt-relogin-new" {
		t.Fatalf("替换后快照=%d/%q/%q（三者必须来自同一次持锁读）", epoch, at, rt)
	}
	// EpochLocked 与 Epoch 语义一致（前者供已持锁的 applyRefresh 使用）。
	a.Lock()
	lockedEpoch := a.EpochLocked()
	a.Unlock()
	if lockedEpoch != a.Epoch() {
		t.Errorf("EpochLocked=%d Epoch=%d 语义必须一致", lockedEpoch, a.Epoch())
	}
}
