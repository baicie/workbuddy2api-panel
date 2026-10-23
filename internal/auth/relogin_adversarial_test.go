package auth_test

// 合并前对抗性审查：**原位重登录 vs 在途 refresh** 的凭证一致性。
//
// 与 relogin_epoch_test.go 的差别（不是重复，而是补上真实调用链的最后一步）：
// 那边只验证 `RefreshToken` 返回值会不会被写回；这里补的是 **调用方拿到 nil 之后
// 仍会 `SaveAtomicRetry()`** 这一步（handler / scheduler keepalive 都是这么写的），
// 以及「连续多次重登录 + 多次在途刷新」的叠加场景。
//
// 必须成立的结论（任一失败都意味着上线后用户会遇到「重登成功但账号又坏了」）：
//  1. 旧 refresh 返回成功 → 不得把旧世界 token 写回内存或磁盘；
//  2. 旧 refresh 返回 12153 → 不得让账号被判死（调用方据此会 Disable）；
//  3. 旧调用方随后主动 SaveAtomicRetry → 写出的必须是**新**凭证（不能回滚）；
//  4. 多轮叠加后，磁盘上恒等于最后一次重登录的凭证与代次。

import (
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

// advRT / advJSON 独立的最小 RoundTripper 装置（不依赖同包其它测试文件的 helper，
// 避免将来改名互相牵连）。
type advRT func(*http.Request) (*http.Response, error)

func (f advRT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func advJSON(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// advUpstream 造一个「refresh 请求进入后阻塞，直到 release 关闭才回 status/body」的上游。
// entered 每次请求都会收到一次信号，便于精确排在「旧 refresh 已发出、尚未返回」这个点上。
func advUpstream(release <-chan struct{}, status int, body string) *upstream.Client {
	return &upstream.Client{
		HTTP: &http.Client{Transport: advRT(func(r *http.Request) (*http.Response, error) {
			if !strings.HasSuffix(r.URL.Path, "/v2/plugin/auth/token/refresh") {
				return nil, &httpError{r.URL.Path}
			}
			<-release
			return advJSON(status, body), nil
		})},
		ChatBaseCN:    "https://chat.example",
		BillingBaseCN: "https://billing.example",
	}
}

type httpError struct{ path string }

func (e *httpError) Error() string { return "unexpected upstream path: " + e.path }

// advSeed 落盘一个「旧世界」账号（旧 AT/RT，CN 域）。
func advSeed(t *testing.T, dir string) *auth.Auth {
	t.Helper()
	a := &auth.Auth{
		AccessToken:  "at-old",
		RefreshToken: "rt-old",
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		Domain:       "copilot.tencent.com",
		UID:          "uid-1",
		Nickname:     "old",
		FilePath:     filepath.Join(dir, "workbuddy-uid-1.json"),
	}
	if err := a.SaveAtomic(); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	return a
}

// advNew 造一份新的授权凭据（panel.finishRelogin 同形：只带 OAuth 域字段）。
func advNew(at, rt string) *auth.Auth {
	return &auth.Auth{
		AccessToken:  at,
		RefreshToken: rt,
		ExpiresAt:    time.Now().Add(2 * time.Hour).Unix(),
		Domain:       "copilot.tencent.com",
		UID:          "uid-1",
		Nickname:     "new",
	}
}

// diskCred 从磁盘读回凭证（重登最终是否生效，只看这里）。
func diskCred(t *testing.T, fp string) *auth.Auth {
	t.Helper()
	raw, err := os.ReadFile(fp)
	if err != nil {
		t.Fatalf("read cred: %v", err)
	}
	parsed, err := auth.Parse(raw)
	if err != nil {
		t.Fatalf("parse cred: %v", err)
	}
	return parsed
}

// TestStaleRefresherCannotRollbackRelogin 任务书要求的 5 步竞态，逐字复现：
//
//	① 旧 refresh 请求开始（已拿到旧 RT 快照，HTTP 悬停在锁外）；
//	② 新 OAuth 完成并原位替换凭证（AdoptCredentials，落盘 + 代次 +1）；
//	③ 旧 refresh 请求返回成功（旧世界换来的 token）；
//	④ 旧请求按真实调用方写法尝试保存结果（SaveAtomicRetry）；
//	⑤ 断言内存与磁盘都保持新凭证。
func TestStaleRefresherCannotRollbackRelogin(t *testing.T) {
	dir := t.TempDir()
	a := advSeed(t, dir)

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	c := &upstream.Client{
		HTTP: &http.Client{Transport: advRT(func(r *http.Request) (*http.Response, error) {
			entered <- struct{}{} // ① 请求已发出（持有旧 RT 快照）
			<-release
			return advJSON(http.StatusOK,
				`{"code":0,"msg":"ok","data":{"accessToken":"at-stale","refreshToken":"rt-stale","expiresIn":3600}}`), nil
		})},
		ChatBaseCN:    "https://chat.example",
		BillingBaseCN: "https://billing.example",
	}

	refreshDone := make(chan error, 1)
	go func() {
		// 真实调用方：refresh 成功后无条件 SaveAtomicRetry（handler.go / scheduler）。
		err := c.RefreshToken(a)
		if err == nil {
			err = a.SaveAtomicRetry() // ④ 旧请求尝试保存结果
		}
		refreshDone <- err
	}()
	<-entered

	if err := a.AdoptCredentials(advNew("at-new", "rt-new")); err != nil { // ②
		t.Fatalf("adopt: %v", err)
	}
	close(release) // ③ 放行旧 refresh

	select {
	case err := <-refreshDone:
		if err != nil {
			t.Fatalf("旧世界刷新结果必须被静默丢弃（返回 nil），得到: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("refresh 未返回（装置失效）")
	}

	// ⑤ 内存：新授权优先（含旧调用方在之后主动 SaveAtomicRetry 的路径）。
	if got := a.AccessTokenValue(); got != "at-new" {
		t.Errorf("内存 accessToken=%q want at-new", got)
	}
	if got := a.RefreshTokenValue(); got != "rt-new" {
		t.Errorf("内存 refreshToken=%q want rt-new", got)
	}
	// ⑤ 磁盘：必须仍是新授权（旧调用方的 SaveAtomicRetry 写的是"当前内存"，
	// 内存已被代次守卫保护，所以写出的也是新凭证）。
	onDisk := diskCred(t, a.FilePath)
	if onDisk.AccessToken != "at-new" || onDisk.RefreshToken != "rt-new" {
		t.Fatalf("磁盘被旧世界结果覆盖：at=%q rt=%q", onDisk.AccessToken, onDisk.RefreshToken)
	}
	raw, _ := os.ReadFile(a.FilePath)
	if strings.Contains(string(raw), "at-stale") || strings.Contains(string(raw), "rt-stale") {
		t.Error("凭证文件出现旧世界 token（重登等于白做）")
	}
	if got, want := a.Epoch(), uint64(1); got != want {
		t.Errorf("credEpoch=%d want %d", got, want)
	}
	// 落盘代次与内存一致（重启对账的前提）。
	if onDisk.Epoch() != a.Epoch() {
		t.Errorf("文件代次=%d 内存代次=%d，必须一致（否则重启对账会误判）", onDisk.Epoch(), a.Epoch())
	}
}

// TestStaleSessionDeadDoesNotKillRelogin 旧 refresh 返回 **12153（session dead）** 时，
// 调用方会据此 Disable 账号。重登刚换了新凭据，这个判死结论必须作废：
// RefreshToken 返回 nil（既不报错也不判死），账号保持可用。
func TestStaleSessionDeadDoesNotKillRelogin(t *testing.T) {
	dir := t.TempDir()
	a := advSeed(t, dir)

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	c := &upstream.Client{
		HTTP: &http.Client{Transport: advRT(func(r *http.Request) (*http.Response, error) {
			entered <- struct{}{}
			<-release
			// 上游对**旧** RT 的判死响应（真实形态：401 + 业务码 12153）。
			return advJSON(http.StatusUnauthorized,
				`{"code":12153,"msg":"Offline user session not found"}`), nil
		})},
		ChatBaseCN:    "https://chat.example",
		BillingBaseCN: "https://billing.example",
	}

	done := make(chan error, 1)
	go func() { done <- c.RefreshToken(a) }()
	<-entered

	if err := a.AdoptCredentials(advNew("at-new2", "rt-new2")); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	close(release)

	select {
	case err := <-done:
		// handler 的写法：err==nil → 不 Disable；err!=nil 且 Kind==SessionDead → Disable。
		if err != nil {
			t.Fatalf("旧世界的 12153 必须被丢弃（否则刚恢复的号会被立即禁用）: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("refresh 未返回（装置失效）")
	}
	if onDisk := diskCred(t, a.FilePath); onDisk.AccessToken != "at-new2" {
		t.Errorf("磁盘 accessToken=%q want at-new2", onDisk.AccessToken)
	}
}

// TestRefreshStillAppliesWithoutRelogin 对照组：没有重登时，在途 refresh 结果必须
// 正常写回（证明上面两个用例不是被装置"永远丢弃"式地假绿）。
func TestRefreshStillAppliesWithoutRelogin(t *testing.T) {
	dir := t.TempDir()
	a := advSeed(t, dir)

	release := make(chan struct{})
	close(release) // 不阻塞
	c := &upstream.Client{
		HTTP: &http.Client{Transport: advRT(func(r *http.Request) (*http.Response, error) {
			return advJSON(http.StatusOK,
				`{"code":0,"msg":"ok","data":{"accessToken":"at-refreshed","refreshToken":"rt-refreshed","expiresIn":3600}}`), nil
		})},
		ChatBaseCN:    "https://chat.example",
		BillingBaseCN: "https://billing.example",
	}
	if err := c.RefreshToken(a); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := a.AccessTokenValue(); got != "at-refreshed" {
		t.Errorf("对照组：refresh 结果应写回，得到 %q", got)
	}
	if err := a.SaveAtomicRetry(); err != nil {
		t.Fatalf("save: %v", err)
	}
	if onDisk := diskCred(t, a.FilePath); onDisk.AccessToken != "at-refreshed" {
		t.Errorf("对照组：磁盘应写回刷新结果，得到 %q", onDisk.AccessToken)
	}
	// 普通刷新不 bump 代次（只有整体替换才 bump）——否则重启对账会把普通刷新
	// 误判成"重新授权过"。
	if a.Epoch() != 0 {
		t.Errorf("普通刷新不应改变代次，得到 %d", a.Epoch())
	}
}

// TestConcurrentReloginAndRefreshStress 多轮叠加压测：N 个在途 refresh 与 M 次重登录
// 交错执行，最后必须收敛到「最后一次重登录的凭证」，且代次单调、文件与内存一致。
// 竞态检测交给 `go test -race`；断言只关心可承诺的收敛性。
//
// 分两段是为了让断言有意义：**并发段**只断言「代次单调 + 无错误 + 无死锁」；
// 停掉 refresher 并 join 之后再做**最后一次**替换，此时才有资格断言「最终凭证
// 就是这次替换的结果」。否则一个「重登录之后才发起」的 refresh 合法地拿到更新的
// token（它用的是新 RT），拿它当失败证据是测试写错而不是实现有 bug。
func TestConcurrentReloginAndRefreshStress(t *testing.T) {
	dir := t.TempDir()
	a := advSeed(t, dir)

	c := &upstream.Client{
		HTTP: &http.Client{Transport: advRT(func(r *http.Request) (*http.Response, error) {
			time.Sleep(time.Millisecond) // 拉长锁外窗口，提高交错概率
			return advJSON(http.StatusOK,
				`{"code":0,"msg":"ok","data":{"accessToken":"at-refreshed","refreshToken":"rt-refreshed","expiresIn":3600}}`), nil
		})},
		ChatBaseCN:    "https://chat.example",
		BillingBaseCN: "https://billing.example",
	}

	const refreshers = 8
	const relogins = 6
	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < refreshers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// 与真实调用方一致：refresh 成功就落盘（handler / scheduler 都这么写）。
				if err := c.RefreshToken(a); err == nil {
					_ = a.SaveAtomicRetry()
				}
			}
		}()
	}

	// —— 并发段：与 refresher 交错的 M-1 次重登录 ——
	var lastEpoch uint64
	for i := 0; i < relogins-1; i++ {
		at := "at-new-" + string(rune('a'+i))
		rt := "rt-new-" + string(rune('a'+i))
		if err := a.AdoptCredentials(advNew(at, rt)); err != nil {
			t.Fatalf("adopt #%d: %v", i, err)
		}
		epoch := a.Epoch()
		if epoch <= lastEpoch {
			t.Fatalf("代次必须单调递增：%d → %d", lastEpoch, epoch)
		}
		lastEpoch = epoch
	}

	// 停掉所有 refisher 并 join：此后不再有人写凭证，收敛断言才有意义。
	close(stop)
	wg.Wait()

	// 并发段结束后：内存与磁盘必须一致（代次一致说明没有"迟到的旧世界落盘"）。
	//
	// 注意不断言"等于某次 adopt"：并发段里合法的 refresh 也可能最后落盘。
	if mem, disk := a.AccessTokenValue(), diskCred(t, a.FilePath).AccessToken; mem != disk {
		t.Fatalf("并发段结束时内存(%q)与磁盘(%q)不一致 —— 有写回丢失或错序", mem, disk)
	}
	if d := diskCred(t, a.FilePath); d.Epoch() != a.Epoch() {
		t.Fatalf("并发段结束时文件代次=%d 内存代次=%d 必须一致", d.Epoch(), a.Epoch())
	}

	// —— 收敛段：无人并发时的最后一次替换，必须完整生效 ——
	const finalAT, finalRT = "at-final", "rt-final"
	if err := a.AdoptCredentials(advNew(finalAT, finalRT)); err != nil {
		t.Fatalf("final adopt: %v", err)
	}
	if got := a.AccessTokenValue(); got != finalAT {
		t.Errorf("内存 accessToken=%q want %q", got, finalAT)
	}
	if got := a.RefreshTokenValue(); got != finalRT {
		t.Errorf("内存 refreshToken=%q want %q", got, finalRT)
	}
	onDisk := diskCred(t, a.FilePath)
	if onDisk.AccessToken != finalAT || onDisk.RefreshToken != finalRT {
		t.Fatalf("磁盘 at=%q rt=%q want %q/%q（最终替换未落盘）",
			onDisk.AccessToken, onDisk.RefreshToken, finalAT, finalRT)
	}
	if onDisk.Epoch() != a.Epoch() {
		t.Errorf("磁盘代次=%d 内存代次=%d 必须一致", onDisk.Epoch(), a.Epoch())
	}
	if a.Epoch() != uint64(relogins) {
		t.Errorf("代次=%d want %d（每次整体替换必须 +1）", a.Epoch(), relogins)
	}
}
