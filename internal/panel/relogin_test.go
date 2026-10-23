package panel

// 401 失效账号「原位重新登录」的面板接口（relogin.go + login.go 的 poll 分叉）。
//
// 本文件防的回归：
//   - 重登录变成「新增账号」：账号池多一个号、历史统计/优先级/冷却脱节、磁盘多一个凭证文件；
//   - 串号：授权弹窗里登录了**别的**账号，凭据被写进目标账号的文件（A/B 互持 token）；
//   - 打错域：global 授权写进 CN 账号（或反之），之后整号持续 401 且极难定位；
//   - 陈旧的 state 还能改凭据：超过 loginTTL 的授权不该还能落盘；
//   - 面板响应泄露 accessToken/refreshToken（前端会把响应写进日志/页面）；
//   - 凭据写入失败却回「成功」（运维以为重登生效，实际还是旧凭证）；
//   - 重登录顺手跑了「新账号初始化任务」（expert 系每轮 8 次真实对话，白烧额度）。
//
// 手法：loginHTTP 是包级变量，替换成按 URL 路径分发的假 Transport 模拟
// auth/state → auth/token → login/account 三段设备授权；全程零真实网络。

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
	"github.com/misakano7545/workbuddy2api-panel/internal/pool"
	"github.com/misakano7545/workbuddy2api-panel/internal/upstream"
)

const (
	// 假凭据字面值：测试断言这些字符串绝不出现在任何 HTTP 响应里。
	fakeAccessToken  = "AT-RELGIN-SECRET-9f3a"
	fakeRefreshToken = "RT-RELGIN-SECRET-7c1b"

	panelTestKey = "test-panel-key"
)

// loginFake 假设备授权上游：state → token → account 三段按路径分发。
type loginFake struct {
	mu       sync.Mutex
	stateSeq int
	// pending=true 时 token 端点回业务错误（= 用户还没完成授权）。
	pending  bool
	domain   string // token 响应里的 domain（realm 校验用）
	uid      string // account 端点返回的 uid（可故意返回别的账号 → 串号测试）
	nickname string

	hosts      []string // 依次命中的 host（验证 realm→端点切换）
	stateCalls int
	tokenCalls int
	acctCalls  int
}

func newLoginFake(uid, nickname, domain string) *loginFake {
	return &loginFake{uid: uid, nickname: nickname, domain: domain}
}

func fakeHTTPResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func (f *loginFake) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.hosts = append(f.hosts, r.URL.Host)
	f.mu.Unlock()

	path := r.URL.Path
	switch {
	case strings.HasSuffix(path, "/v2/plugin/auth/state"):
		f.mu.Lock()
		f.stateSeq++
		f.stateCalls++
		st := fmt.Sprintf("fake-state-%d", f.stateSeq)
		f.mu.Unlock()
		return fakeHTTPResponse(http.StatusOK,
			`{"code":0,"data":{"state":"`+st+`","authUrl":"https://auth.example/?state=`+st+`"}}`), nil
	case strings.HasSuffix(path, "/v2/plugin/auth/token"):
		f.mu.Lock()
		f.tokenCalls++
		pending, domain := f.pending, f.domain
		f.mu.Unlock()
		if pending {
			return fakeHTTPResponse(http.StatusOK, `{"code":1,"msg":"login ing"}`), nil
		}
		return fakeHTTPResponse(http.StatusOK,
			`{"code":0,"data":{"accessToken":"`+fakeAccessToken+`","refreshToken":"`+fakeRefreshToken+`","expiresIn":3600,"domain":"`+domain+`"}}`), nil
	case strings.HasSuffix(path, "/v2/plugin/login/account"):
		f.mu.Lock()
		f.acctCalls++
		uid, nick := f.uid, f.nickname
		f.mu.Unlock()
		return fakeHTTPResponse(http.StatusOK,
			`{"code":0,"data":{"uid":"`+uid+`","enterpriseId":"","nickname":"`+nick+`"}}`), nil
	}
	return nil, fmt.Errorf("unexpected login endpoint: %s", r.URL.String())
}

// lastHost 最近一次命中上游的 host（realm 端点切换的观察点）。
func (f *loginFake) lastHost() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.hosts) == 0 {
		return ""
	}
	return f.hosts[len(f.hosts)-1]
}

// roundTripStub 把函数适配成 http.RoundTripper（余额端点假上游用）。
type roundTripStub func(*http.Request) (*http.Response, error)

func (f roundTripStub) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// withLoginFake 替换包级 loginHTTP 并在测试结束还原（避免污染同包其它用例）。
func withLoginFake(t *testing.T, f *loginFake) {
	t.Helper()
	old := loginHTTP
	loginHTTP = &http.Client{Transport: f}
	t.Cleanup(func() { loginHTTP = old })
}

// newReloginAccount 造一个已落盘的 OAuth 账号（cn/global 由 realm 决定）。
func newReloginAccount(t *testing.T, p *pool.Pool, dir, uid, realm string) *auth.Auth {
	t.Helper()
	a := &auth.Auth{
		AccessToken:  "at-old-" + uid,
		RefreshToken: "rt-old-" + uid,
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		Domain:       "copilot.tencent.com",
		UID:          uid,
		Nickname:     "Nick-" + uid,
		FilePath:     filepath.Join(dir, "workbuddy-"+uid+".json"),
	}
	if realm == "global" {
		a.Domain = "www.workbuddy.ai"
	}
	if _, err := auth.BackfillRealmFor(a, realm); err != nil {
		t.Fatalf("set realm: %v", err)
	}
	if err := a.SaveAtomic(); err != nil {
		t.Fatalf("precondition: save credentials: %v", err)
	}
	p.Add(a)
	return a
}

func newReloginPanel(t *testing.T, p *pool.Pool, up *upstream.Client) *Panel {
	t.Helper()
	return New(Config{
		Pool:             p,
		Upstream:         up,
		APIKey:           panelTestKey,
		Version:          "test",
		AuthDir:          t.TempDir(),
		AutoTasksEnabled: func() bool { return true },
	})
}

// panelCall 发一次带合法 Bearer 的面板请求（不依赖 *testing.T，可在 goroutine 里用）。
func panelCall(pn *Panel, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Authorization", "Bearer "+panelTestKey)
	rec := httptest.NewRecorder()
	pn.ServeHTTP(rec, req)
	doc := map[string]any{}
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	}
	return rec, doc
}

func startRelogin(pn *Panel, uid string) (*httptest.ResponseRecorder, map[string]any) {
	return panelCall(pn, http.MethodPost, "/panel/api/accounts/"+uid+"/relogin/start", "{}")
}

func pollLogin(pn *Panel, state string) (*httptest.ResponseRecorder, map[string]any) {
	return panelCall(pn, http.MethodGet, "/panel/api/login/poll?state="+state, "")
}

// assertNoSecrets 响应体不得出现任何凭据（新旧都不行）：
// 面板响应会被前端写进页面/日志，泄露一次等于凭证公开。
func assertNoSecrets(t *testing.T, where, body string) {
	t.Helper()
	for _, secret := range []string{fakeAccessToken, fakeRefreshToken, "at-old-", "rt-old-", "device_token"} {
		if strings.Contains(body, secret) {
			t.Errorf("%s 响应体泄露凭据 %q: %s", where, secret, body)
		}
	}
}

func readAccountFile(t *testing.T, fp string) []byte {
	t.Helper()
	raw, err := os.ReadFile(fp)
	if err != nil {
		t.Fatalf("read credentials %s: %v", fp, err)
	}
	return raw
}

func mustString(t *testing.T, doc map[string]any, key string) string {
	t.Helper()
	v, ok := doc[key]
	if !ok {
		t.Fatalf("响应缺少字段 %q: %+v", key, doc)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("字段 %q 不是字符串: %#v", key, v)
	}
	return s
}

// TestReloginStartReturnsServerDerivedTarget start 只回「服务端从池内账号推导」的目标信息：
// realm 不信任前端（请求体带 realm 也被忽略），否则一次构造请求就能把 global 授权写进 CN 账号。
func TestReloginStartReturnsServerDerivedTarget(t *testing.T) {
	dir := t.TempDir()
	p := pool.New("")
	newReloginAccount(t, p, dir, "u1", "cn")
	f := newLoginFake("u1", "Nick-u1", "copilot.tencent.com")
	withLoginFake(t, f)
	pn := newReloginPanel(t, p, nil)

	// 请求体故意带 realm=global：服务端必须无视。
	rec, doc := panelCall(pn, http.MethodPost, "/panel/api/accounts/u1/relogin/start", `{"realm":"global"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	assertNoSecrets(t, "relogin/start", rec.Body.String())
	if doc["ok"] != true {
		t.Errorf("ok=%v want true", doc["ok"])
	}
	if got := mustString(t, doc, "mode"); got != string(LoginModeRelogin) {
		t.Errorf("mode=%q want relogin", got)
	}
	if got := mustString(t, doc, "uid"); got != "u1" {
		t.Errorf("uid=%q want u1", got)
	}
	if got := mustString(t, doc, "nickname"); got != "Nick-u1" {
		t.Errorf("nickname=%q want Nick-u1", got)
	}
	if got := mustString(t, doc, "realm"); got != "cn" {
		t.Errorf("realm=%q want cn（服务端按账号推导，忽略请求体）", got)
	}
	if got := mustString(t, doc, "url"); !strings.HasPrefix(got, "https://auth.example/") {
		t.Errorf("url=%q 应为上游授权链接", got)
	}
	if got := mustString(t, doc, "state"); got == "" {
		t.Error("state 不能为空")
	}
	if got, _ := doc["expires_in"].(float64); int(got) != int(loginTTL.Seconds()) {
		t.Errorf("expires_in=%v want %d", doc["expires_in"], int(loginTTL.Seconds()))
	}
	// CN 账号 → CN 端点（realm 推导正确才会打对域）。
	if host := f.lastHost(); host != "copilot.tencent.com" {
		t.Errorf("命中上游 host=%q want copilot.tencent.com", host)
	}

	// 会话已登记为 relogin 且绑定目标 uid（后续 poll 据此校验身份）。
	state := mustString(t, doc, "state")
	pn.loginMu.Lock()
	sess, known := pn.logins[state]
	pn.loginMu.Unlock()
	if !known {
		t.Fatal("start 成功后 state 必须登记到会话表")
	}
	if sess.mode != LoginModeRelogin || sess.targetUID != "u1" || sess.realm != "cn" {
		t.Errorf("会话=%+v want mode=relogin target=u1 realm=cn", sess)
	}
}

// TestReloginStartGlobalAccountUsesGlobalEndpoints global 账号的重登必须打国际版端点
// （否则拿回的凭据属于另一个域）。
func TestReloginStartGlobalAccountUsesGlobalEndpoints(t *testing.T) {
	dir := t.TempDir()
	p := pool.New("")
	newReloginAccount(t, p, dir, "g1", "global")
	f := newLoginFake("g1", "Nick-g1", "www.workbuddy.ai")
	withLoginFake(t, f)
	pn := newReloginPanel(t, p, nil)

	rec, doc := startRelogin(pn, "g1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := mustString(t, doc, "realm"); got != "global" {
		t.Errorf("realm=%q want global", got)
	}
	if host := f.lastHost(); host != "www.workbuddy.ai" {
		t.Errorf("命中上游 host=%q want www.workbuddy.ai", host)
	}
}

// TestReloginStartValidation 入口校验：非法 uid / 不存在 / 静态 API Key 账号都必须在
// 发起 OAuth 之前被挡住（静态 Key 没有 OAuth 身份，重登只会得到另一个账号）。
func TestReloginStartValidation(t *testing.T) {
	t.Run("非法 uid", func(t *testing.T) {
		p := pool.New("")
		p.Add(&auth.Auth{UID: "u1", AccessToken: "at"})
		f := newLoginFake("u1", "n", "copilot.tencent.com")
		withLoginFake(t, f)
		pn := newReloginPanel(t, p, nil)

		rec, _ := panelCall(pn, http.MethodPost, "/panel/api/accounts/bad.uid/relogin/start", "{}")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status=%d want 400（uid 只允许 [A-Za-z0-9_-]，防路径穿越）", rec.Code)
		}
		if f.stateCalls != 0 {
			t.Error("非法 uid 不得触达上游授权端点")
		}
	})

	t.Run("账号不存在", func(t *testing.T) {
		p := pool.New("")
		f := newLoginFake("u1", "n", "copilot.tencent.com")
		withLoginFake(t, f)
		pn := newReloginPanel(t, p, nil)

		rec, _ := startRelogin(pn, "ghost")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status=%d want 404", rec.Code)
		}
		if f.stateCalls != 0 {
			t.Error("账号不存在不得触达上游授权端点")
		}
	})

	t.Run("静态 API Key 账号", func(t *testing.T) {
		p := pool.New("")
		p.Add(&auth.Auth{UID: "k1", AccessToken: "ck_static_key", FilePath: ""})
		f := newLoginFake("k1", "n", "copilot.tencent.com")
		withLoginFake(t, f)
		pn := newReloginPanel(t, p, nil)

		rec, doc := startRelogin(pn, "k1")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status=%d want 400", rec.Code)
		}
		if got := mustString(t, doc, "error"); got != "static_api_key_account" {
			t.Errorf("error=%q want static_api_key_account", got)
		}
		assertNoSecrets(t, "static_api_key_account", rec.Body.String())
		if f.stateCalls != 0 {
			t.Error("静态 Key 账号不得触达 OAuth 端点")
		}
	})
}

// TestReloginStartRejectsConcurrentStart 同一账号并发/连续发起重登必须 409：
// 两个 OAuth 会话会抢写同一个凭证文件，后完成者覆盖先完成者，用户看到「重登成功但号又坏了」。
func TestReloginStartRejectsConcurrentStart(t *testing.T) {
	dir := t.TempDir()
	p := pool.New("")
	newReloginAccount(t, p, dir, "u1", "cn")
	f := newLoginFake("u1", "Nick-u1", "copilot.tencent.com")
	withLoginFake(t, f)
	pn := newReloginPanel(t, p, nil)

	rec, _ := startRelogin(pn, "u1")
	if rec.Code != http.StatusOK {
		t.Fatalf("第一次 start status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec2, doc2 := startRelogin(pn, "u1")
	if rec2.Code != http.StatusConflict {
		t.Fatalf("第二次 start status=%d want 409", rec2.Code)
	}
	if got := mustString(t, doc2, "error"); got != "relogin_in_progress" {
		t.Errorf("error=%q want relogin_in_progress", got)
	}

	// 真正并发：两个请求同时进来，只允许一个拿到会话（另一个 409）。
	p2 := pool.New("")
	newReloginAccount(t, p2, t.TempDir(), "u2", "cn")
	pn2 := newReloginPanel(t, p2, nil)
	var wg sync.WaitGroup
	codes := make([]int, 2)
	errs := make([]string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec, doc := startRelogin(pn2, "u2")
			codes[i] = rec.Code
			if e, ok := doc["error"].(string); ok {
				errs[i] = e
			}
		}(i)
	}
	wg.Wait()
	okCount, conflictCount := 0, 0
	for i, c := range codes {
		switch c {
		case http.StatusOK:
			okCount++
		case http.StatusConflict:
			conflictCount++
			if errs[i] != "relogin_in_progress" {
				t.Errorf("并发落败方 error=%q want relogin_in_progress", errs[i])
			}
		}
	}
	if okCount != 1 || conflictCount != 1 {
		t.Fatalf("并发 start 结果 %v（errs=%v）want 恰好 1 个 200 + 1 个 409", codes, errs)
	}
}

// TestReloginFullFlow 「开始 → 授权完成 → 原位换凭据」的端到端语义：
// 账号数不变、指针不变、统计保留、文件换新、故障解除、会话不重复。
func TestReloginFullFlow(t *testing.T) {
	dir := t.TempDir()
	p := pool.New("")
	acct := newReloginAccount(t, p, dir, "u1", "cn")
	p.SetCredits("u1", 4321, 9000)
	p.NoteSuccess("u1")
	p.SetAccountPriority(map[string]int{"u1": 5})
	// 模拟 12153 判死后的状态：禁用 + 需重登。
	p.DisableAuth("u1", "12153 session dead", pool.AuthFaultSessionDead)
	if st, _ := p.Status("u1"); !st.NeedsRelogin {
		t.Fatalf("precondition: %+v", st)
	}
	stBefore, _ := p.Status("u1")
	ptrBefore := p.AuthByUID("u1")
	pathBefore := acct.FilePath
	fileBefore := readAccountFile(t, pathBefore)

	f := newLoginFake("u1", "Nick-u1", "copilot.tencent.com")
	withLoginFake(t, f)
	pn := newReloginPanel(t, p, nil)
	if pn.getTaskJobManager() != nil {
		t.Fatal("precondition: 任务侧未初始化")
	}

	rec, doc := startRelogin(pn, "u1")
	if rec.Code != http.StatusOK {
		t.Fatalf("start status=%d body=%s", rec.Code, rec.Body.String())
	}
	state := mustString(t, doc, "state")

	prec, pd := pollLogin(pn, state)
	if prec.Code != http.StatusOK {
		t.Fatalf("poll status=%d body=%s", prec.Code, prec.Body.String())
	}
	assertNoSecrets(t, "relogin poll", prec.Body.String())
	if pd["done"] != true || pd["relogin"] != true || pd["auth_ok"] != true {
		t.Errorf("poll 成功字段不全: %+v", pd)
	}
	if got := mustString(t, pd, "mode"); got != string(LoginModeRelogin) {
		t.Errorf("mode=%q want relogin", got)
	}
	if got := mustString(t, pd, "uid"); got != "u1" {
		t.Errorf("uid=%q want u1", got)
	}
	if got := mustString(t, pd, "realm"); got != "cn" {
		t.Errorf("realm=%q want cn", got)
	}
	// Upstream 为 nil：余额未查询，credits=-1、balance_ok=true（不因未查而报失败）。
	if got, _ := pd["credits"].(float64); got != -1 {
		t.Errorf("credits=%v want -1（未查询）", pd["credits"])
	}
	if pd["balance_ok"] != true {
		t.Errorf("balance_ok=%v want true", pd["balance_ok"])
	}

	// 池：仍是 1 个账号、同一个指针、统计/偏好/余额保留、故障解除。
	list := p.List()
	if len(list) != 1 {
		t.Fatalf("账号数=%d want 1（重登绝不新增账号）", len(list))
	}
	if got := p.AuthByUID("u1"); got != ptrBefore {
		t.Error("*auth.Auth 指针身份必须不变（在途请求仍持有它）")
	}
	st, _ := p.Status("u1")
	if st.Disabled || st.NeedsRelogin || st.AuthFault != "" {
		t.Errorf("重登后应恢复: disabled=%v needs_relogin=%v auth_fault=%q",
			st.Disabled, st.NeedsRelogin, st.AuthFault)
	}
	if st.SuccessCount != stBefore.SuccessCount || st.Priority != 5 || st.Credits != 4321 {
		t.Errorf("历史统计/偏好/余额被改动: success %d→%d priority=%d credits=%d",
			stBefore.SuccessCount, st.SuccessCount, st.Priority, st.Credits)
	}
	if got := ptrBefore.AccessTokenValue(); got != fakeAccessToken {
		t.Errorf("池内凭据未换新: %q", got)
	}

	// 磁盘：同一个文件、内容是新 token、没有第二个凭证文件。
	if acct.FilePath != pathBefore {
		t.Errorf("FilePath 被重拼: %q → %q", pathBefore, acct.FilePath)
	}
	parsed, err := auth.Parse(readAccountFile(t, pathBefore))
	if err != nil {
		t.Fatalf("parse credentials: %v", err)
	}
	if parsed.AccessToken != fakeAccessToken || parsed.RefreshToken != fakeRefreshToken {
		t.Errorf("磁盘凭据未换新: %q/%q", parsed.AccessToken, parsed.RefreshToken)
	}
	if string(readAccountFile(t, pathBefore)) == string(fileBefore) {
		t.Error("磁盘凭据文件内容未变化（重登未落盘）")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	jsonCount := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			jsonCount++
		}
	}
	if jsonCount != 1 {
		t.Errorf("凭证目录 json 文件数=%d want 1（不许产生第二个 workbuddy-*.json）", jsonCount)
	}

	// 重登不跑「新账号初始化任务」。
	if pn.getTaskJobManager() != nil {
		t.Error("重登录不得启动新账号后台任务")
	}

	// 会话作废：同一 state 再 poll 得 410，不会重复写盘。
	fileAfterSuccess := readAccountFile(t, pathBefore)
	again, _ := pollLogin(pn, state)
	if again.Code != http.StatusGone {
		t.Errorf("成功后重复 poll status=%d want 410", again.Code)
	}
	if string(readAccountFile(t, pathBefore)) != string(fileAfterSuccess) {
		t.Error("重复 poll 不得再次写盘")
	}

	// 面板总览：needs_relogin=false、disabled=false（前端据此撤掉「重新登录」按钮）。
	orec, odoc := panelCall(pn, http.MethodGet, "/panel/api/overview", "")
	if orec.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", orec.Code, orec.Body.String())
	}
	accts, _ := odoc["accounts"].([]any)
	if len(accts) != 1 {
		t.Fatalf("overview accounts=%v", odoc["accounts"])
	}
	row, _ := accts[0].(map[string]any)
	if row["disabled"] == true {
		t.Error("overview: 重登后 disabled 应为 false")
	}
	if row["needs_relogin"] == true {
		t.Error("overview: 重登后 needs_relogin 应为 false")
	}
	if row["auth_fault"] != nil && row["auth_fault"] != "" {
		t.Errorf("overview: auth_fault=%v want 空", row["auth_fault"])
	}
}

// TestReloginUIDMismatchRejected 授权账号与目标账号不一致 → 409 且池内/磁盘零改动。
// 这是整个流程的安全核心：授权弹窗里可以登录任意账号。
func TestReloginUIDMismatchRejected(t *testing.T) {
	dir := t.TempDir()
	p := pool.New("")
	acct := newReloginAccount(t, p, dir, "u1", "cn")
	p.DisableAuth("u1", "12153 session dead", pool.AuthFaultSessionDead)
	fileBefore := readAccountFile(t, acct.FilePath)
	atBefore := acct.AccessTokenValue()

	f := newLoginFake("attacker-uid", "Evil", "copilot.tencent.com")
	withLoginFake(t, f)
	pn := newReloginPanel(t, p, nil)

	_, doc := startRelogin(pn, "u1")
	state := mustString(t, doc, "state")

	rec, pd := pollLogin(pn, state)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d want 409 body=%s", rec.Code, rec.Body.String())
	}
	if got := mustString(t, pd, "error"); got != "relogin_uid_mismatch" {
		t.Errorf("error=%q want relogin_uid_mismatch", got)
	}
	assertNoSecrets(t, "uid mismatch", rec.Body.String())
	if got := acct.AccessTokenValue(); got != atBefore {
		t.Errorf("拒绝覆盖后内存凭据被改动: %q", got)
	}
	if string(readAccountFile(t, acct.FilePath)) != string(fileBefore) {
		t.Error("拒绝覆盖后磁盘凭据被改动")
	}
	if st, _ := p.Status("u1"); !st.Disabled || !st.NeedsRelogin || st.AuthFault != "session_dead" {
		t.Errorf("拒绝覆盖后账号状态必须原样: %+v", st)
	}
	// 会话作废：同一 state 再 poll → 410。
	if rec2, _ := pollLogin(pn, state); rec2.Code != http.StatusGone {
		t.Errorf("拒绝后重复 poll status=%d want 410", rec2.Code)
	}
}

// TestReloginRealmMismatchRejected global 账号拿到 CN 域凭据 → 409 且零改动。
// 若放行，该账号之后所有出站请求都打错域，表现为整号持续 401。
func TestReloginRealmMismatchRejected(t *testing.T) {
	dir := t.TempDir()
	p := pool.New("")
	acct := newReloginAccount(t, p, dir, "g1", "global")
	p.DisableAuth("g1", "12153 session dead", pool.AuthFaultSessionDead)
	fileBefore := readAccountFile(t, acct.FilePath)

	// global 账号却拿到 copilot.tencent.com（CN 域）的 token 响应。
	f := newLoginFake("g1", "Nick-g1", "copilot.tencent.com")
	withLoginFake(t, f)
	pn := newReloginPanel(t, p, nil)

	_, doc := startRelogin(pn, "g1")
	state := mustString(t, doc, "state")

	rec, pd := pollLogin(pn, state)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d want 409 body=%s", rec.Code, rec.Body.String())
	}
	if got := mustString(t, pd, "error"); got != "relogin_realm_mismatch" {
		t.Errorf("error=%q want relogin_realm_mismatch", got)
	}
	if string(readAccountFile(t, acct.FilePath)) != string(fileBefore) {
		t.Error("域不一致时磁盘凭据必须原样")
	}
	if st, _ := p.Status("g1"); !st.NeedsRelogin {
		t.Errorf("域不一致时账号状态必须原样: %+v", st)
	}
}

// TestReloginPollExpired 超过 loginTTL 的 state 必须 410 并回收：
// 陈旧的授权链接不该还能改凭据（否则「15 分钟有效」是空话）。
func TestReloginPollExpired(t *testing.T) {
	dir := t.TempDir()
	p := pool.New("")
	acct := newReloginAccount(t, p, dir, "u1", "cn")
	p.DisableAuth("u1", "12153 session dead", pool.AuthFaultSessionDead)
	fileBefore := readAccountFile(t, acct.FilePath)

	f := newLoginFake("u1", "Nick-u1", "copilot.tencent.com")
	withLoginFake(t, f)
	pn := newReloginPanel(t, p, nil)
	_, doc := startRelogin(pn, "u1")
	state := mustString(t, doc, "state")

	// 把创建时刻挪到 TTL 之外（等价于用户开着弹窗走开了 16 分钟）。
	pn.loginMu.Lock()
	sess := pn.logins[state]
	sess.created = time.Now().Add(-loginTTL - time.Minute)
	pn.logins[state] = sess
	pn.loginMu.Unlock()

	rec, _ := pollLogin(pn, state)
	if rec.Code != http.StatusGone {
		t.Fatalf("过期 state poll status=%d want 410", rec.Code)
	}
	if string(readAccountFile(t, acct.FilePath)) != string(fileBefore) {
		t.Error("过期会话不得写盘")
	}
	pn.loginMu.Lock()
	_, still := pn.logins[state]
	pn.loginMu.Unlock()
	if still {
		t.Error("过期会话应被回收")
	}
	// 过期后可以重新发起重登（不会被僵尸会话挡住）。
	if rec2, _ := startRelogin(pn, "u1"); rec2.Code != http.StatusOK {
		t.Errorf("过期后重新 start status=%d want 200", rec2.Code)
	}
}

// TestReloginCancel 取消：会话作废、后续 poll 410；处理中的会话拒绝取消（409）；
// 未知 state 幂等成功。用户在浏览器里关掉弹窗时必须能真正停下，否则会一直占位。
func TestReloginCancel(t *testing.T) {
	dir := t.TempDir()
	p := pool.New("")
	newReloginAccount(t, p, dir, "u1", "cn")
	f := newLoginFake("u1", "Nick-u1", "copilot.tencent.com")
	withLoginFake(t, f)
	pn := newReloginPanel(t, p, nil)

	_, doc := startRelogin(pn, "u1")
	state := mustString(t, doc, "state")

	rec, cd := panelCall(pn, http.MethodPost, "/panel/api/login/cancel", `{"state":"`+state+`"}`)
	if rec.Code != http.StatusOK || cd["ok"] != true || cd["cancelled"] != true {
		t.Fatalf("cancel status=%d doc=%+v", rec.Code, cd)
	}
	if prec, _ := pollLogin(pn, state); prec.Code != http.StatusGone {
		t.Errorf("取消后 poll status=%d want 410", prec.Code)
	}

	// 未知 state：幂等成功（cancelled=false），不报错（前端关闭弹窗时会盲发）。
	rec2, cd2 := panelCall(pn, http.MethodPost, "/panel/api/login/cancel", `{"state":"never-existed"}`)
	if rec2.Code != http.StatusOK || cd2["cancelled"] != false {
		t.Errorf("未知 state cancel status=%d doc=%+v", rec2.Code, cd2)
	}
	// 缺 state → 400。
	if rec3, _ := panelCall(pn, http.MethodPost, "/panel/api/login/cancel", `{}`); rec3.Code != http.StatusBadRequest {
		t.Errorf("缺 state status=%d want 400", rec3.Code)
	}

	// 处理中的会话拒绝取消：那一段已在改凭据，中途「取消」只会让前端以为没生效。
	_, doc3 := startRelogin(pn, "u1")
	state3 := mustString(t, doc3, "state")
	pn.loginMu.Lock()
	sess := pn.logins[state3]
	sess.processing = true
	pn.logins[state3] = sess
	pn.loginMu.Unlock()
	rec4, cd4 := panelCall(pn, http.MethodPost, "/panel/api/login/cancel", `{"state":"`+state3+`"}`)
	if rec4.Code != http.StatusConflict {
		t.Fatalf("处理中取消 status=%d want 409", rec4.Code)
	}
	if got := mustString(t, cd4, "error"); got != "login_processing" {
		t.Errorf("error=%q want login_processing", got)
	}
	pn.loginMu.Lock()
	_, alive := pn.logins[state3]
	pn.loginMu.Unlock()
	if !alive {
		t.Error("处理中的会话不得被删除")
	}
}

// TestReloginPollProcessingGate processing 闸门：并发 poll 不得把写凭据/余额校验跑两遍。
func TestReloginPollProcessingGate(t *testing.T) {
	dir := t.TempDir()
	p := pool.New("")
	acct := newReloginAccount(t, p, dir, "u1", "cn")
	p.DisableAuth("u1", "12153 session dead", pool.AuthFaultSessionDead)
	fileBefore := readAccountFile(t, acct.FilePath)

	f := newLoginFake("u1", "Nick-u1", "copilot.tencent.com")
	withLoginFake(t, f)
	pn := newReloginPanel(t, p, nil)
	_, doc := startRelogin(pn, "u1")
	state := mustString(t, doc, "state")

	pn.loginMu.Lock()
	sess := pn.logins[state]
	sess.processing = true // 模拟另一个 poll 正在落盘
	pn.logins[state] = sess
	pn.loginMu.Unlock()

	rec, pd := pollLogin(pn, state)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if pd["done"] != false {
		t.Errorf("闸门命中时应返回 done=false: %+v", pd)
	}
	if !strings.Contains(mustString(t, pd, "message"), "正在写入凭据") {
		t.Errorf("message=%q 应提示正在写入", pd["message"])
	}
	if string(readAccountFile(t, acct.FilePath)) != string(fileBefore) {
		t.Error("闸门命中时不得写盘")
	}
	if st, _ := p.Status("u1"); !st.NeedsRelogin {
		t.Error("闸门命中时账号状态不得变化")
	}
}

// TestReloginWriteFailureKeepsOldState 凭据写盘失败：接口必须返回 500 并明确说「已保留
// 原有凭证」，池状态与旧文件原样。返回假成功会让运维以为重登生效，实际仍是旧凭证。
func TestReloginWriteFailureKeepsOldState(t *testing.T) {
	dir := t.TempDir()
	p := pool.New("")
	acct := newReloginAccount(t, p, dir, "u1", "cn")
	p.DisableAuth("u1", "12153 session dead", pool.AuthFaultSessionDead)
	fileBefore := readAccountFile(t, acct.FilePath)

	f := newLoginFake("u1", "Nick-u1", "copilot.tencent.com")
	withLoginFake(t, f)
	pn := newReloginPanel(t, p, nil)
	_, doc := startRelogin(pn, "u1")
	state := mustString(t, doc, "state")

	// 注入写盘失败：把 safefile 的备份位置占成目录（rename 必然失败），
	// 旧凭证文件本身保留 —— 等价于「auths 目录只读/磁盘满」的现场。
	if err := os.Mkdir(acct.FilePath+".bak", 0o755); err != nil {
		t.Fatalf("inject write failure: %v", err)
	}
	if err := os.WriteFile(filepath.Join(acct.FilePath+".bak", "occupied"), []byte("x"), 0o600); err != nil {
		t.Fatalf("populate: %v", err)
	}

	rec, pd := pollLogin(pn, state)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("写盘失败 status=%d want 500 body=%s", rec.Code, rec.Body.String())
	}
	assertNoSecrets(t, "write failure", rec.Body.String())
	msg, _ := pd["error"].(string)
	if !strings.Contains(msg, "凭据写入失败") {
		t.Errorf("错误信息应明确是写入失败: %q", msg)
	}
	if acct.AccessTokenValue() != "at-old-u1" {
		t.Errorf("写盘失败后内存凭据被改动: %q", acct.AccessTokenValue())
	}
	if string(readAccountFile(t, acct.FilePath)) != string(fileBefore) {
		t.Error("写盘失败后旧凭证文件必须原样")
	}
	st, _ := p.Status("u1")
	if !st.Disabled || !st.NeedsRelogin {
		t.Errorf("写盘失败后账号状态必须原样（仍是需重登）: %+v", st)
	}
}

// TestReloginBalanceFailureReportedNotBlocking 登录成功 ≠ 上游全部服务可用：
// 余额端点 401（降级 token 的既有结论）只体现在 balance_ok/balance_error，
// 不得回滚凭据、不得禁用账号。
func TestReloginBalanceFailureReportedNotBlocking(t *testing.T) {
	dir := t.TempDir()
	p := pool.New("")
	acct := newReloginAccount(t, p, dir, "u1", "cn")
	p.DisableAuth("u1", "12153 session dead", pool.AuthFaultSessionDead)

	f := newLoginFake("u1", "Nick-u1", "copilot.tencent.com")
	withLoginFake(t, f)
	// 余额端点一律 401：模拟降级 token（billing 拒绝、chat 可能仍可用）。
	up := &upstream.Client{
		HTTP: &http.Client{Transport: roundTripStub(func(r *http.Request) (*http.Response, error) {
			return fakeHTTPResponse(http.StatusUnauthorized, `{"code":12153,"msg":"session dead"}`), nil
		})},
		ChatBaseCN:    "https://billing.example",
		BillingBaseCN: "https://billing.example",
	}
	pn := newReloginPanel(t, p, up)
	_, doc := startRelogin(pn, "u1")
	state := mustString(t, doc, "state")

	rec, pd := pollLogin(pn, state)
	if rec.Code != http.StatusOK {
		t.Fatalf("余额失败不该让重登失败: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if pd["done"] != true {
		t.Errorf("done=%v want true（凭据已换新）", pd["done"])
	}
	if pd["balance_ok"] != false {
		t.Errorf("balance_ok=%v want false", pd["balance_ok"])
	}
	if msg, _ := pd["balance_error"].(string); msg == "" {
		t.Error("balance_error 必须如实回报（否则运维只看到「已重登」却继续 401）")
	}
	if got := acct.AccessTokenValue(); got != fakeAccessToken {
		t.Errorf("凭据应已换新: %q", got)
	}
	if st, _ := p.Status("u1"); st.Disabled || st.NeedsRelogin {
		t.Errorf("余额失败不得禁用账号: %+v", st)
	}
}

// TestReloginTargetRemovedDuringLogin OAuth 期间账号被运维移除 → 409 且**不新建账号**：
// 「顺手 Add 一个」会把重登变成新增，与原账号的历史/配置脱节。
func TestReloginTargetRemovedDuringLogin(t *testing.T) {
	dir := t.TempDir()
	p := pool.New("")
	newReloginAccount(t, p, dir, "u1", "cn")
	f := newLoginFake("u1", "Nick-u1", "copilot.tencent.com")
	withLoginFake(t, f)
	pn := newReloginPanel(t, p, nil)
	_, doc := startRelogin(pn, "u1")
	state := mustString(t, doc, "state")

	p.Remove("u1")

	rec, pd := pollLogin(pn, state)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d want 409 body=%s", rec.Code, rec.Body.String())
	}
	if got := mustString(t, pd, "error"); got != "relogin_target_missing" {
		t.Errorf("error=%q want relogin_target_missing", got)
	}
	if got := len(p.List()); got != 0 {
		t.Errorf("账号数=%d want 0（重登绝不新建账号）", got)
	}
}

// TestReloginWrongPanelKeyDoesNotTouchPool 面板鉴权失败与账号重登完全无关：
// 401 时池内账号的 disabled/fault/凭据一律不变。
func TestReloginWrongPanelKeyDoesNotTouchPool(t *testing.T) {
	dir := t.TempDir()
	p := pool.New("")
	acct := newReloginAccount(t, p, dir, "u1", "cn")
	p.DisableAuth("u1", "12153 session dead", pool.AuthFaultSessionDead)
	stBefore, _ := p.Status("u1")
	fileBefore := readAccountFile(t, acct.FilePath)

	pn := newReloginPanel(t, p, nil)
	req := httptest.NewRequest(http.MethodPost, "/panel/api/accounts/u1/relogin/start", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer wrong-key")
	rec := httptest.NewRecorder()
	pn.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", rec.Code)
	}
	assertNoSecrets(t, "panel 401", rec.Body.String())
	stAfter, _ := p.Status("u1")
	if !reflect.DeepEqual(stAfter, stBefore) {
		t.Errorf("面板鉴权失败不得改动池状态:\nbefore=%+v\nafter =%+v", stBefore, stAfter)
	}
	if string(readAccountFile(t, acct.FilePath)) != string(fileBefore) {
		t.Error("面板鉴权失败不得改动凭证文件")
	}
	if pn.getTaskJobManager() != nil {
		t.Error("面板鉴权失败不得启动任务")
	}
}
