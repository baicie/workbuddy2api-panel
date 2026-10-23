package server

// 面板管理接口鉴权（api_key）与上游账号鉴权的**完全隔离**。
//
// 两条 401 的成因毫无关系，混在一起会造成两种事故：
//   - 面板收到错误 Bearer 却去动账号池（禁用/冷却/换凭据）→ 一次误触发把好号打掉；
//   - 上游账号 401 被判死时连带影响面板 api_key 校验 → 运维打不开面板、无法重登救号。
//
// 本文件防的回归：
//   - /panel/api/* 的 401 只返回 {"error":"invalid_api_key"}，绝不碰 pool（历史实现就是
//     纯鉴权失败，零池操作）；
//   - 上游 12153 走 applyErrorPolicy → DisableAuth(...AuthFaultSessionDead)，只改账号状态，
//     面板鉴权仍用同一 api_key 正常放行；
//   - 两个鉴权域的 401 响应契约不同（面板扁平 / 网关 OpenAI 形），前端与客户端各认自己的。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
	"github.com/misakano7545/workbuddy2api-panel/internal/panel"
	"github.com/misakano7545/workbuddy2api-panel/internal/pool"
	"github.com/misakano7545/workbuddy2api-panel/internal/upstream"
)

const isolationAPIKey = "iso-key-123"

// newIsolationHandler 装配「主路由 + 面板」同体部署（main 的真实形态）：
// 两个 handler 共用同一个 api_key，但各自独立鉴权。
func newIsolationHandler(t *testing.T, p *pool.Pool, up *upstream.Client) *Handler {
	t.Helper()
	pnl := panel.New(panel.Config{
		Pool:     p,
		Upstream: up,
		APIKey:   isolationAPIKey,
		Version:  "test",
	})
	return NewHandler(Config{
		Pool:     p,
		Upstream: up,
		APIKey:   isolationAPIKey,
		Panel:    pnl,
	})
}

// isoReq 发一次请求；key 为空表示不带 Authorization。
func isoReq(h *Handler, method, path, body, key string) (*httptest.ResponseRecorder, map[string]any) {
	var rd *strings.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	var req *http.Request
	if rd == nil {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, rd)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	doc := map[string]any{}
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	}
	return rec, doc
}

// TestPanelAPIKey401DoesNotTouchPoolAccount 面板鉴权失败是纯 401：池内账号的
// 禁用/故障/冷却/余额/凭据一律不变，且不触达上游。
func TestPanelAPIKey401DoesNotTouchPoolAccount(t *testing.T) {
	p := testPoolWith(
		&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999},
		&auth.Auth{UID: "u2", AccessToken: "at2", ExpiresAt: 9999999999},
	)
	// u2 处于「认证失效需重登」态：错误 Bearer 不该把它救活或改写成别的状态。
	p.DisableAuth("u2", "12153 session dead", pool.AuthFaultSessionDead)
	upCalls := 0
	up := newFakeUpstream(t, func(string) (int, string, bool) {
		upCalls++
		return 200, sseOK, true
	})
	h := newIsolationHandler(t, p, up)

	before := p.List()
	at1Before := p.AuthByUID("u1").AccessTokenValue()
	at2Before := p.AuthByUID("u2").AccessTokenValue()

	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/panel/api/overview", ""},
		{http.MethodPost, "/panel/api/accounts/u1/relogin/start", "{}"},
		{http.MethodPost, "/panel/api/accounts/u2/relogin/start", "{}"},
	} {
		rec, doc := isoReq(h, c.method, c.path, c.body, "wrong-key")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s status=%d want 401", c.method, c.path, rec.Code)
			continue
		}
		// 面板契约：扁平 {"error":"invalid_api_key"}（与网关 OpenAI 形不同）。
		if got, _ := doc["error"].(string); got != "invalid_api_key" {
			t.Errorf("%s %s error=%v want invalid_api_key", c.method, c.path, doc["error"])
		}
	}

	if !reflect.DeepEqual(p.List(), before) {
		t.Errorf("面板鉴权失败改动了账号池:\nbefore=%+v\nafter =%+v", before, p.List())
	}
	if got := p.AuthByUID("u1").AccessTokenValue(); got != at1Before {
		t.Errorf("面板鉴权失败改动了凭据: %q", got)
	}
	if got := p.AuthByUID("u2").AccessTokenValue(); got != at2Before {
		t.Errorf("面板鉴权失败改动了凭据: %q", got)
	}
	if upCalls != 0 {
		t.Errorf("面板鉴权失败不该触达上游，实际 %d 次", upCalls)
	}
	// 缺 Authorization 同样是 401（不是放行）。
	if rec, _ := isoReq(h, http.MethodGet, "/panel/api/overview", "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("缺 Bearer status=%d want 401", rec.Code)
	}
}

// TestUpstreamAccount401DoesNotAffectPanelAuth 上游账号 401 只影响账号状态：
// 面板仍能用同一 api_key 正常访问（并看到 needs_relogin=true，给出重登入口）；
// 网关侧的错误 Bearer 仍是 401，与账号状态无关。
func TestUpstreamAccount401DoesNotAffectPanelAuth(t *testing.T) {
	up := newFakeUpstream(t, func(authz string) (int, string, bool) {
		return http.StatusUnauthorized, `{"code":12153,"msg":"Offline user session not found"}`, false
	})
	p := testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999})
	h := newIsolationHandler(t, p, up)

	// 前提：鉴权正常的两个入口都能用。
	if rec, _ := isoReq(h, http.MethodGet, "/panel/api/overview", "", isolationAPIKey); rec.Code != http.StatusOK {
		t.Fatalf("precondition: panel overview status=%d body=%s", rec.Code, rec.Body.String())
	}

	// 上游 12153：账号被判死（需重登）。
	rec, _ := isoReq(h, http.MethodPost, "/v1/chat/completions",
		`{"model":"glm-5.2","messages":[]}`, isolationAPIKey)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("chat status=%d want 503（唯一账号已禁用）body=%s", rec.Code, rec.Body.String())
	}
	st, _ := p.Status("u1")
	if !st.Disabled {
		t.Fatalf("上游 12153 应禁用账号: %+v", st)
	}
	if st.AuthFault != string(pool.AuthFaultSessionDead) || !st.NeedsRelogin {
		t.Fatalf("应打上 session_dead 认证故障标记: %+v", st)
	}

	// 面板鉴权不受影响：同一 api_key 仍能读到「需重登」的账号。
	prec, pd := isoReq(h, http.MethodGet, "/panel/api/overview", "", isolationAPIKey)
	if prec.Code != http.StatusOK {
		t.Fatalf("账号 401 后面板鉴权被牵连: status=%d body=%s", prec.Code, prec.Body.String())
	}
	accts, _ := pd["accounts"].([]any)
	if len(accts) != 1 {
		t.Fatalf("overview accounts=%v", pd["accounts"])
	}
	row, _ := accts[0].(map[string]any)
	if row["disabled"] != true {
		t.Errorf("overview: disabled=%v want true", row["disabled"])
	}
	if row["needs_relogin"] != true {
		t.Errorf("overview: needs_relogin=%v want true（面板据此给重登按钮）", row["needs_relogin"])
	}
	if row["auth_fault"] != string(pool.AuthFaultSessionDead) {
		t.Errorf("overview: auth_fault=%v want session_dead", row["auth_fault"])
	}

	// 面板错误 Bearer 仍是 401（与账号状态无关）；网关错误 Bearer 也是 401。
	if bad, _ := isoReq(h, http.MethodGet, "/panel/api/overview", "", "wrong-key"); bad.Code != http.StatusUnauthorized {
		t.Errorf("面板错误 Bearer status=%d want 401", bad.Code)
	}
	if bad, _ := isoReq(h, http.MethodGet, "/v1/models", "", "wrong-key"); bad.Code != http.StatusUnauthorized {
		t.Errorf("网关错误 Bearer status=%d want 401", bad.Code)
	}
}

// TestTwoAuthDomainsHaveDistinct401Contracts 两个鉴权域的 401 响应必须各认各的：
// 面板是扁平 {"error":"invalid_api_key"}，网关是 OpenAI 错误信封。混用会让前端
// 或客户端把「面板 key 错」当成「网关 key 错」，反之亦然。
func TestTwoAuthDomainsHaveDistinct401Contracts(t *testing.T) {
	p := testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999})
	h := newIsolationHandler(t, p, newFakeUpstream(t, func(string) (int, string, bool) {
		return 200, sseOK, true
	}))

	prec, pdoc := isoReq(h, http.MethodGet, "/panel/api/overview", "", "nope")
	if prec.Code != http.StatusUnauthorized {
		t.Fatalf("panel status=%d want 401", prec.Code)
	}
	if _, isString := pdoc["error"].(string); !isString {
		t.Errorf("面板 401 应是扁平 error 字符串，得到 %#v", pdoc["error"])
	}

	grec, gdoc := isoReq(h, http.MethodGet, "/v1/models", "", "nope")
	if grec.Code != http.StatusUnauthorized {
		t.Fatalf("gateway status=%d want 401", grec.Code)
	}
	errObj, ok := gdoc["error"].(map[string]any)
	if !ok {
		t.Fatalf("网关 401 应是 OpenAI 错误信封，得到 %#v", gdoc["error"])
	}
	if errObj["code"] != "invalid_api_key" {
		t.Errorf("网关 401 code=%v want invalid_api_key", errObj["code"])
	}
	// 两条路径的 401 都不包含任何凭据。
	for _, body := range []string{prec.Body.String(), grec.Body.String()} {
		if strings.Contains(body, "at1") {
			t.Errorf("401 响应泄露凭据: %s", body)
		}
	}
	// 池内账号不受任何一次鉴权失败影响。
	if st, _ := p.Status("u1"); st.Disabled || st.AuthFault != "" {
		t.Errorf("鉴权失败不得改动账号状态: %+v", st)
	}
}
