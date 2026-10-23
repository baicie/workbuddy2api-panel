// relogin.go 401/12153 失效账号的**原位**重新登录。
//
// 与 login.go（添加账号）的区别只在「完成之后做什么」——前置的设备授权流程完全复用：
//
//	POST /panel/api/accounts/{uid}/relogin/start → 依池内现有账号确定 realm，发起 OAuth，
//	  在 loginSession 里绑定 {targetUID, realm, mode=relogin, state, TTL}；
//	GET  /panel/api/login/poll?state= → 完成时**校验身份与域**，然后原位替换凭据；
//	POST /panel/api/login/cancel     → 显式取消（关闭弹窗/放弃等待）时清理会话。
//
// 三条硬约束（本文件存在的主要理由）：
//  1. **不删号重建**：走 auth.Auth.AdoptCredentials 原位换凭据，账号池条目、历史统计、
//     优先级/份额/路由配置、冷却态全部保留；绝不 pool.Remove + pool.Add。
//  2. **不串号**：新授权返回的 UID 必须等于目标 UID，Realm 必须等于目标账号的 Realm，
//     任一不符就拒绝覆盖（旧凭证与账号状态原样保留）。
//  3. **不误清状态**：成功后只走 pool.ClearAuthFault 的窄口径恢复，绝不调 pool.Revive
//     （那会把管理员暂停选号、模型级冷却、熔断、连败降权一起清空）。
package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
)

// loginToken 设备授权 token 端点的成功响应（auth/token）。
// 只在内存中流转：任何日志/HTTP 响应都不得包含 accessToken / refreshToken。
type loginToken struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int64  `json:"expiresIn"`
	Domain       string `json:"domain"`
}

// loginAccount 账号信息端点（login/account）的响应。
type loginAccount struct {
	UID          string `json:"uid"`
	EnterpriseID string `json:"enterpriseId"`
	Nickname     string `json:"nickname"`
}

// sweepExpiredLoginsLocked 回收超过 loginTTL 的会话（调用方必须已持 loginMu）。
// 新增账号与重新登录共用：状态表是进程内唯一来源，不清理会让"开弹窗走开"的 state
// 永久占位（尤其是重登的并发查重会被一条永不过期的僵尸会话挡住）。
func (p *Panel) sweepExpiredLoginsLocked() {
	now := time.Now()
	for st, sess := range p.logins {
		if now.Sub(sess.created) > loginTTL {
			delete(p.logins, st)
		}
	}
}

// loginSessionExpired 报告会话是否已超过 TTL（不修改状态，供调用方决定 410/清表）。
func loginSessionExpired(sess loginSession, now time.Time) bool {
	return now.Sub(sess.created) > loginTTL
}

// dropLoginSession 删除指定 state 的会话（幂等）。取消/失败终态时用：
// 会话一旦作废，同一 state 的后续 poll 会得到 410，不会重复落盘。
func (p *Panel) dropLoginSession(state string) {
	p.loginMu.Lock()
	delete(p.logins, state)
	p.loginMu.Unlock()
}

// reloginStart POST /panel/api/accounts/{uid}/relogin/start
//
// 请求体被忽略（可空）：目标账号与 Realm 一律由服务端依池内现有账号推导。
// 这是刻意的——若接受前端传入 realm，一次构造请求就能把 global 授权写进 CN 账号，
// 该账号后续所有出站请求都会打错域（表现为整号持续 401，且极难定位）。
func (p *Panel) reloginStart(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	// UID 来自 URL 且会被拿去拼文件名/查表：复用添加账号路径的同一套白名单校验，
	// 防路径穿越与异常超长串（口径与 loginPoll 对上游 uid 的校验完全一致）。
	if !validUID(uid) {
		writeErr(w, http.StatusBadRequest, "invalid uid")
		return
	}
	if p.cfg.Pool == nil {
		writeErr(w, http.StatusNotImplemented, "账号池未装配")
		return
	}
	acct := p.cfg.Pool.AuthByUID(uid)
	if acct == nil {
		writeErr(w, http.StatusNotFound, "账号不存在")
		return
	}
	// 静态 API Key 账号没有 OAuth 身份可重新授权（ck_/pt_ 是控制台签发的固定 Key，
	// 不属于设备授权流）；对它开放重登只会得到一个和原账号无关的新账号。
	if acct.IsAPIKey() {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":      false,
			"error":   "static_api_key_account",
			"message": "静态 API Key 账号不支持 OAuth 重新登录；Key 失效请在「添加账号 → API Key」里重新添加",
		})
		return
	}
	// Realm 取**标识**口径（ResolveRealm：显式 realm 优先，其次按 domain 推断），
	// 而不是 acct.Realm()——后者含 global 逃生门（config 关掉 global 时恒返回 cn），
	// 那是**路由**锁，不该参与身份判定：否则纯 CN 部署下一开关就让 global 账号的
	// 重登被迫走 CN 端点，拿回来的凭据域对不上，重登永远失败。
	realm := auth.ResolveRealm(acct.RealmStored(), acct.DomainValue())
	if realm != "global" {
		realm = "cn"
	}
	nickname := acct.Nickname

	// 并发保护（第一段）：占住 uid，挡住"两个请求都在会话入表前通过校验"的并发窗口。
	if !p.reserveRelogin(uid) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok":      false,
			"error":   "relogin_in_progress",
			"message": "该账号已有进行中的重新登录，请先完成或关闭后再试",
		})
		return
	}
	var reserved = true
	release := func() {
		if reserved {
			p.releaseRelogin(uid)
			reserved = false
		}
	}
	defer release()

	// 发起设备授权（端点随目标账号的 realm 切换，与添加账号同源）。
	epState, _, _, origin := loginEndpoints(realm)
	data, status, err := doJSON(http.MethodPost, epState, "", bytes.NewReader([]byte("{}")), origin)
	if err != nil {
		writeErr(w, http.StatusBadGateway, fmt.Sprintf("auth state (upstream %d): %v", status, err))
		return
	}
	var st struct {
		State   string `json:"state"`
		AuthURL string `json:"authUrl"`
	}
	if err := json.Unmarshal(data, &st); err != nil || st.State == "" || st.AuthURL == "" {
		writeErr(w, http.StatusBadGateway, "auth state: missing state or authUrl")
		return
	}

	// 并发保护（第二段）：会话入表，此后由 logins 查重接管。
	p.loginMu.Lock()
	p.sweepExpiredLoginsLocked()
	p.logins[st.State] = loginSession{
		created:        time.Now(),
		realm:          realm,
		mode:           LoginModeRelogin,
		targetUID:      uid,
		targetNickname: nickname,
	}
	p.loginMu.Unlock()
	release()

	log.Printf("panel: 发起 OAuth 重新登录 uid=%s nickname=%q realm=%s（state=%s...）",
		uid, nickname, realm, st.State[:min(8, len(st.State))])
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"mode":       string(LoginModeRelogin),
		"uid":        uid,
		"nickname":   nickname,
		"realm":      realm,
		"url":        st.AuthURL,
		"state":      st.State,
		"expires_in": int(loginTTL.Seconds()),
	})
}

// reserveRelogin 占住某账号的重新登录；已有在途（发起中或会话未过期）返回 false。
func (p *Panel) reserveRelogin(uid string) bool {
	p.loginMu.Lock()
	defer p.loginMu.Unlock()
	p.sweepExpiredLoginsLocked()
	if p.reloginBusy == nil {
		p.reloginBusy = map[string]bool{}
	}
	if p.reloginBusy[uid] {
		return false
	}
	// 已有一条未过期的重登会话 → 拒绝并发（两个 OAuth 会话会抢写同一个凭证文件，
	// 后完成者覆盖先完成者，用户看到的是"重登成功但账号又坏了"）。
	for _, sess := range p.logins {
		if sess.mode == LoginModeRelogin && sess.targetUID == uid {
			return false
		}
	}
	p.reloginBusy[uid] = true
	return true
}

// releaseRelogin 释放发起占位（幂等）。
func (p *Panel) releaseRelogin(uid string) {
	p.loginMu.Lock()
	delete(p.reloginBusy, uid)
	p.loginMu.Unlock()
}

// loginCancel POST /panel/api/login/cancel {"state":"..."}
//
// 显式取消一次进行中的授权（前端关闭弹窗 / 用户放弃等待）。删除会话后同一 state
// 的后续 poll 得到 410，前端据此停止轮询；15 分钟 TTL 仍是兜底。
// 正在落盘的会话拒绝取消（409）：那一段已经在改凭据/池状态，中途"取消"只会让
// 前端以为没生效、实际却已生效，比不取消更糟。
func (p *Panel) loginCancel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		State string `json:"state"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&body)
	}
	state := strings.TrimSpace(body.State)
	if state == "" {
		writeErr(w, http.StatusBadRequest, "missing state")
		return
	}
	p.loginMu.Lock()
	sess, known := p.logins[state]
	if known && sess.processing {
		p.loginMu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok":      false,
			"error":   "login_processing",
			"message": "正在写入凭据，请稍候",
		})
		return
	}
	delete(p.logins, state)
	p.loginMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cancelled": known})
}

// finishRelogin 重新登录的完成分支：严格校验 → 原位换凭据 → 窄口径恢复 → 如实回报。
//
// 校验顺序刻意是「先校验全部、再做任何有副作用的动作」：任何一项不过都必须让
// 旧凭证与账号状态**原样保留**，绝不能出现"文件写了但身份不对"的中间态。
func (p *Panel) finishRelogin(w http.ResponseWriter, state string, sess loginSession, tok loginToken, acct loginAccount) {
	target := sess.targetUID
	label := fmt.Sprintf("uid=%s nickname=%q realm=%s", target, acct.Nickname, sess.realm)

	// 会话可能在写入途中被取消/过期（loginCancel 会拒绝处理中的会话，这里是兜底）。
	p.loginMu.Lock()
	_, alive := p.logins[state]
	p.loginMu.Unlock()
	if !alive {
		writeErr(w, http.StatusGone, "login session 已作废，请重新发起")
		return
	}

	// ---- 校验 1：目标账号仍存在（OAuth 期间可能被运维移除）----
	// 不存在就失败退出，**绝不**顺手 pool.Add 建一个新账号：那会让"重新登录"
	// 变成"新增账号"，与原账号的历史统计/优先级/路由配置全部脱节。
	cur := p.cfg.Pool.AuthByUID(target)
	if cur == nil {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok":      false,
			"error":   "relogin_target_missing",
			"message": "目标账号已不存在，已取消这次重新登录（不会新建账号）",
		})
		return
	}

	// ---- 校验 2：UID 必须一致（防串号）----
	// 这是整个流程的安全核心：授权弹窗里用户可以登录**任意**账号，若不做这一步，
	// 登录 A 账号会把 A 的凭证写进 B 的凭证文件，两个账号同时持对方的 token。
	if acct.UID != target {
		log.Printf("WARN: panel: 重新登录 uid 不匹配，拒绝覆盖（target=%s got=%s）", target, acct.UID)
		p.dropLoginSession(state)
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok":          false,
			"error":       "relogin_uid_mismatch",
			"message":     "新授权登录的账号与目标账号不一致，已拒绝覆盖原凭证",
			"target_uid":  target,
			"granted_uid": acct.UID,
		})
		return
	}
	if !validUID(acct.UID) {
		writeErr(w, http.StatusBadGateway, "上游返回的 uid 含非法字符，拒绝落盘（防路径穿越）")
		return
	}

	// ---- 校验 3：Realm 必须一致 ----
	// 目标账号的域由服务端在 start 时锁定（sess.realm）；新授权再验一次：
	// 响应带 domain 时按 auth.ResolveRealm 归一化后比对（口径与 auth.Realm() 一致）。
	// domain 缺失时不否决——上游 CN 登录可能不回 domain，而端点本身已经锁定了域；
	// 但目标账号当前的 Realm 若在 OAuth 期间变了（例如配置开关翻转），仍要拒。
	if auth.ResolveRealm(cur.RealmStored(), cur.DomainValue()) != sess.realm {
		p.dropLoginSession(state)
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok":      false,
			"error":   "relogin_realm_mismatch",
			"message": "目标账号的 Realm 在授权期间发生变化，已拒绝覆盖，请重试",
			"realm":   sess.realm,
		})
		return
	}
	if dom := strings.TrimSpace(tok.Domain); dom != "" {
		if got := auth.ResolveRealm("", dom); got != sess.realm {
			p.dropLoginSession(state)
			writeJSON(w, http.StatusConflict, map[string]any{
				"ok":      false,
				"error":   "relogin_realm_mismatch",
				"message": fmt.Sprintf("新授权返回的是 %s 域凭据（domain=%s），与目标账号的 %s 域不一致，已拒绝覆盖", got, dom, sess.realm),
				"realm":   sess.realm,
			})
			return
		}
	}

	// ---- 校验 4：Token 数据满足既有有效性校验 ----
	// accessToken 非空（上面已过）、过期时间按现有口径换算；expiresIn 缺失时
	// 记 0 = 尽快刷新（Auth.NeedsRefresh 对 ExpiresAt<=0 恒判需要刷新），
	// 不让"没有过期时间"变成"永不过期"。
	expiresAt := int64(0)
	if tok.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Unix()
	}
	if strings.TrimSpace(tok.RefreshToken) == "" {
		// 没有 RT 的账号只能用到 AT 过期，之后必然要再重登一次。不阻断（上游偶发不返
		// RT 时把用户挡在门外更糟），但必须留痕，避免日后"为什么又要重登"无从查起。
		log.Printf("WARN: panel: 重新登录未拿到 refreshToken %s —— 该账号在 accessToken 过期后需再次重登", label)
	}

	// 构造新凭据：FilePath 沿用原账号文件（绝不产生第二个 workbuddy-*.json）；
	// DeviceToken 留空 → AdoptCredentials 保留旧值（重登不该丢设备风控 token）。
	next := &auth.Auth{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		ExpiresAt:    expiresAt,
		Domain:       tok.Domain,
		UID:          acct.UID,
		EnterpriseID: acct.EnterpriseID,
		Nickname:     acct.Nickname,
		FilePath:     cur.FilePath,
	}
	// realm 显式写入（不依赖 domain 后缀推断：CN 可能不回 domain）。
	if _, err := auth.BackfillRealmFor(next, sess.realm); err != nil {
		writeErr(w, http.StatusInternalServerError, "set realm: "+err.Error())
		return
	}

	// ---- 落盘 + 原位换内存（失败时旧凭证/旧状态完好，绝不会假成功）----
	rep, err := p.cfg.Pool.ReplaceCredentials(target, next)
	if err != nil {
		log.Printf("ERROR: panel: 重新登录凭据写入失败 %s: %v", label, err)
		writeErr(w, http.StatusInternalServerError,
			"重新授权成功但凭据写入失败，已保留原有凭证与账号状态："+err.Error())
		return
	}
	// 认证相关缓存失效：余额 401 求证的退避窗口清掉，否则重登后第一次余额探测
	// 会被旧窗口直接跳过（最长 30 分钟），面板上表现为"重登没生效"。
	if p.cfg.Scheduler != nil {
		p.cfg.Scheduler.ClearAuthHeal(target)
	}
	p.dropLoginSession(state)

	// ---- 登录成功 ≠ 上游全部服务可用：余额单独求证、单独回报 ----
	// Billing 401 不能否定 Chat 可用性（降级 token 的既有结论），所以这里只把结果
	// 如实回传（billing_verified / balance_error），**不因为余额失败而回滚或禁用账号**。
	remain, total := int64(-1), int64(0)
	balanceOK := true
	balanceErr := ""
	if p.cfg.Upstream != nil {
		if rm, tt, uerr := p.cfg.Upstream.UserResource(next); uerr == nil {
			remain, total = rm, tt
			// 与既有余额刷新同口径：余额恢复可解「余额耗尽硬冷却」，但不动熔断/限流态。
			p.cfg.Pool.ReenableIfCredits(target, rm, tt)
		} else {
			balanceOK = false
			balanceErr = uerr.Error()
			log.Printf("panel: 重新登录后余额校验失败 %s: %v（不影响重登结果，Chat 可能仍可用）", label, uerr)
		}
	}

	// ---- 如实回报：把「授权完成」「凭据已换」「是否回到选号」「Chat/Billing 各验到哪一步」分开 ----
	// 绝不因为 auth_ok=true 就笼统说「账号已恢复」：账号可能仍被管理员禁用、可能仍暂停选号，
	// 也可能换了凭据但 chat 根本没验证过。前端按各字段决定文案（见 app.js pollLogin）。
	warnings := make([]string, 0, 3)
	if !rep.StatePersisted {
		warnings = append(warnings, "运行状态未写入 state.json（重启后会按凭证代次自动校正）")
	}
	if rep.Disabled {
		cause := ""
		if st, ok := p.cfg.Pool.Status(target); ok {
			cause = st.DisabledReason
		}
		warnings = append(warnings, "账号仍处于禁用状态（"+cause+"），需人工解冻后才会重新参与选号")
	}
	if rep.Paused {
		warnings = append(warnings, "账号仍处于暂停选号，签到/保活照常但不接流量")
	}

	log.Printf("panel: 账号已重新授权 %s（credentials_updated=true recovered=%v in_rotation=%v state_persisted=%v）",
		label, rep.Recovered, rep.InRotation(), rep.StatePersisted)
	writeJSON(w, http.StatusOK, map[string]any{
		"done":     true,
		"mode":     string(LoginModeRelogin),
		"relogin":  true,
		"uid":      target,
		"nickname": acct.Nickname,
		"realm":    sess.realm,

		// —— 分阶段真实状态（前端不得把它们合并成一个「成功」）——
		"auth_ok":             true,               // OAuth 完成且身份/域校验通过
		"credentials_updated": true,               // 凭据已换新并 fsync 落盘（auth 文件）
		"state_persisted":     rep.StatePersisted, // 运行状态是否已落盘
		"recovered":           rep.Recovered,      // 认证禁用是否真的被解除
		"in_rotation":         rep.InRotation(),   // 当前是否已回到可选号状态
		"disabled":            rep.Disabled,
		"paused":              rep.Paused,
		"cooling":             rep.Cooling,
		"credentials_epoch":   rep.Epoch,

		// Chat 未做任何探测：宁可标「未验证」也不伪造健康结论。
		"chat_verified": false,
		// Billing 单独求证（401 只说明计费通道不可用，不等于 Chat 不可用）。
		"billing_verified": balanceOK,
		"balance_ok":       balanceOK,
		"balance_error":    balanceErr,
		// 余额字段与添加账号同形：-1 = 未知/未查询成功。
		"credits":         remain,
		"credits_total":   total,
		"checkin_message": "",
		"warnings":        warnings,
	})
}
