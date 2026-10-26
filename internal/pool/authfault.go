// authfault.go 账号禁用的**类型化成因**、认证故障标记，以及「重新登录后窄口径恢复」。
//
// 背景（issue 复盘）：401/12153 类失效此前只能从 disabled=true 看出，运维无从区分
//   - 管理员手点「禁用」、
//   - 上游 403 风控（11140 request illegal）、
//   - 认证失效（12153 session dead / 网关 401 invalid_token），
//
// 于是「解冻」成了唯一恢复手段：解冻会把**全部**惩罚态（含管理员暂停选号、
// 模型级冷却、熔断、连败降权）一起清掉，一次重登录等于把运维手工积累的状态全抹平。
//
// 本文件负责三件事，都不改既有状态机语义：
//  1. DisableCause 记录「这次禁用是谁造成的」，并用**优先级**决定谁能覆盖谁
//     （管理员/上游 > 认证 > 未知）。认证故障不允许把管理员禁用改写成「需重新登录」，
//     重登录也不允许解除管理员禁用。
//  2. AuthFault 记录「观测到的认证故障类型」，只用于展示与重登入口判定，
//     本身不代表禁用成因（判定一律看 DisableCause，不看 reason 文本）。
//  3. 跨文件对账：auths/*.json 的凭证代次（auth.Auth.Epoch）与 state.json 的
//     auth_epoch 比对，修复「凭据换新成功但 state.json 写失败」的重启窗口。
package pool

import (
	"errors"
	"log"
	"strings"
	"time"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
)

// AuthFault 认证故障的**类型化**观测结果（落 state.json 的 auth_fault 键）。
//
// 空串 = 未观测到认证故障。非空只说明「最近一次判死是哪种认证失效」，
// **不**代表当前禁用成因——用于「要不要显示重新登录入口」的判定一律看
// DisableCause == DisableCauseAuth，避免管理员禁用被伪装成认证失效。
type AuthFault string

const (
	// AuthFaultNone 无认证故障（零值，旧 state.json 缺键即此值）。
	AuthFaultNone AuthFault = ""
	// AuthFaultSessionDead 业务层会话已死：refresh 回 12153 / offline session not found。
	// 这是最权威的「只能重登」信号（一次即禁用，见 server.applyErrorPolicy）。
	AuthFaultSessionDead AuthFault = "session_dead"
	// AuthFaultGateway401 网关自行回 401（APISIX `invalid_token`，无业务信封）。
	// 边缘节点抖动也会出现这种形态，故按连续阈值才判死（见 handler 与 NoteSessionDeadWith）。
	AuthFaultGateway401 AuthFault = "gateway_401"
)

// DisableCause 禁用成因（落 state.json 的 disabled_cause 键）。它决定**恢复路径**，
// 与 reason（给人看的自由文本）彻底分开——判定绝不依赖 reason 字符串。
type DisableCause string

const (
	// DisableCauseNone 未禁用（零值）。
	DisableCauseNone DisableCause = ""
	// DisableCauseUnknown 存量数据里的禁用（旧 state.json 无 disabled_cause 键）。
	// 无法判断成因，因此按「不可自动恢复」处理：重登录不会解除它，需人工解冻。
	DisableCauseUnknown DisableCause = "unknown"
	// DisableCauseAuth 认证失效禁用：可由重新登录窄口径恢复（只解禁 + 清认证计数）。
	DisableCauseAuth DisableCause = "auth"
	// DisableCauseAdmin 管理员手动禁用：只能人工解除，重登录不得自动解禁。
	DisableCauseAdmin DisableCause = "admin"
	// DisableCauseUpstream 上游风控/封禁（如 11140 request illegal）：需申诉，不可自动恢复。
	DisableCauseUpstream DisableCause = "upstream"
)

// ErrAccountNotFound 池内无此账号。按 uid 操作的运维入口用它区分
// 「账号不存在」与「账号存在但操作失败」。
var ErrAccountNotFound = errors.New("pool: account not found")

// Valid 报告 f 是否为已知的认证故障类型（AuthFaultNone 视为合法：无故障）。
func (f AuthFault) Valid() bool {
	switch f {
	case AuthFaultNone, AuthFaultSessionDead, AuthFaultGateway401:
		return true
	}
	return false
}

// NormalizeAuthFault 把外部输入（如旧 state.json 里的脏值）归一化为已知枚举：
// 未知值一律降级成 AuthFaultNone，而不是留着让面板/前端去猜。
func NormalizeAuthFault(f AuthFault) AuthFault {
	if f.Valid() {
		return f
	}
	return AuthFaultNone
}

// faultForKey 由持久化/配置里读到的字符串还原 AuthFault（脏值归一化为无故障）。
func faultForKey(s string) AuthFault {
	return NormalizeAuthFault(AuthFault(strings.TrimSpace(s)))
}

// Valid 报告 c 是否为已知成因。
func (c DisableCause) Valid() bool {
	switch c {
	case DisableCauseNone, DisableCauseUnknown, DisableCauseAuth, DisableCauseAdmin, DisableCauseUpstream:
		return true
	}
	return false
}

// NormalizeDisableCause 把持久化读到的字符串归一化；空串保持「未禁用」，脏值降级为
// DisableCauseUnknown（= 不可自动恢复，安全侧）。
func NormalizeDisableCause(s string) DisableCause {
	c := DisableCause(strings.TrimSpace(s))
	if c.Valid() {
		return c
	}
	if c == DisableCauseNone {
		return DisableCauseNone
	}
	return DisableCauseUnknown
}

// disableCauseRank 成因优先级：数字大者不可被小者覆盖。
//
//	admin / upstream = 3  人工或上游的终态，认证故障不得改写
//	auth             = 2  可被重登录窄口径恢复
//	unknown          = 2  与 auth 同级：认证故障无法「升级」一个来路不明的禁用
//	none             = 0
//
// 关键：unknown 与 auth 同级（用 <= 判拒绝），保证「历史禁用 + 新来的 401」不会
// 被标成需重登；反过来 admin/upstream 也永远压得住 auth。
func disableCauseRank(c DisableCause) int {
	switch c {
	case DisableCauseAdmin, DisableCauseUpstream:
		return 3
	case DisableCauseAuth, DisableCauseUnknown:
		return 2
	}
	return 0
}

// authFaultForReason 把既有 Disable/NoteSessionDead 的 reason 文案映射到类型化故障。
//
// 只用于「已判定为认证失效」的调用点做细分（12153 vs 网关 401），不承担分类职责：
// 判定仍由 upstream.Classify / handler 的 applyErrorPolicy 负责。无法识别时按
// 业务 12153 处理（更常见、更权威）。
func authFaultForReason(reason string) AuthFault {
	r := strings.ToLower(reason)
	switch {
	case strings.Contains(r, "invalid token"), strings.Contains(r, "invalid_token"),
		strings.Contains(r, "gateway"), strings.Contains(r, "网关"):
		return AuthFaultGateway401
	case strings.Contains(r, "12153"), strings.Contains(r, "session dead"),
		strings.Contains(r, "offline user session"), strings.Contains(r, "refresh"):
		return AuthFaultSessionDead
	}
	return AuthFaultSessionDead
}

// applyDisableLocked 按成因优先级落禁用（调用方必须已持 p.mu 写锁）。
// 返回 false = 账号已被更高/同级成因禁用，本次请求**不生效**（不覆盖原因文案）。
func (p *Pool) applyDisableLocked(e *entry, cause DisableCause, reason string) bool {
	if cause == DisableCauseNone {
		// 无成因的禁用没有恢复语义，按「未知」处理（不可被重登录自动解除）。
		cause = DisableCauseUnknown
	}
	if e.disabled && disableCauseRank(cause) <= disableCauseRank(e.disabledCause) {
		return false
	}
	p.disableLocked(e, reason)
	e.disabledCause = cause
	p.dirty.Store(true)
	return true
}

// DisableWithCause 按指定成因禁用。管理员禁用用 DisableCauseAdmin，上游风控用
// DisableCauseUpstream，认证失效用 DisableAuth（它还会打认证故障标记）。
// uid 不存在返回 false。
func (p *Pool) DisableWithCause(uid string, cause DisableCause, reason string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byUID[uid]
	if !ok {
		return false
	}
	return p.applyDisableLocked(e, cause, reason)
}

// DisableAuth 因认证失效禁用并记录类型化故障（= 需要重新登录）。
//
// 优先级保护：若账号已因**更高优先级**成因被禁用（管理员/上游风控），本次调用
// 只被忽略——不覆盖禁用原因、不写认证故障标记。否则面板会把一条「管理员手点禁用」
// 显示成「需重新登录」，而重登录还会误以为可以解禁。
// 返回 true 表示本次确实完成了「因认证失效而禁用」。
func (p *Pool) DisableAuth(uid, reason string, fault AuthFault) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byUID[uid]
	if !ok {
		return false
	}
	if !p.applyDisableLocked(e, DisableCauseAuth, reason) {
		log.Printf("pool: uid=%s 已因 %q 禁用，忽略认证故障（不覆盖禁用原因、不标需重登）",
			uid, e.disabledCause)
		return false
	}
	e.authFault = NormalizeAuthFault(fault)
	e.authFaultAt = time.Now()
	p.dirty.Store(true)
	return true
}

// NoteSessionDeadFault 记一次连续 session dead，达阈值才禁用（计数语义不变）。
// 达阈值时若已有更高优先级禁用成因，同样只记录不覆盖（见 DisableAuth）。
func (p *Pool) NoteSessionDeadFault(uid string, fault AuthFault, reason string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byUID[uid]
	if !ok {
		return false
	}
	e.sessionDeadFails++
	if e.sessionDeadFails < sessionDeadThreshold {
		// 上游修复：中间计数也落盘——重启丢进度会让「离禁用还差几次」重新从零学。
		p.dirty.Store(true)
		return false
	}
	e.sessionDeadFails = 0
	if !p.applyDisableLocked(e, DisableCauseAuth, reason) {
		log.Printf("pool: uid=%s 连续 %d 次判死，但已因 %q 禁用 —— 保留原禁用原因（不标需重登）",
			uid, sessionDeadThreshold, e.disabledCause)
		return false
	}
	e.authFault = NormalizeAuthFault(fault)
	e.authFaultAt = time.Now()
	p.dirty.Store(true)
	return true
}

// AuthFaultOf 返回账号最近观测到的认证故障类型（uid 不存在返回 AuthFaultNone）。
func (p *Pool) AuthFaultOf(uid string) AuthFault {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if e, ok := p.byUID[uid]; ok {
		return e.authFault
	}
	return AuthFaultNone
}

// clearAuthFaultLocked 清认证故障域的**无锁**实现（调用方必须已持 p.mu 写锁）。
// 返回是否确有状态被清除。
//
// 只做三件事：
//  1. 清 authFault / authFaultAt（不再需要重登）；
//  2. 清 sessionDeadFails 连续计数（账号已被证明活着，旧的死亡进度作废）；
//  3. **仅当** disabledCause == DisableCauseAuth 时解除禁用（清 disabled/reason/cause）。
//
// 明确**不清**（这些都不属于认证故障域，一次重登录不该替运维做决定）：
//   - paused 暂停选号（管理员让它让位，与凭据无关）；
//   - until / coolKind / softStreak（429 限流冷却与它的退避计数）；
//   - modelCooldowns（6004 模型级独立冷却）；
//   - breakerUntil / fails / retryCount（5xx 熔断）；
//   - degradeUntil / consecutiveFails（连败降权）；
//   - credits / creditsTotal / expiryBuckets（余额快照）；
//   - modelOff / modelCost（手动关模型与成本账本）。
//
// 这就是为什么不能直接复用 Revive（"解冻"）：Revive 会把上面全部清空，它是
// 「人工判定该号可用」的口径，而重登录只证明了「凭据换了新的」。
func (p *Pool) clearAuthFaultLocked(e *entry) bool {
	authDisabled := e.disabled && e.disabledCause == DisableCauseAuth
	changed := authDisabled || e.authFault != AuthFaultNone || e.sessionDeadFails != 0
	if !changed {
		return false
	}
	e.authFault = AuthFaultNone
	e.authFaultAt = time.Time{}
	e.sessionDeadFails = 0
	if authDisabled {
		e.disabled = false
		e.reason = ""
		e.disabledCause = DisableCauseNone
	}
	p.dirty.Store(true)
	return true
}

// ClearAuthFault 认证恢复的**窄口径**入口（重新登录成功后调用）。
// 只清认证故障域；管理员/上游禁用一律不动（见 clearAuthFaultLocked）。
// 返回 true 表示确有状态被清除（含「解除认证禁用」或「清掉陈旧计数」）。
func (p *Pool) ClearAuthFault(uid string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byUID[uid]
	if !ok {
		return false
	}
	return p.clearAuthFaultLocked(e)
}

// CredentialReplaceResult 原位换凭据的结果。刻意把「授权成功」「状态已持久化」
// 「是否真的解除了认证禁用」拆开：调用方不允许把它们合并成一个笼统的成功。
type CredentialReplaceResult struct {
	// Epoch 换凭据后的凭证代次（已写入 auth 文件，用于跨重启对账）。
	Epoch uint64
	// StatePersisted state.json 是否已把本次变更落盘。false 时运行态已生效，
	// 重启会由 reconcileCredEpochLocked 依据凭证代次自动校正。
	StatePersisted bool
	// Recovered 是否真的解除了「认证失效造成的禁用」。false 可能是：账号从未禁用、
	// 账号被管理员/上游禁用（重登录不解除）、或账号已被移除。
	Recovered bool
	// Disabled / Paused / Cooling 换凭据后的真实状态快照（供接口如实回报）。
	Disabled bool
	Paused   bool
	Cooling  bool
}

// InRotation 报告账号换完凭据后是否已真正回到可选号状态（不是「已恢复」的同义词，
// 只是当前是否参与调度：未禁用、未暂停、无冷却/熔断/降权）。
func (r CredentialReplaceResult) InRotation() bool {
	return !r.Disabled && !r.Paused && !r.Cooling
}

// ReplaceCredentials 用新授权凭据**原位替换**池内账号的凭据（401 账号重新登录）。
//
// 关键约束（与「删号重建」/「换 *auth.Auth 指针」都不同）：
//   - 保留池内**同一个** *auth.Auth 对象（不 upsert 新指针）：账号池条目、历史
//     统计（successCount/errTotal/tokenUsage）、优先级/份额/成本账本、冷却状态
//     全部天然保留，handler/scheduler 手里已在途持有的指针也仍然有效；
//   - 只改认证域字段，由 auth.Auth.AdoptCredentials 在单次持锁事务内完成
//     （先落盘成功→再换内存→代次 +1，防止在途 refresh 用旧 token 覆盖新文件）；
//   - **不新增账号**：走原账号的 FilePath，不会产生第二个 workbuddy-*.json。
//
// 落盘失败时返回错误且账号状态不变（AdoptCredentials 保证），调用方必须把错误
// 如实报给运维，不得返回假成功。
//
// 锁序：先 p.mu.RLock 取条目并完成 auth 文件写入（阻止并发的 Remove/SyncToDir
// 换掉/删掉条目），再 p.mu.Lock 做状态清理与持久化；不放写锁做文件 I/O。
func (p *Pool) ReplaceCredentials(uid string, src *auth.Auth) (CredentialReplaceResult, error) {
	var res CredentialReplaceResult
	if src == nil {
		return res, errors.New("pool: replace credentials: nil auth")
	}
	p.mu.RLock()
	e, ok := p.byUID[uid]
	if !ok {
		p.mu.RUnlock()
		return res, ErrAccountNotFound
	}
	cur := e.a
	if cur == nil {
		p.mu.RUnlock()
		return res, ErrAccountNotFound
	}
	err := cur.AdoptCredentials(src)
	p.mu.RUnlock()
	if err != nil {
		return res, err
	}
	res.Epoch = cur.Epoch()

	p.mu.Lock()
	if e2, ok := p.byUID[uid]; ok {
		// 与 auth 文件里的代次对齐：state.json 记录它，重启时用它判断「凭证是否
		// 比 state 新」（见 reconcileCredEpochLocked）。
		e2.authEpoch = res.Epoch
		// 窄口径恢复：只解认证禁用，管理员/上游禁用保持不变。
		res.Recovered = p.clearAuthFaultLocked(e2)
		res.Disabled, res.Paused = e2.disabled, e2.paused
		res.Cooling = !e2.until.IsZero() || !e2.breakerUntil.IsZero() || !e2.degradeUntil.IsZero()
	}
	p.dirty.Store(true)
	res.StatePersisted = p.flushLocked()
	p.mu.Unlock()

	if !res.StatePersisted {
		// 凭据文件已 fsync 成功（AdoptCredentials 保证），失败的只是 state.json。
		// 运行态是对的；重启后凭据代次对账会自动把这条认证禁用纠正回来，所以这里
		// 既不返回错误（凭据确实换新了），也不假装一切正常（调用方会看到
		// StatePersisted=false 并如实回报）。
		p.notePersistFail(errors.New("relogin 后 state.json 未落盘"))
		log.Printf("WARN: pool: 重新登录后 state.json 未落盘 uid=%s epoch=%d（凭据已生效，重启将按凭证代次自动校正）",
			uid, res.Epoch)
	}
	return res, nil
}

// reconcileCredEpochLocked 凭据代次对账：比较 auth 文件里的代次与 state.json 记录的
// auth_epoch，修复「凭证换新成功、但 state.json 写失败」这一跨文件窗口。
//
// 场景（真实会发生）：ReplaceCredentials 写完 auth 文件（fsync）后 state.json 写失败
// （磁盘满/只读/bind-mount 抖动），进程随后重启。此时 state.json 仍写着
// disabled + auth_cause + auth_fault，而 auth 文件里已经是全新授权凭据 ——
// 若不校正，账号会永久卡在「需重新登录」，运维反复重登也没用（每次都成功换凭据，
// 但只要那次 state 写失败又回到原样）。
//
// 判据只用凭证代次（不猜 reason 文本）：
//   - 文件代次 > state 记录：凭证已被整体替换过 ⇒ state 里的认证禁用已不成立，
//     按窄口径恢复（只解 auth 成因；管理员/上游禁用保持不动）。
//   - 文件代次 < state 记录（且文件代次非 0）：凭证可能被回滚/从备份恢复，只告警
//     并以文件为准（旧 token 可能已被上游废弃，最终仍需重登）。
//
// 调用方必须已持 p.mu 写锁（由 upsertLocked 在把 auth 绑到 entry 时调用）。
func (p *Pool) reconcileCredEpochLocked(e *entry, a *auth.Auth) {
	if a == nil || e == nil {
		return
	}
	fileEpoch := a.Epoch()
	switch {
	case fileEpoch > e.authEpoch:
		switch {
		case e.disabled && e.disabledCause == DisableCauseAuth:
			e.disabled = false
			e.reason = ""
			e.disabledCause = DisableCauseNone
			e.authFault = AuthFaultNone
			e.authFaultAt = time.Time{}
			e.sessionDeadFails = 0
			log.Printf("WARN: pool: 启动对账 uid=%s 凭证代次(%d) 领先 state.json(%d) 且当前为认证禁用 "+
				"→ 按重新授权口径窄口径恢复（凭据已是新的，该禁用已不成立）", a.UID, fileEpoch, e.authEpoch)
		case e.authFault != AuthFaultNone || e.sessionDeadFails != 0:
			e.authFault = AuthFaultNone
			e.authFaultAt = time.Time{}
			e.sessionDeadFails = 0
			log.Printf("WARN: pool: 启动对账 uid=%s 凭证代次领先 state.json，已清除陈旧的认证故障标记", a.UID)
		default:
			log.Printf("pool: 启动对账 uid=%s 凭证代次(%d) 领先 state.json(%d)，已对齐", a.UID, fileEpoch, e.authEpoch)
		}
		// 对齐值必须落盘：否则每次启动都重复对账、重复打同一条日志（日志噪声本身
		// 会把真正需要关注的 WARN 淹掉）。
		e.authEpoch = fileEpoch
		p.dirty.Store(true)
	case fileEpoch < e.authEpoch:
		// 反向异常：state.json 记录的代次高于凭据文件。可能来源：凭证文件从备份
		// 恢复/被手工替换/被不写 epoch 的旧版本改写。以**文件**为准（它才是真正
		// 生效的凭据），但不擅自改动禁用状态——旧 token 是否还有效是上游说了算。
		log.Printf("WARN: pool: 启动对账 uid=%s 凭证文件代次(%d) 落后于 state.json(%d) —— "+
			"凭证可能被回滚或从备份恢复，旧 token 可能已失效，建议重新登录", a.UID, fileEpoch, e.authEpoch)
		e.authEpoch = fileEpoch
		p.dirty.Store(true)
	}
}
