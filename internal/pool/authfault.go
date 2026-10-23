// authfault.go 账号认证故障的类型化标记与「重新登录后窄口径恢复」。
//
// 背景（issue 复盘）：401/12153 类失效此前只能从 disabled=true 看出，运维无从区分
//   - 管理员手点「禁用」、
//   - 上游 403 风控（11140 request illegal）、
//   - 认证失效（12153 session dead / 网关 401 invalid_token），
//
// 于是「解冻」成了唯一恢复手段：解冻会把**全部**惩罚态（含管理员暂停选号、
// 模型级冷却、熔断、连败降权）一起清掉，一次重登录等于把运维手工积累的状态全抹平。
//
// 本文件只做两件事，都不改既有状态机语义：
//  1. 给「因认证失效而不可用」打一个类型化标记 authFault（随 state.json 持久化，
//     旧文件缺该键 = 零值 = 无故障，向后兼容）；
//  2. 提供 ClearAuthFault 这个**窄口径**恢复入口：只清认证故障域，管理员状态一律不动。
//
// 不做的事：不新增「需重登」布尔字段（由 authFault 派生，避免两个字段打架）；
// 不把 429/402/5xx 记为 authFault（它们各有既有惩罚路径）；不改变 NoteSessionDead
// 的连续计数语义（阈值内仍是「疑似」，面板据 sessionDeadFails 单独展示）。
package pool

import (
	"errors"
	"log"
	"strings"
	"time"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
)

// AuthFault 认证故障的**类型化**原因（落 state.json 的 auth_fault 键）。
//
// 空串 = 无认证故障。非空时账号处于「需要重新登录」口径（通常同时 disabled=true，
// 由 NoteSessionDead* / DisableAuth 写入）。之所以要类型化而不是靠 reason 字符串：
// reason 是给人看的自由文本（本地化/文案调整都会变），面板要拿它决定「显示重登按钮」
// 「是否允许 OAuth 重登」，必须有一份稳定的枚举。
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

// authFaultForReason 把既有 Disable/NoteSessionDead 的 reason 文案映射到类型化故障。
//
// 只用于「已判定为认证失效」的调用点做细分（12153 vs 网关 401），不承担分类职责：
// 判定仍由 upstream.Classify / handler 的 applyErrorPolicy 负责，这里只回答
// 「这条已知的认证 reason 属于哪一类」。无法识别时按业务 12153 处理（更常见、更权威）。
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

// DisableAuth 禁用账号并记录**类型化**认证故障（= 需要重新登录）。
// 除多打一个标记外与 Disable 完全一致（同样清冷却域、置 disabled、清 paused）。
// uid 不存在返回 false。
func (p *Pool) DisableAuth(uid, reason string, fault AuthFault) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byUID[uid]
	if !ok {
		return false
	}
	p.disableLocked(e, reason)
	e.authFault = NormalizeAuthFault(fault)
	e.authFaultAt = time.Now()
	p.dirty.Store(true)
	return true
}

// NoteSessionDeadFault 同 NoteSessionDeadWith，但由调用方显式指定类型化故障。
// 连续计数语义完全不变（达 sessionDeadThreshold 才禁用）。
func (p *Pool) NoteSessionDeadFault(uid string, fault AuthFault, reason string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byUID[uid]
	if !ok {
		return false
	}
	e.sessionDeadFails++
	if e.sessionDeadFails < sessionDeadThreshold {
		return false
	}
	e.sessionDeadFails = 0
	p.disableLocked(e, reason)
	e.authFault = NormalizeAuthFault(fault)
	e.authFaultAt = time.Now()
	p.dirty.Store(true)
	return true
}

// AuthFaultOf 返回账号当前的认证故障类型（uid 不存在返回 AuthFaultNone）。
// 供面板/HTTP 处理器判定「该账号是否该显示重新登录」。
func (p *Pool) AuthFaultOf(uid string) AuthFault {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if e, ok := p.byUID[uid]; ok {
		return e.authFault
	}
	return AuthFaultNone
}

// ClearAuthFault 认证恢复的**窄口径**入口：重新登录成功后调用。
//
// 只做三件事：
//  1. 清 authFault / authFaultAt（不再需要重登）；
//  2. 清 sessionDeadFails 连续计数（账号已被证明活着，旧的死亡进度作废）；
//  3. **仅当**账号是因认证故障被禁用时解除该禁用（清 disabled 与 reason）。
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
// 这就是为什么不能直接复用 Revive（"解冻"）：Revive 会把上面全部清空，
// 它是「人工判定该号可用」的口径，而重登录只证明了「凭据换了新的」。
// 返回 true 表示确有认证故障状态被清除（供调用方区分 no-op）。
func (p *Pool) ClearAuthFault(uid string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byUID[uid]
	if !ok {
		return false
	}
	wasFaulted := e.authFault != AuthFaultNone
	hadCounter := e.sessionDeadFails != 0
	if !wasFaulted && !hadCounter {
		return false
	}
	// 禁用是否由认证故障造成：只有 authFault 非空才说明是（Disable/disableLocked
	// 在非认证路径会把 authFault 清空，见 transition.go）。
	authDisabled := wasFaulted && e.disabled
	e.authFault = AuthFaultNone
	e.authFaultAt = time.Time{}
	e.sessionDeadFails = 0
	if authDisabled {
		e.disabled = false
		e.reason = ""
	}
	p.dirty.Store(true)
	return true
}

// ReplaceCredentials 用新授权凭据**原位替换**池内账号的凭据（401 账号重新登录）。
//
// 关键约束（与「删号重建」/「换 *auth.Auth 指针」都不同）：
//   - 保留池内**同一个** *auth.Auth 对象（不 upsert 新指针）：账号池条目、历史
//     统计（successCount/errTotal/tokenUsage）、优先级/份额/成本账本、冷却状态
//     全部天然保留，handler/scheduler 手里已在途持有的指针也仍然有效；
//   - 只改认证域字段，由 auth.Auth.AdoptCredentials 在单次持锁事务内完成
//     （先落盘成功→再换内存→代次 +1，防止在途 refresh 用旧 token 覆盖新文件）；
//   - **不新增账号**：置凭据走的是原账号的 FilePath，不会产生第二个 workbuddy-*.json。
//
// 落盘失败时返回错误且账号状态不变（AdoptCredentials 保证），调用方必须把错误
// 如实报给运维，不得返回假成功。
//
// 锁序：先 p.mu.RLock 取条目（阻止并发的 Remove/SyncToDir 换掉/删掉条目），
// 再 a.mu（AdoptCredentials 内部）；不放 p.mu 写锁做文件 I/O（会阻塞选号热路径）。
func (p *Pool) ReplaceCredentials(uid string, src *auth.Auth) error {
	if src == nil {
		return errors.New("pool: replace credentials: nil auth")
	}
	p.mu.RLock()
	e, ok := p.byUID[uid]
	if !ok {
		p.mu.RUnlock()
		return ErrAccountNotFound
	}
	cur := e.a
	if cur == nil {
		p.mu.RUnlock()
		return ErrAccountNotFound
	}
	// 持读锁期间完成替换：Remove/SyncToDir（写锁）必须等它结束，
	// 避免「刚写完盘账号已被移除」或「条目被换成别的 *Auth 对象」。
	err := cur.AdoptCredentials(src)
	p.mu.RUnlock()
	if err != nil {
		return err
	}
	// 凭据已生效，再窄口径清认证故障并立即落盘（state.json 的 auth_fault/disabled
	// 必须与 auths/ 下的新凭据同时反映恢复，否则重启后面板仍显示"需重登"）。
	p.ClearAuthFault(uid)
	p.Flush()
	if p.dirty.Load() {
		// 凭据文件已 fsync 落盘成功（上面 AdoptCredentials 保证），这里失败的只是
		// state.json（磁盘满 / 只读 / bind-mount 抖动）。运行态是对的，重启后
		// state.json 会显示旧的「需重登」标记 —— 再点一次重登即可恢复。
		// 不返回错误：把一次成功的凭证替换报成失败，会让运维以为凭据没换新而重复操作。
		p.notePersistFail(errors.New("relogin 后 state.json 未落盘"))
		log.Printf("WARN: pool: 重新登录成功但 state.json 未落盘 uid=%s（凭据已生效；重启后可能仍显示需重登）", uid)
	}
	return nil
}
