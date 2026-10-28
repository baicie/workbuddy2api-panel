// Package auth 解析 WorkBuddy auth 文件（嵌套形/扁平形双形态），
// 提供 refresh 后的原子写回。
package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/misakano7545/workbuddy2api-panel/internal/logfmt"
	"github.com/misakano7545/workbuddy2api-panel/internal/safefile"
)

// Auth 是归一化后的账号凭证（来源可以是插件 OAuth 嵌套形或手写扁平形）。
type Auth struct {
	// mu 串行化 RefreshToken 写与 SaveAtomic 读，防止并发写回半更新 token。
	mu sync.Mutex

	AccessToken  string
	RefreshToken string
	ExpiresAt    int64 // Unix 秒
	Domain       string
	// realm 账号域（"cn" / "global"），落盘于 auth.realm（嵌套形）或顶层 realm（扁平形）。
	// 空 = 缺省：Realm() 按 domain 后缀回落，最终恒非空。
	//
	// 命名注记：Go 不允许字段与方法同名，持久化字段用未导出 realm，计算访问器用
	// 导出的 Realm()（跨包调用全部走方法）。Parse/SaveAtomic/login 在包内读写字段。
	realm        string
	UID          string
	EnterpriseID string
	Nickname     string
	FilePath     string // 来源文件；refresh 后原子写回此处

	// DeviceToken 设备风控 Token（X-Device-Token 头），来源 auth 文件的 device_token 键。
	// 缺省为空 = 不注入该头（容器内无桌面端 Turing SDK 的常见部署）。
	// 手写扁平形 auth 文件可直接写 "device_token": "..."；插件 OAuth 嵌套形
	// 顶层 device_token 也会被解析（与桌面端共用状态文件的部署方式）。
	DeviceToken string

	// credEpoch 凭证代次：凭据被**整体替换**（401 失效账号原点重新登录）时 +1，
	// 受 a.mu 保护。用途单一且关键——在途 refresh 发起时记下代次，写回前发现
	// 代次已变即丢弃本次结果（成功与失败都丢）：那次刷新是拿**旧** RefreshToken
	// 换来的，若照写就会把刚落盘的新授权凭证覆盖回旧凭证，重登录等于白做。
	//
	// 为什么光有「换 token 指针」不够：pool.upsertLocked 换 a 指针只换掉池内的
	// 引用，handler / scheduler 手里在途请求持有的旧 *auth.Auth 指针照样会把
	// 旧 token SaveAtomic 到同一个 FilePath。代次把这类跨指针的写回也一并挡住。
	credEpoch uint64
}

// Lock 供同进程内其他包（upstream.RefreshToken）在改写 Auth 字段期间加锁。
func (a *Auth) Lock() { a.mu.Lock() }

// Unlock 释放 a.Lock 获取的锁。
func (a *Auth) Unlock() { a.mu.Unlock() }

// Epoch 返回当前凭证代次（锁内读）。0 = 从未整体替换过。
func (a *Auth) Epoch() uint64 {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.credEpoch
}

// EpochLocked 返回凭证代次的**无锁**实现：仅限**已持 a.mu** 的调用方使用。
// 用途：upstream.applyRefresh 在锁内既要比对代次又要改写 token 字段，若在那里
// 调 Epoch() 会自锁（sync.Mutex 不可重入）。语义与 Epoch 完全一致。
func (a *Auth) EpochLocked() uint64 {
	if a == nil {
		return 0
	}
	return a.credEpoch
}

// KeyID 返回 refresh 去重用的**稳定身份标识**（锁内读 UID，回落 FilePath）。
// 空串表示两者都没有（测试用匿名 Auth），调用方自行回落指针。
//
// 存在的理由：upstream.refreshKey 原先无锁直读 a.UID / a.FilePath，而
// AdoptCredentials 会在锁内改写这些字段（重新登录），两者并发即是数据竞争
// （go test -race 实测抓到）。身份字段改为「重登不写」后竞争已消失，但读取侧
// 仍应走锁内访问器，避免将来任何写入方重新引入同一类问题。
func (a *Auth) KeyID() string {
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.UID != "" {
		return a.UID
	}
	return a.FilePath
}

// RefreshSnapshot 一次持锁读出「代次 + 当前 AccessToken + 当前 RefreshToken」。
//
// 必须一次读齐：分三次调用（Epoch / AccessTokenValue / RefreshTokenValue）会让
// 「读代次」与「读 token」之间插入一次整体替换，代次校验随即形同虚设——要么
// 拿新代次配旧 token（写回被判新鲜而覆盖新凭证），要么拿旧代次配新 token
// （写回被误判为陈旧而丢掉一次合法刷新）。
func (a *Auth) RefreshSnapshot() (epoch uint64, accessToken, refreshToken string) {
	if a == nil {
		return 0, "", ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.credEpoch, a.AccessToken, a.RefreshToken
}

// AccessTokenValue 加锁读取 AccessToken（出站请求头一律经此取值，勿直读字段）。
//
// 为什么必须加锁：RefreshToken 在 a.mu 内改写 AccessToken/RefreshToken/Domain/ExpiresAt
// （client.go「第 2 段（锁内）：校验快照一致后写回」），而所有出站请求头构造
// （ChatHeaders / BillingHeaders / fetchEnterpriseModels / fetchV3Models /
// global_models）与调度器的 token 检查都在锁外直读这些字段。生产上两侧真会并发：
// Scheduler.RunKeepaliveNow 定时对**每个**非禁用账号刷新（与是否有在途请求无关），
// 而 handler 正基于**同一个** *auth.Auth 指针构造请求头（Pool.AuthByUID/List 返回的
// 就是池内同一个对象）。无同步直读构成数据竞争（go test -race 实证）。
func (a *Auth) AccessTokenValue() string {
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.AccessToken
}

// DomainValue 加锁读取 Domain（同 AccessTokenValue：RefreshToken 在锁内改写它）。
func (a *Auth) DomainValue() string {
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Domain
}

// RefreshTokenValue 加锁读取 RefreshToken（同 AccessTokenValue：RefreshToken 在锁内
// 改写它）。调度器的「有无凭证」前置守卫（checkin/keepalive/travel 的
// `a.RefreshToken == ""`）必须经此取值，勿直读字段。
func (a *Auth) RefreshTokenValue() string {
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.RefreshToken
}

// globalEnabled 全局开关：global realm 是否路由（D5 双保险）。
// 默认开启（与 config global.enabled 缺省 true 一致）：Realm() 正常按显式 realm/
// domain 判定 global/cn。显式 SetGlobalEnabled(false)（config "enabled": false）关闭
// → 逃生门：纯 CN 部署，即便 auth 文件写了 realm=global 或 domain 为 .workbuddy.ai
// 也恒判 cn——「关了才锁死」的单一闸口集中收敛在 Realm()/IsGlobal() 里。
var globalEnabled atomic.Bool

func init() { globalEnabled.Store(true) }

// SetGlobalEnabled 注入 global realm 路由开关（false = 锁死纯 CN，逃生门）。
func SetGlobalEnabled(enabled bool) { globalEnabled.Store(enabled) }

// GlobalEnabled 报告 global realm 路由开关当前状态（测试/运维观测）。
func GlobalEnabled() bool { return globalEnabled.Load() }

// Realm 返回账号的归一化域：显式 Realm=="global" 或 domain 后缀 .workbuddy.ai → "global"，
// 否则 "cn"。显式 global 优先于 domain 回落（D1）。
// 全局开关 SetGlobalEnabled(false) 时恒 "cn"（逃生门：纯 CN 锁定，不影响默认行为）。
// 空 realm + 空 domain → "cn"（老 CN 凭证零回归）。
func (a *Auth) Realm() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.realmLocked()
}

// realmLocked Realm 的无锁内部实现：仅限**已持 a.mu** 的调用方使用（sync.Mutex 不可重入，
// 锁内再调 Realm() 会自锁）。realm 由 BackfillRealm 改写、Domain 由 RefreshToken 在锁内
// 改写，故读取必须与写方同锁（理由见 AccessTokenValue 注释）。
func (a *Auth) realmLocked() string {
	if !globalEnabled.Load() {
		return "cn"
	}
	if strings.TrimSpace(a.realm) == "global" || isGlobalDomain(a.Domain) {
		return "global"
	}
	return "cn"
}

// ResolveRealm 归一化 realm（cn/global）：显式非空优先，否则按原始 domain 推断
// （isGlobalDomain）。不受逃生门影响（逃生门是路由锁，不应影响标识判定）；
// domain 也为空 → "cn"（老 CN 凭证零回归）。
func ResolveRealm(explicit, domain string) string {
	if r := strings.TrimSpace(explicit); r != "" {
		return r
	}
	if isGlobalDomain(domain) {
		return "global"
	}
	return "cn"
}

// BackfillRealm 为缺省 realm 标识的账号持久化补标识：a.realm 为空时按「原始 domain 推断」
// 写回（cn/global），返回 (是否有变更, 归一化后的 realm)。已有标识不动（幂等）。
//
// 注意用 isGlobalDomain(a.Domain) 直接推断，而非 Realm()——Realm() 在逃生门
// （SetGlobalEnabled(false)）下恒降级 cn，把 global 账号写死成 cn 会永久污染凭证
// （逃生门是纯 CN 部署的临时锁，不应改写落盘数据）。domain 也为空时写 "cn"（老 CN 凭证）。
func (a *Auth) BackfillRealm() (bool, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if strings.TrimSpace(a.realm) != "" {
		return false, a.realm
	}
	r := ResolveRealm("", a.Domain)
	a.realm = r
	return true, r
}

// RealmStored 直读持久化的 realm 标识（可能为空 = 未 backfill 的旧文件，Realm() 会 fallback）。
func (a *Auth) RealmStored() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.realm
}

// BackfillRealmFor 显式写入 realm 标识（包外登录路径使用：panel login 已知用户选了
// global，直接落盘 realm=global，不依赖 domain 后缀推断）。realm 需为 cn/global，
// 非法值报错（防写脏）。返回是否发生变更。
func BackfillRealmFor(a *Auth, realm string) (bool, error) {
	if a == nil {
		return false, fmt.Errorf("nil auth")
	}
	switch strings.TrimSpace(realm) {
	case "cn", "global":
	default:
		return false, fmt.Errorf("realm must be cn/global, got %q", realm)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.realm == realm {
		return false, nil
	}
	a.realm = realm
	return true, nil
}

// IsGlobal 报告账号是否属于 global realm（= Realm() == "global"）。
func (a *Auth) IsGlobal() bool { return a.Realm() == "global" }

// IsEnterprise 报告账号是否为企业版（auth 文件带非空 enterpriseId）。
//
// 企业版**没有个人成长体系**：签到 / 成长任务 / 连登管家 / 猫猫旅行 / 夜猫子
// 在上游一律被拒——实测（2026-10-07，同一时刻 A/B 对照）：
//   - POST /v2/billing/meter/daily-checkin                → 400 code 10001「企业账号不支持该操作」
//   - POST /billing/meter/claim-gift / claim-compensation → 400 code 10001 同上
//   - GET  /activity/growth/{streak,buddy/info,heatmap,lottery/summary}
//     与 GET /v2/activity/growth/tasks                    → 403「growth system is only available for personal users」
//
// 因此引用处（scheduler 五类任务 + panel 成长任务/签到入口）必须与 IsGlobal 门控
// 并列跳过，避免每日对注定失败的端点空发请求、面板按钮必然报错。
//
// 不受影响的能力：选号派发、保活（token 刷新）、额度查询（企业额度改走
// /v2/billing/meter/get-enterprise-user-usage，见 upstream.enterpriseResource）。
//
// 直读字段（EnterpriseID 自 Parse 后不再改写，与 upstream 读取方式一致），
// 无需加锁——Realm() 加锁是因为 realm/Domain 会被 RefreshToken 在锁内改写。
func (a *Auth) IsEnterprise() bool { return strings.TrimSpace(a.EnterpriseID) != "" }

// apiTokenPrefixes 静态 API Key 的前缀集合：ck_（CodeBuddy 控制台签发）与
// pt_（官方 CLI @tencent-ai/codebuddy-code 另有该前缀）。
//
// 官方 CLI 的判据是 tokenType === "ApiKey" 且 token 以这两个前缀之一开头；auth
// 文件不持久化 tokenType（refresh 只认 OAuth 设备流，静态 Key 无法刷新），前缀是
// 落盘形态里唯一稳定、跨进程一致的判据。
var apiTokenPrefixes = []string{"ck_", "pt_"}

// isAPIKeyToken 判 token 是否以静态 API Key 前缀开头。
func isAPIKeyToken(at string) bool {
	for _, p := range apiTokenPrefixes {
		if strings.HasPrefix(at, p) {
			return true
		}
	}
	return false
}

// isAPIKeyLocked IsAPIKey 的无锁内部实现：仅限**已持 a.mu** 的调用方使用
// （sync.Mutex 不可重入，锁内再调 AccessTokenValue 会自锁）。
func (a *Auth) isAPIKeyLocked() bool { return isAPIKeyToken(a.AccessToken) }

// IsAPIKey 报告账号是否为静态 API Key 账号（AccessToken 以 ck_/pt_ 开头）。
//
// 静态 Key 直接可用（Authorization: Bearer <key>，官方 CLI 同时发 X-API-Key），
// 但它**没有**个人账号身份：签到 / 成长任务 / 连登 / 旅行 / 夜猫子一律不适用，
// 额度只能走企业口径端点（个人 get-user-resource 对静态 Key 返回空 Accounts），
// 见 UsesEnterpriseBilling。
//
// 经 AccessTokenValue() 加锁读取：RefreshToken 会在锁内改写 AccessToken。
func (a *Auth) IsAPIKey() bool {
	if a == nil {
		return false
	}
	return isAPIKeyToken(a.AccessTokenValue())
}

// UsesEnterpriseBilling 报告账号的额度查询是否该走企业口径端点
// （/v2/billing/meter/get-enterprise-user-usage）。
//
// 企业版与静态 API Key 账号同属此列：个人 get-user-resource 对二者均返回空
// Accounts（企业账号无个人资源包；静态 Key 无个人账号身份），额度必须走企业口径，
// 否则余额恒为 0 → 积分保底把可用号当成耗尽号挡掉。
func (a *Auth) UsesEnterpriseBilling() bool { return a.IsEnterprise() || a.IsAPIKey() }

// TokenSource 从 AccessToken 的 JWT payload 里读 token_source 声明（官方客户端用它
// 填出站 X-Auth-Method 与 X-Userinfo.token_source）。非 JWT / 无该声明 / 解码失败一律
// 返回空串——空表示「这个账号没有该维度」，调用方随之不发对应头（不伪造）。
//
// 每次现解码而不缓存：RefreshToken 会整体换发 token，token_source 可能随重新授权翻转。
// 成本是一次 base64 + 小 JSON，相对一次上游请求可忽略。
func (a *Auth) TokenSource() string {
	if a == nil {
		return ""
	}
	return jwtClaim(a.AccessTokenValue(), "token_source")
}

// IdSource 从 AccessToken 的 JWT payload 里读 `id_source` 声明（官方客户端据此填
// 出站 X-Id-Source 头与 X-Userinfo.id_source 段）。
//
// 与 TokenSource 的差别很重要：token_source 描述「这次授权走了哪条流程」（企业切换等，
// 个人号也有），id_source 描述「身份来源」——两者在真机 runIdentityHeaders() 里是
// 各自独立触发的条件维度。同样现解码不缓存：换发 token 后声明可能变。
func (a *Auth) IdSource() string {
	if a == nil {
		return ""
	}
	return jwtClaim(a.AccessTokenValue(), "id_source")
}

// jwtClaim 解出 JWT payload 里的指定字符串声明；非 JWT / 解码失败返回空。
// 先按无填充 base64url 解（JWT 标准），失败再试带填充形态（兼容非标准签发方）。
func jwtClaim(token, name string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if raw, err = base64.URLEncoding.DecodeString(parts[1]); err != nil {
			return ""
		}
	}
	var payload map[string]any
	if json.Unmarshal(raw, &payload) != nil {
		return ""
	}
	v, _ := payload[name].(string)
	return strings.TrimSpace(v)
}

// SupportsPersonalGrowth 报告账号是否具备个人成长体系（签到 / 成长任务 / 连登管家 /
// 猫猫旅行 / 夜猫子）。企业版与静态 API Key 都没有该体系：
//   - 企业版：上游一律拒绝（400 code 10001 / 403 growth-only，见 IsEnterprise）；
//   - 静态 API Key：根本没有个人账号身份。
//
// scheduler 各任务与 panel 成长入口统一用本方法门控，避免对注定失败的端点空发请求、
// 把本可正常对话的号攒出一串上游报错。
func (a *Auth) SupportsPersonalGrowth() bool { return !a.IsEnterprise() && !a.IsAPIKey() }

// SupportsPersonalEndpoints 报告账号是否可调用「签到 / 任务列表」这类显式报错的个人端点。
// 与 SupportsPersonalGrowth（执行类门控）刻意分开命名：两者当前的判据相同，但语义不同
// ——将来若某类账号「读得到、记不上账」，只需改这一处而不影响执行类门控。
func (a *Auth) SupportsPersonalEndpoints() bool { return !a.IsEnterprise() && !a.IsAPIKey() }

// 不要再用 AccessToken 的 token_source=enterprise_switch 判定「企业上下文」：
// 实测两个只带该章的**个人版**号（enterpriseId 空）成长任务全部 claimed、行为事件
// 照常计分——该章只记本次授权走了哪条流程。企业形态一律以 enterpriseId 为准。

// isGlobalDomain 判定 domain 是否指向 www.workbuddy.ai 家族。
// 同时接受裸域 workbuddy.ai 与任意子域（HasSuffix("www.workbuddy.ai") 或裸域本身）。
func isGlobalDomain(d string) bool {
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "workbuddy.ai" || strings.HasSuffix(d, ".workbuddy.ai") {
		return true
	}
	// 官方 CLI 国际站域（product.json externalDomain: www.codebuddy.ai）。与 workbuddy.ai
	// 同后端不同主机名，但 domain 落盘值不同，不认它会把国际站账号误判成 cn
	// （显式 realm 键可兜住面板登录的账号，手写 auth 文件则直接错域路由）。
	return d == "codebuddy.ai" || strings.HasSuffix(d, ".codebuddy.ai")
}

// NeedsRefresh 报告 token 是否将在 within 内过期（或已过期/无 expiry）。
func (a *Auth) NeedsRefresh(within time.Duration) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	// 静态 API Key 永不刷新（refresh 端点只认 OAuth 设备流）：恒 false，否则请求
	// 路径会先 refresh、失败后把该号当坏号冷却换号——Key 本身是好的。
	if a.isAPIKeyLocked() {
		return false
	}
	if a.ExpiresAt <= 0 {
		return true
	}
	return time.Now().Add(within).Unix() >= a.ExpiresAt
}

// Parse 兼容两种磁盘形态：
//
//	嵌套形 {"auth":{...},"account":{...}}  （插件 OAuth 输出）
//	扁平形 {"accessToken":...,"uid":...}   （手写/旧版）
func Parse(raw []byte) (*Auth, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty auth storage")
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("storage_parse_error: %w", err)
	}
	var a Auth
	if _, nested := probe["auth"]; nested {
		var n struct {
			Auth struct {
				AccessToken  string `json:"accessToken"`
				RefreshToken string `json:"refreshToken"`
				ExpiresAt    int64  `json:"expiresAt"`
				Domain       string `json:"domain"`
				Realm        string `json:"realm"`
				Epoch        uint64 `json:"epoch"`
			} `json:"auth"`
			Account struct {
				UID          string `json:"uid"`
				EnterpriseID string `json:"enterpriseId"`
				Nickname     string `json:"nickname"`
			} `json:"account"`
			// DeviceToken 顶层 device_token（嵌套形与扁平形共用；手写时无需嵌进 auth 对象）。
			DeviceToken string `json:"device_token"`
		}
		if err := json.Unmarshal(raw, &n); err != nil {
			return nil, fmt.Errorf("storage_parse_error: %w", err)
		}
		a = Auth{
			AccessToken:  n.Auth.AccessToken,
			RefreshToken: n.Auth.RefreshToken,
			ExpiresAt:    n.Auth.ExpiresAt,
			Domain:       n.Auth.Domain,
			realm:        n.Auth.Realm,
			UID:          n.Account.UID,
			EnterpriseID: n.Account.EnterpriseID,
			Nickname:     n.Account.Nickname,
			DeviceToken:  n.DeviceToken,
			credEpoch:    n.Auth.Epoch,
		}
	} else {
		var f struct {
			AccessToken  string `json:"accessToken"`
			RefreshToken string `json:"refreshToken"`
			ExpiresAt    int64  `json:"expiresAt"`
			Domain       string `json:"domain"`
			Realm        string `json:"realm"`
			Epoch        uint64 `json:"epoch"`
			UID          string `json:"uid"`
			EnterpriseID string `json:"enterpriseId"`
			Nickname     string `json:"nickname"`
			DeviceToken  string `json:"device_token"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("storage_parse_error: %w", err)
		}
		a = Auth{
			AccessToken:  f.AccessToken,
			RefreshToken: f.RefreshToken,
			ExpiresAt:    f.ExpiresAt,
			Domain:       f.Domain,
			realm:        f.Realm,
			UID:          f.UID,
			EnterpriseID: f.EnterpriseID,
			Nickname:     f.Nickname,
			DeviceToken:  f.DeviceToken,
			credEpoch:    f.Epoch,
		}
	}
	if strings.TrimSpace(a.AccessToken) == "" {
		return nil, fmt.Errorf("parse_error: missing accessToken")
	}
	a.ExpiresAt = normalizeExpiresAt(a.ExpiresAt)
	return &a, nil
}

// expiresAtMillisThreshold 区分「秒」与「毫秒」时间戳的分界（1e11）。
//
// 单位到 1e11 秒已是公元 5138 年，真实凭证不可能；而 1e11 毫秒 = 1973 年，
// 毫秒制当前值（~1.8e12）远在其上。阈值取在两者之间不会误判任一侧。
const expiresAtMillisThreshold = 100_000_000_000

// normalizeExpiresAt 把上游凭据的 expiresAt 归一到 Unix 秒。
//
// 为什么需要：官方 CodeBuddy CLI 的凭据文件
// （%LOCALAPPDATA%\CodeBuddyExtension\Data\Public\auth\*.info）写的是**毫秒**
// （实测 1795254516410），而本仓与旧插件 OAuth 落盘的是**秒**。直接按秒解释毫秒
// 会把到期时间推到公元 58800 年 → NeedsRefresh 恒 false → token 永不刷新 →
// 到期后账号静默失效（表现为「用了一个月突然全部 401」）。导入官方凭据是本仓
// 支持的用法，所以解析入口必须归一，而不是靠使用者手改文件。
func normalizeExpiresAt(v int64) int64 {
	if v > expiresAtMillisThreshold {
		return v / 1000
	}
	return v
}

// SaveAtomic 以嵌套形原子写回 FilePath（tmp + rename），保持嵌套形（插件可读）格式。
// 全程持 a.mu：防止与 RefreshToken 修改 token 字段并发，杜绝写回半更新。
// 防御：accessToken 为空时拒绝写回，避免误用空凭证覆盖有效文件。
func (a *Auth) SaveAtomic() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.saveAtomicLocked()
}

// credDoc 待落盘的凭证文档字段（嵌套形 auth + account + 顶层 device_token）。
// 单独成结构是为了让 SaveAtomic（取 a 当前字段）与 AdoptCredentials（取
// 新旧合并后的字段）共用同一份序列化逻辑，不会出现两种文件形态。
type credDoc struct {
	accessToken  string
	refreshToken string
	expiresAt    int64
	domain       string
	realm        string
	uid          string
	enterpriseID string
	nickname     string
	deviceToken  string
	// epoch 凭证代次（落盘键 auth.epoch）。>0 才写：普通 refresh 写回不带该键，
	// 存量文件形态不变；只有「整体替换凭据」才写，且写入值与内存 credEpoch 一致。
	//
	// 落盘意义（跨进程一致性）：auths/*.json 与 state.json 是两个文件、两次写。
	// 若凭据换新成功而 state.json 写失败，重启时内存无据可判——代次是唯一能跨重启
	// 证明「凭证比 state 记录的新」的证据（见 pool.reconcileCredEpochLocked）。
	epoch uint64
}

// docLocked 取 a 当前字段快照（仅限**已持 a.mu** 的调用方）。
func (a *Auth) docLocked() credDoc {
	return credDoc{
		accessToken:  a.AccessToken,
		refreshToken: a.RefreshToken,
		expiresAt:    a.ExpiresAt,
		domain:       a.Domain,
		realm:        a.realm,
		uid:          a.UID,
		enterpriseID: a.EnterpriseID,
		nickname:     a.Nickname,
		deviceToken:  a.DeviceToken,
		epoch:        a.credEpoch,
	}
}

// writeLocked 把 doc 原子写到 a.FilePath（仅限**已持 a.mu** 的调用方；
// 调用方负责 FilePath 非空与 accessToken 非空的前置校验）。
func (a *Auth) writeLocked(d credDoc) error {
	doc := map[string]any{
		"auth": map[string]any{
			"accessToken":  d.accessToken,
			"refreshToken": d.refreshToken,
			"expiresAt":    d.expiresAt,
			"domain":       d.domain,
			"realm":        d.realm,
		},
		"account": map[string]any{
			"uid":          d.uid,
			"enterpriseId": d.enterpriseID,
			"nickname":     d.nickname,
		},
	}
	// DeviceToken 非空才写回顶层 device_token：避免在无该字段的旧文件里引入空键
	// （保持与插件 OAuth 输出形状一致，插件读取忽略未知键）。
	if d.deviceToken != "" {
		doc["device_token"] = d.deviceToken
	}
	// epoch 同理：0 不写，避免所有存量账号的每次 refresh 都给文件新增一个键。
	if d.epoch > 0 {
		if authObj, ok := doc["auth"].(map[string]any); ok {
			authObj["epoch"] = d.epoch
		}
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	// 落盘走 safefile：tmp fsync 后才 rename（掉电不会留下长度正确、内容全 0 的
	// 凭证文件），并把上一份有效内容留成 <file>.bak —— LoadDir 读到坏文件时用它。
	if err := safefile.WriteKeep(a.FilePath, raw, 0o600); err != nil {
		// Docker bind-mount 权限问题的典型现场：容器内 app 用户（uid 10001）
		// 对宿主机挂载目录无写权限。给出可操作指引而不是裸 syscall 错误。
		msg := fmt.Sprintf("写入 %s 失败: %v", a.FilePath, err)
		if errors.Is(err, fs.ErrPermission) {
			msg += "\n（Docker 部署：容器内用户对宿主机挂载目录无写权限。解法任选：" +
				"1) 以本机 uid 运行容器：PUID=$(id -u) PGID=$(id -g) docker compose up -d；" +
				"2) sudo chown -R 10001:10001 ./auths ./data ./config.json；" +
				"3) compose 设 user: \"0:0\" 以 root 运行）"
		}
		return errors.New(msg)
	}
	return nil
}

// saveAtomicLocked SaveAtomic 的无锁内部实现（仅限**已持 a.mu** 的调用方）。
func (a *Auth) saveAtomicLocked() error {
	if strings.TrimSpace(a.AccessToken) == "" {
		return fmt.Errorf("save refused: empty accessToken (uid=%s)", a.UID)
	}
	if a.FilePath == "" {
		return fmt.Errorf("no FilePath set")
	}
	return a.writeLocked(a.docLocked())
}

// AdoptCredentials 用 src 的凭据**原位整体替换** a 的凭据，用于「401 失效账号
// 重新登录」：账号身份、账号池条目、历史统计、优先级/份额/路由配置全部保持不变，
// 只换认证域（token / 过期时间 / 身份展示 / realm）。
//
// 单次持锁事务，顺序不可换：
//  1. 校验（空 token 拒绝；UID 双方均非空且不等 → 拒绝覆盖，防串号）；
//  2. **先落盘**到 a.FilePath（沿用原账号文件，绝不产生第二个凭证文件）；
//  3. 写盘成功后，才修改内存字段；
//  4. credEpoch + 1。
//
// 写盘失败时 a 的任何字段都不变、代次不变 —— 调用方可以放心把错误报给用户，
// 旧凭证与账号状态完好（不存在"内存已换、文件还是旧的"或假成功）。
//
// 保留项（重登录不该抹掉的东西）：
//   - FilePath：原账号文件路径（不重新拼 workbuddy-<uid>.json，避免同名 UID
//     在多 realm / 手工改名场景下写出第二个文件）；
//   - DeviceToken：src 未携带时沿用旧值（重登只换 OAuth 凭据，桌面端设备风控
//     token 与本账号绑定，丢了会让出站请求被打上"非官方客户端"）；
//   - realm：src 未给出时沿用旧值（realm 由 panel 依原账号推导后显式写入，
//     src 为空只可能来自测试或旧调用方）。
//
// src 必须是**新建且未被共享**的对象（panel 登录流程里刚构造出来的凭证）；
// 本方法对它只做一次字段快照，不改写它。
func (a *Auth) AdoptCredentials(src *Auth) error {
	if a == nil || src == nil {
		return fmt.Errorf("adopt credentials: nil auth")
	}
	if a == src {
		// 自我替换会把「先锁 src 再锁 a」变成自锁（sync.Mutex 不可重入）。
		return fmt.Errorf("adopt credentials: src is the same object as target")
	}
	// src 快照（逐字段拷贝，不整体复制含 sync.Mutex 的结构体）。
	src.mu.Lock()
	next := credDoc{
		accessToken:  src.AccessToken,
		refreshToken: src.RefreshToken,
		expiresAt:    src.ExpiresAt,
		domain:       src.Domain,
		realm:        src.realm,
		uid:          src.UID,
		enterpriseID: src.EnterpriseID,
		nickname:     src.Nickname,
		deviceToken:  src.DeviceToken,
	}
	src.mu.Unlock()

	if strings.TrimSpace(next.accessToken) == "" {
		return fmt.Errorf("adopt credentials: empty accessToken (uid=%s)", next.uid)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// 身份安全闸：目标账号已有 UID 时，新凭据的 UID 必须一致。
	// 上游返回的 UID 未经此校验就写入磁盘 = 把别的账号的凭据写到本账号文件上，
	// 两个账号同时持有对方 token，排查起来极难（日志里只看到某个 uid 的请求 401）。
	if a.UID != "" && next.uid != "" && a.UID != next.uid {
		return fmt.Errorf("adopt credentials: uid mismatch (target=%s new=%s)，拒绝覆盖", a.UID, next.uid)
	}
	if next.uid == "" {
		next.uid = a.UID
	}
	if a.FilePath == "" {
		if src.FilePath == "" {
			return fmt.Errorf("adopt credentials: no FilePath set (uid=%s)", a.UID)
		}
		a.FilePath = src.FilePath
	}
	// —— 身份与展示字段：重新登录**不改**（唯一例外：目标账号原本就缺该字段）——
	//
	// 这不是"图省事"：UID / Nickname / EnterpriseID 在仓库里有大量**无锁**读点
	// （面板任务中心、autotask、taskjobs、状态渲染都直接读 a.UID / a.Nickname），
	// 而 AdoptCredentials 只持 a.mu。若重登改写它们，就与那些读者构成数据竞争
	// （go test -race 已实测到 UID 的竞争）。改成"重登只换凭据，不换身份"后：
	//   - 竞争面消失（这几个字段装载后不再变）；
	//   - 落盘与内存一致（写文件也取同样的值，不会出现"文件里新昵称、内存里旧昵称"）。
	// 真需要更新昵称/企业标识时，那是"重新导入/重加账号"的语义，不是重登。
	if a.UID != "" {
		next.uid = a.UID
	}
	next.nickname = a.Nickname
	next.enterpriseID = a.EnterpriseID
	// 保留项合并。
	if next.deviceToken == "" {
		next.deviceToken = a.DeviceToken
	}
	if strings.TrimSpace(next.realm) == "" {
		next.realm = a.realm
	}
	// 代次在落盘**之前**定稿：文件里写的就是「替换完成后内存里的代次」，
	// 两者必须一致，否则重启对账（pool.reconcileCredEpochLocked）会误判。
	next.epoch = a.credEpoch + 1

	// 先落盘：失败直接返回，下面任何一行都不会执行到。
	if err := a.writeLocked(next); err != nil {
		return err
	}

	// 盘上已是新凭据，再换内存。此刻若有在途 refresh 正持旧代次等锁，它会在
	// 拿到锁后发现 credEpoch 已变而丢弃结果（见 upstream.applyRefresh）。
	a.AccessToken = next.accessToken
	a.RefreshToken = next.refreshToken
	a.ExpiresAt = next.expiresAt
	a.Domain = next.domain
	a.realm = next.realm
	// 身份/展示字段只在目标原本为空时补全（见上方说明），常见路径不写：
	// 避免与面板/任务中心那些无锁读者构成数据竞争。
	if a.UID == "" {
		a.UID = next.uid
	}
	if a.EnterpriseID == "" {
		a.EnterpriseID = next.enterpriseID
	}
	if a.Nickname == "" {
		a.Nickname = next.nickname
	}
	if a.DeviceToken != next.deviceToken {
		a.DeviceToken = next.deviceToken
	}
	a.credEpoch++
	return nil
}

// SaveAtomicRetry 在 SaveAtomic 基础上做有界重试（0/100ms/300ms）。
//
// 为什么需要：refresh 成功后上游已经轮换了 RT，新 token 只在内存里；如果这一次
// 落盘失败（磁盘瞬时满、bind-mount 抖动），进程重启会拿旧 RT 去刷新——旧 RT 可能
// 已被消费，账号直接进入「需要重新登录」。重试把瞬时失败挡掉；仍失败由调用方
// 打 ERR（错误汇总可见），至少不让问题静默。
func (a *Auth) SaveAtomicRetry() error {
	var err error
	for i, delay := range []time.Duration{0, 100 * time.Millisecond, 300 * time.Millisecond} {
		if i > 0 {
			time.Sleep(delay)
		}
		if err = a.SaveAtomic(); err == nil {
			return nil
		}
	}
	return err
}

// LoadDir 扫描并解析 dir 下 workbuddy*.json；解析失败的文件静默跳过（启动日志由调用方统计）。
// 顺带做 realm 标识存量迁移：对空 realm 的 auth 自动 backfill（原始 domain 推断）并 SaveAtomic
// 落盘，一次性把旧文件补上 realm 键。单个文件写失败不阻断启动（log WARN 继续），
// 避免历史 auth 目录个别文件不可写时整个服务起不来。
func LoadDir(dir string) ([]*Auth, error) {
	files, err := filepath.Glob(filepath.Join(dir, "workbuddy*.json"))
	if err != nil {
		return nil, err
	}
	// seenUID 重复 UID 检测：同 UID 出现在多个文件时（双 realm 同名 UID 概率近零）
	// 打 WARN 告警含两文件路径，由「后载入者胜出」保持现状行为（不改变加载结果）。
	seenUID := make(map[string]string, len(files))
	var out []*Auth
	for _, f := range files {
		// 坏文件不再静默跳过：safefile.Read 在正文损坏时回退到 .bak（掉电留下的
		// 全 0 文件因此还能救回账号），两边都坏才放弃，并且说清是哪个文件、坏在哪
		// ——「账号凭空少了一个」比多打一行 ERROR 难查得多。
		raw, err := safefile.Read(f, func(b []byte) bool {
			_, perr := Parse(b)
			return perr == nil
		})
		if err != nil {
			log.Printf("ERROR: auth 文件 %s 无法读取: %v —— 该账号本次不在池里，修好文件或重新登录", f, err)
			continue
		}
		a, err := Parse(raw)
		if err != nil {
			log.Printf("ERROR: auth 文件 %s 解析失败: %v —— 该账号本次不在池里", f, err)
			continue
		}
		a.FilePath = f
		if prev, ok := seenUID[a.UID]; ok {
			log.Printf("WARN: uid %s duplicated across %s and %s — 后者覆盖（不同 realm 同名 UID？）",
				logfmt.Label(a.UID, a.Nickname), prev, f)
		}
		seenUID[a.UID] = f
		if a.RealmStored() == "" {
			if changed, r := a.BackfillRealm(); changed {
				if err := a.SaveAtomic(); err != nil {
					log.Printf("WARN: auth %s realm backfill save: %v", logfmt.Label(a.UID, a.Nickname), err)
				} else if r == "global" {
					log.Printf("auth %s 存量迁移: 补 realm=global（domain=%s）", logfmt.Label(a.UID, a.Nickname), a.Domain)
				}
			}
		}
		out = append(out, a)
	}
	return out, nil
}
