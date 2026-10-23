# 401 账号原位重新登录（Account Re-login）

> 契约来源：`/tmp/wb2api-relogin/SPEC.md`（Lead 权威版）+ 本轮「合并前审查与加固」。实现细节以代码为准，本文随实现更新。
> 相关文档：[upstream-sync.md](upstream-sync.md)（上游同步与发版约定）。
> 关键结论（先看这个）：**恢复判定只看 `disabled_cause`，不看 `auth_fault`、不看 reason 文本**；`auth_fault` 只是「最近观测到的认证故障类型」的展示明细。

---

## 1. 功能概述与适用场景

**要解决的问题**：上游注销会话或把 token 判为无效后，账号在池里变成 `disabled`，旧处置只有「移除账号 → 重新添加」。

| 旧处置 | 代价 |
|---|---|
| 移除账号后重新添加 | 池内状态全部丢失：积分/总额度/到期批次、签到日、优先级与份额、熔断/冷却/连败降权计数、成本账本、token 用量；重登期间该 uid 的请求直接失败；授权链接要手工复制，容易登错账号 |
| 直接点「解冻」（`Revive`） | 全清惩罚态，把管理员「暂停选号」、模型级冷却、熔断、连败降权一起抹掉 —— 一次重登等于替运维清空手工积累的运维意图 |

**现在的行为**：账号行出现「重新登录」按钮 → 浏览器完成 OAuth → 新凭证**原位**写进池里同一个 `*auth.Auth` 对象与同一个 `auths/workbuddy-<uid>.json` → 只按「认证故障」窄口径清除禁用（且仅当 `disabled_cause == auth`），其余状态（暂停、冷却、熔断、降权、积分、优先级）一律保留；**账号身份（UID/Nickname/EnterpriseID）不变**（见 §4.6）。

| 适用 | 判据 |
|---|---|
| 上游判死、账号已禁用 | `overview` 里 `accounts[].needs_relogin === true`（= `disabled && disabled_cause === "auth"`） |
| 上游已判死但还没禁用（中间态） | `session_dead_fails > 0 && !disabled`，前端同样给按钮 |
| 手工排查 | `disabled_cause` ∈ `auth` / `admin` / `upstream` / `unknown`；`auth_fault` ∈ `session_dead` / `gateway_401` 只是观测明细（见 §5.2） |
| global 账号（**含 `global.enabled=false` 的纯 CN 部署**） | 身份判定走**标识**口径 `auth.ResolveRealm(a.RealmStored(), a.DomainValue())`，与逃生门无关：仍按 global 端点授权、realm 校验通过、凭证文件 realm 仍写 `global`。重登只换凭据；重登后能否被路由仍受 `global.enabled` 的既有路由锁约束（不影响身份标识） |

| 不适用 | 原因 |
|---|---|
| 静态 API Key 账号（`api_key=true`） | 无 OAuth 流程、无 RT 可刷新，后端直接 400 `static_api_key_account` |
| 上游封号 / 风控 11140 / 配额 14017 | 不是 token 层问题，重登无效；11140 记 `disabled_cause=upstream`，需上游侧恢复后人工解冻 |
| 管理员手动禁用的账号（`disabled_cause=admin`） | 重登能换成新凭据，但**不会**解除管理员禁用（成因优先级保护，见 §5.2），要恢复请点「解冻」 |
| 存量禁用号（`disabled_cause=unknown`） | 旧 `state.json` 没有成因字段，判定为不可自动恢复：不给重登入口、重登也不解禁，需人工「解冻」 |

---

## 2. 故障分类与判定

判定链：上游响应 → `upstream.Classify`（`ErrKind`）→ `server.applyErrorPolicy` / 调度器 → `pool` 状态机。**只有认证失效（第 1、2 类）才会落 `disabled_cause=auth` + `auth_fault`**，其余各类走既有冷却/熔断/降权路径；管理员禁用与上游风控的成因优先级更高（§5.2），不会被 401 改写。

| # | 形态 | 判定依据 | 需重登 | 是否禁用账号 |
|---|---|---|---|---|
| 1 | 网关 401 `invalid_token` | `upstream.IsGatewayUnauthorized()`：`status==401` 且 body **无业务信封**（APISIX/openresty HTML 页、空体、纯文本）；`Kind=ErrSessionDead` | ✅ | **连续达阈**（`sessionDeadThreshold`，默认 3）才禁用；`disabled_cause=auth`、`auth_fault=gateway_401`、reason = `401 invalid token (re-login required)` |
| 2 | 业务码 12153 | 401 + JSON 信封 `code=12153`（`Offline user session not found` / `12153:refresh token is invalid`），或 body 命中 `sessionDeadMarkers`；refresh 链路回 12153 同判 | ✅ | **分路径**：chat 路径一次即禁（`DisableAuth(..., session_dead)`）；请求前 refresh 判死一次即禁（同上）；保活 refresh / 余额探针判死按连续阈值。均落 `disabled_cause=auth` |
| 3 | Billing 401 但 Chat 可用（降级 token） | `scheduler.noteBalanceAuthFailure`：余额端点 401 → 先 `RefreshToken` 求证；refresh **成功**（换到新 AT）→ 非死号，清 `session_dead_fails`；refresh 回 12153 → 才算死 | ❌（凭据仍活） | 不禁用。同一账号 `authHealBackoff`（30min）内不重复求证，避免一天轮换 288 次 RT |
| 4 | AT 过期但 RT 可刷新 | `auth.NeedsRefresh(refreshSkew)` + `upstream.RefreshTokenIfNeeded()` 换新成功；`SaveAtomicRetry` 落盘 | ❌ | 不禁用、不进认证故障域（落盘失败才打 ERR 日志） |
| 5 | 429 / 402 / 5xx / 网络超时 | `ErrKind`：`ErrSoftRate`（429，含 14003 模型繁忙）/ `ErrHardCredit`（402 余额不足）/ `ErrServer`（5xx）/ 传输层错误 | ❌ | 只冷却/熔断/降权，**绝不置 disabled**（402 → `CoolHard` 长冷却；429 → soft 退避 + `softStreak`；5xx → `breakerUntil`；未知 4xx/传输层 → `consecutiveFails` 降权） |
| 6 | 面板 API Key 401 | `Panel.withAuth` → `httpauth.VerifyBearer` 失败，返回 `401 {"error":"invalid_api_key"}` | ❌（是运维侧密钥问题） | **完全不碰 pool**：面板鉴权失败绝不改动任何账号状态 |
| 7 | 403 WAF / 11140 `request illegal` | `ErrWafBlock`（403 非业务信封）→ 软冷却；11140 → `DisableWithCause(uid, upstream, ...)`：账号级硬禁用，**不是认证故障** | ❌ | WAF 软冷却不禁用；11140 落 `disabled_cause=upstream`（不可自动恢复，需上游侧恢复后人工解冻） |

> 关键区分：`disabled_cause` 是**判据**（决定能不能重登恢复）；`auth_fault` 是「最近观测到的认证故障类型」的**观测明细**（只用于面板文案/排错）；`session_dead_fails` 是判死前的连续计数（「疑似」进度）。三者都会出现在 `overview` 里。

---

## 3. 实现结构

### 3.1 新增文件与改动点

状态列核对时间：2026-10-23 14:45（`git status --short` + `git log --oneline`）；本轮加固提交：`c48697e`/`425d79b`/`0c43cd9`/`a886819`/`698f04f`/`4405137`/`05c5543`。

| 文件 | 状态 | 职责 |
|---|---|---|
| `internal/pool/authfault.go` | ✅（新增+加固） | `AuthFault`、**`DisableCause` 枚举与优先级**、`applyDisableLocked`/`DisableWithCause`/`DisableAuth`/`NoteSessionDeadFault`、`ClearAuthFault`、`CredentialReplaceResult`、`ReplaceCredentials`、`reconcileCredEpochLocked`、`ErrAccountNotFound` |
| `internal/pool/entry.go` | ✅（改） | `entry.disabledCause/authEpoch`、`stateAccount.DisabledCause/AuthEpoch`、`Status.DisabledCause/AuthFault/AuthFaultAt/NeedsRelogin` |
| `internal/pool/state.go` | ✅（改） | `statusOf` 输出 `disabled_cause`，`needs_relogin = disabled && disabled_cause == auth`；`Revive`/`ReviveDisabled` 清标记与成因 |
| `internal/pool/transition.go` | ✅（改） | `disableLocked` 清认证标记；成因由 `applyDisableLocked` 按优先级落 |
| `internal/pool/pool.go` | ✅（改） | `upsertLocked` 绑定凭证前先调 `reconcileCredEpochLocked`（启动对账） |
| `internal/pool/persist.go` | ✅（改） | `disabled_cause`/`auth_epoch` 落盘与恢复；`restoredDisableCause` 兼容三种历史形态（新格式 / 本分支中间格式 / 更早格式→unknown） |
| `internal/auth/auth.go` | ✅（改） | `credEpoch`/`Epoch()`/`RefreshSnapshot()`/`KeyID()`、`AdoptCredentials`（**只换凭据不改身份**）、`writeLocked` 写 `auth.epoch`、`refreshKey` 改走锁内 `KeyID()` |
| `internal/upstream/client.go` | ✅（改） | `refresh()` 取「代次+AT+RT」快照；`applyRefresh(..., epochBefore)` 锁内丢弃旧代次结果；`refreshKey` 改走锁内 `Auth.KeyID()`（消除无锁读 `a.UID` 的竞争） |
| `internal/server/handler.go` | ✅（改） | 网关 401 达阈 → `NoteSessionDeadFault(..., gateway_401)`；12153 与 refresh session dead → `DisableAuth(..., session_dead)`；11140 → `DisableWithCause(..., upstream)` |
| `internal/scheduler/balance_401.go` | ✅（改） | 余额 401 求证路径达阈 → `NoteSessionDeadFault(..., session_dead)`；`ClearAuthHeal(uid)` 清重登后的求证退避 |
| `internal/panel/relogin.go` | ✅（新增+加固） | `reloginStart`、`loginCancel`、`finishRelogin`（**分阶段如实回报**）、`reserveRelogin`/`releaseRelogin`、会话回收与 TTL 判定 |
| `internal/panel/login.go` | ✅（改） | `loginPoll` 完成分支按 `mode` 分叉到 `finishRelogin`；poll 侧 TTL 检查；`loginStart` 写 `mode=LoginModeAdd` |
| `internal/panel/panel.go` | ✅（改） | `LoginMode`、`loginSession{mode,targetUID,targetNickname}`、`reloginBusy`、路由（含 `POST /panel/api/login/cancel`） |
| `internal/panel/app.js` | ✅（改） | 重登入口判定（`disabled_cause` 双保险）、双模式弹窗、**五档成功文案**、`.state.warn` 分档 |
| `internal/panel/index.html` | ✅（改） | 弹窗锁定信息块 `#addRelogin`、按钮文案、`.state.warn` 样式 |
| 测试（9 个文件） | ✅ 已落地 | `internal/auth/relogin_cred_test.go`、`internal/auth/relogin_epoch_test.go`、`internal/auth/relogin_adversarial_test.go`、`internal/pool/authfault_test.go`、`internal/pool/disablecause_test.go`、`internal/pool/credreconcile_test.go`、`internal/panel/relogin_test.go`、`internal/scheduler/relogin_fault_test.go`、`internal/server/relogin_isolation_test.go`；覆盖点见 §7.2。前端未新增测试文件，由既有 `frontend_test.go`/`login_poll_test.go`/`paused_test.go` 的 node+vm 切块覆盖 |

设计约束（与 `AGENTS.md` 及 SPEC 一致）：只新增小 Handler/辅助函数/独立测试文件；不重排现有代码；不新增依赖；不改 `go.mod` 的 module 路径 —— 目的是保住上游同步能力，见 [upstream-sync.md](upstream-sync.md)。

### 3.2 OAuth 会话绑定（uid + realm + mode + state + TTL）

| 维度 | 规则 |
|---|---|
| `state` | 上游 `auth/state` 签发，服务端只存在进程内存 `Panel.logins map[string]loginSession`（`loginMu` 保护），不落盘 |
| `TTL` | `loginTTL = 15min`；`loginStart`/`reloginStart` 入表前调 `sweepExpiredLoginsLocked()` 回收；**poll 侧同样校验**（`loginSessionExpired`，过期按未知 state 处理 → `410`），避免陈旧授权还能改凭据 |
| `mode` | `LoginMode`：`"add"`（现有添加账号，行为不变）/ `"relogin"`（原位重登）。`loginSession` 零值 mode = `add`，旧调用方与旧测试零回归 |
| `uid` | 字段 `targetUID`，relogin 会话**绑定目标 uid**；poll 完成时上游返回的 uid 必须等于 `targetUID`，否则 409 且不落盘 |
| `realm` | 字段 `realm`，**绑定账号现有 realm**（服务端用**标识**口径 `auth.ResolveRealm(a.RealmStored(), a.DomainValue())` 推导，不信任前端，也不受 `global.enabled` 逃生门影响）；上游授权结果 realm 必须一致，否则 409 |
| `targetNickname` | 仅回显给前端（「正在给谁重登」），不参与任何校验 |
| `processing` | 既有重复 poll 闸门（前端每 3s 轮询，成功分支副作用数秒），relogin 复用同一语义 |
| 并发 | 两段保护：① `reloginBusy` 占住 uid，挡「查重通过但 state 尚未入表」的双击窗口；② 入表后在 `logins` 里查重 —— 同一 uid 已有未过期 relogin 会话 → `409 relogin_in_progress`。不同 uid 可并行，`loginMu` 临界区只做 map 读写 |
| 取消 | `POST /panel/api/login/cancel {"state":"..."}` 显式作废会话；会话作废后同一 state 的 poll 得 `410`；**处理中**（正在写凭据）的会话拒绝取消，返回 `409 login_processing` |

绑定 uid+realm 的目的：防止「A 账号的授权结果写进 B 账号文件」和「用 CN 端点授权后写进 global 账号」这两类不可逆事故；两者都会让两个账号同时持有错误 token，日志里只表现为某个 uid 的请求 401。

### 3.3 端点契约

#### `POST /panel/api/accounts/{uid}/relogin/start`

| 项 | 值 |
|---|---|
| 鉴权 | `withAuth`（Bearer 面板 API Key） |
| 请求体 | **被忽略（可空）**；目标 uid 来自路径，realm 由服务端推导，前端无法指定 |
| 服务端 | `validUID(uid)`（防路径穿越）→ `Pool.AuthByUID(uid)` 必须存在 → `a.IsAPIKey()` 则 400 → **标识口径** `auth.ResolveRealm(a.RealmStored(), a.DomainValue())` 推导 realm（非 global 归为 cn；不受 `global.enabled` 影响）→ `reserveRelogin(uid)` 占位 → `loginEndpoints(realm)` 取上游 `auth/state` → `sweepExpiredLoginsLocked` + 写 `loginSession{created, realm, mode:relogin, targetUID, targetNickname}` → 释放占位 |
| 成功 200 | `{"ok":true,"mode":"relogin","uid","nickname","realm","url","state","expires_in":900}` |
| 错误 | `400 {"ok":false,"error":"invalid uid"}`；`404 "账号不存在"`；`400 {"ok":false,"error":"static_api_key_account","message":"静态 API Key 账号不支持 OAuth 重新登录；Key 失效请在「添加账号 → API Key」里重新添加"}`；`409 {"ok":false,"error":"relogin_in_progress","message":...}`；`502`（上游 `auth/state` 失败）；`501`（账号池未装配） |

#### `POST /panel/api/login/cancel`

| 项 | 值 |
|---|---|
| 鉴权 | `withAuth` |
| 请求体 | `{"state":"..."}` |
| 成功 200 | `{"ok":true,"cancelled":bool}`（`cancelled=false` 表示该 state 本就不存在，幂等） |
| 错误 | `400 missing state`；`409 {"error":"login_processing","message":"正在写入凭据，请稍候"}`（正在落盘/恢复的会话不允许中途取消：会让前端以为没生效，实际已生效） |

#### `GET /panel/api/login/poll?state=...`

现有添加账号语义**保持不变**（`mode=add`）。relogin 成功响应**不再有笼统的「成功=已恢复」**：`auth_ok=true` 只代表「授权与身份校验通过」，其余阶段各有字段。

| 字段 | 类型 | 语义 |
|---|---|---|
| `done` / `mode` / `relogin` | bool/string | 流程终态与模式（`mode="relogin"`、`relogin=true`） |
| `uid` / `realm` | string | 目标账号（服务端绑定值） |
| `nickname` | string | **本次授权账号**的昵称（信息性，不写回账号身份，见 §4.6） |
| `auth_ok` | bool | OAuth 完成 + 身份/域校验通过（**不代表已恢复**） |
| `credentials_updated` | bool | 凭据已换新并 fsync 到 auth 文件；为 true 后端才敢说「已重新授权」 |
| `state_persisted` | bool | 运行状态是否已写入 state.json；false 时重启会按凭证代次自动校正（§5.6） |
| `recovered` | bool | 认证禁用是否**真的**被解除；false 也可能是账号本来没被禁用 |
| `in_rotation` | bool | 当前是否真的回到可选号 = `!disabled && !paused && !cooling` |
| `disabled` / `paused` / `cooling` | bool | 换凭据后的真实状态快照（不再靠猜） |
| `credentials_epoch` | uint | 换后凭证代次（与 auth 文件 `auth.epoch` 同值） |
| `chat_verified` | bool | **恒 false**：本轮不做任何 chat 探测，宁可标「未验证」也不伪造健康结论 |
| `billing_verified` / `balance_ok` | bool | 余额端点是否验证通过（401 只说明计费通道不可用，不等于 Chat 不可用） |
| `balance_error` | string | 计费验证失败原因 |
| `credits` / `credits_total` | int | 余额；`-1` = 未知/未查到（前端显示「积分未知」，不显示 0） |
| `warnings` | []string | 结构化告警：运行状态未落盘 / 仍禁用（含原因）/ 仍暂停；供 API 消费方（前端当前主要按上面的分阶段字段自拼文案） |
| `checkin_message` | string | 重登不跑签到/新账号初始化，恒空 |

| 失败结果 | HTTP | Body |
|---|---|---|
| uid 不一致 | 409 | `{"ok":false,"error":"relogin_uid_mismatch","message":"新授权登录的账号与目标账号不一致，已拒绝覆盖原凭证","target_uid","granted_uid"}` —— **不落盘、不改池** |
| realm 不一致 | 409 | `{"ok":false,"error":"relogin_realm_mismatch","message":"...","realm"}`：① 目标账号**标识** realm 在授权期间变了；② 新授权 `domain` 归一化后与目标域不符 —— 都**不落盘、不改池** |
| 目标账号已不存在 | 409 | `{"ok":false,"error":"relogin_target_missing","message":"目标账号已不存在，已取消这次重新登录（不会新建账号）"}` |
| 凭据写盘失败 | 500 | 错误原文 + 「已保留原有凭证与账号状态」；不得返回成功 |
| state 过期/进程重启/已取消 | 410 | 前端停止轮询 |
| 未完成 | 200 | `{"done":false,"message":"..."}`（继续轮询） |

安全红线：**任何响应与日志都不得包含 accessToken / refreshToken**；只允许出现 uid、nickname、state 前 8 字符。

#### 状态字段（`GET /panel/api/overview` → `accounts[]`）

| 字段 | 类型 | 含义 |
|---|---|---|
| `disabled_cause` | string | `""` / `"auth"` / `"admin"` / `"upstream"` / `"unknown"` —— **恢复判据** |
| `needs_relogin` | bool | 后端结论 = `disabled && disabled_cause == "auth"`，前端不再自行拼条件 |
| `auth_fault` | string | `""` / `"session_dead"` / `"gateway_401"` —— 最近观测到的认证故障类型（**仅供参考展示，不参与恢复判定**） |
| `auth_fault_at` | time | 打出标记的时刻（观测用） |
| `session_dead_fails` | int | 判死前的连续计数（「疑似」进度） |
| `disabled_reason` | string | 给人看的禁用文案（**绝不用于判定成因**） |

### 3.4 身份与 Realm 校验规则

校验顺序是刻意的：`finishRelogin` **先做完所有校验、再执行任何有副作用的动作**，任一项不过都让旧凭证与账号状态原样保留。

| 层/步骤 | 校验 | 失败表现 |
|---|---|---|
| 路径 | `validUID(uid)`：仅 `[A-Za-z0-9_-]`、长度 ≤ 64 | `400 invalid uid`（防 `workbuddy-../../evil.json` 路径穿越） |
| 账号存在性 | `Pool.AuthByUID(uid)` | `404 账号不存在` |
| 账号类型 | `a.IsAPIKey()`（AT 以 `ck_`/`pt_` 开头） | `400 static_api_key_account` |
| realm 来源 | `auth.ResolveRealm(a.RealmStored(), a.DomainValue())`（**标识**口径：显式 realm 优先、其次按 domain 推断；**不受 `global.enabled` 逃生门影响**），非 global 归一为 cn | 不信任请求体；start 时锁定进会话 |
| ① 会话仍有效 | `logins[state]` 存在（期间可能被 cancel/过期） | `410`，不落盘 |
| ② 目标账号仍存在（OAuth 期间可能被移除） | `Pool.AuthByUID(targetUID)` | `409 relogin_target_missing`，**绝不 pool.Add 新建** |
| ③ uid 一致（防串号） | 上游 `login/account` 的 uid == `targetUID` | `409 relogin_uid_mismatch`（附 `target_uid`/`granted_uid`），不落盘 |
| ④ uid 合法性 | `validUID(acct.UID)` | `502`，拒绝落盘 |
| ⑤ realm 标识不变 | `auth.ResolveRealm(cur.RealmStored(), cur.DomainValue()) != sess.realm` → 拒绝（`global.enabled` 翻转**不影响**该判定；真正会变的是凭证文件里的 realm/domain 字段被改写） | `409 relogin_realm_mismatch`，不落盘 |
| ⑥ 域名一致 | 响应带 `domain` 时 `auth.ResolveRealm("", domain) == sess.realm`；`domain` 缺失不否决（CN 可能不回 domain，端点已锁定域） | `409 relogin_realm_mismatch`，不落盘 |
| ⑦ token 有效性 | `expiresIn` 缺失记 `expiresAt=0`（= 尽快刷新，不是永不过期）；`refreshToken` 缺失时打 WARN 但**不阻断** | 不阻断，仅日志 |
| auth 层兜底 | `AdoptCredentials` 内再查一次 `a.UID != src.UID` | 返回 error，凭据与文件均不变 |

### 3.5 前端交互（重登模式）

失败文案（`reloginStartErrMsg`）：静态 Key / 在途会话 / 目标已被移除（404）/ 服务端正在写凭据（409 `login_processing`）/ 会话过期（410）分别给人话，绝不暗示成功。

成功文案按后端**分阶段状态**分五档（`reloginDoneText`，取自 `internal/panel/app.js` 实测）：

| 档 | 触发条件 | 文案（head） |
|---|---|---|
| ① 真恢复 | `recovered && in_rotation` | `已重新授权，账号已恢复参与选号` |
| ② 仍暂停 | `recovered && !in_rotation && paused` | `已重新授权，但账号仍处于暂停选号（签到/保活照常，不接流量）` |
| ③ 仍冷却 | `recovered && !in_rotation && cooling` | `已重新授权，但账号仍在冷却/熔断中，恢复后自动回池` |
| ④ 仍禁用 | `!recovered && disabled` | `已重新授权（凭证已更新），但账号仍处于禁用状态，需人工解冻` |
| ⑤ 兜底 | 其余（含 200 但未确认换凭据） | `已重新授权（凭证已更新），账号可用性以列表状态为准` / `授权流程已完成，但服务端未确认凭据已更新，账号状态以列表为准` |

五档之后统一追加真相：`：<昵称或 uid>（国际版）`、积分（`credits=-1` 显示「积分未知（未查到…）」）、`；Chat 未验证`（`chat_verified` 恒 false）；计费未通过追加「计费通道未验证通过：<原因>（不代表 Chat 不可用…）」；`state_persisted === false` 追加「运行状态尚未落盘，重启后会自动校正（不影响本次授权）」。

颜色与停留：只有 ① 用 `.state.ok`；②③④ 用新增 `.state.warn`；真干净（①且已落盘且计费验证通过）停留 1.6s 自动关闭，其余 8s 让人看清。

账号行（双保险，防旧后端/字段漂移）：`disabled_cause ∈ {admin, upstream}` → 不给「需重新授权」标签、不给重登按钮；「已禁用」tag 的 title 写明不可重登原因（管理员禁用 → 点「解冻」；上游风控 → 需上游恢复后解冻）。`openRelogin` 再挡一次并 toast 对应原因。

---

## 4. 原位凭证替换机制

### 4.1 为什么不删号重建

| 维度 | 删号重建（旧做法） | 原位替换（本功能） |
|---|---|---|
| 池条目 | 新 entry，历史清零 | 同一个 `*entry` + 同一个 `*auth.Auth` 指针 |
| 积分/到期批次 | 丢失，要等下一轮余额刷新 | 保留（`credits`/`creditsTotal`/`expiryBuckets`） |
| 签到/任务状态 | `StartNewAccountTasks` 重跑，签到态可能丢 | 保留 |
| 冷却/熔断/降权/暂停 | 全丢（或误清） | 全部保留 |
| 优先级/份额（`account_priority`/`account_share`） | 需重新配置（按 uid 匹配，重建后可能失效窗口） | 天然保留 |
| 在途请求 | 重建窗口内该 uid 不可选；`inFlight`/`lastUsed` 复位 | 指针不变，handler/scheduler 已持有的指针继续有效 |
| 磁盘 | 先删后写，存在「无文件」窗口 | 单次原子写，旧文件始终可读 |

### 4.2 `auth.Auth.AdoptCredentials(src)`：单锁事务，先写盘后换字段

调用顺序（除第 1 步读 `src` 快照外，全程持 `a.mu`；这是唯一写内存字段的入口）：

1. **取 src 快照**：在 `src.mu` 内逐字段拷贝到内部 `credDoc`（不整体复制含 `sync.Mutex` 的结构体），随即释放 `src.mu`。
2. **拒绝非法入参**：`src == nil`、`src == a`（自我替换会导致自锁，`sync.Mutex` 不可重入）。
3. **拒绝空凭证**：`src.AccessToken` 为空 → 报错，不写盘。
4. **身份闸**：`a.UID` 与 `src.UID` 均非空且不等 → 报错拒绝覆盖（防止把别的账号凭据写到本账号文件上）。
5. **身份字段保持装载值**：`UID`/`Nickname`/`EnterpriseID` 一律取目标账号已有值（仅目标为空时用 `src` 补全）——重登**不改身份**，理由见 §4.6；`FilePath` 保留旧路径（仅旧为空时采用 `src.FilePath`）。
6. **保留项合并**：`DeviceToken`（`src` 为空时保留旧值，避免重登抹掉设备风控 token）、`realm`（`src` 为空时保留旧值）。
7. **代次定稿**：`next.epoch = a.credEpoch + 1`，在落盘**之前**确定 —— 文件里写的就是替换完成后内存里的代次，两者必须一致，否则重启对账会误判（§5.6）。
8. **先落盘**：`writeLocked(next)`（safefile：tmp fsync → rename），`auth.epoch` 仅 `>0` 时写入（存量文件形态不变）。
9. **写盘成功后才改内存字段**：只换 `AccessToken/RefreshToken/ExpiresAt/Domain/realm`（身份字段仅空值补全），最后 `credEpoch++`。

失败语义：任一步失败（尤其第 8 步写盘失败）→ 返回 error，**内存字段、`credEpoch`、磁盘文件全部保持旧值**，旧凭证不受损，重试或继续排错都安全。

### 4.3 `credEpoch` 代次：防止在途 refresh 用旧结果覆盖新授权

问题来源：`refresh()` 的既有形态是「锁内取 RT 快照 → 锁外 HTTP → 锁内写回」。重登成功替换凭据的那几秒里，可能有一个 refresh 正拿**旧 RT** 在飞：

- 它若成功写回 → 把刚落盘的新授权凭证覆盖回旧 token，**重登等于白做**；
- 它若失败（12153）→ 把刚恢复的账号再判死一次，**误杀**。

方案：

| 环节 | 实现 |
|---|---|
| 取快照 | `RefreshSnapshot()` 一次持锁读齐 `(epoch, accessToken, refreshToken)`；分开读会在「读代次」与「读 token」之间插入一次整体替换，代次校验随即失效 |
| 写回校验 | `applyRefresh(a, res, atBefore, rtSnapshot, epochBefore)`：锁内先比 `a.EpochLocked() != epochBefore` |
| 结果处置 | 代次已变 → **无论成功失败一律丢弃并返回 `nil`**（本次刷新不算失败，调用方不会禁用/冷却）；成功分支额外 `log` 一行「凭据已被重新授权替换，丢弃本次刷新结果」 |
| 既有语义保留 | 代次未变时仍走原双检 `AccessToken/RefreshToken` 是否已被并发刷新换新；失败且 token 已变 → 返回 `nil`（并发落败不是判死） |
| 自增点 | 只有 `AdoptCredentials` 成功时 `credEpoch++`（唯一来源） |
| 跨重启 | 代次随凭证落盘（`auth.epoch`）并记入 `state.json` 的 `auth_epoch`，重启后用于双文件对账（§5.6） |

| 场景 | 在途 refresh 的结果 | 处置 |
|---|---|---|
| 成功，代次未变 | 新 AT/RT | 正常写回 |
| 成功，代次已变 | 旧 RT 换来的结果 | 丢弃（否则覆盖新授权） |
| 失败，代次已变 | 旧 RT 的 12153 | 丢弃（否则误杀刚恢复的账号） |
| 失败，代次未变但 token 已变 | 并发落败 | 返回 `nil`，不判死 |
| 失败，代次与 token 均未变 | 真死 | 返回 error → 12153 计数/按策略禁用 |

### 4.4 `pool.ReplaceCredentials(uid, src)`：池层不换指针，且如实回报

| 步骤 | 行为 |
|---|---|
| 取条目 + 换 auth 文件 | `p.mu.RLock()` 内取 `e.a` → `cur.AdoptCredentials(src)`（文件 I/O 期间不持写锁，选号热路径不被阻塞；读锁同时阻止 `Remove`/`SyncToDir` 换掉条目） |
| 落池状态 | `p.mu.Lock()`：`e.authEpoch = res.Epoch`（与 auth 文件对齐）→ `clearAuthFaultLocked`（**仅当 `disabled_cause == auth`** 才解禁）→ 快照 `disabled/paused/cooling` → `flushLocked()` 返回 `StatePersisted` |
| 返回值 | `CredentialReplaceResult{Epoch, StatePersisted, Recovered, Disabled, Paused, Cooling}`；`InRotation() = !Disabled && !Paused && !Cooling` |
| `state_persisted=false` | 凭据文件已 fsync（成功不可撤销），但 state.json 没落盘：**不返回错误、也不谎报** —— 调用方据此如实回报，重启由 §5.6 自动对账 |
| 错误 | uid 不存在 / 条目无 `*auth.Auth` → `ErrAccountNotFound`；auth 文件写盘失败 → 原样上报（账号状态不变） |

`src` 由 `finishRelogin` 用上游响应在内存构造：`AccessToken/RefreshToken/ExpiresAt/Domain/UID/EnterpriseID/Nickname`，`FilePath` **沿用原账号文件**（`cur.FilePath`），`DeviceToken` 留空（由 `AdoptCredentials` 保留旧值），`realm` 用 `auth.BackfillRealmFor(next, sess.realm)` 显式写入。它只用于内存替换，**不会**新增 `auths/workbuddy-*.json`，也不会创建第二个账号条目。

替换成功后的收尾（都在 `finishRelogin` 内，失败不影响「凭据已换新」这一事实）：

| 收尾动作 | 目的 |
|---|---|
| `Scheduler.ClearAuthHeal(uid)` | 清余额 401 求证退避窗口，否则重登后第一次余额探测被旧窗口跳过（最长 30min），表现为「重登没生效」 |
| `Upstream.UserResource(next)` → `ReenableIfCredits` | 余额刷新（幂等）。成功则按既有口径解「余额耗尽硬冷却」，**不动**熔断/限流态；失败只回传 `billing_verified=false`，不回滚、不禁用 |
| `dropLoginSession(state)` | 会话作废，同一 state 后续 poll 得 410，不会重复落盘 |

### 4.5 失败矩阵

| 失败点 | 磁盘 `auths/*.json` | 内存 `*auth.Auth` | 池状态 | 前端表现 |
|---|---|---|---|---|
| relogin/start（上游 state 失败） | 不变 | 不变 | 不变 | 502 + 重试 |
| relogin/start（并发占位冲突） | 不变 | 不变 | 不变 | 409 `relogin_in_progress` |
| poll：会话已取消/过期 | 不写 | 不变 | 不变 | 410 + 重新发起 |
| poll：目标账号已被移除 | 不写 | 不变 | 不变 | 409 `relogin_target_missing`（不新建账号） |
| poll：uid 不一致 | 不写 | 不变 | 不变 | 409 `relogin_uid_mismatch`（附 target/granted uid） |
| poll：realm 不一致 | 不写 | 不变 | 不变 | 409 `relogin_realm_mismatch` |
| poll 期间取消（processing） | 不变 | 不变 | 不变 | 409 `login_processing`（写盘已完成则返回成功） |
| `AdoptCredentials` 写盘失败 | 不变（原子写失败不留半文件） | 不变（`credEpoch` 不增） | 不变 | 500 + 「已保留原有凭证与账号状态」 |
| `AdoptCredentials` uid 不一致（auth 层兜底） | 不变 | 不变 | 不变 | 500，凭据未被改动 |
| 凭据换新成功但 **state.json 写失败** | **已写新凭证**（fsync） | 已换 | 运行态已恢复、`state_persisted=false` | 200 + `state_persisted:false` + 文案「运行状态尚未落盘，重启后会自动校正」；重启按 §5.6 自愈 |
| 替换成功但账号仍被 admin/upstream 禁用 | 已写新凭证 | 已换 | 禁用保持（`recovered=false`，`disabled=true`） | 200 + 第 ④ 档文案「仍处于禁用状态，需人工解冻」 |
| 替换成功但余额校验失败 | 已写新凭证 | 已换 | 已窄口径恢复 + `ReenableIfCredits` | 200 + `billing_verified:false`（不代表 Chat 不可用，见 §6） |
| 替换成功但未拿到 RT | 已写新凭证 | 已换 | 已恢复 | 200 + WARN 日志；AT 过期后需再次重登 |

### 4.6 重新登录只换凭据，不改身份

`AdoptCredentials` 现在只写 `AccessToken / RefreshToken / ExpiresAt / Domain / realm`（外加 `DeviceToken` 缺省保留），**`UID` / `Nickname` / `EnterpriseID` 一律保持装载值**（仅目标为空时补全），落盘也取同样的值。

**为什么**：`a.UID` / `a.Nickname` 在面板任务中心、autotask、taskjobs、状态渲染里有大量**无锁直读**点，而 `AdoptCredentials` 只持 `a.mu` —— 若重登改写它们，就与这些读者构成数据竞争。本轮 `go test -race` **实测抓到**了真实竞争（`refreshKey` 无锁读 `a.UID` 与 adopt 写 `a.UID`），修法是两条一起上：

1. `AdoptCredentials` 不再改写身份字段（竞争面消失：这几个字段装载后不再变）；
2. `refreshKey` 改为走锁内 `Auth.KeyID()`（`UID` 优先、回落 `FilePath`）。

**运维可见后果**：重登后账号的昵称/企业标识**不会刷新**（那是「重新导入账号」的语义）；HTTP `login/poll` 响应里的 `nickname` 是**本次授权账号的昵称**，仅作信息展示。

---

## 5. 恢复流程：认证故障标记 + 禁用成因 + 窄口径恢复

### 5.1 认证故障标记（`auth_fault`）写入点

`disableLocked` 会先清空 `authFault`（保证非认证原因的禁用不残留旧标记），因此**认证失效必须走带 fault 的入口**；且必须通过成因优先级闸门（§5.2），管理员/上游禁用不会被标记。

| 触发路径 | 调用 | `auth_fault` | `disabled_cause` | 状态 |
|---|---|---|---|---|
| 网关 401 `invalid_token` 连续达阈 | `NoteSessionDeadFault(uid, AuthFaultGateway401, "401 invalid token (re-login required)")`（兼容包装：`NoteSessionDeadWith` 按 reason 自动判类） | `gateway_401` | `auth` | ✅ |
| 12153（chat 路径，一次即禁） | `DisableAuth(uid, "12153 session dead", AuthFaultSessionDead)` | `session_dead` | `auth` | ✅ |
| 请求前 refresh 判死（chat 路径） | `DisableAuth(uid, "refresh session dead", AuthFaultSessionDead)` | `session_dead` | `auth` | ✅ |
| 余额探针 401 + refresh 判死达阈 | `NoteSessionDeadFault(uid, AuthFaultSessionDead, "12153 session dead")` | `session_dead` | `auth` | ✅ |
| 保活 refresh 判死（连续阈值） | `NoteSessionDead(uid)` → `NoteSessionDeadWith` → `NoteSessionDeadFault(...)` | `session_dead` | `auth` | ✅ |
| 管理员手动禁用 | 面板「禁用」→ `Pool.Disable(uid, "manual disable (panel)")` → `applyDisableLocked(..., DisableCauseAdmin, ...)`（等价入口：`DisableWithCause(uid, admin, reason)`） | 空（且清旧标记） | `admin` | ✅ |
| 上游风控 11140 `request illegal` | `DisableWithCause(uid, DisableCauseUpstream, ...)` | 空（且清旧标记） | `upstream` | ✅ |
| 存量/未知成因 | 旧 `state.json` 无 `disabled_cause` 的禁用、脏值归一化 | 兼容中间格式时可能非空 | `unknown` | ✅ |
| 人工解冻 | `Revive` / `ReviveDisabled` → 清标记与成因 | 空 | `none` | ✅ |

### 5.2 禁用成因优先级（DisabledCause）

`DisabledCause` 是**恢复判据**（落 `state.json` 的 `disabled_cause`），与给人看的 `reason` 文本彻底分开：判定绝不解析 reason。

| 成因 | 值 | 优先级 | 谁写入 | 重登能否解除 |
|---|---|---|---|---|
| `none` | `""` | 0 | 未禁用（零值） | — |
| `unknown` | `"unknown"` | 2 | 旧 `state.json` 无 `disabled_cause` 键的禁用；脏值归一化；`DisableWithCause(none)` 的安全侧兜底 | ❌ 需人工「解冻」 |
| `auth` | `"auth"` | 2 | `DisableAuth` / `NoteSessionDeadFault`；本分支中间格式（只有 `auth_fault`）还原为 `auth` | ✅ 窄口径恢复 |
| `admin` | `"admin"` | 3 | 面板「禁用」（`Pool.Disable` → `applyDisableLocked(..., admin)`；等价 `DisableWithCause(uid, admin, ...)`） | ❌ 需人工「解冻」 |
| `upstream` | `"upstream"` | 3 | 上游风控/封禁（如 11140） | ❌ 需上游侧恢复 + 人工「解冻」 |

优先级规则（`disableCauseRank`：`admin = upstream (3) > auth = unknown (2) > none (0)`，`applyDisableLocked` **只在成因更强时**才落禁用，同级或更弱一律忽略）：

| 情形 | 结果 |
|---|---|
| 管理员/上游风控禁用的账号，随后收到历史在途请求的 401 | **不覆盖 reason、不打 `auth_fault`、不标 `needs_relogin`**（日志一行「已因 … 禁用，忽略认证故障」） |
| 管理员对一个 `auth` 禁用账号再点禁用 | 升级为 `admin`（3 > 2），并按 `disableLocked` 语义清掉认证标记 → 之后重登也不会解禁 |
| 历史禁用（`unknown`）+ 新来的 401 | 同级（2 ≤ 2）→ 拒绝升级，保持 `unknown`，不会莫名其妙变成「需重登」 |
| `ClearAuthFault` | **仅当 `disabled_cause == auth`** 才解禁；`admin`/`upstream`/`unknown` 一律不动 |

**`needs_relogin` 判据**：`disabled && disabled_cause == "auth"`（`pool/state.go` 的 `statusOf`）。`auth_fault` 已降级为「最近观测到的认证故障类型」的展示明细，**不参与恢复判定** —— 后人不要再用 `auth_fault != ""` 去判按钮或解禁。

存量数据口径：旧 `state.json` 里没有 `disabled_cause` 的禁用号一律记 `unknown` → **不给「重新登录」入口、重登录也不会解禁，需人工「解冻」**。这是刻意的安全侧选择（任务要求不得依赖 reason 文本判断成因，无法从旧 reason 反推 auth）；本分支中间格式（只有 `auth_fault` 没有 `disabled_cause`）会被还原成 `auth`，不会误伤调试期数据。

### 5.3 `ClearAuthFault(uid)`：清什么 / 不清什么

**清（仅认证故障域）**：

| 字段 | 处理 |
|---|---|
| `authFault` / `authFaultAt` | 归零 |
| `sessionDeadFails` | 归零（账号已被证明活着，旧的死亡进度作废） |
| `disabled` / `reason` / `disabled_cause` | **仅当** `disabled_cause == auth` 才解禁并清 reason/cause |
| 返回值 | `false` = 无认证故障可清（no-op，供调用方区分） |

**不清（明确保留 —— 重登录只证明「凭据换了新的」，不证明「运维希望它立刻接单」）**：

| 保留项 | 为什么不清 |
|---|---|
| `paused` 暂停选号 | 管理员让它让位，与凭据无关 |
| `until` / `coolKind` / `softStreak` | 429 冷却与软退避指数（上游行为观测） |
| `modelCooldowns`（6004 模型级冷却） | 模型级独立限流，不是账号认证问题 |
| `breakerUntil` / `fails` / `retryCount` | 5xx 熔断与退避指数 |
| `degradeUntil` / `consecutiveFails` | 连败降权（临时出池） |
| `credits` / `creditsTotal` / `creditsExpiring` / `expiryBuckets` | 余额账本，由余额刷新更新，不由重登改写 |
| `modelOff` | 运维手动关闭的「(账号,模型)」组合 |
| `modelCost` | 实测成本账本 |
| `successCount` / `errTotal` / `lastErr` / `lastSuccess` / `tokenUsage` | 历史统计 |
| `lastCheckinDay` / 签到态 | 「今日已签到」状态 |
| `lastUsed` / `usedSeq` / 优先级 / 份额 | 路由状态与运维配置 |
| `disabled_cause`（admin/upstream/unknown 时） | 成因不是 auth，重登无权解禁 |

### 5.4 三条恢复入口对比

| 入口 | 清 `disabled` | 清 `disabled_cause` | 清 `auth_fault` | 清 `paused` | 清冷却/熔断/降权 | 清余额快照 | 适用 |
|---|---|---|---|---|---|---|---|
| `ClearAuthFault`（重登成功自动调用） | **仅 `cause==auth`** | 仅 auth → none | ✅ | ❌ | ❌ | ❌ | 认证判死后原位重登 |
| `ReviveDisabled`（只解禁） | ✅ | ✅ 清空 | ✅ | ❌ | ❌ | ❌ | 仅想解掉 disabled、保留惩罚态 |
| `Revive`（面板「解冻」） | ✅ | ✅ 清空 | ✅ | ✅ | ✅ | ❌ | 人工判定该号完全可用，一键全清（也是 admin/upstream/unknown 的唯一恢复路径） |

### 5.5 端到端时序（relogin）

1. 前端点「重新登录」→ `POST /panel/api/accounts/{uid}/relogin/start`（body 被忽略）。
2. `reloginStart`：`validUID` → 账号存在 → 非静态 Key → **标识口径** `auth.ResolveRealm(a.RealmStored(), a.DomainValue())` 定 realm（与 `global.enabled` 无关）→ `reserveRelogin(uid)`（挡双击）→ 上游 `auth/state` → 回收过期会话 + 写 `loginSession{mode:"relogin", targetUID, targetNickname, realm, created}` → 释放占位 → 200 返回 `url`/`state`/`expires_in:900`。
3. 浏览器完成授权 → 前端每 3s `GET /panel/api/login/poll?state=...`；关闭弹窗时前端发 `login/cancel`（已作废的 state 回 404/410，照常关闭）。
4. `loginPoll`：TTL 检查（过期 → 410）→ `processing` 闸门 → `auth/token` 成功 → `login/account` 取 uid/nickname → `mode == relogin` 分叉到 `finishRelogin`（**不落盘、不 pool.Add、不跑新账号任务**）。
5. `finishRelogin` 按 §3.4 顺序校验：会话有效 → 目标账号仍存在 → uid 一致 → uid 合法 → **标识 realm** 未变 → `domain` 归一化一致 → token 有效期换算；任何一步失败立即返回，旧凭证与账号状态原样保留。
6. `Pool.ReplaceCredentials(target, next)`：`AdoptCredentials`（先写盘 → 再换内存 → `credEpoch++`，身份字段不动）→ 落 `authEpoch` → `clearAuthFaultLocked`（仅 auth 成因）→ `flushLocked()` 得到 `StatePersisted`。
7. `Scheduler.ClearAuthHeal(target)` 清余额求证退避；`Upstream.UserResource(next)` 刷新余额 → 成功则 `ReenableIfCredits`（只解余额硬冷却）；失败只回传 `billing_verified=false`，**不回滚、不禁用**。
8. `dropLoginSession(state)`；200 返回分阶段字段（`credentials_updated` / `state_persisted` / `recovered` / `in_rotation` / `disabled` / `paused` / `cooling` / `credentials_epoch` / `chat_verified=false` / `billing_verified` / `warnings[]`）；前端按五档文案提示 + `loadOverview(true)`。
9. 中间态清理：`session_dead_fails` 在阈值内尚未禁用的，重登同样清计数并保持账号在池中；已因认证故障禁用的由 `ClearAuthFault` 解禁；**paused/冷却/熔断/降权/积分一字不动**；管理员/上游/未知成因的禁用**保持不变**。

### 5.6 双文件持久化一致性与启动对账

凭据与运行状态分属两个文件（`auths/workbuddy-<uid>.json` 与 `state.json`），不可能原子地一起写。本轮用**单调凭证代次**做单向对账收敛，不引入事务框架（两个文件、两次写、一个字段的代价，换取重启自愈）。

| 落点 | 键 | 何时写 |
|---|---|---|
| auth 文件 | `auth.epoch` | `AdoptCredentials` 整体替换凭据时写；**仅 >0 才写**（普通 refresh 写回不带该键，存量文件形态不变） |
| `state.json` | `auth_epoch`（`stateAccount.auth_epoch`） | 每次落盘该账号的运行状态时记录内存里的代次 |

失败窗口（真实会发生）：凭据换新 fsync 成功 → 内存已恢复 → **`state.json` 写失败**（磁盘满/只读/bind-mount 抖动）→ 进程重启 → state 仍是 `disabled + disabled_cause=auth`。

启动路径：`auth.LoadDir` → `pool.New` → `pool.SyncToDir` → `upsertLocked` → **`reconcileCredEpochLocked`**（只比代次，不猜 reason）：

| 代次关系 | 含义 | 启动动作 |
|---|---|---|
| 文件 == state | 一致 | 无事发生 |
| 文件 > state | 凭据已被整体替换过（上次 state 写失败） | 若 `disabled_cause == auth` → **窄口径恢复**（只解 auth 成因，admin/upstream 不动）；否则清掉陈旧的 `auth_fault`/`sessionDeadFails`；随后把对齐值落盘（避免每次启动重复告警） |
| 文件 < state（含「文件无该键但 state 有」） | 凭证可能被回滚/从备份恢复/被不写 epoch 的旧版本改写 | **只告警**（WARN：凭证可能已回滚，建议重新登录），以**文件**为准，不改禁用状态 |
| 文件 == state == 0 | 存量文件（从未整体替换过） | 无动作 |

接口侧配套：`ReplaceCredentials` 返回 `CredentialReplaceResult{Epoch, StatePersisted, Recovered, Disabled, Paused, Cooling}`，`flushLocked()` 返回 `bool`；`state_persisted=false` 时接口**不谎报**（200 + 明确字段，前端提示「运行状态尚未落盘，重启后会自动校正」），重启后由上述对账自愈。

---

## 6. 限制与已知风险

| # | 限制/风险 | 表现 | 处置 |
|---|---|---|---|
| 1 | **Billing 401 ≠ Chat 不可用** | 降级 token 形态：billing 恒 401、chat 仍可用；反过来，授权成功也可能 `billing_verified:false` | 不要只看 `done:true`：同时看 `billing_verified`/`balance_error`；`balance_error` 非空说明凭据已换但额度端点仍拒，属上游侧问题 |
| 2 | **授权成功 ≠ 上游全部服务可用** | `chat_verified` 恒 false（本轮不做 chat 探测）；trial 未激活（14017）、企业口径端点、模型级限制都独立于 token | 重登后至少在面板跑一次「额度」+ 一次真实 chat，确认两侧都通 |
| 3 | **静态 API Key 不支持重登** | `api_key=true` 无 OAuth 流程，后端 400 `static_api_key_account` | 在面板「导入 API Key」重新添加（或先移除再加），没有原位路径 |
| 4 | **凭证文件的 realm/domain 在授权期间被外部改写** | 目标账号 `auths/*.json` 里的 `realm`/`domain` 被另一个进程或手工编辑改动 → **标识** realm 与 start 时锁定的 `sess.realm` 不符 → 409 `relogin_realm_mismatch` | 属保护性拒绝（不会写坏凭证）：确认无人改动文件后重试。`global.enabled` 翻转**不再**触发该错误（身份判定已与逃生门解耦） |
| 5 | **state 只存进程内存** | 面板重启 → 410，前端停止轮询；旧 state 最长滞留 15min | 关闭弹窗重发一次，不要反复刷新页面 |
| 6 | **并发重登** | 同一 uid 两个浏览器/两个标签 → 409 `relogin_in_progress` | 等已有的浏览器授权完成，或过期后重试 |
| 7 | **不解除上游封禁** | 11140 风控（`disabled_cause=upstream`）、封号、配额耗尽重登无效 | 上游侧恢复后人工「解冻」；连续两次重登都立刻再 401 → 停止重试，按账号级问题处理 |
| 8 | **反复重登有成本** | 每次授权都轮换 AT/RT；高频重登可能触发上游设备风控 | 不做脚本循环重试；`DeviceToken` 会在替换时保留以降低风控 |
| 9 | **不修复「为什么判死」** | 重登只解决凭据层；若根因是上游持续注销会话，重登后仍会再次判死 | 结合 §2 分类定位根因（网关 401 抖动 vs 12153 真死 vs 降级 token） |
| 10 | **授权期间账号被移除** | 完成时目标 uid 已不在池里 → 409 `relogin_target_missing` | 重新添加账号；本流程**绝不**顺手 `pool.Add` 新建（否则「重登」变「新增」，历史统计/优先级全脱节） |
| 11 | **外部进程/并发重登改写凭证文件** | 单实例内的并发重登已被 `reloginBusy` + 409 挡住；但 `logins`/`reloginBusy` 都是**进程内**状态，多实例共享同一 `auths/` 目录时可能各持一个同一 uid 的会话，后完成者覆盖先完成者；手工编辑文件同理 | 同一 `auths/` 只跑一个面板实例；此类冲突表现为 409 保护性拒绝或后写覆盖，不会产生半截凭证 |
| 12 | **处理中不可取消** | 正在写凭据的会话 cancel 返回 409 `login_processing` | 等待该次 poll 返回；此时前端应按「成功/失败」处理，而不是显示「已取消」 |
| 13 | **可能拿不到 refreshToken** | 上游偶发不返 RT：不阻断重登，但 AT 过期后必须再重登一次 | 关注 WARN 日志；此类账号重登后不要指望自动续期 |
| 14 | **重登不改昵称/企业标识** | `AdoptCredentials` 只换凭据、不改身份（并发安全要求，见 §4.6）；面板昵称与 `enterprise` 标记不会因重登刷新 | 这是刻意的：改身份属于「重新导入/重加账号」语义；确实需要更新昵称时只能重新导入账号 |
| 15 | **存量禁用号 `disabled_cause=unknown` 不可自动恢复** | 旧 `state.json` 无成因字段的禁用号：不给「重新登录」入口，重登也不会解禁 | 人工「解冻」；解冻后若再因认证失效禁用，会自动获得 `auth` 成因 |
| 16 | **`disabled_cause` 与 `auth_fault` 双键同源** | 前者是**判据**（能不能重登恢复），后者是**观测明细**（最近看到哪种认证故障）；两者可能不同步（如管理员禁用后仍残留旧观测、或已清标记） | 恢复判断、按钮显示一律用 `disabled_cause`；`auth_fault` 只用于文案与排错 |
| 17 | **state.json 落盘失败** | 凭据已 fsync、运行态正确，但 `state_persisted=false`；重启后按凭证代次自动对账恢复，**无需人工干预**，但会留一条 WARN 日志 | 确认磁盘空间/权限；若反复出现，检查 `data/state.json` 挂载是否只读 |
| 18 | **前端切片求值仍有遗留 sloppy** | `login_poll_test.go` / `paused_test.go` 两处重登相关切片已改**严格模式**求值；其余两处无关切片仍是 sloppy 求值（既有隐患，本轮未改） | 后续同步上游严格化时统一（上游 `9151570` 已把 `frontend_test.go` 的 28 处改为严格模式，本仓另有 14 处待跟进） |

---

## 7. 测试方式

### 7.1 命令

```bash
go build ./...
go vet ./...

# 全量（真实跑过，结果见下方「实测结论」）
go test ./internal/auth/ ./internal/pool/ ./internal/panel/ ./internal/scheduler/ ./internal/server/ -count=1

# 并发时序必跑：P0 用例（在途 refresh vs 重登）集中在这几个包
go test -race ./internal/auth/ ./internal/pool/ ./internal/panel/ ./internal/scheduler/ -count=1

# 定向
go test ./internal/auth      -run 'AdoptCredentials|InflightRefresh|StaleRefresher|StaleSessionDead|RefreshSnapshot|SaveAtomicFormat' -v
go test ./internal/pool      -run 'DisableCause|DisableAuth|ClearAuthFault|ReplaceCredentials|Reconcile|LegacyDisabled|AuthFault' -v
go test ./internal/panel     -run 'Relogin' -v
go test ./internal/scheduler -run 'Balance401|ClearAuthHeal' -v
go test ./internal/server    -run 'PanelAPIKey401|UpstreamAccount401|TwoAuthDomains' -v
```

`-race` 必跑：`credEpoch` 的验证本质是并发时序（在途 refresh vs 整体替换），单线程测试证明不了；本轮正是靠它抓到「adopt 写 UID vs 无锁读 UID」的真实竞争（见 §4.6）。

**实测结论**：

```text
go test ./internal/auth/ ./internal/pool/ ./internal/panel/ ./internal/scheduler/ ./internal/server/ -count=1 → 全 ok
go test -race ./internal/auth/ ./internal/pool/ ./internal/panel/ ./internal/scheduler/ -count=1 → 全 ok，零 data race
go vet ./... → 干净
```

两个历史失败均已由独立提交修复，不再是基线负担：

- `internal/server` 的 `TestUsageCreditTotalRequiresValidExplicitCreditAndTokens/out_of_range_total` —— 提交 `c48697e` 修掉（真因：`float64(2^63)` 越界转 `int` 饱和 + round-trip 校验在边界恒成立；已把值域闸门移到转换之前）。
- `internal/scheduler` 的 `-race` 告警（时区用例）—— 提交 `a886819` 修掉（join 后台 goroutine 之后再恢复全局时区）。

### 7.2 测试文件与覆盖点

核对时间 2026-10-23 14:45：9 个测试文件均已落地并跑绿。

| 文件 | 覆盖点 | 状态 |
|---|---|---|
| `internal/auth/relogin_cred_test.go` | `AdoptCredentials` 事务：字段整体替换、`FilePath` 不重拼、`DeviceToken`/`realm` 保留、**身份字段不被改写**、`credEpoch` +1、UID 不一致拒绝、空 AT 拒绝、两种写盘失败注入后字段与磁盘字节零改动；`SaveAtomic` 嵌套形格式回归 | ✅ |
| `internal/auth/relogin_epoch_test.go` | 在途 refresh vs 重登（单点）：阻塞式 Transport 让 refresh 悬停在锁外，期间 `AdoptCredentials` 换新并落盘，放行后断言 `RefreshToken()` 返回 `nil`、内存与磁盘均为新 token、`epoch==1`；旧世界 12153 失败结果同样丢弃；对照组（无重登时必须正常写回）；`RefreshSnapshot` 三元组一致 | ✅ |
| `internal/auth/relogin_adversarial_test.go` | 任务书 5 步竞态逐字复现（旧 refresh 在途 → 重登 → 旧 refresh 成功 → 旧调用方仍 `SaveAtomicRetry` → 内存/磁盘必须是新凭证）；旧 refresh 回 12153 不判死；对照组；多轮重登 × 多线程刷新收敛（`TestStaleRefresherCannotRollbackRelogin` / `TestStaleSessionDeadDoesNotKillRelogin` / `TestRefreshStillAppliesWithoutRelogin` / `TestConcurrentReloginAndRefreshStress`） | ✅ |
| `internal/pool/authfault_test.go` | `DisableAuth`/`NeedsRelogin`/JSON 字面值；非认证禁用清 fault 且不被 `ClearAuthFault` 解除；`ClearAuthFault` 窄口径逐字段；`ReplaceCredentials` 指针身份/统计/不新增账号/`ErrAccountNotFound`/失败零改动；`state.json` round-trip 与旧文件兼容；`NormalizeAuthFault` | ✅ |
| `internal/pool/disablecause_test.go` | 成因优先级 6 组：管理员/上游禁用扛住认证故障、管理员禁用可把 auth 升级为 admin、`ClearAuthFault` 不动 paused、旧禁用无成因不可自动恢复、成因跨重启持久化（`TestAdminDisableSurvivesAuthFault` 等） | ✅ |
| `internal/pool/credreconcile_test.go` | `ReplaceCredentials` 分阶段结果；**端到端**「state 目录只读制造落盘失败 → 陈旧 state + 新 auth 文件 → 重启自动恢复」；管理员禁用不被对账解除；非禁用时清陈旧 fault；容忍凭证回滚（`TestReplaceCredentialsReportsStagedResult` / `TestRestartRecoversAuthDisableAfterStateWriteFailure` 等） | ✅ |
| `internal/panel/relogin_test.go` | start 契约（body 忽略 / realm 服务端推导 / 400-404-409 / `expires_in`）；全流程（disabled+needs_relogin → poll 成功 → 单账号/指针不变/统计保留/磁盘新 token/同 state 再 poll 410）；UID 与 realm 不一致 409 + 零改动；TTL 410；cancel 410/409；processing 闸门；并发 start 恰 1 成功 1 冲突；写盘失败 500；余额 401 仍 `auth_ok` 但 `billing_verified=false`；目标被移除 409 不新建；响应体不含 AT/RT | ✅ |
| `internal/scheduler/relogin_fault_test.go` | Billing 401 + refresh 成功不禁用、无 fault、计数归零；12153 达阈 → disabled + `disabled_cause=auth` + `needs_relogin`；429/402/5xx/400 不 refresh 且无 fault；`ClearAuthHeal` 退避窗口与幂等 | ✅ |
| `internal/server/relogin_isolation_test.go` | 面板错误/缺失 Bearer 401 且池状态 DeepEqual 全等、上游零调用；上游 12153 禁用后同 key 面板仍 200 且 overview `needs_relogin=true`；两域 401 契约不同且不泄露凭据 | ✅ |

> 前端未新增测试文件：由既有 `internal/panel/frontend_test.go`、`login_poll_test.go`、`paused_test.go` 的 `node`+`vm` 切块测试覆盖重登入口判定、分阶段文案与轮询分支；其中 `login_poll_test.go`/`paused_test.go` 的两处切片已改为**严格模式求值**（提交 `05c5543`），其余两处无关切片仍 sloppy（见 §6 #18）。

### 7.3 Mock 上游做法

| 要求 | 做法 |
|---|---|
| 禁真实网络 | 全部用 `httptest.NewServer` 起假上游，`loginEndpoints`/`upstream` 端点指向本地；禁止访问 `copilot.tencent.com` / `workbuddy.ai` |
| 伪设备授权 | `/v2/plugin/auth/state` 返回固定 `state`+`authUrl`；`/v2/plugin/auth/token?state=` 按阶段返回 `code!=0`（pending）或 `{accessToken,refreshToken,expiresIn}`；`/v2/plugin/login/account?state=` 返回 `uid`/`nickname`/`enterpriseId` |
| 伪业务 | `/v2/billing/*`、chat 端点按用例返回 `{code:12153}`、网关 401 HTML、429、5xx 等形态 |
| 伪造 token | 只用形如 `fake-at-*` / `fake-rt-*` 的字符串；**禁止**把真实 token 写进 fixture/日志/文档 |
| 身份不匹配 | 让 fake `login/account` 返回另一个 uid 或另一 realm，断言 409 且磁盘文件未被改写 |
| 并发用例 | 阻塞式 `RoundTripper` 让 refresh 悬停在锁外，同时执行 `ReplaceCredentials`；`-race` 下断言最终磁盘/内存均为新授权凭证 |
| 落盘失败注入 | 把 state 目录设只读（或注入 save 失败）制造 `state_persisted=false`，重启池后断言按凭证代次自动恢复且管理员禁用不受影响 |

### 7.4 手工验证

```bash
PANEL=http://127.0.0.1:8080
KEY='<面板 API Key>'
ACCT_UID='<目标 uid>'          # 注意：不要用 UID 作变量名，bash 里 UID 是只读内置变量

# 1) 发起重登：body 被忽略，realm/uid 由服务端决定
curl -sS -X POST "$PANEL/panel/api/accounts/$ACCT_UID/relogin/start" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -d '{}'

# 2) 浏览器打开返回的 url 完成授权，然后轮询（<STATE> 用上一步返回值）
curl -sS "$PANEL/panel/api/login/poll?state=<STATE>" -H "Authorization: Bearer $KEY"

# 3) 复核状态：needs_relogin 应为 false、disabled_cause 应为空，session_dead_fails 归零
curl -sS "$PANEL/panel/api/overview" -H "Authorization: Bearer $KEY" |
  python3 -c 'import json,sys; a=[x for x in json.load(sys.stdin)["accounts"] if x["uid"]=="'"$ACCT_UID"'"]; print(json.dumps(a, ensure_ascii=False, indent=2))'

# 4) 放弃等待时显式取消（否则该 uid 在 15min TTL 内禁止再次发起）
curl -sS -X POST "$PANEL/panel/api/login/cancel" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -d "{\"state\":\"<STATE>\"}"
```

> 排错时看 `disabled_cause` / `needs_relogin` / `auth_fault` / `auth_fault_at` / `session_dead_fails` / `disabled_reason`，不要打印 token。重登成功的响应要按字段读：`credentials_updated`、`state_persisted`、`recovered`、`in_rotation`、`chat_verified`、`billing_verified` —— 不存在一个「done=true 就等于已恢复」的捷径。
