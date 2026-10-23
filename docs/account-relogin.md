# 401 账号原位重新登录（Account Re-login）

> 契约来源：`/tmp/wb2api-relogin/SPEC.md`（Lead 权威版）。实现细节以代码为准，本文随实现更新。
> 相关文档：[upstream-sync.md](upstream-sync.md)（上游同步与发版约定）。

---

## 1. 功能概述与适用场景

**要解决的问题**：上游注销会话或把 token 判为无效后，账号在池里变成 `disabled`，旧处置只有「移除账号 → 重新添加」。

| 旧处置 | 代价 |
|---|---|
| 移除账号后重新添加 | 池内状态全部丢失：积分/总额度/到期批次、签到日、优先级与份额、熔断/冷却/连败降权计数、成本账本、token 用量；重登期间该 uid 的请求直接失败；授权链接要手工复制，容易登错账号 |
| 直接点「解冻」（`Revive`） | 全清惩罚态，把管理员「暂停选号」、模型级冷却、熔断、连败降权一起抹掉 —— 一次重登等于替运维清空手工积累的运维意图 |

**现在的行为**：账号行出现「重新登录」按钮 → 浏览器完成 OAuth → 新凭证**原位**写进池里同一个 `*auth.Auth` 对象与同一个 `auths/workbuddy-<uid>.json` → 只按「认证故障」窄口径清除禁用，其余状态（暂停、冷却、熔断、降权、积分、优先级）一律保留。

| 适用 | 判据 |
|---|---|
| 上游判死、账号已禁用 | `overview` 里 `accounts[].needs_relogin === true`（= `disabled && auth_fault != ""`） |
| 上游已判死但还没禁用（中间态） | `session_dead_fails > 0 && !disabled`，前端同样给按钮 |
| 手工排查 | `auth_fault` ∈ `session_dead`（12153 / refresh offline）/ `gateway_401`（APISIX invalid_token） |
| global 账号（**含 `global.enabled=false` 的纯 CN 部署**） | 身份判定走**标识**口径 `auth.ResolveRealm(a.RealmStored(), a.DomainValue())`，与逃生门无关：仍按 global 端点授权、realm 校验通过、凭证文件 realm 仍写 `global`。重登只换凭据；重登后能否被路由仍受 `global.enabled` 的既有路由锁约束（不影响身份标识） |

| 不适用 | 原因 |
|---|---|
| 静态 API Key 账号（`api_key=true`） | 无 OAuth 流程、无 RT 可刷新，后端直接 400 `static_api_key_account` |
| 上游封号 / 风控 11140 / 配额 14017 | 不是 token 层问题，重登无效 |

---

## 2. 故障分类与判定

判定链：上游响应 → `upstream.Classify`（`ErrKind`）→ `server.applyErrorPolicy` / 调度器 → `pool` 状态机。**只有认证失效（第 1、2 类）才会写 `auth_fault` 标记**，其余各类走既有冷却/熔断/降权路径。

| # | 形态 | 判定依据 | 需重登 | 是否禁用账号 |
|---|---|---|---|---|
| 1 | 网关 401 `invalid_token` | `upstream.IsGatewayUnauthorized()`：`status==401` 且 body **无业务信封**（APISIX/openresty HTML 页、空体、纯文本）；`Kind=ErrSessionDead` | ✅ | **连续达阈**（`sessionDeadThreshold`，默认 3）才禁用；reason = `401 invalid token (re-login required)`，`auth_fault=gateway_401` |
| 2 | 业务码 12153 | 401 + JSON 信封 `code=12153`（`Offline user session not found` / `12153:refresh token is invalid`），或 body 命中 `sessionDeadMarkers`；refresh 链路回 12153 同判 | ✅ | **分路径**：chat 路径一次即禁（`DisableAuth(..., session_dead)`）；请求前 refresh 判死一次即禁（同上）；保活 refresh 判死按连续阈值（`NoteSessionDead`）；余额探针 401+refresh 判死按连续阈值 |
| 3 | Billing 401 但 Chat 可用（降级 token） | `scheduler.noteBalanceAuthFailure`：余额端点 401 → 先 `RefreshToken` 求证；refresh **成功**（换到新 AT）→ 非死号，清 `session_dead_fails`；refresh 回 12153 → 才算死 | ❌（凭据仍活） | 不禁用。同一账号 `authHealBackoff`（30min）内不重复求证，避免一天轮换 288 次 RT |
| 4 | AT 过期但 RT 可刷新 | `auth.NeedsRefresh(refreshSkew)` + `upstream.RefreshTokenIfNeeded()` 换新成功；`SaveAtomicRetry` 落盘 | ❌ | 不禁用、不进认证故障域（落盘失败才打 ERR 日志） |
| 5 | 429 / 402 / 5xx / 网络超时 | `ErrKind`：`ErrSoftRate`（429，含 14003 模型繁忙）/ `ErrHardCredit`（402 余额不足）/ `ErrServer`（5xx）/ 传输层错误 | ❌ | 只冷却/熔断/降权，**绝不置 disabled**（402 → `CoolHard` 长冷却；429 → soft 退避 + `softStreak`；5xx → `breakerUntil`；未知 4xx/传输层 → `consecutiveFails` 降权） |
| 6 | 面板 API Key 401 | `Panel.withAuth` → `httpauth.VerifyBearer` 失败，返回 `401 {"error":"invalid_api_key"}` | ❌（是运维侧密钥问题） | **完全不碰 pool**：面板鉴权失败绝不改动任何账号状态 |
| 7 | 403 WAF / 11140 `request illegal` | `ErrWafBlock`（403 非业务信封）→ 软冷却；11140 → 账号级硬禁用，但**不是认证故障** | ❌ | WAF 软冷却不禁用；11140 硬禁用但 `auth_fault` 为空（不会出现「重新登录」入口） |

> 关键区分：`auth_fault` 非空 = 「凭据层已判死，只能重登」；`session_dead_fails` 非零 = 「疑似，尚未判死」。两者都是 `overview` 的透出字段。

---

## 3. 实现结构

### 3.1 新增文件与改动点

状态列核对时间：2026-10-23 14:00（`git status --short` + `git diff --stat`）；所有实现文件与测试文件均已落地。

| 文件 | 状态 | 职责 |
|---|---|---|
| `internal/pool/authfault.go` | ✅ 已落地（新增） | `AuthFault` 枚举与归一化、`DisableAuth`、`NoteSessionDeadFault`、`AuthFaultOf`、`ClearAuthFault`、`ReplaceCredentials`、`ErrAccountNotFound` |
| `internal/pool/entry.go` | ✅ 已落地（改） | `entry.authFault/authFaultAt`、`stateAccount.AuthFault/AuthFaultAt`、`Status.AuthFault/AuthFaultAt/NeedsRelogin` |
| `internal/pool/state.go` | ✅ 已落地（改） | `NoteSessionDeadWith` 按 reason 细分 fault；`Revive`/`ReviveDisabled` 清标记；`statusOf` 计算 `needs_relogin` |
| `internal/pool/transition.go` | ✅ 已落地（改） | `disableLocked` 先清标记，保证「非认证原因的禁用」不残留旧认证标记 |
| `internal/pool/persist.go` | ✅ 已落地（改） | `auth_fault`/`auth_fault_at` 落盘与恢复（旧 `state.json` 缺键 = 零值 = 无故障） |
| `internal/auth/auth.go` | ✅ 已落地（改） | `credEpoch`、`Epoch()`/`EpochLocked()`、`RefreshSnapshot()`、`AdoptCredentials()`、`credDoc` + `writeLocked()` |
| `internal/upstream/client.go` | ✅ 已落地（改） | `refresh()` 取「代次+AT+RT」快照；`applyRefresh(..., epochBefore)` 在锁内丢弃旧代次结果（3 处调用点） |
| `internal/upstream/refresh_test.go` | ✅ 已落地（改） | `applyRefresh` 签名适配 |
| `internal/server/handler.go` | ✅ 已落地（改） | 网关 401 达阈 → `NoteSessionDeadFault(..., gateway_401)`；12153 与 refresh session dead → `DisableAuth(..., session_dead)` |
| `internal/scheduler/balance_401.go` | ✅ 已落地（改） | 余额 401 求证路径达阈 → `NoteSessionDeadFault(..., session_dead)`；新增 `ClearAuthHeal(uid)`（重登后清 30min 求证退避，避免「刚重登余额还是旧值」） |
| `internal/panel/relogin.go` | ✅ 已落地（新增） | `reloginStart`、`loginCancel`、`finishRelogin`、`reserveRelogin`/`releaseRelogin`、会话回收与 TTL 判定（`sweepExpiredLoginsLocked`/`loginSessionExpired`/`dropLoginSession`） |
| `internal/panel/login.go` | ✅ 已落地（改） | `loginPoll` 在完成分支按 `mode` 分叉到 `finishRelogin`；poll 侧补 TTL 检查（过期按未知 state → 410）；`loginStart` 写 `mode=LoginModeAdd` |
| `internal/panel/panel.go` | ✅ 已落地（改） | `LoginMode`（`add`/`relogin`）、`loginSession{mode,targetUID,targetNickname}`、`reloginBusy`、路由注册（含 `POST /panel/api/login/cancel`） |
| `internal/panel/app.js` | ✅ 已落地（改） | `reloginOffer()` 入口判定、「重新登录」主色按钮、双模式弹窗（`applyAddMode('relogin')`）、失败文案 |
| `internal/panel/index.html` | ✅ 已落地（改） | 弹窗标题/锁定信息块 `#addRelogin`（uid/nickname/realm 只读）、按钮文案 |
| 测试（6 个新文件） | ✅ 已落地 | `internal/auth/relogin_cred_test.go`、`internal/auth/relogin_epoch_test.go`、`internal/pool/authfault_test.go`、`internal/panel/relogin_test.go`、`internal/scheduler/relogin_fault_test.go`、`internal/server/relogin_isolation_test.go`；覆盖点见 §7.2。前端**未新增**测试文件，由既有 `internal/panel/frontend_test.go` / `login_poll_test.go` / `paused_test.go` 的 node+vm 切块测试覆盖 |

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
| 取消 | `POST /panel/api/login/cancel {"state":"..."}` 显式作废会话（脚本/后续前端释放用；当前前端关闭弹窗只停止轮询，靠 15min TTL 兜底）；会话作废后同一 state 的 poll 得 `410`；**处理中**（正在写凭据）的会话拒绝取消，返回 `409 login_processing` |

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

现有添加账号语义**保持不变**（`mode=add`）。relogin 会话额外校验：

| 结果 | HTTP | Body |
|---|---|---|
| 成功 | 200 | `{"done":true,"mode":"relogin","relogin":true,"auth_ok":true,"uid","nickname","realm","credits","credits_total","balance_ok":bool,"balance_error":"","checkin_message":""}` |
| uid 不一致 | 409 | `{"ok":false,"error":"relogin_uid_mismatch","message":"新授权登录的账号与目标账号不一致，已拒绝覆盖原凭证","target_uid","granted_uid"}` —— **不落盘、不改池** |
| realm 不一致 | 409 | `{"ok":false,"error":"relogin_realm_mismatch","message":"...","realm"}`：① 目标账号的**标识** realm（`ResolveRealm(RealmStored(), DomainValue())`）在授权期间变了；② 新授权返回 `domain` 归一化后与目标域不符 —— 两种情况都**不落盘、不改池** |
| 目标账号已不存在 | 409 | `{"ok":false,"error":"relogin_target_missing","message":"目标账号已不存在，已取消这次重新登录（不会新建账号）"}` |
| 凭据写盘失败 | 500 | 错误原文 + 「已保留原有凭证与账号状态」；不得返回成功 |
| state 过期/进程重启/已取消 | 410 | 同现状；前端停止轮询 |
| 未完成 | 200 | `{"done":false,"message":"..."}`（继续轮询） |

安全红线：**任何响应与日志都不得包含 accessToken / refreshToken**；只允许出现 uid、nickname、state 前 8 字符。

#### 状态字段（`GET /panel/api/overview` → `accounts[]`）

| 字段 | 类型 | 含义 |
|---|---|---|
| `auth_fault` | string | `""` / `"session_dead"` / `"gateway_401"`（认证故障类型化原因） |
| `auth_fault_at` | time | 打出标记的时刻（观测用） |
| `needs_relogin` | bool | 后端结论 = `disabled && auth_fault != ""`，前端不再自行拼条件 |
| `session_dead_fails` | int | 既有字段：判死前的连续计数（「疑似」进度） |

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
5. **保留项合并**：
   - `FilePath`：保留旧路径；仅当旧为空时采用 `src.FilePath`；
   - `DeviceToken`：`src` 为空时保留旧值（重登不应抹掉设备风控 token）；
   - `realm`：`src` 为空时保留旧值。
6. **先落盘**：`writeLocked(next)`（tmp + rename 原子写）。
7. **写盘成功后才改内存字段**，最后 `credEpoch++`。

失败语义：任一步失败（尤其第 6 步写盘失败）→ 返回 error，**内存字段、`credEpoch`、磁盘文件全部保持旧值**，旧凭证不受损，重试或继续排错都安全。

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
| 自增点 | 只有 `AdoptCredentials` 成功时 `credEpoch++`（唯一来源，避免多点自增互相踩） |

| 场景 | 在途 refresh 的结果 | 处置 |
|---|---|---|
| 成功，代次未变 | 新 AT/RT | 正常写回 |
| 成功，代次已变 | 旧 RT 换来的结果 | 丢弃（否则覆盖新授权） |
| 失败，代次已变 | 旧 RT 的 12153 | 丢弃（否则误杀刚恢复的账号） |
| 失败，代次未变但 token 已变 | 并发落败 | 返回 `nil`，不判死 |
| 失败，代次与 token 均未变 | 真死 | 返回 error → 12153 计数/按策略禁用 |

### 4.4 `pool.ReplaceCredentials(uid, src)`：池层不换指针

| 步骤 | 行为 |
|---|---|
| 取条目 | `p.mu.RLock()` 内取 `e.a`；持读锁的原因：阻止并发的 `Remove`/`SyncToDir` 在替换过程中删掉条目或换掉 `*auth.Auth` 指针 |
| 替换 | `cur.AdoptCredentials(src)`（`src` 是 poll 里在内存构造的临时 `*auth.Auth`，其 `FilePath` 不参与落盘目标）|
| 恢复 | 成功后 `ClearAuthFault(uid)`（窄口径）+ `Flush()`（state.json 立即落盘，避免重启后又显示「需重登」）|
| 不加写锁做 I/O | 文件写盘期间不持 `p.mu` 写锁，选号热路径不被阻塞 |
| 错误 | uid 不存在 / 条目无 `*auth.Auth` → `ErrAccountNotFound`；写盘失败 → 原样上报，调用方必须返回失败，不得假成功 |

`src` 由 `finishRelogin` 用上游响应在内存构造：`AccessToken/RefreshToken/ExpiresAt/Domain/UID/EnterpriseID/Nickname`，`FilePath` **沿用原账号文件**（`cur.FilePath`），`DeviceToken` 留空（由 `AdoptCredentials` 保留旧值），`realm` 用 `auth.BackfillRealmFor(next, sess.realm)` 显式写入（不依赖 domain 后缀推断，CN 可能不回 domain）。它只用于内存替换，**不会**新增 `auths/workbuddy-*.json`，也不会创建第二个账号条目。

替换成功后的收尾（都在 `finishRelogin` 内，失败不影响「凭据已换新」这一事实）：

| 收尾动作 | 目的 |
|---|---|
| `Scheduler.ClearAuthHeal(uid)` | 清余额 401 求证退避窗口，否则重登后第一次余额探测被旧窗口跳过（最长 30min），表现为「重登没生效」 |
| `Upstream.UserResource(next)` → `ReenableIfCredits` | 余额刷新（幂等）。成功则按既有口径解「余额耗尽硬冷却」，**不动**熔断/限流态；失败只回传 `balance_ok:false`，不回滚、不禁用 |
| `dropLoginSession(state)` | 会话作废，同一 state 后续 poll 得 410，不会重复落盘 |

`Flush()` 失败**不改变成功语义**：凭证文件已由 `safefile`（tmp fsync → rename）落盘，`ReplaceCredentials` 只记持久化失败并打 WARN、仍返回 `nil`（把一次成功的凭证替换报成失败会让运维重复操作）；代价是重启后可能仍显示「需重登」，再点一次即可（见 §6 #14）。

### 4.5 失败矩阵

| 失败点 | 磁盘 `auths/*.json` | 内存 `*auth.Auth` | 池状态 | 前端表现 |
|---|---|---|---|---|
| relogin/start（上游 state 失败） | 不变 | 不变 | 不变 | 502 + 重试 |
| relogin/start（并发占位冲突） | 不变 | 不变 | 不变 | 409 `relogin_in_progress` |
| poll：会话已取消/过期 | 不写 | 不变 | 不变 | 410 + 重新发起 |
| poll：目标账号已被移除 | 不写 | 不变 | 不变 | 409 `relogin_target_missing`（不新建账号） |
| poll：uid 不一致 | 不写 | 不变 | 不变 | 409 `relogin_uid_mismatch`（附 target/granted uid） |
| poll：realm 不一致 | 不写 | 不变 | 不变 | 409 `relogin_realm_mismatch` |
| poll 期间取消（processing） | 不变 | 不变 | 不变 | 409 `login_processing`（写盘已完成则返回成功，前端按成功处理） |
| `AdoptCredentials` 写盘失败 | 不变（原子写失败不留半文件） | 不变（`credEpoch` 不增） | 不变 | 500 + 「已保留原有凭证与账号状态」 |
| `AdoptCredentials` uid 不一致（auth 层兜底） | 不变 | 不变 | 不变 | 500，凭据未被改动 |
| 替换成功但余额校验失败 | 已写新凭证 | 已换 | 已窄口径恢复 + `ReenableIfCredits` | `done:true` 且 `balance_ok:false` / `balance_error` 非空（见 §6） |
| 替换成功但未拿到 RT | 已写新凭证 | 已换 | 已恢复 | `done:true` + WARN 日志；AT 过期后需再次重登 |

---

## 5. 恢复流程：AuthFault 窄口径清除

### 5.1 标记写入点

`disableLocked` 会先清空 `authFault`（保证非认证原因的禁用不残留旧标记），因此**认证失效必须走带 fault 的入口**：

| 触发路径 | 调用 | `auth_fault` | 状态 |
|---|---|---|---|
| 网关 401 `invalid_token` 连续达阈 | `NoteSessionDeadFault(uid, AuthFaultGateway401, "401 invalid token (re-login required)")`（兼容包装：`NoteSessionDeadWith` 按 reason 自动判类） | `gateway_401` | ✅ |
| 12153（chat 路径，一次即禁） | `DisableAuth(uid, "12153 session dead", AuthFaultSessionDead)` | `session_dead` | ✅ |
| 请求前 refresh 判死（chat 路径） | `DisableAuth(uid, "refresh session dead", AuthFaultSessionDead)` | `session_dead` | ✅ |
| 余额探针 401 + refresh 判死达阈 | `NoteSessionDeadFault(uid, AuthFaultSessionDead, "12153 session dead")` | `session_dead` | ✅ |
| 保活 refresh 判死（连续阈值） | `NoteSessionDead(uid)` → `NoteSessionDeadWith` → `NoteSessionDeadFault(uid, AuthFaultSessionDead, "12153 session dead")` | `session_dead` | ✅ |
| 管理员手动禁用 / 11140 风控 / 非认证禁用 | `Disable(...)` | 清空（不产生重登入口） | ✅ |
| 人工解冻 | `Revive` / `ReviveDisabled` → 清标记 | 清空 | ✅ |

### 5.2 `ClearAuthFault(uid)`：清什么 / 不清什么

**清（仅认证故障域）**：

| 字段 | 处理 |
|---|---|
| `authFault` / `authFaultAt` | 归零 |
| `sessionDeadFails` | 归零（账号已被证明活着，旧的死亡进度作废） |
| `disabled` / `reason` | **仅当**「本次禁用由认证故障造成」（`authFault` 非空且 `disabled`）才解禁并清 reason |
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
| `FilePath` / `DeviceToken` / `enterpriseId` / `nickname` | 身份与设备信息（`AdoptCredentials` 有保留规则） |

### 5.3 三条恢复入口对比

| 入口 | 清 `disabled` | 清 `authFault` | 清 `paused` | 清冷却/熔断/降权 | 清余额快照 | 适用 |
|---|---|---|---|---|---|---|
| `ClearAuthFault`（重登成功自动调用） | 仅认证禁用 | ✅ | ❌ | ❌ | ❌ | 401/12153 判死后原位重登 |
| `ReviveDisabled`（只解禁） | ✅ | ✅ | ❌ | ❌ | ❌ | 仅想解掉 disabled、保留惩罚态 |
| `Revive`（面板「解冻」） | ✅ | ✅ | ✅ | ✅ | ❌ | 人工判定该号完全可用，一键全清 |

### 5.4 端到端时序（relogin）

1. 前端点「重新登录」→ `POST /panel/api/accounts/{uid}/relogin/start`（body 被忽略）。
2. `reloginStart`：`validUID` → 账号存在 → 非静态 Key → **标识口径** `auth.ResolveRealm(a.RealmStored(), a.DomainValue())` 定 realm（与 `global.enabled` 无关）→ `reserveRelogin(uid)`（挡双击）→ 上游 `auth/state` → 回收过期会话 + 写 `loginSession{mode:"relogin", targetUID, targetNickname, realm, created}` → 释放占位 → 200 返回 `url`/`state`/`expires_in:900`。
3. 浏览器完成授权 → 前端每 3s `GET /panel/api/login/poll?state=...`（关闭弹窗只停止轮询；`POST /panel/api/login/cancel` 是显式释放入口，前端当前未调用，靠 15min TTL 与 cancel 兜底）。
4. `loginPoll`：TTL 检查（过期 → 410）→ `processing` 闸门 → `auth/token` 成功 → `login/account` 取 uid/nickname → `mode == relogin` 分叉到 `finishRelogin`（**不落盘、不 pool.Add、不跑新账号任务**）。
5. `finishRelogin` 按 §3.4 顺序校验：会话有效 → 目标账号仍存在 → uid 一致 → uid 合法 → **标识 realm**（`ResolveRealm(RealmStored(), DomainValue())`）未变 → `domain` 归一化一致 → token 有效期换算；任何一步失败立即返回，旧凭证与账号状态原样保留。
6. `Pool.ReplaceCredentials(target, next)`：`AdoptCredentials`（先写盘 → 再换内存 → `credEpoch++`）→ `ClearAuthFault`（窄口径）→ `Flush()`。
7. `Scheduler.ClearAuthHeal(target)` 清余额求证退避；`Upstream.UserResource(next)` 刷新余额 → 成功则 `ReenableIfCredits`（只解余额硬冷却）；失败只回传 `balance_ok:false`，**不回滚、不禁用**。
8. `dropLoginSession(state)`；200 `{"done":true,"mode":"relogin","relogin":true,"auth_ok":true,...,"balance_ok":...,"balance_error":...}`；前端 `loadOverview(true)` + 提示「已重新授权，账号恢复」（不得提示「已添加」）。
9. `session_dead_fails` 若在阈值内尚未禁用（中间态），重登同样清计数并保持账号在池中；已因认证故障禁用的账号由 `ClearAuthFault` 解禁，但 paused/冷却/熔断/降权/积分一字不动。

---

## 6. 限制与已知风险

| # | 限制/风险 | 表现 | 处置 |
|---|---|---|---|
| 1 | **Billing 401 ≠ Chat 不可用** | 降级 token 形态：billing 恒 401、chat 仍可用；反过来，授权成功也可能 `balance_ok:false` | 不要只看 `done:true`：同时看 `balance_ok`/`balance_error`；`balance_error` 非空说明凭据已换但额度端点仍拒，属上游侧问题 |
| 2 | **授权成功 ≠ 上游全部服务可用** | trial 未激活（14017）、企业口径端点、模型级限制都独立于 token | 重登后至少在面板跑一次「额度」+ 一次真实 chat，确认两侧都通 |
| 3 | **静态 API Key 不支持重登** | `api_key=true` 无 OAuth 流程，后端 400 `static_api_key_account` | 在面板「导入 API Key」重新添加（或先移除再加），没有原位路径 |
| 4 | **凭证文件的 realm/domain 在授权期间被外部改写** | 目标账号 `auths/*.json` 里的 `realm`/`domain` 被另一个进程或手工编辑改动 → **标识** realm 与 start 时锁定的 `sess.realm` 不符 → 409 `relogin_realm_mismatch` | 属保护性拒绝（不会写坏凭证）：确认无人改动文件后重试。注意 `global.enabled` 翻转**不再**触发该错误（身份判定已与逃生门解耦） |
| 5 | **state 只存进程内存** | 面板重启 → 410，前端停止轮询；旧 state 最长滞留 15min | 关闭弹窗重发一次，不要反复刷新页面 |
| 6 | **并发重登** | 同一 uid 两个浏览器/两个标签 → 409 `relogin_in_progress` | 等已有的浏览器授权完成，或过期后重试 |
| 7 | **不解除上游封禁** | 11140 风控、封号、配额耗尽重登无效（重登后仍判死） | 查「错误汇总」中的 11140/14017；连续两次重登都立刻再 401 → 停止重试，按账号级问题处理 |
| 8 | **反复重登有成本** | 每次授权都轮换 AT/RT；高频重登可能触发上游设备风控 | 不做脚本循环重试；`DeviceToken` 会在替换时保留以降低风控 |
| 9 | **不修复「为什么判死」** | 重登只解决凭据层；若根因是上游持续注销会话，重登后仍会再次判死 | 结合 §2 分类定位根因（网关 401 抖动 vs 12153 真死 vs 降级 token） |
| 10 | **授权期间账号被移除** | 完成时目标 uid 已不在池里 → 409 `relogin_target_missing` | 重新添加账号；本流程**绝不**顺手 `pool.Add` 新建（否则「重登」变「新增」，历史统计/优先级全脱节） |
| 11 | **外部进程/并发重登改写凭证文件** | 单实例内的并发重登已被 `reloginBusy` + 409 挡住；但 `logins`/`reloginBusy` 都是**进程内**状态，多实例共享同一 `auths/` 目录时可能各持一个同一 uid 的会话，后完成者覆盖先完成者；手工编辑文件同理 | 同一 `auths/` 只跑一个面板实例；此类冲突表现为 409 保护性拒绝或后写覆盖，不会产生半截凭证 |
| 12 | **处理中不可取消** | 正在写凭据的会话 cancel 返回 409 `login_processing` | 等待该次 poll 返回；此时前端应按「成功/失败」处理，而不是显示「已取消」 |
| 13 | **可能拿不到 refreshToken** | 上游偶发不返 RT：不阻断重登，但 AT 过期后必须再重登一次 | 关注 WARN 日志；此类账号重登后不要指望自动续期 |
| 14 | **`state.json` 写盘失败留下一致性缺口** | `ReplaceCredentials` 末尾 `ClearAuthFault` + `Flush()`：若 state.json 写盘失败（磁盘满/只读），凭证文件本身已原子落盘生效、接口仍返回成功，但 state.json 可能仍留着旧的 `disabled + auth_fault` | 不是假成功（凭证文件已 fsync）：重启后面板会继续显示「需重登」，再点一次重登即可恢复；同时排查磁盘/权限 |
| 15 | **达阈判定会覆盖管理员写入的禁用原因** | `NoteSessionDeadFault` 达阈时覆盖 `reason` 并写入 `auth_fault`（属既有 `NoteSessionDead` 行为、非本轮引入，但 `auth_fault` 让它在面板上更显眼）；若同时开了 `schedule.include_disabled_in_tasks`，对已手工禁用的号做余额求证而回 12153，会把它改标成「需重登」 | 视为「账号确实已认证失效」的正常升级；不想被改标可关闭 `schedule.include_disabled_in_tasks`，或解冻后重新禁用 |

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
go test ./internal/auth      -run 'AdoptCredentials|InflightRefresh|RefreshSnapshot|SaveAtomicFormat' -v
go test ./internal/pool      -run 'DisableAuth|ClearAuthFault|ReplaceCredentials|AuthFaultState|AuthFaultNormalize' -v
go test ./internal/panel     -run 'Relogin' -v
go test ./internal/scheduler -run 'Balance401|ClearAuthHeal' -v
go test ./internal/server    -run 'PanelAPIKey401|UpstreamAccount401|TwoAuthDomains' -v
```

`-race` 必跑：`credEpoch` 的验证本质是并发时序（在途 refresh vs 整体替换），单线程测试证明不了。

**实测结论**：

```text
go test ./internal/auth/ ./internal/pool/ ./internal/panel/ ./internal/scheduler/ ./internal/server/ -count=1
→ 仅 internal/server TestUsageCreditTotalRequiresValidExplicitCreditAndTokens/out_of_range_total 失败，
  该失败在 f8f6db6 干净 worktree 上同样复现 = 基线既有问题，与本功能无关
go test -race ./internal/auth/ ./internal/pool/ ./internal/panel/ ./internal/scheduler/ -count=1 → 全 ok，零 data race
go vet ./... → 干净
```

> 已知 flake（与本功能无关）：四包并行 `-race` 时 `internal/scheduler` 的 `TestWaitSlotFiresAtWallclock` 偶发时序抖动失败；单独跑该用例与整包复跑均通过。

### 7.2 测试文件与覆盖点

核对时间 2026-10-23 14:00：6 个测试文件均已落地并跑绿（`internal/server` 的基线失败除外，见 §7.1「实测结论」）。

| 文件 | 覆盖点 | 状态 |
|---|---|---|
| `internal/auth/relogin_cred_test.go` | `AdoptCredentials` 事务：字段整体替换、`FilePath` 不重拼、`DeviceToken`/`realm` 保留、`credEpoch` +1、UID 不一致拒绝、空 AT 拒绝、两种写盘失败注入后字段与磁盘字节零改动；`SaveAtomic` 嵌套形格式回归 | ✅ |
| `internal/auth/relogin_epoch_test.go` | **P0 在途 refresh vs 重登**：阻塞式 Transport 让 refresh 悬停在锁外，期间 `AdoptCredentials` 换新并落盘，放行后断言 `RefreshToken()` 返回 `nil`、内存与磁盘均为新 token、`epoch==1`；旧世界 12153 失败结果同样丢弃、不误杀；对照组（无重登时必须正常写回）；`RefreshSnapshot` 三元组一致 | ✅ |
| `internal/pool/authfault_test.go` | `DisableAuth`/`NeedsRelogin` 与 JSON 字面值；非认证禁用清 fault 且不被 `ClearAuthFault` 解除；`ClearAuthFault` 窄口径逐字段；`ReplaceCredentials` 指针身份/统计/不新增账号/`ErrAccountNotFound`/失败零改动；`state.json` round-trip 与旧文件兼容；`NormalizeAuthFault` | ✅ |
| `internal/panel/relogin_test.go` | start 契约（body 忽略 / realm 服务端推导 / 400-404-409 / `expires_in`）；全流程（disabled+needs_relogin → poll 成功 → 单账号/指针不变/统计保留/磁盘新 token/同 state 再 poll 410）；UID 与 realm 不一致 409 + 零改动；TTL 410；cancel 410/409；processing 闸门；并发 start 恰 1 成功 1 冲突；写盘失败 500 + 保留旧态；余额 401 仍 `auth_ok` 但 `balance_ok=false`；目标被移除 409 不新建；响应体不含 AT/RT | ✅ |
| `internal/scheduler/relogin_fault_test.go` | Billing 401 + refresh 成功不禁用、无 fault、计数归零；12153 达阈 → disabled + `auth_fault=session_dead` + `needs_relogin`；429/402/5xx/400 不 refresh 且无 fault；`ClearAuthHeal` 退避窗口与幂等 | ✅ |
| `internal/server/relogin_isolation_test.go` | 面板错误/缺失 Bearer 401 且池状态 DeepEqual 全等、上游零调用；上游 12153 禁用后同 key 面板仍 200 且 overview `needs_relogin=true`；两域 401 契约不同且不泄露凭据 | ✅ |

> 前端**未新增**测试文件：由既有 `internal/panel/frontend_test.go`、`login_poll_test.go`、`paused_test.go` 的 `node`+`vm` 切块测试覆盖重登入口判定、按钮渲染与轮询分支。

### 7.3 Mock 上游做法

| 要求 | 做法 |
|---|---|
| 禁真实网络 | 全部用 `httptest.NewServer` 起假上游，`loginEndpoints`/`upstream` 端点指向本地；禁止访问 `copilot.tencent.com` / `workbuddy.ai` |
| 伪设备授权 | `/v2/plugin/auth/state` 返回固定 `state`+`authUrl`；`/v2/plugin/auth/token?state=` 按阶段返回 `code!=0`（pending）或 `{accessToken,refreshToken,expiresIn}`；`/v2/plugin/login/account?state=` 返回 `uid`/`nickname`/`enterpriseId` |
| 伪业务 | `/v2/billing/*`、chat 端点按用例返回 `{code:12153}`、网关 401 HTML、429、5xx 等形态 |
| 伪造 token | 只用形如 `fake-at-*` / `fake-rt-*` 的字符串；**禁止**把真实 token 写进 fixture/日志/文档 |
| 身份不匹配 | 让 fake `login/account` 返回另一个 uid 或另一 realm，断言 409 且磁盘文件未被改写（比对 `SaveAtomic` 前后文件内容/`credEpoch`） |
| 并发用例 | `-race` 下同时跑 `ReplaceCredentials` 与 `RefreshToken`，断言最终磁盘是新的授权凭证 |

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

# 3) 复核状态：needs_relogin 应为 false，auth_fault 为空，session_dead_fails 归零
curl -sS "$PANEL/panel/api/overview" -H "Authorization: Bearer $KEY" |
  python3 -c 'import json,sys; a=[x for x in json.load(sys.stdin)["accounts"] if x["uid"]=="'"$ACCT_UID"'"]; print(json.dumps(a, ensure_ascii=False, indent=2))'

# 4) 放弃等待时显式取消（否则该 uid 在 15min TTL 内禁止再次发起）
curl -sS -X POST "$PANEL/panel/api/login/cancel" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -d "{\"state\":\"<STATE>\"}"
```

> 排错时看 `auth_fault` / `auth_fault_at` / `session_dead_fails` / `disabled_reason`，不要打印 token。
