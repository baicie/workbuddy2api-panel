# 上游同步（Upstream Sync）

> 目的：在保留本 fork 自有功能（401 账号原位重登等）的前提下，安全吸收上游 `misakano7545/workbuddy2api-panel` 的更新。
> 本功能相关文档：[account-relogin.md](account-relogin.md)。发版约定见仓库根 `AGENTS.md`（§5 摘录）。
>
> 入库提示：仓库 `.gitignore` 忽略 `docs/` 与 `*.md`（仅 `README.md`/`AGENTS.md` 例外），因此 `docs/` 下的文档默认不进版本库；确需提交时用 `git add -f docs/account-relogin.md docs/upstream-sync.md`（`-f` 只覆盖 ignore，不改规则）。

---

## 1. Remote 拓扑

`git remote -v`（本仓库实测输出）：

```
origin    https://github.com/baicie/workbuddy2api-panel.git (fetch)
origin    https://github.com/baicie/workbuddy2api-panel.git (push)
upstream  https://github.com/misakano7545/workbuddy2api-panel.git (fetch)
upstream  https://github.com/misakano7545/workbuddy2api-panel.git (push)
```

| remote | 角色 | 用途 |
|---|---|---|
| `origin` | 本 fork（`baicie/...`） | 推送自己的分支与时间标签，触发 Release 工作流 |
| `upstream` | 上游原始仓库（`misakano7545/...`） | 只读同步源，**永远不推** |

| 事实 | 值 | 影响 |
|---|---|---|
| 当前分支 | `feat/account-relogin`（基线 `main` = `f8f6db6`，与 `upstream/main` 同源） | 同步在临时分支上做，不直接动 `main` |
| 本地克隆形态 | **浅克隆**（`git rev-parse --is-shallow-repository` → `true`，历史只有一个提交） | 日常 merge/diff 够用；需要考古、revert、跨大版本对比时先 `git fetch --unshallow` |
| 上游多余分支 | `upstream/autobot/*`、`upstream/ci/*`、`upstream/feat/*`、`upstream/fix/*` | 只同步 `upstream/main`，其余不动 |
| module 路径 | `github.com/misakano7545/workbuddy2api-panel` | 不可改，改了会让 CI 与上游 PR 路径全失效 |

---

## 2. 安全同步命令序列（可直接复制）

原则：**先 fetch 只读观察 → 预演冲突 → 临时分支合并 → 跑测试 → 快进合入 `main` → 才推送**。任何一步异常都可以干净回退。

### 步骤 0：前置检查（工作区必须干净）

```bash
git switch main
git status --short          # 必须无输出；有 WIP 先执行下一行
git stash push -u -m "wip: before upstream sync"   # 有未提交改动时才需要
```

### 步骤 1：拉取上游引用（只更新 remote-tracking，不动工作区）

```bash
git fetch upstream --prune
git fetch origin --prune
```

### 步骤 2：看清差多少、差在哪

```bash
# 左 = 本地领先 upstream 的提交数；右 = upstream 领先本地的提交数
git rev-list --left-right --count main...upstream/main

# 上游新增提交清单
git log --oneline --no-decorate main..upstream/main

# 上游改了哪些文件（先看规模，再决定要不要细读）
git diff --stat main...upstream/main
git diff --name-only main...upstream/main
```

### 步骤 3：冲突预演（不改工作区、不产生 merge commit）

```bash
# 退出码 0 = 可干净合并；1 = 有冲突（会打印冲突文件路径）
git merge-tree --write-tree main upstream/main >/dev/null; echo "冲突退出码=$?"

# 只列冲突文件
git merge-tree --write-tree main upstream/main | grep -E 'CONFLICT'
```

### 步骤 4：在临时分支上合并

```bash
BR="sync/upstream-$(date +%Y%m%d)"
git switch -c "$BR" main
git merge --no-ff upstream/main        # 保留 upstream 的合并点，便于日后再同步
```

有冲突 → 按 §3 逐文件处理 → `git add` 后 `git merge --continue`（或 `git commit` 完成合并）。

### 步骤 5：回归测试（合入 main 之前必须全绿）

```bash
git status --short          # 不应再有 UU/AA/DU 等未解决状态
git diff --check            # 空白错误 / 冲突标记残留检查
go build ./...
go vet ./...
go test ./...
```

### 步骤 6：快进合入 `main` 并推送

```bash
git switch main
git merge --ff-only "$BR"   # 只接受快进：失败说明 main 被别的提交动过，先查清再合
git branch -d "$BR"
git push origin main        # 不加 --force
```

### 步骤 7：出错回退（按阶段选一条）

```bash
# 合并到一半想放弃（工作区可恢复）
git merge --abort

# 临时分支还没合进 main：直接丢弃
git switch main && git branch -D "$BR"

# 已经合进 main 但还没 push：撤回到合并前
git reset --hard ORIG_HEAD

# 之前 stash 了 WIP
git stash pop
```

### 变体：把本功能分支 rebase 到上游（仅限**未推送**分支）

```bash
git switch feat/account-relogin
git fetch upstream --prune
git rebase upstream/main
go test ./...
# 冲突时：解决 → git add <file> → git rebase --continue
# 放弃：git rebase --abort
```

> 已推送到 `origin` 的分支**不要** rebase：rebase 后必须 force push，而 force push 是禁止事项（§4）。这类分支一律用 merge。

### 变体：浅克隆缺历史

```bash
git fetch --unshallow upstream     # 一次性补全历史（之后 diff/revert/cherry-pick 才完整）
```

典型症状：`git log --follow`/`git blame` 断历史，或上游强推过历史导致合并报「refusing to merge unrelated histories」。

---

## 3. 冲突处理原则

### 3.1 四条原则

1. **功能主体放新文件**：`internal/pool/authfault.go`、`internal/panel/relogin.go`、各测试文件天然不冲突；新功能尽量别往既有文件的函数中段插代码。
2. **既有文件只加「短挂点」**：路由一行、结构体一个字段、函数末尾一个分支。越短、越靠边，冲突概率越低、解起来越快。
3. **冲突时「先上游，再重放本功能」**：先把文件取成上游版本，再把自己的挂点按新锚点重新插入。**禁止** `git checkout --ours/--theirs` 整文件取舍、禁止 `-X ours`/`-X theirs` 批量策略 —— 那会静默删掉上游（或本 fork）的整块功能。
4. **结构改动按「签名/顺序」重建**：如 `applyRefresh` 新增 `epochBefore` 参数，先取上游实现，再补参数与全部调用点，最后跑测试确认没有漏改的调用方。

### 3.2 高发冲突文件与逐个处理建议

| 文件 | 冲突形态 | 处理建议 |
|---|---|---|
| `internal/panel/relogin.go` | 新增文件，正常不冲突 | 上游若也改登录流程，本文件保持独立；公共辅助（`loginToken`/`loginAccount`/会话回收）已在本文件，勿与上游同名符号重复定义 |
| `internal/panel/login.go` | `loginPoll` 函数体中段（realm 分支、签到、余额、返回字段）被上游改动；本 fork 在此处多了 TTL 检查与 `mode` 分叉 | 取上游整函数，再把「poll 侧 TTL 检查」「`mode == LoginModeRelogin → finishRelogin` 分叉」重放到拿到 token+uid 之后的**同一点**；`mode=add` 路径逐字段与上游一致 |
| `internal/panel/panel.go` | 路由注册行、`LoginMode`/`loginSession` 定义、`reloginBusy` 字段、`accountRevive` 邻域 | `loginSession` 按字段追加合并（两边都保留）；路由每行独立插入；`reloginBusy` 初始化与字段成对出现，漏一处会 nil map panic |
| `internal/panel/app.js` | 函数级大块（`renderAccounts`、事件委托、`openAdd`/`pollLogin`） | 取上游函数整体，再把本功能片段按上游锚点重放（`reloginOffer`、`data-a="relogin"` 按钮、`applyAddMode`）；不要两边整块并存。重放后跑前端测试 |
| `internal/panel/index.html` | `#addVeil` 内部 DOM、按钮/标题文案 | 取上游版本后**在其内部尾部追加**自有节点（`#addRelogin` 等），保证 id 唯一；不要整块替换弹窗结构 |
| `internal/pool/state.go` | `Disable`/`Revive*`/`NoteSessionDeadWith`/`statusOf` 等函数相邻 | 逐个函数重放（一次一个函数）；`NoteSessionDeadWith` 的「达阈清零再禁用」语义不可破坏；`statusOf` 只加字段赋值 |
| `internal/pool/entry.go` | `entry` 与 `stateAccount` 结构体字段、`statusOf` 数据源 | 字段按追加合并（两侧都保留），检查 JSON tag 不重名；`entry` 与 `stateAccount` **必须同步加字段**，否则落盘/恢复丢标记 |
| `internal/pool/persist.go` | `applyAccountsLocked`（恢复）与 `stateOverviewLocked`（落盘）映射 | 最容易漏：加了字段没加映射 = 重启后标记消失。上游若重构快照结构，逐字段对齐后跑 authfault 持久化测试 |
| `internal/pool/transition.go` | `disableLocked` 的清理序列 | 本功能在 `disableLocked` 内清 `authFault`（认证路径随后写回）。上游若在此加冷却/原因逻辑，保持「先清标记」在前，避免非认证禁用残留旧标记 |
| `internal/auth/auth.go` | `Auth` 字段、`SaveAtomic`/`writeLocked`、`credEpoch` | 先取上游写盘实现，再恢复「锁内先写盘成功 → 再换内存字段 → `credEpoch++`」的顺序；`credEpoch` 自增点只能有一个（`AdoptCredentials`） |
| `internal/upstream/client.go` | `refresh()` 编排 / `applyRefresh` 签名（本 fork 多了 `epochBefore`） | 最容易冲突。取上游 `refresh`/`applyRefresh` 后，重新插入：① `RefreshSnapshot()` 取三元组；② 3 处调用点补 `epochBefore`；③ 失败分支 `superseded \|\| changed` → `nil`；④ 成功分支锁内代次校验后丢弃。改完 `go build ./...` 会直接暴露漏改的调用点 |
| `internal/server/handler.go` | `applyErrorPolicy` 的 401/12153 分支、refresh 判死分支 | 取上游分支结构，再把 `Disable` 替换为 `DisableAuth`/`NoteSessionDeadFault`；注意上游可能新增错误类型，别把新分支删掉 |
| `internal/scheduler/balance_401.go` | 余额 401 求证逻辑 | 保留上游求证/退避结构，把达阈调用换成 `NoteSessionDeadFault(..., session_dead)`，并保留 `ClearAuthHeal` |

### 3.3 同步后回归清单

```bash
go build ./... && go vet ./... && go test ./...
go test -race ./internal/auth ./internal/pool ./internal/upstream

# 挂点还在（期望有输出）
grep -rn "auth_fault\|needs_relogin" internal/pool internal/panel | head
grep -n "relogin" internal/panel/app.js internal/panel/index.html | head
```

验收口径：`overview` 里 401/12153 账号仍显示 `auth_fault` + `needs_relogin`，重登成功后被清除且暂停/冷却/积分不受影响。

---

## 4. 禁止事项

| # | 禁止 | 原因 |
|---|---|---|
| 1 | `git push --force` / `--force-with-lease` 到 `origin/main` 或任何已推送分支 | 覆盖他人提交；fork 的 Release 工作流基于 `main`，强推会让历史与标签脱节 |
| 2 | 改 `go.mod` 的 module 路径（`github.com/misakano7545/workbuddy2api-panel`） | 包路径全失效，CI/构建脚本/上游 PR 对不上 |
| 3 | 重排/重格式化无关代码（`gofmt -w ./...`、整文件重排、改缩进风格） | 制造巨量无关 diff，下次同步冲突爆炸 |
| 4 | 把未测试的上游更新直接合进 `main` 或直接推送 | 上游有回归时整池不可用；必须 `go build/vet/test` 全绿 |
| 5 | 起新项目 / 另建仓库 / `git subtree` 拆库 | 失去与上游的同步能力，本仓库唯一价值就是「可同步的 fork」 |
| 6 | 整文件 `--ours`/`--theirs`、`-X ours`/`-X theirs` 策略合并 | 静默丢掉一整侧功能（上游修复或本 fork 的重登能力） |
| 7 | 删除/改写上游文件以「解决冲突」 | 下次同步会再冲突一次，且上游修复拿不到 |
| 8 | 把真实 `accessToken`/`refreshToken` 写进文档、日志、测试 fixture、提交信息 | 凭据泄露不可逆；测试只用 `fake-at-*`/`fake-rt-*` |
| 9 | 在 `feat/*` 分支上直接 `git merge upstream/main` 后立刻 push | 未测试就推送；应先在临时分支验证 |
| 10 | 打上游风格的 `v1.x` 标签或跟上游版本号 | 本 fork 用时间标签，见 §5；工作流只认 `v*`，撞上 1.x 会误发 Release |

---

## 5. 版本发布约定（引用 `AGENTS.md`）

摘自仓库根 `AGENTS.md`：**不跟上游 `1.x`**，发版是打时间标签并推送，工作流看到 `v*` 才创建 Release。

| 规则 | 值 |
|---|---|
| 标签形态 | `v2026.9.26.711` = `v` + 上海时间「年.月.日.时分」 |
| 日期/时间格式 | 月和日不补零（`9.26` 不是 `09.26`）；时不补零、分两位、不带秒 |
| 一致性 | 标签、Release、二进制用同一个号；二进制里不带 `v`（面板自己加） |
| 禁止 | 不打 `v1.x`、不手改 `appVersion`、不跟上游版本号 |
| 撞号 | 同一分钟再发才会撞号 |

`AGENTS.md` 原文命令块（macOS 与 Windows/git-bash 通用；含 tzdata 缺失时的 UTC 回退）：

```bash
VERSION=$(TZ=Asia/Shanghai date +%Y.%-m.%-d.%-H%M)
[ "$(TZ=UTC date +%H)" = "$(TZ=Asia/Shanghai date +%H)" ] && VERSION=$(date -u -d '+8 hours' +%Y.%-m.%-d.%-H%M)
git tag "v$VERSION"
git push origin "v$VERSION"
```

发布前自查（不创建标签）：

```bash
TZ=Asia/Shanghai date +%Y.%-m.%-d.%-H%M          # 形如 2026.10.23.1340，与 UTC 差 8 小时
git tag -l 'v*' | tail -5                        # 确认没有同分钟已发版本
git log --oneline -1                             # 确认要发的提交已在 main
```

> 本机（macOS，Apple date）实测：`%-m`/`%-d`/`%-H` 可用，`TZ=Asia/Shanghai` 与 `TZ=UTC` 的小时不同（13 vs 05），因此不会进入 GNU `date -d` 回退分支；在 Windows/git-bash（GNU date、无 tzdata）下第一行会静默回落 UTC，第二行的条件会命中并用 `date -u -d '+8 hours'` 纠正。

同步与发版的关系：**先完成上游同步并测试通过，再打时间标签**。`git fetch upstream` 会自动跟进上游 tag（`v2026.10.22.*` 等），那只是本地参考：不复用其版本号、不在 upstream 上打任何标签、不用上游 tag 触发自己的 Release —— 自己的工作流只认 `origin` 上自己的 `v*` 时间标签。
