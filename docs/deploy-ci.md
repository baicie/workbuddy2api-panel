# CI 发布与自动部署（Build and Push）

打 `v*` 标签时自动：构建 `linux/amd64` 镜像 → 推送 GHCR → SSH 滚动更新自有服务器上的容器。
工作流文件：`.github/workflows/build-and-push.yml`。

## 1. 触发条件与前提

- 触发：`push` 标签 `v*`（如 `v2026.10.24.1614`）；另有 `workflow_dispatch` 用于补发。
- **标签必须打在 `dev`（或任何包含本工作流文件的提交）上**：本仓 `main` 是上游镜像，不含
  本工作流，打在 `main` 上的标签不会触发它。
- 与 `docker-ghcr.yml` 的关系：两者都监听 `v*` 标签，因此一次打标签会构建两次
  （本工作流 amd64 + 本工作流部署；`docker-ghcr.yml` 多架构并推 semver 标签）。
  不想重复可去掉 `docker-ghcr.yml` 的 `tags` 触发。

## 2. 需要配置的仓库 Secrets / Variables

Settings → Secrets and variables → Actions：

| 类型 | 名称 | 必填 | 说明 |
|---|---|---|---|
| Secret | `DEPLOY_SSH_KEY` | 二选一（推荐） | 部署用 SSH 私钥（对应公钥加进服务器 `~/.ssh/authorized_keys`） |
| Secret | `DEPLOY_SSH_PASSWORD` | 二选一 | 服务器 SSH 密码（仅在无法改用密钥时使用；见第 5 节安全提示） |
| Variable | `DEPLOY_HOST` | 否 | 默认 `82.156.234.84`（来自 `docker_targets_*.csv`） |
| Variable | `DEPLOY_USER` | 否 | 默认 `ubuntu` |
| Variable | `DEPLOY_PORT` | 否 | 默认 `22` |
| Variable | `DEPLOY_DIR` | 否 | 默认 `$HOME/workbuddy2api`；支持 `~` / `$HOME` 写法 |
| Variable | `DEPLOY_CONTAINER` | 否 | **默认 `workbuddy2api`**；若服务器上容器名不同（CSV 里记录的是 `grokcli-2api`）请务必改成实际名字 |
| Variable | `DEPLOY_HEALTH_URL` | 否 | 部署后健康检查地址，需返回 200，例如 `http://127.0.0.1:7863/panel/`。**不要填 `/healthz`**：它在账号池为空时按设计返回 503 |

> `GITHUB_TOKEN` 不能用于服务器侧拉镜像；GHCR 包当前是 public，服务器 `docker pull` 无需登录。
> 若将来把包改成 private，需要在服务器上 `docker login ghcr.io` 或改用带 `read:packages` 的 PAT。

## 3. 服务器一次性准备

工作流会自动上传 `deploy/docker-compose.deploy.yml` 到 `$DEPLOY_DIR`，并执行
`docker compose -f docker-compose.deploy.yml up -d --pull always`。首次部署前需要：

```bash
# 1) 目录与配置（config.json 必须先存在，否则 Docker 会把挂载点建成目录导致容器起不来）
mkdir -p ~/workbuddy2api
cp config.example.json ~/workbuddy2api/config.json     # 再按需填 api_key 等
mkdir -p ~/workbuddy2api/auths ~/workbuddy2api/data

# 2) 挂载目录属主与容器用户（镜像内以 uid 10001 运行）
sudo chown -R 10001:10001 ~/workbuddy2api/auths ~/workbuddy2api/data ~/workbuddy2api/config.json
# 或者改用你自己的 uid：在 $DEPLOY_DIR/.env 里写 PUID=$(id -u) / PGID=$(id -g)

# 3) 如果之前用仓库根目录的 docker-compose.yml（build: .）起过容器，
#    先停掉那一个，避免与本工作流创建的容器（同名 workbuddy2api）冲突：
cd <旧目录> && docker compose down
```

## 4. 手动补发

```bash
git tag v2026.10.24.1614 && git push origin v2026.10.24.1614
```

`workflow_dispatch` 只有在默认分支（`main`）也存在本文件时才会出现在 Actions 列表里。

## 5. 安全提示

- 不要把 `docker_targets_*.csv` 提交进仓库：它含**明文 SSH 密码**。建议轮换该密码并改用 SSH 密钥。
- 工作流只在 runner 的临时 HOME 里写 key/password 文件（600），结束步骤里删除。
- 远端脚本通过 stdin + 位置参数传递，不把凭据/参数拼进命令串。
