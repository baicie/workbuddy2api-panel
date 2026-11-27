#!/usr/bin/env bash
# Server maintenance for new-api + workbuddy2api panel + caddy
set -uo pipefail
BACKUP_DIR="$HOME/backups"
mkdir -p "$BACKUP_DIR"
STAMP=$(date +%F)
log() { echo "[$(date '+%F %T')] $*"; }
DB="$HOME/new-api/data/one-api.db"

# 1) new-api SQLite online backup (WAL-safe); needs root to read -wal/-shm
backup_db() {
  local src="$1" out="$2" label="$3"
  [ -f "$src" ] || return 0
  sudo -n python3 - "$src" "$out" <<'PY'
import sqlite3, sys
src = sqlite3.connect(sys.argv[1])
dst = sqlite3.connect(sys.argv[2])
src.backup(dst)
print("integrity:", dst.execute("PRAGMA integrity_check").fetchone()[0])
dst.close(); src.close()
PY
  sudo -n chown ubuntu:ubuntu "$out" 2>/dev/null || true
  log "$label -> $out ($(du -h "$out" 2>/dev/null | cut -f1))"
}
backup_db "$DB" "$BACKUP_DIR/new-api-$STAMP.db" "new-api db"
# Agent2API（Rust）：账号/网关 Key/插件状态都在这个库里
backup_db "$HOME/agent2api/data/agent2api.db" "$BACKUP_DIR/agent2api-$STAMP.db" "agent2api db"

# 2) panel account pools (auths owned by container uid -> use root)
for d in workbuddy2api workbuddy2api-global; do
  if [ -d "$HOME/$d" ]; then
    OUT="$BACKUP_DIR/$d-$STAMP.tgz"
    sudo -n tar czf "$OUT" -C "$HOME" "$d/auths" "$d/data" "$d/config.json" 2>/dev/null
    sudo -n chown ubuntu:ubuntu "$OUT" 2>/dev/null || true
    log "panel $d -> $OUT ($(du -h "$OUT" 2>/dev/null | cut -f1))"
  fi
done

# 3) caddy config, TLS certs, compose files, deepaicode2api state/.env, cliproxy config/auths,
#    agent2api 的 compose/.env/account.key（DB 单独走上面的 backup_db，runtimes/debug 不入包）
#    .env 是加密状态文件的唯一解钥途径（主密钥 + 管理口令），必须同包备份
#    cliproxy/data 是面板静态文件（3.9MB，可随时重新下载），不入每日备份；
#    cliproxy/config.yaml 含管理密钥，整包仍按 chmod 600 落盘（见下）
OUT="$BACKUP_DIR/configs-$STAMP.tgz"
sudo -n tar czf "$OUT" -C "$HOME" caddy/Caddyfile caddy/docker-compose.yml caddy/certs \
  new-api/docker-compose.deploy.yml \
  agent2api/docker-compose.deploy.yml agent2api/.env agent2api/data/account.key \
  deepaicode2api/data deepaicode2api/.env deepaicode2api/docker-compose.deploy.yml \
  cliproxy/config.yaml cliproxy/auths cliproxy/docker-compose.deploy.yml cliproxy/.env 2>/dev/null
sudo -n chown ubuntu:ubuntu "$OUT" 2>/dev/null || true
sudo -n chmod 600 "$OUT" 2>/dev/null || true
log "configs -> $OUT ($(du -h "$OUT" 2>/dev/null | cut -f1) mode=$(stat -c %a "$OUT" 2>/dev/null))"

# 4) keep 7 days
find "$BACKUP_DIR" -maxdepth 1 -type f -mtime +7 -print -delete | sed 's/^/removed /'

# 5) compact SQLite after the backup (best effort)
if [ -f "$DB" ]; then
  sudo -n python3 - "$DB" <<'PY'
import sqlite3, sys, time
try:
    c = sqlite3.connect(sys.argv[1], timeout=60, isolation_level=None)
    # logs.other 存的是每次请求的完整路由策略 JSON（平均 ~930B/行），是库里最大的一块。
    # 保留最近 3 天的完整详情，更早的只清这一列 —— 模型/token/额度等记账字段不动。
    cut = int(time.time()) - 3 * 86400
    trimmed = 0
    while True:
        cur = c.execute("update logs set other='' where id in "
                        "(select id from logs where created_at < ? and length(other)>0 limit 5000)", (cut,))
        if cur.rowcount < 5000:
            trimmed += cur.rowcount
            break
        trimmed += cur.rowcount
    if trimmed:
        print("db: logs.other trimmed %d rows" % trimmed)
    c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    c.execute("VACUUM")
    c.close()
    print("db: vacuum ok ->", sys.argv[1])
except Exception as exc:
    print("db: vacuum skipped (%s)" % exc)
PY
fi

# 6) optional docker prune (weekly caller passes "prune")
if [ "${1:-}" = "prune" ]; then
  sudo -n docker image prune -a --filter "until=168h" -f >/dev/null 2>&1 && log "docker images pruned"
  sudo -n docker builder prune -a --filter "until=168h" -f >/dev/null 2>&1 && log "docker build cache pruned"
fi
log "done"
