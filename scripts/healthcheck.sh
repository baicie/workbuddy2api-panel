#!/usr/bin/env bash
# Health: 6 个域名经真实 DNS 走 8443 直连 + 容器 + 磁盘 + 证书 + CF token
set -uo pipefail
STATE="$HOME/backups/health.log"
WEBHOOK_FILE="$HOME/.alert_webhook"
ts() { date '+%F %T'; }
fail=0
note() { echo "[$(ts)] ALERT $*" | tee -a "$STATE"; fail=1; }
warn() { echo "[$(ts)] WARN $*" | tee -a "$STATE"; }

# CLIProxyAPI pause switch: when ~/cliproxy/PAUSED exists its checks are skipped
# (delete that file to resume monitoring).
PAUSED_MARK="$HOME/cliproxy/PAUSED"
pairs="gw.moonbyte.top:/v1/models newapi.moonbyte.top:/api/status panel.moonbyte.top:/healthz "
pairs="$pairs panel-global.moonbyte.top:/healthz opsweave.moonbyte.top:/ home.moonbyte.top:/"
[ -f "$PAUSED_MARK" ] || pairs="$pairs cpa.moonbyte.top:/healthz"
for pair in $pairs; do
  h=${pair%%:*}; path=${pair#*:}
  code=$(curl -sS -m 15 -o /dev/null -w '%{http_code}' "https://$h:8443$path" 2>/dev/null)
  case "$h:$path:$code" in
    gw.moonbyte.top:/v1/models:401|gw.moonbyte.top:/v1/models:200) ;;
    *:200) ;;
    *) note "$h:8443$path -> ${code:-conn-fail}" ;;
  esac
done

containers="new-api workbuddy2api workbuddy2api-global caddy cloudflared"
[ -f "$PAUSED_MARK" ] || containers="$containers cli-proxy-api mihomo"
for c in $containers; do
  st=$(sudo -n docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo missing)
  [ "$st" = "running" ] || note "container $c = $st"
done

use=$(df --output=pcent / 2>/dev/null | tail -1 | tr -dc '0-9')
[ -n "$use" ] && [ "$use" -ge 85 ] && note "disk root at ${use}%"

# 证书按文件到期日判定（不看 issuer：CA 会换，ZeroSSL/LE 都可能）
# 覆盖 caddy/certs 下全部证书：fullchain.pem + 所有 *-fullchain.pem，逐个报文件名
certs=()
[ -f "$HOME/caddy/certs/fullchain.pem" ] && certs+=("$HOME/caddy/certs/fullchain.pem")
for f in "$HOME/caddy/certs/"*-fullchain.pem; do
  [ -f "$f" ] && certs+=("$f")
done
if [ ${#certs[@]} -eq 0 ]; then
  note "cert file missing"
else
  for cert in "${certs[@]}"; do
    name=${cert##*/}
    # 阈值语义沿用原有单文件判断：fullchain.pem 30 天即 ALERT；新增证书 21 天 WARN，过期一律 ALERT
    days=21; sev=warn
    [ "$name" = "fullchain.pem" ] && { days=30; sev=note; }
    end=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2)
    if [ -z "$end" ]; then
      warn "cert $name unreadable (openssl -enddate failed)"
      continue
    fi
    left=$(( ( $(date -d "$end" +%s) - $(date +%s) ) / 86400 ))
    echo "[$(ts)] cert $name notAfter=$end left=${left}d" >> "$STATE"
    if [ "$left" -lt 0 ]; then
      note "cert $name EXPIRED (notAfter=$end, left=${left}d)"
    elif [ "$left" -lt "$days" ]; then
      "$sev" "cert $name expires in ${left}d (notAfter=$end)"
    fi
  done
fi

# Cloudflare token（acme.sh DNS-01 凭据）：只看有效性与有效期，值不落日志。
# 提前 3 个月暴露「token 已作废、到期续期必失败」，而不是等证书快过期才发现。
CF_CONF="$HOME/.acme.sh/account.conf"
if [ -f "$CF_CONF" ]; then
  cftok=$(sed -n 's/^SAVED_CF_Token=//p' "$CF_CONF" 2>/dev/null | head -1 | tr -d "'\"")
  if [ -n "$cftok" ]; then
    cfcfg=$(mktemp) && chmod 600 "$cfcfg"
    printf 'header = "Authorization: Bearer %s"\n' "$cftok" > "$cfcfg"
    cfjson=$(curl -s -m 8 -K "$cfcfg" https://api.cloudflare.com/client/v4/user/tokens/verify 2>/dev/null || true)
    rm -f "$cfcfg"; unset cftok
    cf_ok=$(printf '%s' "$cfjson" | grep -o '"success":[a-z]*' | head -1 | cut -d: -f2)
    cf_exp=$(printf '%s' "$cfjson" | grep -o '"expires_on":"[^"]*"' | head -1 | cut -d'"' -f4)
    case "$cf_ok" in
      true)
        if [ -n "$cf_exp" ]; then
          cfleft=$(( ( $(date -d "$cf_exp" +%s) - $(date +%s) ) / 86400 ))
          echo "[$(ts)] cf-token ok expires_on=$cf_exp left=${cfleft}d" >> "$STATE"
          [ "$cfleft" -lt 7 ] && note "cf token expires in ${cfleft}d (expires_on=$cf_exp)"
          [ "$cfleft" -ge 7 ] && [ "$cfleft" -lt 30 ] && warn "cf token expires in ${cfleft}d (expires_on=$cf_exp)"
        else
          echo "[$(ts)] cf-token ok (no expiry)" >> "$STATE"
        fi
        ;;
      false) note "cf token invalid (tokens/verify success=false)" ;;
      *) warn "cf token verify unreachable" ;;
    esac
  else
    warn "cf token not found in acme.sh account.conf"
  fi
fi

if [ "$fail" -eq 0 ]; then
  echo "[$(ts)] ok" >> "$STATE"
elif [ -f "$WEBHOOK_FILE" ]; then
  url=$(head -1 "$WEBHOOK_FILE")
  tail -5 "$STATE" | python3 -c "import json,sys;print(json.dumps({'text':'health ALERT\n'+sys.stdin.read()}))" \
    | curl -sS -m 10 -X POST -H 'Content-Type: application/json' --data-binary @- "$url" >/dev/null 2>&1 || true
fi
tail -2000 "$STATE" > "$STATE.tmp" 2>/dev/null && mv "$STATE.tmp" "$STATE"
exit 0
