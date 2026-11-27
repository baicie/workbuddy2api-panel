#!/usr/bin/env python3
"""按「真实可服务账号数」守护 new-api 渠道上的模型：0 就摘掉，恢复就加回。

为什么不能直接用面板 /status 的 model_locks.servable：那个口径不扣积分保底
（credit_floor），会出现「面板说还有 6 个号，实际一个都接不了」。这里按选号
规则自己算一遍：

    可服务 = 上游目录里还有这个模型
          && 有账号未禁用
          && 该模型没对它限流
          && (credits >= credit_floor  或  该模型倍率 <= credit_floor_max_rate)

「上游目录里还有」这一条是 20261127 补的：hy4free 被上游改名成 hy4flash-free，
映射没跟着改，请求稳定回 11102 model service info not found——积分和限流都正常，
旧逻辑完全不报警。

new-api 每 SYNC_FREQUENCY（默认 60s）从库重载渠道缓存，所以只改库即可生效。
摘除需要连续 CONFIRM 次判定为 0（滤抖），恢复立刻生效（积分回来就放开）。
"""
import json
import sqlite3
import subprocess
import time
from pathlib import Path

PANEL = "http://127.0.0.1:7863"
PANEL_CFG = Path("/home/ubuntu/workbuddy2api/config.json")
DB = "/home/ubuntu/new-api/data/one-api.db"
CHANNEL_ID = 1
CONFIRM = 2
STATE = Path("/home/ubuntu/backups/model-guard-state.json")
LOG = Path("/home/ubuntu/backups/model-guard.log")


def log(msg):
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a") as handle:
        handle.write("[%s] [guard] %s\n" % (time.strftime("%F %T"), msg))


def panel_get(path):
    key = json.loads(PANEL_CFG.read_text())["api_key"]
    raw = subprocess.run(
        ["curl", "-s", "-m", "20", PANEL + path, "-H", "Authorization: Bearer " + key],
        capture_output=True, text=True).stdout
    return json.loads(raw or "{}")


def parse_rate(text):
    """'x0.11' -> 0.11；无法解析返回 None（未知倍率按放行处理，与面板一致）。"""
    if not isinstance(text, str):
        return None
    try:
        return float(text.strip().lstrip("xX"))
    except ValueError:
        return None


def in_catalog(upstream, catalog):
    """目录里的 id 带域前缀（cn:/global:），映射值也带；裸名兜底查两域。"""
    if upstream in catalog:
        return True
    return any(realm + ":" + upstream in catalog for realm in ("cn", "global"))


def survey(models, upstream_of):
    status = panel_get("/status")
    floor = status.get("credit_floor")
    accounts = status.get("accounts") or []
    if floor is None or not accounts:
        return None
    # 目录与倍率同源（/v1/models），只拉一次：拉空多半是上游探测失败，
    # 不是「模型全没了」——照空处理会把渠道摘空。
    entries = panel_get("/v1/models").get("data") or []
    catalog = {item.get("id") for item in entries}
    if not catalog:
        return None
    rates = {item.get("id"): parse_rate(item.get("credits")) for item in entries}
    max_rate = status.get("credit_floor_max_rate")
    if max_rate is None:
        max_rate = 0.0
    counts, missing = {}, []
    for model in models:
        upstream = upstream_of.get(model, model)
        if not in_catalog(upstream, catalog):
            counts[model] = 0
            missing.append("%s->%s" % (model, upstream))
            continue
        rate = rates.get(upstream)
        total = 0
        for account in accounts:
            if account.get("disabled"):
                continue
            limited = [m.get("model") for m in account.get("rate_limited_models") or []]
            if upstream in limited or model in limited:
                continue
            if (account.get("credits") or 0) < floor and (rate is None or rate > max_rate):
                continue
            total += 1
        counts[model] = total
    return counts, missing


def main():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    rows = db.execute(
        """select model, enabled from abilities
           where channel_id = ? and "group" = 'default'""", (CHANNEL_ID,)).fetchall()
    if not rows:
        return
    mapping = json.loads((db.execute(
        "select model_mapping from channels where id = ?", (CHANNEL_ID,)).fetchone()[0]) or "{}")
    surveyed = survey([r["model"] for r in rows], mapping)
    if surveyed is None:
        log("面板不可达或目录为空，本次跳过")
        return
    counts, missing = surveyed
    streak = json.loads(STATE.read_text()) if STATE.exists() else {}
    changes = []
    for row in rows:
        model = row["model"]
        usable = counts.get(model, 0)
        streak[model] = streak.get(model, 0) + 1 if usable == 0 else 0
        want = 0 if streak[model] >= CONFIRM else 1
        if want != (1 if row["enabled"] else 0):
            db.execute(
                """update abilities set enabled = ?
                   where channel_id = ? and model = ? and "group" = 'default'""",
                (want, CHANNEL_ID, model))
            changes.append((model, want, usable))
    db.commit()
    STATE.write_text(json.dumps(streak, ensure_ascii=False))
    for model, want, usable in changes:
        log("%s：%s（可服务账号 %s 个）" % (model, "摘除" if want == 0 else "恢复", usable))
    if missing:
        log("上游目录缺失：%s" % ", ".join(missing))
    if not changes:
        log("无变化；可服务账号数 %s" % json.dumps(counts, ensure_ascii=False))


if __name__ == "__main__":
    main()
