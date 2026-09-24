"""服务端会话存储。

每个用户一个分片文件 data/sessions/<user_id>.json，结构：
{
  "records": [
    {
      "id": "sxxxx",            # 会话 ID（写入 token）
      "login_at": "2026-..",    # 登录时间
      "last_seen": "2026-..",   # 最近活跃时间
      "ip": "127.0.0.1",        # 来源 IP
      "source": "Chrome · Windows @ 本机 (127.0.0.1)",  # 来源描述
      "user_agent": "...",
      "revoked": false,         # 是否已踢下线
      "revoked_at": null,
      "revoke_reason": null     # kicked | password_change | logout
    }, ...
  ]
}

会话即「登录记录」：被踢下线/登出后记录保留并标记状态，仍可在页面查看；
最近记录超过上限时，只裁剪最旧且已失效的记录。
"""
import os

from backend import config
from backend.storage import read_json, locked_update
from backend.utils import now_iso, gen_id, parse_user_agent, describe_ip

MAX_RECORDS = 30


def _path(user_id):
    return os.path.join(config.SESSIONS_DIR, f"{user_id}.json")


def client_ip():
    from flask import request
    fwd = request.headers.get("X-Forwarded-For", "")
    ip = (fwd.split(",")[0].strip() if fwd else "")
    return ip or request.remote_addr or ""


def create_session(user_id):
    """登录/注册时创建一条新会话，返回 (sid, record)。"""
    from flask import request
    ua = request.headers.get("User-Agent", "")
    ip = client_ip()
    sid = gen_id("s")
    record = {
        "id": sid,
        "login_at": now_iso(),
        "last_seen": now_iso(),
        "ip": ip,
        "source": f"{parse_user_agent(ua)} @ {describe_ip(ip)}",
        "user_agent": parse_user_agent(ua),
        "revoked": False,
        "revoked_at": None,
        "revoke_reason": None,
    }

    def _upd(data):
        data = data or {"records": []}
        records = data.get("records", [])
        records.append(record)
        data["records"] = _trim(records)
        return data

    locked_update(_path(user_id), _upd, {"records": []})
    return sid, record


def _trim(records):
    """超过上限时，优先丢弃最旧且已失效的记录；活跃记录始终保留。"""
    if len(records) <= MAX_RECORDS:
        return records
    dead = [r for r in records if r.get("revoked")]
    alive = [r for r in records if not r.get("revoked")]
    dead.sort(key=lambda r: r.get("revoked_at") or r.get("login_at", ""))
    while dead and len(dead) + len(alive) > MAX_RECORDS:
        dead.pop(0)
    result = alive + dead
    result.sort(key=lambda r: r.get("login_at", ""), reverse=True)
    return result


def list_records(user_id):
    """返回用户全部登录记录，按登录时间倒序。"""
    data = read_json(_path(user_id), {"records": []})
    records = (data or {}).get("records", [])
    return sorted(records, key=lambda r: r.get("login_at", ""), reverse=True)


def get_record(user_id, sid):
    if not sid:
        return None
    for r in list_records(user_id):
        if r.get("id") == sid:
            return r
    return None


def touch(user_id, sid):
    """更新会话最近活跃时间（60 秒节流，窗口内完全不写盘）。"""
    from backend.utils import parse_time

    data = read_json(_path(user_id))
    if not data:
        return
    now = now_iso()
    now_ts = parse_time(now) or 0
    for r in data.get("records", []):
        if r.get("id") == sid:
            last = parse_time(r.get("last_seen")) or 0
            if now_ts - last < 60:
                return
            break
    else:
        return  # 会话不存在（可能已被踢），无需更新

    def _upd(d):
        for r in (d or {}).get("records", []):
            if r.get("id") == sid:
                r["last_seen"] = now
                break
        return d or {"records": []}

    locked_update(_path(user_id), _upd)


def revoke(user_id, sid, reason="kicked"):
    """作废指定会话。返回是否命中（会话存在且原本有效）。"""
    hit = {"v": False}

    def _upd(data):
        data = data or {"records": []}
        for r in data.get("records", []):
            if r.get("id") == sid:
                if not r.get("revoked"):
                    r["revoked"] = True
                    r["revoked_at"] = now_iso()
                    r["revoke_reason"] = reason
                    hit["v"] = True
                break
        return data

    locked_update(_path(user_id), _upd, {"records": []})
    return hit["v"]


def rotate(user_id, old_sid):
    """保留同一条登录记录但更换会话 ID（用于改密后让旧 token 失效）。

    返回新 sid；找不到旧会话时返回 None。
    """
    new_sid = gen_id("s")
    found = {"v": None}

    def _upd(data):
        data = data or {"records": []}
        for r in data.get("records", []):
            if r.get("id") == old_sid:
                r["id"] = new_sid
                r["last_seen"] = now_iso()
                found["v"] = new_sid
                break
        return data

    locked_update(_path(user_id), _upd, {"records": []})
    return found["v"]


def revoke_all_except(user_id, keep_sid, reason="kicked"):
    """作废除 keep_sid 外的全部有效会话，返回被作废数量。"""
    count = {"n": 0}

    def _upd(data):
        data = data or {"records": []}
        now = now_iso()
        for r in data.get("records", []):
            if r.get("id") != keep_sid and not r.get("revoked"):
                r["revoked"] = True
                r["revoked_at"] = now
                r["revoke_reason"] = reason
                count["n"] += 1
        return data

    locked_update(_path(user_id), _upd, {"records": []})
    return count["n"]
