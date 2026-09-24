"""认证与用户管理 API。"""
import os

from flask import Blueprint, request

from backend import config
from backend import sessions
from backend.api import ok, err, require_auth, require_admin, \
    get_current_user, find_user_by_username, find_user_by_id
from backend.storage import read_json, locked_update, atomic_write_json, list_files
from backend.utils import (now_iso, gen_id, hash_password, verify_password,
                           sign_token, password_strength_error)

auth_bp = Blueprint("auth", __name__)


def _public_user(u):
    if not u:
        return None
    return {k: u[k] for k in ("id", "username", "nickname", "role", "email",
                              "created_at", "is_banned") if k in u}


@auth_bp.post("/auth/register")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    nickname = (data.get("nickname") or "").strip() or username

    if not username or not password:
        return err("用户名和密码不能为空", 400)
    strength_err = password_strength_error(password)
    if strength_err:
        return err(strength_err, 400)
    if find_user_by_username(username):
        return err("用户名已存在", 400)

    settings = read_json(config.SETTINGS_FILE, config.DEFAULT_SETTINGS)
    if not (settings or {}).get("registration", {}).get("allow", True):
        return err("系统已关闭开放注册", 403)

    user_id = gen_id("u")
    salt, digest = hash_password(password)
    user = {
        "id": user_id, "username": username, "nickname": nickname,
        "salt": salt, "password_hash": digest, "role": "user",
        "email": data.get("email", ""), "created_at": now_iso(),
        "last_login": now_iso(), "is_banned": False,
    }
    atomic_write_json(os.path.join(config.USERS_DIR, f"{user_id}.json"), user)
    sid, _ = sessions.create_session(user_id)
    token = sign_token(user_id, config.SECRET_KEY, sid)
    return ok({"token": token, "user": _public_user(user)})


@auth_bp.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    user = find_user_by_username(username)
    if not user or not verify_password(password, user.get("salt"), user.get("password_hash")):
        return err("用户名或密码错误", 401, 401)
    if user.get("is_banned"):
        return err("账号已被封禁", 403, 403)

    def _upd(u):
        u["last_login"] = now_iso()
        return u
    locked_update(os.path.join(config.USERS_DIR, f"{user['id']}.json"), _upd)
    sid, _ = sessions.create_session(user["id"])
    token = sign_token(user["id"], config.SECRET_KEY, sid)
    return ok({"token": token, "user": _public_user(user)})


@auth_bp.get("/auth/me")
@require_auth
def me():
    return ok(_public_user(request.user))


@auth_bp.post("/auth/logout")
@require_auth
def logout():
    # 作废当前会话；token 本身仍由前端清除
    sessions.revoke(request.user["id"], request.session_sid, reason="logout")
    return ok()


# ---- 账号安全：修改密码、登录记录与会话管理 ----
@auth_bp.post("/account/change-password")
@require_auth
def change_password():
    data = request.get_json(silent=True) or {}
    old_password = data.get("old_password") or ""
    new_password = data.get("new_password") or ""
    uid = request.user["id"]

    if not verify_password(old_password, request.user.get("salt"),
                           request.user.get("password_hash")):
        return err("旧密码不正确", 400)

    strength_err = password_strength_error(new_password)
    if strength_err:
        return err(strength_err, 400)
    if verify_password(new_password, request.user.get("salt"),
                       request.user.get("password_hash")):
        return err("新密码不能与旧密码相同", 400)

    salt, digest = hash_password(new_password)

    def _upd(u):
        u["salt"], u["password_hash"] = salt, digest
        return u

    locked_update(os.path.join(config.USERS_DIR, f"{uid}.json"), _upd)
    # 改密后其他登录立即失效；当前这台设备保留登录状态
    kicked = sessions.revoke_all_except(uid, request.session_sid,
                                        reason="password_change")
    # 当前会话 ID 轮换：旧 token 立刻失效，登录记录仍是「当前这次」
    new_sid = sessions.rotate(uid, request.session_sid) or request.session_sid
    token = sign_token(uid, config.SECRET_KEY, new_sid)
    return ok({"token": token, "kicked_sessions": kicked})


@auth_bp.get("/account/sessions")
@require_auth
def list_sessions():
    uid = request.user["id"]
    records = sessions.list_records(uid)
    reason_text = {
        "kicked": "已被踢下线",
        "password_change": "密码已修改",
        "logout": "主动退出",
    }
    items = [{
        "id": r["id"],
        "login_at": r.get("login_at"),
        "last_seen": r.get("last_seen"),
        "source": r.get("source", "未知来源"),
        "ip": r.get("ip", ""),
        "revoked": bool(r.get("revoked")),
        "revoked_at": r.get("revoked_at"),
        "status_text": reason_text.get(r.get("revoke_reason"), "已失效"),
        "current": r["id"] == request.session_sid,
    } for r in records]
    active = [r for r in items if not r["revoked"]]
    return ok({
        "items": items,
        "active_count": len(active),
        "other_active_count": len([r for r in active if not r["current"]]),
        "current_sid": request.session_sid,
    })


@auth_bp.post("/account/sessions/<sid>/revoke")
@require_auth
def revoke_session(sid):
    uid = request.user["id"]
    if sid == request.session_sid:
        return err("不能踢掉当前正在使用的这次登录", 400)
    record = sessions.get_record(uid, sid)
    if not record:
        return err("登录记录不存在", 404)
    if not sessions.revoke(uid, sid, reason="kicked"):
        return err("该登录已下线，无需重复操作", 400)
    return ok({"sid": sid})


@auth_bp.post("/account/sessions/revoke-others")
@require_auth
def revoke_other_sessions():
    uid = request.user["id"]
    count = sessions.revoke_all_except(uid, request.session_sid,
                                       reason="kicked")
    return ok({"revoked_count": count})


# ---- 用户管理（管理员） ----
@auth_bp.get("/users")
@require_admin
def list_users():
    users = []
    for uid in list_files(config.USERS_DIR):
        u = read_json(os.path.join(config.USERS_DIR, f"{uid}.json"))
        if u:
            users.append(_public_user(u))
    users.sort(key=lambda u: u.get("created_at", ""))
    return ok(users)


@auth_bp.post("/users")
@require_admin
def create_user():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or "123456"
    if not username:
        return err("用户名不能为空", 400)
    if find_user_by_username(username):
        return err("用户名已存在", 400)
    user_id = gen_id("u")
    salt, digest = hash_password(password)
    user = {
        "id": user_id, "username": username,
        "nickname": data.get("nickname") or username,
        "salt": salt, "password_hash": digest,
        "role": data.get("role", "user"),
        "email": data.get("email", ""), "created_at": now_iso(),
        "last_login": None, "is_banned": False,
    }
    atomic_write_json(os.path.join(config.USERS_DIR, f"{user_id}.json"), user)
    return ok(_public_user(user))


@auth_bp.put("/users/<user_id>")
@require_admin
def update_user(user_id):
    user = find_user_by_id(user_id)
    if not user:
        return err("用户不存在", 404)
    data = request.get_json(silent=True) or {}

    def _upd(u):
        if "nickname" in data:
            u["nickname"] = data["nickname"] or u.get("username", "")
        if "email" in data:
            u["email"] = data["email"]
        if "role" in data and data["role"] in ("admin", "judge", "user"):
            u["role"] = data["role"]
        if "is_banned" in data:
            u["is_banned"] = bool(data["is_banned"])
        if data.get("password"):
            salt, digest = hash_password(data["password"])
            u["salt"], u["password_hash"] = salt, digest
        return u

    updated = locked_update(os.path.join(config.USERS_DIR, f"{user_id}.json"), _upd)
    if data.get("password"):
        # 管理员重置密码后，该账号所有登录立即失效
        sessions.revoke_all_except(user_id, None, reason="password_change")
    return ok(_public_user(updated))


@auth_bp.delete("/users/<user_id>")
@require_admin
def delete_user(user_id):
    if user_id == request.user["id"]:
        return err("不能删除当前登录账号", 400)
    path = os.path.join(config.USERS_DIR, f"{user_id}.json")
    if not os.path.exists(path):
        return err("用户不存在", 404)
    os.remove(path)
    sessions_file = os.path.join(config.SESSIONS_DIR, f"{user_id}.json")
    if os.path.exists(sessions_file):
        os.remove(sessions_file)
    return ok()
