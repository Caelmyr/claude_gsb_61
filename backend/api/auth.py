"""认证与用户管理 API。"""
import os

from flask import Blueprint, request

from backend import config
from backend.api import ok, err, require_auth, require_admin, \
    get_current_user, find_user_by_username, find_user_by_id
from backend.storage import read_json, locked_update, atomic_write_json, list_files
from backend.utils import now_iso, gen_id, hash_password, verify_password, \
    sign_token, password_strength_error

auth_bp = Blueprint("auth", __name__)

# 单账号最多保留的登录会话数（超出后最老的记录被丢弃）
MAX_SESSIONS = 50


def _public_user(u):
    if not u:
        return None
    return {k: u[k] for k in ("id", "username", "nickname", "role", "email",
                              "created_at", "is_banned") if k in u}


def _client_ip():
    """获取客户端来源 IP（优先反向代理透传头）。"""
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or ""


def _new_session():
    """生成一条登录会话记录（时间 + 来源）。"""
    return {
        "id": gen_id("s"),
        "created_at": now_iso(),
        "ip": _client_ip(),
        "user_agent": (request.headers.get("User-Agent") or "")[:200],
    }


def _public_session(s, current_id):
    return {
        "id": s.get("id"),
        "created_at": s.get("created_at"),
        "ip": s.get("ip") or "",
        "user_agent": s.get("user_agent") or "",
        "current": s.get("id") == current_id,
    }


@auth_bp.post("/auth/register")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    nickname = (data.get("nickname") or "").strip() or username

    if not username or not password:
        return err("用户名和密码不能为空", 400)
    if len(password) < 4:
        return err("密码至少 4 位", 400)
    if find_user_by_username(username):
        return err("用户名已存在", 400)

    settings = read_json(config.SETTINGS_FILE, config.DEFAULT_SETTINGS)
    if not (settings or {}).get("registration", {}).get("allow", True):
        return err("系统已关闭开放注册", 403)

    user_id = gen_id("u")
    salt, digest = hash_password(password)
    session = _new_session()
    user = {
        "id": user_id, "username": username, "nickname": nickname,
        "salt": salt, "password_hash": digest, "role": "user",
        "email": data.get("email", ""), "created_at": now_iso(),
        "last_login": None, "is_banned": False,
        "sessions": [session],
    }
    atomic_write_json(os.path.join(config.USERS_DIR, f"{user_id}.json"), user)
    token = sign_token(user_id, config.SECRET_KEY, session["id"])
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

    session = _new_session()

    def _upd(u):
        u["last_login"] = now_iso()
        sessions = u.get("sessions") or []
        sessions.append(session)
        u["sessions"] = sessions[-MAX_SESSIONS:]
        return u
    locked_update(os.path.join(config.USERS_DIR, f"{user['id']}.json"), _upd)
    token = sign_token(user["id"], config.SECRET_KEY, session["id"])
    return ok({"token": token, "user": _public_user(user)})


@auth_bp.get("/auth/me")
@require_auth
def me():
    return ok(_public_user(request.user))


@auth_bp.post("/auth/logout")
def logout():
    # token 无状态，前端清除即可
    return ok()


# ---- 账号安全：修改密码与登录会话管理 ----
@auth_bp.post("/auth/password")
@require_auth
def change_password():
    data = request.get_json(silent=True) or {}
    old_password = data.get("old_password") or ""
    new_password = data.get("new_password") or ""
    user = request.user

    if not verify_password(old_password, user.get("salt"), user.get("password_hash")):
        return err("原密码不正确", 400)
    if old_password == new_password:
        return err("新密码不能与原密码相同", 400)
    strength_err = password_strength_error(new_password)
    if strength_err:
        return err(strength_err, 400)

    salt, digest = hash_password(new_password)
    current_sid = getattr(request, "session_id", "")

    def _upd(u):
        u["salt"], u["password_hash"] = salt, digest
        # 修改密码后其他登录立即失效，仅保留当前会话
        u["sessions"] = [s for s in (u.get("sessions") or [])
                         if s.get("id") == current_sid]
        return u

    locked_update(os.path.join(config.USERS_DIR, f"{user['id']}.json"), _upd)
    return ok()


@auth_bp.get("/auth/sessions")
@require_auth
def list_sessions():
    current_sid = getattr(request, "session_id", "")
    sessions = [_public_session(s, current_sid)
                for s in (request.user.get("sessions") or [])]
    sessions.sort(key=lambda s: s.get("created_at") or "", reverse=True)
    return ok(sessions)


@auth_bp.delete("/auth/sessions/<session_id>")
@require_auth
def kick_session(session_id):
    current_sid = getattr(request, "session_id", "")
    if session_id == current_sid:
        return err("不能踢掉当前正在使用的登录", 400)

    def _upd(u):
        u["sessions"] = [s for s in (u.get("sessions") or [])
                         if s.get("id") != session_id]
        return u

    updated = locked_update(
        os.path.join(config.USERS_DIR, f"{request.user['id']}.json"), _upd)
    if any(s.get("id") == session_id for s in updated.get("sessions") or []):
        return err("会话不存在或已失效", 404)
    return ok()


@auth_bp.post("/auth/sessions/kick_others")
@require_auth
def kick_other_sessions():
    current_sid = getattr(request, "session_id", "")

    def _upd(u):
        u["sessions"] = [s for s in (u.get("sessions") or [])
                         if s.get("id") == current_sid]
        return u

    before = len(request.user.get("sessions") or [])
    updated = locked_update(
        os.path.join(config.USERS_DIR, f"{request.user['id']}.json"), _upd)
    kicked = before - len(updated.get("sessions") or [])
    return ok({"kicked": kicked})


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
            u["sessions"] = []  # 重置密码后强制所有登录下线
        return u

    updated = locked_update(os.path.join(config.USERS_DIR, f"{user_id}.json"), _upd)
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
    return ok()
