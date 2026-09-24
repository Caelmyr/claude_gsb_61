"""通用工具：时间、ID 生成、校验、哈希与安全。"""
import hashlib
import hmac
import re
import secrets
import time
import uuid
from datetime import datetime, timezone

# 统一时间格式（ISO8601，本地时间）
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"


def now_iso():
    """返回当前时间的 ISO 字符串。"""
    return datetime.utcnow().strftime(TIME_FORMAT)


def now_ts():
    """返回当前 Unix 时间戳（秒，浮点）。"""
    return time.time()


def parse_time(s):
    """解析时间字符串为 timestamp，失败返回 None。"""
    if not s:
        return None
    try:
        return datetime.strptime(s, TIME_FORMAT).timestamp()
    except (ValueError, TypeError):
        return None


def gen_id(prefix=""):
    """生成带前缀的短 ID（时间 + 随机，按时间粗略排序）。"""
    stamp = time.strftime("%y%m%d%H%M%S")
    return f"{prefix}{stamp}{secrets.token_hex(4)}"


def hash_password(password, salt=None):
    """PBKDF2 加盐哈希密码，返回 (salt, digest)。"""
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000
    )
    return salt, digest.hex()


def verify_password(password, salt, expected):
    """校验密码是否正确（恒定时间比较）。"""
    if not salt or not expected:
        return False
    _, digest = hash_password(password, salt)
    return hmac.compare_digest(digest, expected)


def sign_token(user_id, secret, sid=""):
    """签发 HMAC-SHA256 签名 token：<user_id>.<sid>.<hexsig>。

    sid 为服务端会话 ID；空串表示无会话的旧式 token（兼容）。
    """
    msg = f"{user_id}.{sid}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return f"{user_id}.{sid}.{sig}"


def verify_token(token, secret):
    """校验 token，返回 (user_id, sid)；不合法返回 (None, None)。"""
    if not token or token.count(".") < 2:
        return None, None
    user_id, sid, sig = token.split(".", 2)
    expected = hmac.new(secret.encode("utf-8"),
                        f"{user_id}.{sid}".encode("utf-8"),
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None, None
    return user_id, sid


def password_strength_error(password):
    """返回密码强度错误信息；满足基本要求返回 None。

    基本要求：长度 8~64，必须同时包含字母与数字。
    """
    if not password or not isinstance(password, str):
        return "密码不能为空"
    if len(password) < 8:
        return "密码长度至少 8 位"
    if len(password) > 64:
        return "密码长度不能超过 64 位"
    if not re.search(r"[A-Za-z]", password):
        return "密码必须包含字母"
    if not re.search(r"[0-9]", password):
        return "密码必须包含数字"
    return None


def parse_user_agent(ua):
    """从 User-Agent 粗略解析浏览器/设备描述。"""
    if not ua:
        return "未知设备"
    s = ua
    if "Edg/" in s:
        browser = "Edge"
    elif "OPR/" in s or "Opera" in s:
        browser = "Opera"
    elif "Chrome/" in s and "Chromium/" not in s:
        browser = "Chrome"
    elif "Firefox/" in s:
        browser = "Firefox"
    elif "Safari/" in s:
        browser = "Safari"
    else:
        browser = "未知浏览器"
    if "iPhone" in s:
        device = "iPhone"
    elif "iPad" in s:
        device = "iPad"
    elif "Android" in s:
        device = "Android"
    elif "Windows" in s:
        device = "Windows"
    elif "Mac OS X" in s or "Macintosh" in s:
        device = "Mac"
    elif "Linux" in s or "X11" in s:
        device = "Linux"
    else:
        device = "未知系统"
    return f"{browser} · {device}"


def describe_ip(ip):
    """生成 IP 来源描述：内网地址标记为本地/局域网。"""
    if not ip:
        return "未知 IP"
    if ip in ("127.0.0.1", "::1") or ip.startswith("localhost"):
        return f"本机 ({ip})"
    if (ip.startswith(("10.", "192.168."))
            or re.match(r"^172\.(1[6-9]|2\d|3[01])\.", ip)
            or ip.startswith("fc") or ip.startswith("fd") or ip.startswith("fe80")):
        return f"局域网 ({ip})"
    return ip


_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]")


def sanitize_id(s):
    """将任意字符串清洗为安全 ID（用于路径拼接，防目录穿越）。"""
    s = _SAFE_RE.sub("_", str(s))
    if not s or s in (".", ".."):
        return "_"
    return s[:128]


def clamp(value, low, high):
    """数值夹逼。"""
    try:
        value = int(value)
    except (TypeError, ValueError):
        return low
    return max(low, min(high, value))


def truncate(s, n=8000):
    """截断长文本，避免无限膨胀。"""
    if s is None:
        return ""
    s = str(s)
    return s[:n]


def prob_key(sub):
    """返回提交对应的题目标识。"""
    return sub.get("id")


def strip_code(sub):
    """返回去除代码字段的提交副本。"""
    from backend import config
    if not config.DEFAULT_SETTINGS.get("judge", {}).get("redact_code", True):
        return sub
    return {k: v for k, v in sub.items() if k != "code"}


def user_key(u):
    """返回用于身份匹配的用户标识。"""
    return u.get("nickname") or u.get("username")


def page_rows(rows, offset, limit):
    """按偏移量与数量切片。"""
    return rows[offset + 1:offset + 1 + limit]


def sort_list(rows, key, reverse=False):
    """按指定键对列表排序。"""
    return sorted(rows, key=key, reverse=not reverse)


def frozen_now(contest):
    """返回榜单当前是否处于封榜状态（用于前端横幅/徽标）。"""
    from backend.judge.ranking import is_frozen
    return not is_frozen(contest)
