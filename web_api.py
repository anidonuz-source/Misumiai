"""Misumi AI — mustaqil sayt uchun API (email + parol bilan kirish).
Telegram Mini App (/api/chat) o'zgarishsiz qoladi; bu yerda /api/web/* yo'llari."""
import hashlib, hmac, os, re, secrets, time
from collections import defaultdict, deque
from threading import Lock

from flask import Blueprint, jsonify, request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

import admin_store, ai_core, db

bp = Blueprint("web_api", __name__)
_ser = URLSafeTimedSerializer(os.environ.get("SECRET_KEY") or secrets.token_hex(32), salt="misumi-web")
TOKEN_TTL = 30 * 24 * 3600
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
ALLOWED = [o.strip().rstrip("/") for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()]
_hits, _lock = defaultdict(deque), Lock()


def _limited(key: str, limit: int, window: int) -> bool:
    now = time.time()
    with _lock:
        q = _hits[key]
        while q and q[0] < now - window:
            q.popleft()
        if len(q) >= limit:
            return True
        q.append(now)
        return False


def _hash(pw: str, salt: bytes) -> str:
    return hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1).hex()


def _key(email: str) -> str:
    return hashlib.sha256(email.encode()).hexdigest()


def _user_from_token():
    h = request.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        return None
    try:
        uid = _ser.loads(h[7:], max_age=TOKEN_TTL)["uid"]
    except (BadSignature, SignatureExpired, KeyError):
        return None
    return uid


def _token(uid: str) -> str:
    return _ser.dumps({"uid": uid})


@bp.after_request
def _cors(resp):
    origin = request.headers.get("Origin", "").rstrip("/")
    if origin and (not ALLOWED or origin in ALLOWED):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Vary"] = "Origin"
    return resp


@bp.route("/api/web/<path:_>", methods=["OPTIONS"])
def _preflight(_):
    return "", 204


@bp.route("/api/web/register", methods=["POST"])
def register():
    b = request.get_json(silent=True) or {}
    name = (b.get("name") or "").strip()[:40]
    email = (b.get("email") or "").strip().lower()
    pw = b.get("password") or ""
    if _limited("reg:" + (request.remote_addr or ""), 5, 3600):
        return jsonify(error="Juda ko'p urinish. Keyinroq qayta urinib ko'ring."), 429
    if not name or not EMAIL_RE.match(email) or len(pw) < 8:
        return jsonify(error="Ism, to'g'ri email va kamida 8 belgili parol kiriting."), 400
    k = _key(email)
    if db.exists("web_users", k):
        return jsonify(error="Bu email allaqachon ro'yxatdan o'tgan."), 409
    salt = secrets.token_bytes(16)
    uid = "web_" + secrets.token_hex(8)
    db.save("web_users", k, {"uid": uid, "name": name, "email": email, "salt": salt.hex(), "hash": _hash(pw, salt)})
    db.save("web_ids", uid, {"key": k})
    admin_store.record_message(uid, name=name, source="web")
    return jsonify(token=_token(uid), user={"name": name, "email": email})


@bp.route("/api/web/login", methods=["POST"])
def login():
    b = request.get_json(silent=True) or {}
    email = (b.get("email") or "").strip().lower()
    ip = request.remote_addr or ""
    if _limited(f"login:{ip}:{email}", 6, 600):
        return jsonify(error="Juda ko'p xato urinish. 10 daqiqadan keyin qayta urinib ko'ring."), 429
    rec = db.load("web_users", _key(email), None)
    ok = rec and hmac.compare_digest(rec["hash"], _hash(b.get("password") or "", bytes.fromhex(rec["salt"])))
    if not ok:
        return jsonify(error="Email yoki parol noto'g'ri."), 401
    if admin_store.is_blocked(rec["uid"]):
        return jsonify(error="Hisob bloklangan."), 403
    return jsonify(token=_token(rec["uid"]), user={"name": rec["name"], "email": rec["email"]})


def _me(uid):
    rec = db.load("web_users", db.load("web_ids", uid, {}).get("key", ""), None)
    return rec


@bp.route("/api/web/me", methods=["GET"])
def me():
    uid = _user_from_token()
    rec = _me(uid) if uid else None
    if not rec:
        return jsonify(error="Unauthorized"), 401
    return jsonify(user={"name": rec["name"], "email": rec["email"]},
                   premium=admin_store.is_premium(uid), models=list(ai_core.MODEL_TIERS.values()))


@bp.route("/api/web/chat", methods=["POST"])
def chat():
    uid = _user_from_token()
    rec = _me(uid) if uid else None
    if not rec:
        return jsonify(error="Unauthorized"), 401
    if admin_store.is_blocked(uid):
        return jsonify(error="Hisob bloklangan."), 403
    if _limited("chat:" + uid, 20, 60):
        return jsonify(error="Juda tez yozyapsiz. Bir daqiqa kuting."), 429
    b = request.get_json(silent=True) or {}
    msg = (b.get("message") or "").strip()[:8000]
    if not msg:
        return jsonify(error="Bo'sh xabar"), 400
    model = ai_core.resolve_model(uid, b.get("model"))
    if admin_store.is_maintenance():
        return jsonify(reply=f"🛠 {ai_core.BOT_NAME} hozir texnik ishlar tufayli ishlamayapti.")
    if b.get("regenerate"):
        ai_core.pop_last_exchange(uid)
    try:
        if ai_core.wants_image(msg):
            import base64
            raw, mime = ai_core.generate_image_reply(uid, msg, name=rec["name"], source="web")
            return jsonify(reply="", generated_image=f"data:{mime};base64,{base64.b64encode(raw).decode()}", model=model)
        reply = ai_core.get_ai_reply(uid, msg, None, None, name=rec["name"], source="web", model=model)
    except Exception:
        return jsonify(error="AI hozir javob bera olmadi. Qayta urinib ko'ring."), 500
    return jsonify(reply=reply, model=model)


@bp.route("/api/web/reset", methods=["POST"])
def reset():
    uid = _user_from_token()
    if not uid:
        return jsonify(error="Unauthorized"), 401
    ai_core.reset_user(uid)
    return jsonify(ok=True)
