"""
Misumi AI — Telegram Mini App server.

Serves the premium web chat UI (templates/index.html) and a /api/chat
endpoint that the Mini App's JS calls. Requests are authenticated using
Telegram's official WebApp initData verification algorithm, so we know
for certain which Telegram user is talking — no separate login needed.

Docs: https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
"""
import base64
import hashlib
import hmac
import json
import os
from urllib.parse import parse_qsl

from flask import Flask, jsonify, render_template, request

import admin_store
import ai_core

TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
ADMIN_ID = os.environ.get("ADMIN_ID", "").strip()
import logging as _log
_log.basicConfig(level=_log.INFO)
_log.getLogger("misumi-bot").info(f"[STARTUP] ADMIN_ID={ADMIN_ID!r} (len={len(ADMIN_ID)})")

app = Flask(__name__)
import web_api
app.register_blueprint(web_api.bp)


def verify_init_data(init_data: str) -> dict | None:
    """Validate Telegram WebApp initData. Returns the parsed data dict
    (including 'user') if valid, or None if the signature doesn't match.
    """
    if not init_data:
        return None
    try:
        pairs = dict(parse_qsl(init_data, strict_parsing=True))
    except ValueError:
        return None

    received_hash = pairs.pop("hash", None)
    if not received_hash:
        return None

    data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
    secret_key = hmac.new(b"WebAppData", TELEGRAM_BOT_TOKEN.encode(), hashlib.sha256).digest()
    computed_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(computed_hash, received_hash):
        return None

    if "user" in pairs:
        pairs["user"] = json.loads(pairs["user"])
    return pairs


def verify_admin(init_data: str) -> dict | None:
    """Like verify_init_data, but also requires the user's id to match
    ADMIN_ID. Returns None if unauthenticated, not the admin, or ADMIN_ID
    isn't configured at all.
    """
    import logging
    log = logging.getLogger("misumi-bot")

    # 1. Avval to'liq Telegram initData tekshiruvi
    if init_data:
        data = verify_init_data(init_data)
        if data:
            user = data.get("user", {})
            incoming_id = str(user.get("id", ""))
            log.info(f"[verify_admin] initData OK, incoming_id={incoming_id!r}")
            if ADMIN_ID and incoming_id == ADMIN_ID:
                return data
            log.warning(f"[verify_admin] ID mos kelmadi: {incoming_id!r} != {ADMIN_ID!r}")
            return None

    # 2. initData bo'sh yoki noto'g'ri — secret key tekshiruvi
    # Admin panel Telegram desktop da ochilsa initData kelmaydi
    # Shuning uchun X-Admin-Secret header orqali ham qabul qilamiz
    secret = request.headers.get("X-Admin-Secret", "")
    ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")
    if ADMIN_SECRET and ADMIN_ID and hmac.compare_digest(secret, ADMIN_SECRET):
        log.info("[verify_admin] X-Admin-Secret orqali kirdi")
        return {"user": {"id": int(ADMIN_ID)}}

    log.warning(f"[verify_admin] initData bo'sh va secret yo'q")
    return None


@app.route("/")
def index():
    return render_template(
        "index.html",
        bot_name=ai_core.BOT_NAME,
        author=ai_core.AUTHOR_HANDLE,
        channel=ai_core.CHANNEL_HANDLE,
        model_tiers_json=json.dumps(list(ai_core.MODEL_TIERS.values())),
        default_model=ai_core.DEFAULT_MODEL,
    )


@app.route("/admin")
def admin_page():
    return render_template("admin.html", bot_name=ai_core.BOT_NAME)


@app.route("/api/chat", methods=["POST"])
def api_chat():
    body = request.get_json(silent=True) or {}
    init_data = body.get("initData", "")
    message = (body.get("message") or "").strip()
    image_data_url = body.get("image")  # optional: "data:image/jpeg;base64,...."
    requested_model = body.get("model")  # "flash" | "pro" | "max"
    # Set by the Mini App's regenerate/edit message actions: the client
    # re-sends the last user message (unchanged for regenerate, edited for
    # edit) and we drop the stale turn from history before running it again.
    regenerate = bool(body.get("regenerate"))

    data = verify_init_data(init_data)
    if not data:
        return jsonify({"error": "Unauthorized"}), 401
    if not message and not image_data_url:
        return jsonify({"error": "Empty message"}), 400

    user = data.get("user", {})
    user_id = user.get("id")
    if not user_id:
        return jsonify({"error": "No user id"}), 400

    if admin_store.is_blocked(user_id):
        return jsonify({"error": "Blocked"}), 403

    # Resolve the model tier server-side so a free user can't just send
    # {"model": "max"} to bypass premium gating.
    effective_model = ai_core.resolve_model(str(user_id), requested_model)

    if admin_store.is_maintenance() and str(user_id) != ADMIN_ID:
        return jsonify(
            {"reply": f"🛠 {ai_core.BOT_NAME} hozir texnik ishlar tufayli vaqtincha ishlamayapti."}
        )

    if regenerate:
        ai_core.pop_last_exchange(user_id)

    image_bytes = None
    image_mime = None
    if image_data_url and image_data_url.startswith("data:"):
        try:
            header, b64data = image_data_url.split(",", 1)
            image_mime = header.split(";")[0].replace("data:", "") or "image/jpeg"
            image_bytes = base64.b64decode(b64data)
        except Exception:
            return jsonify({"error": "Invalid image"}), 400

    # If the user is asking us to *generate* an image (and isn't attaching
    # one for us to look at), route to image generation instead of chat.
    if not image_bytes and ai_core.wants_image(message):
        try:
            gen_bytes, gen_mime = ai_core.generate_image_reply(
                str(user_id), message, name=user.get("first_name"), source="miniapp"
            )
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        gen_b64 = base64.b64encode(gen_bytes).decode("ascii")
        return jsonify({
            "reply": "",
            "generated_image": f"data:{gen_mime};base64,{gen_b64}",
            "model": effective_model,
        })

    try:
        reply = ai_core.get_ai_reply(
            str(user_id),
            message,
            image_bytes,
            image_mime,
            name=user.get("first_name"),
            source="miniapp",
            model=effective_model,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"reply": reply, "model": effective_model})


@app.route("/api/me", methods=["POST"])
def api_me():
    """Tells the Mini App whether the current user has premium, so it can
    show/hide the lock icon on the Pro/Max model options without the
    client having to guess or trust its own local state.
    """
    body = request.get_json(silent=True) or {}
    data = verify_init_data(body.get("initData", ""))
    if not data:
        return jsonify({"error": "Unauthorized"}), 401
    user = data.get("user", {})
    user_id = user.get("id")
    premium = admin_store.is_premium(user_id) if user_id else False
    return jsonify({"premium": bool(premium), "models": list(ai_core.MODEL_TIERS.values())})


@app.route("/api/reset", methods=["POST"])
def api_reset():
    body = request.get_json(silent=True) or {}
    init_data = body.get("initData", "")
    data = verify_init_data(init_data)
    if not data:
        return jsonify({"error": "Unauthorized"}), 401
    user = data.get("user", {})
    user_id = user.get("id")
    if user_id:
        ai_core.reset_user(str(user_id))
    return jsonify({"ok": True})


@app.route("/api/admin/stats", methods=["POST"])
def api_admin_stats():
    body = request.get_json(silent=True) or {}
    if not verify_admin(body.get("initData", "")):
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify(admin_store.get_stats())


@app.route("/api/admin/users", methods=["POST"])
def api_admin_users():
    body = request.get_json(silent=True) or {}
    if not verify_admin(body.get("initData", "")):
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify({"users": admin_store.get_users()})


@app.route("/api/admin/toggle-block", methods=["POST"])
def api_admin_toggle_block():
    body = request.get_json(silent=True) or {}
    if not verify_admin(body.get("initData", "")):
        return jsonify({"error": "Unauthorized"}), 403
    target_id = str(body.get("user_id", "")).strip()
    if not target_id:
        return jsonify({"error": "user_id required"}), 400
    if target_id == ADMIN_ID:
        return jsonify({"error": "Can't block the admin"}), 400
    blocked = admin_store.toggle_block(target_id)
    return jsonify({"user_id": target_id, "blocked": blocked})


@app.route("/api/admin/toggle-premium", methods=["POST"])
def api_admin_toggle_premium():
    body = request.get_json(silent=True) or {}
    if not verify_admin(body.get("initData", "")):
        return jsonify({"error": "Unauthorized"}), 403
    target_id = str(body.get("user_id", "")).strip()
    if not target_id:
        return jsonify({"error": "user_id required"}), 400
    premium = admin_store.toggle_premium(target_id)
    return jsonify({"user_id": target_id, "premium": premium})


@app.route("/api/admin/maintenance", methods=["POST"])
def api_admin_maintenance():
    body = request.get_json(silent=True) or {}
    if not verify_admin(body.get("initData", "")):
        return jsonify({"error": "Unauthorized"}), 403
    value = admin_store.set_maintenance(bool(body.get("value")))
    return jsonify({"maintenance": value})


@app.route("/api/admin/persona", methods=["POST"])
def api_admin_persona():
    """GET current persona or SET a new one."""
    body = request.get_json(silent=True) or {}
    if not verify_admin(body.get("initData", "")):
        return jsonify({"error": "Unauthorized"}), 403
    if "persona" in body:
        new_val = admin_store.set_persona(str(body["persona"]))
        return jsonify({"persona": new_val})
    return jsonify({"persona": admin_store.get_persona()})


@app.route("/api/admin/groups", methods=["POST"])
def api_admin_groups():
    """Return all groups the bot has ever talked in, with metadata."""
    body = request.get_json(silent=True) or {}
    if not verify_admin(body.get("initData", "")):
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify({"groups": admin_store.get_groups()})


@app.route("/api/admin/broadcast-groups", methods=["POST"])
def api_admin_broadcast_groups():
    """Send a broadcast message to selected groups (or all groups).
    Body: { initData, message, group_ids?: [str, ...] }
    If group_ids is omitted or empty — broadcasts to ALL currently-member groups.
    Non-member groups are always skipped (bot can't send there anyway).
    Returns { sent, failed, skipped, total }.
    """
    body = request.get_json(silent=True) or {}
    if not verify_admin(body.get("initData", "")):
        return jsonify({"error": "Unauthorized"}), 403

    message = (body.get("message") or "").strip()
    if not message:
        return jsonify({"error": "message required"}), 400

    # Build member-only lookup from store
    all_groups = admin_store.get_groups()
    member_ids = {g["id"] for g in all_groups if g.get("is_member") is True}
    # Groups with is_member=None (unknown) are still attempted — bot may still be in them
    unknown_ids = {g["id"] for g in all_groups if g.get("is_member") is None}
    sendable_ids = member_ids | unknown_ids

    requested_ids = body.get("group_ids")
    if requested_ids and isinstance(requested_ids, list):
        targets = [str(gid) for gid in requested_ids if str(gid).strip()]
    else:
        targets = [g["id"] for g in all_groups]

    # Filter: never try to send to groups we know the bot was removed from
    skipped = [t for t in targets if t not in sendable_ids]
    targets = [t for t in targets if t in sendable_ids]

    if not targets:
        return jsonify({"error": "No sendable groups found (bot removed from all selected groups)"}), 404

    import requests as req_lib
    import time

    bot_token = TELEGRAM_BOT_TOKEN
    send_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    sent, failed = 0, 0
    for chat_id in targets:
        try:
            resp = req_lib.post(send_url, json={
                "chat_id": int(chat_id),
                "text": message,
                "parse_mode": "HTML",
            }, timeout=10)
            if resp.ok and resp.json().get("ok"):
                sent += 1
            else:
                failed += 1
        except Exception:
            failed += 1
        time.sleep(0.05)  # Telegram rate limit: stay under 30 msg/sec

    admin_store.record_broadcast(
        summary=f"Groups broadcast: {message[:80]}",
        sent=sent,
        failed=failed,
    )
    return jsonify({"sent": sent, "failed": failed, "skipped": len(skipped), "total": len(targets) + len(skipped)})


@app.route("/health")
def health():
    return "Misumi AI is running", 200


def run(port: int):
    # threaded=True lets the health check and chat requests be handled
    # concurrently without blocking each other.
    app.run(host="0.0.0.0", port=port, threaded=True)

# ── NEW: broadcast-users, broadcast-groups-v2 (with photo), group-info ──────

@app.route("/api/admin/broadcast-users", methods=["POST"])
def api_admin_broadcast_users():
    """Broadcast text or photo to selected users.
    Body: { initData, message?, photo?: dataURL, user_ids?: [str,...] }
    """
    body = request.get_json(silent=True) or {}
    if not verify_admin(body.get("initData", "")):
        return jsonify({"error": "Unauthorized"}), 403
    message = (body.get("message") or "").strip()
    photo_data_url = body.get("photo", "")
    if not message and not photo_data_url:
        return jsonify({"error": "message or photo required"}), 400

    all_u = admin_store.get_users(limit=5000)
    all_ids = {u["id"] for u in all_u}
    req_ids = body.get("user_ids")
    targets = [str(x) for x in req_ids if str(x).strip()] if (req_ids and isinstance(req_ids, list)) else [u["id"] for u in all_u]
    skipped = [t for t in targets if t not in all_ids]
    targets = [t for t in targets if t in all_ids]
    if not targets:
        return jsonify({"error": "No users found"}), 404

    import requests as rq, time, base64 as b64
    photo_bytes = None
    if photo_data_url and photo_data_url.startswith("data:"):
        try:
            photo_bytes = b64.b64decode(photo_data_url.split(",", 1)[1])
        except Exception:
            pass

    sent = failed = 0
    for cid in targets:
        try:
            if photo_bytes:
                r = rq.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendPhoto",
                    data={"chat_id": int(cid), "caption": message, "parse_mode": "HTML"},
                    files={"photo": ("p.jpg", photo_bytes, "image/jpeg")}, timeout=15)
            else:
                r = rq.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                    json={"chat_id": int(cid), "text": message, "parse_mode": "HTML"}, timeout=10)
            if r.ok and r.json().get("ok"): sent += 1
            else: failed += 1
        except Exception: failed += 1
        time.sleep(0.05)

    admin_store.record_broadcast(f"Users{'📷' if photo_bytes else ''}: {message[:80]}", sent, failed)
    return jsonify({"sent": sent, "failed": failed, "skipped": len(skipped), "total": len(targets)+len(skipped)})


@app.route("/api/admin/broadcast-groups-v2", methods=["POST"])
def api_admin_broadcast_groups_v2():
    """Broadcast text or photo to selected groups.
    Body: { initData, message?, photo?: dataURL, group_ids?: [str,...] }
    """
    body = request.get_json(silent=True) or {}
    if not verify_admin(body.get("initData", "")):
        return jsonify({"error": "Unauthorized"}), 403
    message = (body.get("message") or "").strip()
    photo_data_url = body.get("photo", "")
    if not message and not photo_data_url:
        return jsonify({"error": "message or photo required"}), 400

    all_groups = admin_store.get_groups()
    sendable = {g["id"] for g in all_groups if g.get("is_member") is not False}
    req_ids = body.get("group_ids")
    targets = [str(x) for x in req_ids if str(x).strip()] if (req_ids and isinstance(req_ids, list)) else [g["id"] for g in all_groups]
    skipped = [t for t in targets if t not in sendable]
    targets = [t for t in targets if t in sendable]
    if not targets:
        return jsonify({"error": "No sendable groups found"}), 404

    import requests as rq, time, base64 as b64
    photo_bytes = None
    if photo_data_url and photo_data_url.startswith("data:"):
        try:
            photo_bytes = b64.b64decode(photo_data_url.split(",", 1)[1])
        except Exception:
            pass

    sent = failed = 0
    for cid in targets:
        try:
            if photo_bytes:
                r = rq.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendPhoto",
                    data={"chat_id": int(cid), "caption": message, "parse_mode": "HTML"},
                    files={"photo": ("p.jpg", photo_bytes, "image/jpeg")}, timeout=15)
            else:
                r = rq.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                    json={"chat_id": int(cid), "text": message, "parse_mode": "HTML"}, timeout=10)
            if r.ok and r.json().get("ok"): sent += 1
            else: failed += 1
        except Exception: failed += 1
        time.sleep(0.05)

    admin_store.record_broadcast(f"Groups{'📷' if photo_bytes else ''}: {message[:80]}", sent, failed)
    return jsonify({"sent": sent, "failed": failed, "skipped": len(skipped), "total": len(targets)+len(skipped)})


@app.route("/api/admin/group-info", methods=["POST"])
def api_admin_group_info():
    """Fetch live group info: title, member count, invite link."""
    body = request.get_json(silent=True) or {}
    if not verify_admin(body.get("initData", "")):
        return jsonify({"error": "Unauthorized"}), 403
    chat_id = body.get("chat_id")
    if not chat_id:
        return jsonify({"error": "chat_id required"}), 400
    import requests as rq
    try:
        r = rq.get(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getChat",
                   params={"chat_id": int(chat_id)}, timeout=8).json()
        if not r.get("ok"):
            return jsonify({"error": r.get("description", "Telegram error")}), 400
        chat = r["result"]
        mc = rq.get(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getChatMemberCount",
                    params={"chat_id": int(chat_id)}, timeout=8).json()
        username = chat.get("username")
        invite_link = chat.get("invite_link") or (f"https://t.me/{username}" if username else None)
        return jsonify({
            "title": chat.get("title"),
            "type": chat.get("type"),
            "username": username,
            "invite_link": invite_link,
            "member_count": mc.get("result") if mc.get("ok") else None,
            "description": chat.get("description"),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500




@app.route("/api/admin/love-message", methods=["POST"])
def api_admin_love_message():
    """Admin paneldan istalgan userga yoki guruhga AI tomonidan
    sevgi izhori xabari generatsiya qilib yuboradi.

    Body params:
      initData    : Telegram WebApp auth
      target_id   : user yoki group chat_id (string)
      target_name : ismini bilsa (ixtiyoriy)
      style       : "romantic"|"shy"|"bold"|"poetic"|"playful" (default: romantic)
      custom_hint : qo'shimcha yo'nalish (ixtiyoriy)
      lang        : "uz"|"ru"|"en" (default: uz)
      send        : true = Telegram ga yubor, false = faqat ko'rsat (default: false)
    """
    import requests as rq
    body = request.get_json(silent=True) or {}
    if not verify_admin(body.get("initData", "")):
        return jsonify({"error": "Unauthorized"}), 403

    target_id   = str(body.get("target_id", "")).strip()
    target_name = body.get("target_name") or None
    style       = body.get("style", "romantic")
    custom_hint = body.get("custom_hint") or None
    lang        = body.get("lang", "uz")
    do_send     = bool(body.get("send", False))

    if not target_id:
        return jsonify({"error": "target_id talab qilinadi"}), 400

    # Xabarni AI bilan generatsiya qilamiz
    try:
        message = ai_core.generate_love_confession(
            target_name=target_name,
            style=style,
            custom_hint=custom_hint,
            lang=lang,
        )
    except Exception as e:
        return jsonify({"error": f"Generatsiya xatosi: {e}"}), 500

    result = {"message": message, "sent": False}

    # Agar "send" = true bo'lsa — Telegram ga yubor
    if do_send:
        try:
            r = rq.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={"chat_id": int(target_id), "text": message},
                timeout=10,
            )
            if r.ok and r.json().get("ok"):
                result["sent"] = True
            else:
                result["telegram_error"] = r.json().get("description", "Noma'lum xato")
        except Exception as e:
            result["telegram_error"] = str(e)

    return jsonify(result)


@app.route("/api/admin/broadcast-history", methods=["POST"])
def api_admin_broadcast_history():
    """Return recent broadcast history for the admin panel."""
    body = request.get_json(silent=True) or {}
    if not verify_admin(body.get("initData", "")):
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify({"history": admin_store.get_broadcast_history(limit=20)})
