import base64
import hashlib
import html
import mimetypes
import os
import struct
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.message import Message
from zoneinfo import ZoneInfo

import requests
from dotenv import load_dotenv
from flask import Flask, Response, request

load_dotenv()

app = Flask(__name__)

WECHAT_TOKEN = os.getenv("WECHAT_TOKEN", "")
WECHAT_AES_KEY = os.getenv("WECHAT_AES_KEY", "")
WECHAT_APP_ID = os.getenv("WECHAT_APP_ID", "")
WECHAT_APP_SECRET = os.getenv("WECHAT_APP_SECRET", "")
TRILIUM_BASE_URL = os.getenv("TRILIUM_BASE_URL", "").rstrip("/")
TRILIUM_ETAPI_TOKEN = os.getenv("TRILIUM_ETAPI_TOKEN", "")
TRILIUM_PARENT_NOTE_ID = os.getenv("TRILIUM_PARENT_NOTE_ID", "")
TRILIUM_TARGET_MODE = os.getenv("TRILIUM_TARGET_MODE", "note").strip().lower()
ARCHIVE_TIMEZONE = os.getenv("ARCHIVE_TIMEZONE", "Asia/Shanghai")
OWNER_OPENIDS = {
    item.strip()
    for item in os.getenv("OWNER_OPENIDS", "").replace(";", ",").split(",")
    if item.strip()
}
PROCESS_OWNER_ONLY = os.getenv("PROCESS_OWNER_ONLY", "true").lower() in {"1", "true", "yes", "on"}
REPLY_TO_OWNER = os.getenv("REPLY_TO_OWNER", "false").lower() in {"1", "true", "yes", "on"}
SHOW_MESSAGE_METADATA = os.getenv("SHOW_MESSAGE_METADATA", "false").lower() in {"1", "true", "yes", "on"}

# 简单内存去重；生产多进程/多机器建议换 Redis/数据库。
_seen_msg_ids = {}
SEEN_TTL_SECONDS = 24 * 3600
_wechat_access_token = {"token": "", "expires_at": 0.0}
_executor = ThreadPoolExecutor(max_workers=int(os.getenv("SAVE_WORKERS", "2")))


try:
    _archive_tz = ZoneInfo(ARCHIVE_TIMEZONE)
except Exception:
    _archive_tz = timezone.utc


VALID_TRILIUM_TARGET_MODES = {"note", "journal"}

if TRILIUM_TARGET_MODE not in VALID_TRILIUM_TARGET_MODES:
    raise RuntimeError(
        "TRILIUM_TARGET_MODE must be 'note' or 'journal'"
    )

if TRILIUM_TARGET_MODE == "note" and not TRILIUM_PARENT_NOTE_ID:
    raise RuntimeError(
        "TRILIUM_PARENT_NOTE_ID is required when TRILIUM_TARGET_MODE=note"
    )


def verify_wechat_signature(signature: str, timestamp: str, nonce: str) -> bool:
    if not WECHAT_TOKEN or not signature or not timestamp or not nonce:
        return False
    raw = "".join(sorted([WECHAT_TOKEN, timestamp, nonce]))
    return hashlib.sha1(raw.encode("utf-8")).hexdigest() == signature


def wechat_sha1_signature(*parts: str) -> str:
    raw = "".join(sorted(str(part) for part in parts))
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def verify_wechat_message_signature(msg_signature: str, timestamp: str, nonce: str, encrypted: str) -> bool:
    if not WECHAT_TOKEN or not msg_signature or not timestamp or not nonce or not encrypted:
        return False
    return wechat_sha1_signature(WECHAT_TOKEN, timestamp, nonce, encrypted) == msg_signature


def parse_wechat_xml(xml_bytes: bytes) -> dict:
    root = ET.fromstring(xml_bytes)
    return {child.tag: child.text or "" for child in root}


def get_aes_key() -> bytes:
    if not WECHAT_AES_KEY:
        raise RuntimeError("收到 AES 加密消息，但 .env 没有配置 WECHAT_AES_KEY")
    try:
        key = base64.b64decode(WECHAT_AES_KEY + "=")
    except Exception as exc:
        raise RuntimeError("WECHAT_AES_KEY 格式错误，应为公众号后台的 43 位 EncodingAESKey") from exc
    if len(key) != 32:
        raise RuntimeError("WECHAT_AES_KEY 解码后长度不正确，请确认填写的是 43 位 EncodingAESKey")
    return key


def decrypt_wechat_message(encrypted: str) -> dict:
    # pycryptodome 在 requirements.txt 中；仅 AES 模式才需要导入。
    from Crypto.Cipher import AES

    key = get_aes_key()
    cipher = AES.new(key, AES.MODE_CBC, key[:16])
    plaintext = cipher.decrypt(base64.b64decode(encrypted))
    pad = plaintext[-1]
    if pad < 1 or pad > 32:
        raise RuntimeError("微信 AES 解密 padding 异常")
    plaintext = plaintext[:-pad]

    msg_len = struct.unpack("!I", plaintext[16:20])[0]
    msg_xml = plaintext[20:20 + msg_len]
    app_id = plaintext[20 + msg_len:].decode("utf-8", errors="replace")
    if WECHAT_APP_ID and app_id != WECHAT_APP_ID:
        raise RuntimeError(f"微信 AES 解密 AppID 不匹配：{app_id}")
    return parse_wechat_xml(msg_xml)


def encrypt_wechat_reply(reply_xml: str, timestamp: str, nonce: str) -> str:
    from Crypto.Cipher import AES

    if not WECHAT_APP_ID:
        raise RuntimeError("加密回复需要在 .env 配置 WECHAT_APP_ID")

    key = get_aes_key()
    msg = reply_xml.encode("utf-8")
    plaintext = os.urandom(16) + struct.pack("!I", len(msg)) + msg + WECHAT_APP_ID.encode("utf-8")
    pad_len = 32 - (len(plaintext) % 32)
    if pad_len == 0:
        pad_len = 32
    plaintext += bytes([pad_len]) * pad_len

    cipher = AES.new(key, AES.MODE_CBC, key[:16])
    encrypted = base64.b64encode(cipher.encrypt(plaintext)).decode("utf-8")
    msg_signature = wechat_sha1_signature(WECHAT_TOKEN, timestamp, nonce, encrypted)

    return f"""<xml>
<Encrypt><![CDATA[{encrypted}]]></Encrypt>
<MsgSignature><![CDATA[{msg_signature}]]></MsgSignature>
<TimeStamp>{timestamp}</TimeStamp>
<Nonce><![CDATA[{nonce}]]></Nonce>
</xml>"""


def cleanup_seen():
    now = time.time()
    for key, ts in list(_seen_msg_ids.items()):
        if now - ts > SEEN_TTL_SECONDS:
            _seen_msg_ids.pop(key, None)


def is_duplicate(message: dict) -> bool:
    cleanup_seen()
    msg_id = message.get("MsgId")
    if not msg_id:
        # 事件消息没有 MsgId，可用 FromUserName + CreateTime + MsgType 简单去重
        msg_id = f"{message.get('FromUserName')}:{message.get('CreateTime')}:{message.get('MsgType')}"
    if msg_id in _seen_msg_ids:
        return True
    _seen_msg_ids[msg_id] = time.time()
    return False


def is_owner(message: dict) -> bool:
    return message.get("FromUserName", "") in OWNER_OPENIDS


def get_message_datetime(message: dict) -> datetime:
    create_time = message.get("CreateTime", "")
    if create_time.isdigit():
        return datetime.fromtimestamp(int(create_time), tz=timezone.utc).astimezone(_archive_tz)
    return datetime.now(timezone.utc).astimezone(_archive_tz)


def trilium_request(method: str, path: str, **kwargs) -> requests.Response:
    headers = kwargs.pop("headers", {})
    headers.setdefault("Authorization", TRILIUM_ETAPI_TOKEN)
    resp = requests.request(
        method,
        f"{TRILIUM_BASE_URL}/etapi{path}",
        headers=headers,
        timeout=kwargs.pop("timeout", 20),
        **kwargs,
    )
    resp.raise_for_status()
    return resp


def create_note(parent_note_id: str, title: str, note_type: str, content: str, mime: str | None = None,
                note_id: str | None = None, is_expanded: bool | None = None) -> dict:
    payload = {
        "parentNoteId": parent_note_id,
        "title": title,
        "type": note_type,
        "content": content,
    }
    if mime:
        payload["mime"] = mime
    if note_id:
        payload["noteId"] = note_id
    if is_expanded is not None:
        payload["isExpanded"] = is_expanded

    resp = trilium_request(
        "POST",
        "/create-note",
        json=payload,
        headers={"Content-Type": "application/json"},
    )
    return resp.json()


def create_text_note(parent_note_id: str, title: str, content_html: str) -> dict:
    return create_note(parent_note_id, title, "text", content_html)


def create_binary_note(parent_note_id: str, title: str, note_type: str, mime: str, data: bytes) -> dict:
    initial_content = "image" if note_type == "image" else ""
    note = create_note(parent_note_id, title, note_type, initial_content, mime=mime)
    note_id = note["note"]["noteId"]
    trilium_request(
        "PUT",
        f"/notes/{note_id}/content",
        data=data,
        headers={
            "Content-Type": "application/octet-stream",
            "Content-Transfer-Encoding": "binary",
        },
    )
    return note


def create_attachment(owner_id: str, title: str, role: str, mime: str, data: bytes, position: int = 10) -> dict:
    payload = {
        "ownerId": owner_id,
        "role": role,
        "mime": mime,
        "title": title,
        "position": position,
        "content": "",
    }
    resp = trilium_request(
        "POST",
        "/attachments",
        json=payload,
        headers={"Content-Type": "application/json"},
    )
    attachment = resp.json()
    attachment_id = attachment["attachmentId"]
    trilium_request(
        "PUT",
        f"/attachments/{attachment_id}/content",
        data=data,
        headers={
            "Content-Type": "application/octet-stream",
            "Content-Transfer-Encoding": "binary",
        },
    )
    return attachment


def get_day_parent_note_id(dt: datetime) -> str:
    """
    note 模式：
    在 TRILIUM_PARENT_NOTE_ID 下按日期创建/复用归档节点。
    """
    day = dt.strftime("%Y-%m-%d")
    digest = hashlib.sha1(f"{TRILIUM_PARENT_NOTE_ID}:{day}".encode("utf-8")).hexdigest()[:16]
    day_note_id = f"wx{digest}"
    create_note(
        TRILIUM_PARENT_NOTE_ID,
        day,
        "book",
        "",
        note_id=day_note_id,
        is_expanded=True,
    )
    return day_note_id


def get_journal_day_note_id(dt: datetime) -> str:
    """
    journal 模式：
    获取 Trilium 指定日期的 Day Note。
    如果当天日记不存在，Trilium 会按 Calendar/Journal 机制创建它。
    """
    day = dt.strftime("%Y-%m-%d")
    resp = trilium_request("GET", f"/calendar/days/{day}")
    data = resp.json()

    note_id = data.get("noteId")
    if not note_id:
        raise RuntimeError(f"Trilium Journal Day Note 返回异常：{data}")

    return note_id


def get_target_parent_note_id(dt: datetime) -> str:
    """
    根据 TRILIUM_TARGET_MODE 二选一决定消息最终保存位置：

    note:
        TRILIUM_PARENT_NOTE_ID / YYYY-MM-DD / 消息

    journal:
        Trilium Journal / 当天 Day Note / 消息
    """
    if TRILIUM_TARGET_MODE == "journal":
        return get_journal_day_note_id(dt)

    return get_day_parent_note_id(dt)


def guess_extension(mime: str, fallback: str) -> str:
    ext = mimetypes.guess_extension((mime or "").split(";")[0].strip())
    if ext:
        return ext
    return fallback


def parse_filename_from_content_disposition(value: str) -> str:
    if not value:
        return ""
    msg = Message()
    msg["Content-Disposition"] = value
    filename = msg.get_filename() or ""
    return os.path.basename(filename)


def get_wechat_access_token() -> str:
    now = time.time()
    if _wechat_access_token["token"] and _wechat_access_token["expires_at"] > now + 60:
        return _wechat_access_token["token"]
    if not WECHAT_APP_ID or not WECHAT_APP_SECRET:
        raise RuntimeError("需要在 .env 配置 WECHAT_APP_ID 和 WECHAT_APP_SECRET 才能下载微信临时素材")

    resp = requests.get(
        "https://api.weixin.qq.com/cgi-bin/token",
        params={
            "grant_type": "client_credential",
            "appid": WECHAT_APP_ID,
            "secret": WECHAT_APP_SECRET,
        },
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    if "access_token" not in data:
        raise RuntimeError(f"获取微信 access_token 失败：{data}")

    expires_in = int(data.get("expires_in", 7200))
    _wechat_access_token["token"] = data["access_token"]
    _wechat_access_token["expires_at"] = now + max(expires_in - 300, 60)
    return data["access_token"]


def download_wechat_media(media_id: str, fallback_url: str = "", suggested_name: str = "wechat_media",
                          fallback_ext: str = ".bin", mime_hint: str = "") -> tuple[bytes, str, str]:
    errors = []

    if media_id and WECHAT_APP_ID and WECHAT_APP_SECRET:
        try:
            access_token = get_wechat_access_token()
            resp = requests.get(
                "https://api.weixin.qq.com/cgi-bin/media/get",
                params={"access_token": access_token, "media_id": media_id},
                timeout=30,
            )
            resp.raise_for_status()
            content_type = resp.headers.get("Content-Type", mime_hint or "application/octet-stream").split(";")[0]
            body = resp.content
            # 出错时微信会返回 JSON，而不是二进制素材。
            if content_type == "application/json" or body.lstrip().startswith(b"{"):
                try:
                    err = resp.json()
                except Exception:
                    err = body[:200].decode("utf-8", errors="replace")
                raise RuntimeError(f"下载微信临时素材失败：{err}")

            filename = parse_filename_from_content_disposition(resp.headers.get("Content-Disposition", ""))
            if not filename:
                filename = f"{suggested_name}{guess_extension(content_type or mime_hint, fallback_ext)}"
            return body, content_type or mime_hint or "application/octet-stream", filename
        except Exception as exc:
            errors.append(str(exc))

    if fallback_url:
        try:
            resp = requests.get(fallback_url, timeout=30)
            resp.raise_for_status()
            content_type = resp.headers.get("Content-Type", mime_hint or "application/octet-stream").split(";")[0]
            filename = f"{suggested_name}{guess_extension(content_type or mime_hint, fallback_ext)}"
            return resp.content, content_type or mime_hint or "application/octet-stream", filename
        except Exception as exc:
            errors.append(str(exc))

    raise RuntimeError("; ".join(errors) or "没有可下载的媒体地址")


def compact_text(value: str, limit: int = 32) -> str:
    """
    把消息内容压成适合 Note 标题的一行短文本。
    """
    value = " ".join((value or "").split())
    if len(value) <= limit:
        return value
    return value[:limit - 1].rstrip() + "…"


def message_footer_html(message: dict, dt: datetime) -> str:
    """
    默认只显示简洁来源信息。
    SHOW_MESSAGE_METADATA=true 时，额外显示技术字段，便于排查问题。
    """
    footer = (
        f'<p><small>来自微信 · {html.escape(dt.strftime("%H:%M:%S"))}</small></p>'
    )

    if not SHOW_MESSAGE_METADATA:
        return footer

    items = [
        ("FromUserName", message.get("FromUserName", "")),
        ("ToUserName", message.get("ToUserName", "")),
        ("MsgType", message.get("MsgType", "")),
        ("CreateTime", message.get("CreateTime", "")),
        ("MsgId", message.get("MsgId", "")),
        ("MediaId", message.get("MediaId", "")),
    ]

    rows = "".join(
        "<tr>"
        f"<td><strong>{html.escape(k)}</strong></td>"
        f"<td>{html.escape(v)}</td>"
        "</tr>"
        for k, v in items
        if v
    )

    if not rows:
        return footer

    return (
        f"{footer}"
        "<hr>"
        "<p><small><strong>消息信息</strong></small></p>"
        f"<table><tbody>{rows}</tbody></table>"
    )


def text_content_html(content: str, message: dict, dt: datetime) -> str:
    """
    文本消息采用普通段落显示，不再使用 <pre>，阅读体验更接近日记。
    """
    escaped = html.escape(content or "")
    body = escaped.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>")
    if not body:
        body = "<em>空文本消息</em>"

    return (
        f"<p>{body}</p>"
        "<hr>"
        f"{message_footer_html(message, dt)}"
    )


def save_text_message(message: dict, parent_note_id: str, dt: datetime) -> None:
    content = message.get("Content", "")
    preview = compact_text(content)

    if preview:
        title = f"微信 · 💬 {dt.strftime('%H:%M')} · {preview}"
    else:
        title = f"微信 · 💬 {dt.strftime('%H:%M')} · 文本"

    create_text_note(
        parent_note_id,
        title,
        text_content_html(content, message, dt),
    )


def save_image_message(message: dict, parent_note_id: str, dt: datetime) -> None:
    msg_id = message.get("MsgId") or str(int(time.time()))
    data, mime, filename = download_wechat_media(
        media_id=message.get("MediaId", ""),
        fallback_url=message.get("PicUrl", ""),
        suggested_name=f"wechat_image_{msg_id}",
        fallback_ext=".jpg",
        mime_hint="image/jpeg",
    )

    # 图片 Note 本身就是图片，不再把原始文件名堆进标题。
    title = f"微信 · 🖼️ {dt.strftime('%H:%M')} · 图片"
    create_binary_note(parent_note_id, title, "image", mime, data)


def save_voice_message(message: dict, parent_note_id: str, dt: datetime) -> None:
    fmt = (message.get("Format") or "amr").lower()
    mime_map = {
        "amr": "audio/amr",
        "speex": "audio/speex",
        "silk": "audio/silk",
        "mp3": "audio/mpeg",
    }

    mime_hint = mime_map.get(fmt, "application/octet-stream")
    ext = f".{fmt}" if fmt else ".amr"
    msg_id = message.get("MsgId") or str(int(time.time()))

    data, mime, filename = download_wechat_media(
        media_id=message.get("MediaId", ""),
        suggested_name=f"wechat_voice_{msg_id}",
        fallback_ext=ext,
        mime_hint=mime_hint,
    )

    recognition = (message.get("Recognition") or "").strip()
    preview = compact_text(recognition, 28)

    if preview:
        title = f"微信 · 🎙️ {dt.strftime('%H:%M')} · {preview}"
    else:
        title = f"微信 · 🎙️ {dt.strftime('%H:%M')} · 语音"

    if recognition:
        body = (
            f"<p>{html.escape(recognition)}</p>"
            f"<p><small>语音原文件：{html.escape(filename)}</small></p>"
        )
    else:
        body = (
            "<p><em>这条语音没有识别文字。</em></p>"
            f"<p><small>语音原文件：{html.escape(filename)}</small></p>"
        )

    content_html = (
        body
        + "<hr>"
        + message_footer_html(message, dt)
    )

    note = create_text_note(parent_note_id, title, content_html)
    create_attachment(note["note"]["noteId"], filename, "file", mime, data)


def save_fallback_message(message: dict, parent_note_id: str, dt: datetime, reason: str = "") -> None:
    msg_type = message.get("MsgType", "unknown")
    title = f"微信 · 📩 {dt.strftime('%H:%M')} · {msg_type}"

    visible_items = []
    for key, value in message.items():
        if key in {"FromUserName", "ToUserName", "CreateTime", "MsgId", "MediaId"}:
            continue
        if value:
            visible_items.append(
                f"<li><strong>{html.escape(str(key))}:</strong> "
                f"{html.escape(str(value))}</li>"
            )

    content_parts = []
    if reason:
        content_parts.append(
            f"<p><em>{html.escape(reason)}</em></p>"
        )
    if visible_items:
        content_parts.append("<ul>" + "".join(visible_items) + "</ul>")

    content_parts.append("<hr>")
    content_parts.append(message_footer_html(message, dt))

    create_text_note(
        parent_note_id,
        title,
        "".join(content_parts),
    )


def save_wechat_message(message: dict) -> None:
    msg_type = message.get("MsgType", "unknown")
    dt = get_message_datetime(message)

    try:
        parent_note_id = get_target_parent_note_id(dt)
        if msg_type == "text":
            save_text_message(message, parent_note_id, dt)
        elif msg_type == "image":
            save_image_message(message, parent_note_id, dt)
        elif msg_type == "voice":
            save_voice_message(message, parent_note_id, dt)
        else:
            save_fallback_message(message, parent_note_id, dt, f"暂未专门处理的消息类型：{msg_type}")
    except Exception as exc:
        app.logger.exception("failed to save %s message: %s", msg_type, exc)

        # 如果目标父节点已经成功解析，则至少尝试保留一条文本记录，
        # 方便排查媒体下载或上传失败。
        if "parent_note_id" in locals():
            try:
                save_fallback_message(message, parent_note_id, dt, str(exc))
            except Exception:
                app.logger.exception("failed to save fallback message")


def passive_text_reply(message: dict, content: str, encrypted: bool = False,
                       timestamp: str = "", nonce: str = "") -> Response:
    xml = f"""<xml>
<ToUserName><![CDATA[{message.get("FromUserName", "")}]]></ToUserName>
<FromUserName><![CDATA[{message.get("ToUserName", "")}]]></FromUserName>
<CreateTime>{int(time.time())}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[{content}]]></Content>
</xml>"""
    if encrypted:
        xml = encrypt_wechat_reply(xml, timestamp or str(int(time.time())), nonce or "nonce")
    return Response(xml, mimetype="application/xml")


def create_trilium_note(message: dict) -> None:
    """兼容旧函数名。"""
    save_wechat_message(message)


@app.get("/")
@app.get("/wechat")
def wechat_verify():
    signature = request.args.get("signature", "")
    timestamp = request.args.get("timestamp", "")
    nonce = request.args.get("nonce", "")
    echostr = request.args.get("echostr", "")

    if verify_wechat_signature(signature, timestamp, nonce):
        return Response(echostr, mimetype="text/plain")
    return Response("invalid signature", status=403, mimetype="text/plain")


@app.post("/")
@app.post("/wechat")
def wechat_message():
    signature = request.args.get("signature", "")
    timestamp = request.args.get("timestamp", "")
    nonce = request.args.get("nonce", "")
    encrypt_type = request.args.get("encrypt_type", "")
    msg_signature = request.args.get("msg_signature", "")

    try:
        encrypted_request = encrypt_type == "aes"

        if encrypted_request:
            outer_message = parse_wechat_xml(request.data)
            encrypted_payload = outer_message.get("Encrypt", "")
            if not verify_wechat_message_signature(msg_signature, timestamp, nonce, encrypted_payload):
                return Response("invalid msg_signature", status=403, mimetype="text/plain")
            message = decrypt_wechat_message(encrypted_payload)
        else:
            if not verify_wechat_signature(signature, timestamp, nonce):
                return Response("invalid signature", status=403, mimetype="text/plain")
            message = parse_wechat_xml(request.data)

        owner = is_owner(message)

        # 如果配置了 OWNER_OPENIDS 且 PROCESS_OWNER_ONLY=true，则只保存自己发来的消息。
        if PROCESS_OWNER_ONLY and OWNER_OPENIDS and not owner:
            return Response("success", mimetype="text/plain")

        if not is_duplicate(message):
            # 图片/语音下载可能超过微信 5 秒限制，放到后台线程保存。
            _executor.submit(save_wechat_message, message.copy())

        if owner and REPLY_TO_OWNER:
            return passive_text_reply(message, "已保存", encrypted_request, timestamp, nonce)
    except Exception as exc:
        # 微信要求 5 秒内响应。这里不把异常返回给微信，避免公众号提示服务不可用。
        app.logger.exception("failed to save wechat message: %s", exc)

    return Response("success", mimetype="text/plain")


@app.get("/healthz")
def healthz():
    return {"ok": True}


if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "8000")))
