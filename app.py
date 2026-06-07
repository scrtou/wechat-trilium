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
ARCHIVE_TIMEZONE = os.getenv("ARCHIVE_TIMEZONE", "Asia/Shanghai")
OWNER_OPENIDS = {
    item.strip()
    for item in os.getenv("OWNER_OPENIDS", "").replace(";", ",").split(",")
    if item.strip()
}
PROCESS_OWNER_ONLY = os.getenv("PROCESS_OWNER_ONLY", "true").lower() in {"1", "true", "yes", "on"}
REPLY_TO_OWNER = os.getenv("REPLY_TO_OWNER", "false").lower() in {"1", "true", "yes", "on"}

# 简单内存去重；生产多进程/多机器建议换 Redis/数据库。
_seen_msg_ids = {}
SEEN_TTL_SECONDS = 24 * 3600
_wechat_access_token = {"token": "", "expires_at": 0.0}
_executor = ThreadPoolExecutor(max_workers=int(os.getenv("SAVE_WORKERS", "2")))


try:
    _archive_tz = ZoneInfo(ARCHIVE_TIMEZONE)
except Exception:
    _archive_tz = timezone.utc


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


def metadata_html(message: dict) -> str:
    items = [
        ("FromUserName", message.get("FromUserName", "")),
        ("ToUserName", message.get("ToUserName", "")),
        ("MsgType", message.get("MsgType", "")),
        ("CreateTime", message.get("CreateTime", "")),
        ("MsgId", message.get("MsgId", "")),
        ("MediaId", message.get("MediaId", "")),
    ]
    lines = "\n".join(
        f"<li><strong>{html.escape(k)}:</strong> {html.escape(v)}</li>"
        for k, v in items
        if v
    )
    return f"<ul>{lines}</ul>"


def save_text_message(message: dict, parent_note_id: str, dt: datetime) -> None:
    title = f"文本 - {dt.strftime('%H:%M:%S')}"
    content = message.get("Content", "")
    content_html = f"""
<h1>{html.escape(title)}</h1>
{metadata_html(message)}
<pre>{html.escape(content)}</pre>
""".strip()
    create_text_note(parent_note_id, title, content_html)


def save_image_message(message: dict, parent_note_id: str, dt: datetime) -> None:
    title = f"图片 - {dt.strftime('%H:%M:%S')}"
    msg_id = message.get("MsgId") or str(int(time.time()))
    data, mime, filename = download_wechat_media(
        media_id=message.get("MediaId", ""),
        fallback_url=message.get("PicUrl", ""),
        suggested_name=f"wechat_image_{msg_id}",
        fallback_ext=".jpg",
        mime_hint="image/jpeg",
    )
    create_binary_note(parent_note_id, f"{title} - {filename}", "image", mime, data)


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

    recognition = message.get("Recognition", "")
    title = f"语音 - {dt.strftime('%H:%M:%S')}"
    if recognition:
        title = f"{title} - {recognition[:24]}"

    content_html = f"""
<h1>{html.escape(title)}</h1>
{metadata_html(message)}
<p><strong>格式:</strong> {html.escape(fmt)}</p>
<p><strong>语音识别:</strong> {html.escape(recognition or "无")}</p>
<p>音频文件已作为附件保存：{html.escape(filename)}</p>
""".strip()
    note = create_text_note(parent_note_id, title, content_html)
    create_attachment(note["note"]["noteId"], filename, "file", mime, data)


def save_fallback_message(message: dict, parent_note_id: str, dt: datetime, reason: str = "") -> None:
    msg_type = message.get("MsgType", "unknown")
    title = f"{msg_type} - {dt.strftime('%H:%M:%S')}"
    content_html = f"""
<h1>{html.escape(title)}</h1>
{metadata_html(message)}
{f"<p><strong>保存提示:</strong> {html.escape(reason)}</p>" if reason else ""}
<pre>{html.escape(str(message))}</pre>
""".strip()
    create_text_note(parent_note_id, title, content_html)


def save_wechat_message(message: dict) -> None:
    msg_type = message.get("MsgType", "unknown")
    dt = get_message_datetime(message)
    parent_note_id = get_day_parent_note_id(dt)

    try:
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
        # 至少保留一条文本记录，方便排查媒体下载或上传失败。
        save_fallback_message(message, parent_note_id, dt, str(exc))


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

    title = f"微信消息 - {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}"

    if msg_type == "text":
        content_text = message.get("Content", "")
    else:
        content_text = f"暂未专门处理的消息类型：{msg_type}\n原始字段：{message}"

    content_html = f"""
<h1>{html.escape(title)}</h1>
<ul>
  <li><strong>FromUserName:</strong> {html.escape(from_user)}</li>
  <li><strong>MsgType:</strong> {html.escape(msg_type)}</li>
  <li><strong>CreateTime:</strong> {html.escape(create_time)}</li>
</ul>
<pre>{html.escape(content_text)}</pre>
""".strip()

    url = f"{TRILIUM_BASE_URL}/etapi/create-note"
    payload = {
        "parentNoteId": TRILIUM_PARENT_NOTE_ID,
        "title": title,
        "type": "text",
        "content": content_html,
    }
    headers = {
        "Authorization": TRILIUM_ETAPI_TOKEN,
        "Content-Type": "application/json",
    }
    resp = requests.post(url, json=payload, headers=headers, timeout=10)
    resp.raise_for_status()


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
