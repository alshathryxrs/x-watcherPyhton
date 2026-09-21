import asyncio
import struct
import base64
import json
import httpx
import aiohttp
from datetime import datetime

# ==================== CREDENTIALS ====================
ACCOUNT1 = {
    "MY_USER_ID": "704772337",
    "AUTH_TOKEN": "000109a238c22edaed3918aacb3d8c0a4360d480",
    "CT0":        "6fd94ab6e318068f4e34c27c07d5b055541c8447ddc43e14d8ac0cedbe02a6efb5060c89092b47d6e071e61aca37496f44886a1c141abc20bb5aec817f214dcd2fbc7f22f39372ab5a8664ecb553f439",
    "LABEL":      "1",
}
ACCOUNT2 = {
    "MY_USER_ID": "2050569848002957312",
    "AUTH_TOKEN": "52374ce131bffe2766c9878c792f5e0074a200a1",
    "CT0":        "e0c6dab0995fa9426c647337b5b16678b75852d196a688526489efcfe924ed5cb288e87d5b43562e529f33af770670115413b85aa4f7f3b0f9edec945ab7f62811b4fafb8125de79722be7d8dc7e9e4c",
    "LABEL":      "2",
}

BEARER_TOKEN  = "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"

# ==================== USER ID FILTERS ====================
TARGET_USER_ID = "1885488902670000129"
REEM_USER_ID   = "954222428791681025"
NOORA_USER_ID  = "2082060317358743552"
JAMILA_USER_ID = "2024978767081254912"

TELEGRAM_TOKEN   = "8728595372:AAHL9A3WtjGGQ4042R3OoLPK5XN4IZs70vM"
TELEGRAM_CHAT_ID = "6607397366"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
HEARTBEAT_B64   = "DAACDAACAAAA"
PRESENCE_TIMEOUT = 6  # seconds of your inactivity before notifications resume

# ============================================================
# HELPERS
# ============================================================

def now() -> str:
    return datetime.now().strftime("%H:%M:%S")

def get_label(sender_id: str) -> str:
    return {
        TARGET_USER_ID: "Target",
        REEM_USER_ID:   "Reem",
        NOORA_USER_ID:  "Noora",
        JAMILA_USER_ID: "Jamila",
    }.get(sender_id, "Someone")

# ============================================================
# PRESENCE — mute notifications when YOU are in the chat
# ============================================================

_presence: dict[str, asyncio.TimerHandle] = {}

def mark_presence(conv_id: str) -> None:
    loop = asyncio.get_event_loop()
    old  = _presence.get(conv_id)
    if old:
        old.cancel()
    def expire():
        _presence.pop(conv_id, None)
    _presence[conv_id] = loop.call_later(PRESENCE_TIMEOUT, expire)

def is_muted(conv_id: str) -> bool:
    return conv_id in _presence

# ============================================================
# NTFY
# ============================================================

async def send_ntfy(title: str, message: str) -> None:
    text = f"*{title}*\n{message}"
    url  = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    for attempt in range(1, 4):
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                r = await client.post(url, json={
                    "chat_id":    TELEGRAM_CHAT_ID,
                    "text":       text,
                    "parse_mode": "Markdown",
                })
            if r.is_success:
                return
        except Exception as e:
            print(f"[{now()}] Telegram attempt {attempt}/3 failed: {type(e).__name__}: {e}")
        if attempt < 3:
            await asyncio.sleep(2 * attempt)

# ============================================================
# THRIFT PARSER
# ============================================================

def parse_thrift(buf: bytes, offset: int):
    fields = {}
    while offset < len(buf):
        if offset + 3 > len(buf): break
        type_id = buf[offset]
        field   = struct.unpack_from(">H", buf, offset + 1)[0]
        offset += 3
        if type_id == 0: break
        if type_id == 11:
            if offset + 4 > len(buf): break
            ln = struct.unpack_from(">I", buf, offset)[0]; offset += 4
            if offset + ln > len(buf): break
            fields[field] = buf[offset:offset+ln].decode("utf-8", errors="replace"); offset += ln
        elif type_id == 12:
            inner, offset = parse_thrift(buf, offset); fields[field] = inner
        elif type_id == 15:
            if offset + 5 > len(buf): break
            et = buf[offset]; offset += 1
            cnt = struct.unpack_from(">I", buf, offset)[0]; offset += 4
            lst = []
            for _ in range(cnt):
                if et == 12:
                    inner, offset = parse_thrift(buf, offset); lst.append(inner)
                elif et == 11:
                    if offset + 4 > len(buf): break
                    ln = struct.unpack_from(">I", buf, offset)[0]; offset += 4
                    if offset + ln > len(buf): break
                    lst.append(buf[offset:offset+ln].decode("utf-8", errors="replace")); offset += ln
                else: break
            fields[field] = lst
        elif type_id == 10:
            if offset + 8 > len(buf): break
            hi, lo = struct.unpack_from(">II", buf, offset)
            fields[field] = hi * 4_294_967_296 + lo; offset += 8
        elif type_id == 8:
            if offset + 4 > len(buf): break
            fields[field] = struct.unpack_from(">i", buf, offset)[0]; offset += 4
        elif type_id == 2:
            if offset >= len(buf): break
            fields[field] = buf[offset]; offset += 1
        else: break
    return fields, offset

# ============================================================
# FRAME PARSERS
# ============================================================

def try_parse_seen(buf):
    try:
        root, _ = parse_thrift(buf, 0)
        outer = root.get(1)
        if not outer: return None
        rid = str(outer.get(3, ""))
        if not rid.isdigit() or not (6 <= len(rid) <= 20): return None
        cid = str(outer.get(4, ""))
        if ":" not in cid: return None
        f7 = outer.get(7)
        if not f7: return None
        f12 = f7.get(12)
        if not f12 or not f12.get(1) or not f12.get(2): return None
        return {"reader_id": rid, "conv_id": cid}
    except: return None

def try_parse_message(buf):
    try:
        root, _ = parse_thrift(buf, 0)
        outer = root.get(1)
        if not outer: return None
        sid = str(outer.get(3, ""))
        if not sid.isdigit() or not (6 <= len(sid) <= 20): return None
        cid = str(outer.get(4, ""))
        if ":" not in cid: return None
        f7 = outer.get(7)
        if not f7: return None
        f1 = f7.get(1)
        if not f1 or f1.get(102) != 1: return None
        mid = outer.get(1)
        if not mid or not f1.get(104): return None
        return {"sender_id": sid, "conv_id": cid, "msg_id": str(mid)}
    except: return None

# ============================================================
# TYPING STATE
# ============================================================

_typing_flags:  dict = {}
_typing_timers: dict = {}

async def on_typing(label: str, key: str, acct_label: str) -> None:
    loop = asyncio.get_event_loop()
    if not _typing_flags.get(key):
        _typing_flags[key] = True
        if not is_muted(key):
            asyncio.create_task(send_ntfy(f"{label} {acct_label} ⌨️", f"{label} is typing..."))
    old = _typing_timers.get(key)
    if old: old.cancel()
    def stop():
        _typing_flags[key] = False
    _typing_timers[key] = loop.call_later(4.0, stop)

# ============================================================
# HANDLE FRAME
# ============================================================

async def handle_frame(buf: bytes, account: dict) -> None:
    lbl   = account["LABEL"]
    my_id = account["MY_USER_ID"]

    # ── READ RECEIPT ──────────────────────────────────────────
    seen = try_parse_seen(buf)
    if seen:
        if seen["reader_id"] == my_id:
            mark_presence(seen["conv_id"])  # YOU opened the chat → mute
            return
        if is_muted(seen["conv_id"]): return
        name = get_label(seen["reader_id"])
        asyncio.create_task(send_ntfy(f"{name} {lbl} 👁️", f"{name} has seen your message!"))
        return

    # ── NEW MESSAGE ───────────────────────────────────────────
    msg = try_parse_message(buf)
    if msg:
        sid = msg["sender_id"]
        if sid == my_id:
            mark_presence(msg["conv_id"])  # YOU sent → mute
            return
        if my_id not in msg["conv_id"].split(":"): return
        if is_muted(msg["conv_id"]): return
        name = get_label(sid)
        asyncio.create_task(send_ntfy(f"{name} {lbl} 💬", f"{name} sent you a message!"))
        return

    # ── TYPING ────────────────────────────────────────────────
    try:
        cleaned  = "".join(c if 0x20 <= ord(c) <= 0x7E else " "
                           for c in buf.decode("utf-8", errors="replace")).strip()
        typer_id = cleaned.split()[1] if len(cleaned.split()) > 1 else ""
    except: return

    if not typer_id or not typer_id.isdigit() or not (6 <= len(typer_id) <= 20): return

    if typer_id == my_id:
        # YOUR typing frame — find conv from cleaned text if possible, else skip
        mark_presence(typer_id)  # best effort presence signal
        return

    if is_muted(typer_id): return
    await on_typing(get_label(typer_id), typer_id, lbl)

# ============================================================
# FETCH WS TOKEN
# ============================================================

async def fetch_ws_url(account: dict) -> str:
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.post(
            "https://api.x.com/graphql/Qh3fZRjPPtPoHYR_2sCZsA/GenerateXChatTokenMutation",
            headers={
                "User-Agent":    USER_AGENT,
                "Accept":        "application/json",
                "Content-Type":  "application/json",
                "x-csrf-token":  account["CT0"],
                "authorization": BEARER_TOKEN,
                "Cookie":        f"auth_token={account['AUTH_TOKEN']}; ct0={account['CT0']};",
                "Origin":        "https://x.com",
                "Referer":       "https://x.com/",
            },
            content=json.dumps({"variables": {}}).encode(),
        )
    if not r.is_success:
        raise RuntimeError(f"Token fetch failed: HTTP {r.status_code}")
    data  = r.json()
    token = (
        (data.get("data") or {}).get("user_get_x_chat_auth_token", {}).get("token")
        or data.get("user_get_x_chat_auth_token", {}).get("token")
    )
    if not token:
        raise RuntimeError("Token not found in response")
    return f"wss://chat-ws.x.com/ws?token={token}"

# ============================================================
# MONITOR
# ============================================================

async def monitor(account: dict) -> None:
    tag     = f"[Acc{account['LABEL']}]"
    attempt = 0

    while True:
        attempt += 1
        backoff = min(2 ** (attempt - 1), 60)

        try:
            ws_url = await fetch_ws_url(account)

            # NO heartbeat — let the server's own frames keep it alive.
            # aiohttp heartbeat was crashing the socket on Railway.
            connector = aiohttp.TCPConnector(force_close=False, enable_cleanup_closed=True)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.ws_connect(
                    ws_url,
                    headers={
                        "User-Agent": USER_AGENT,
                        "Origin":     "https://x.com",
                        "Cookie":     f"auth_token={account['AUTH_TOKEN']}; ct0={account['CT0']};",
                    },
                    receive_timeout=90,   # reconnect if silent >90s
                    autoclose=True,
                    autoping=True,        # respond to server pings — keeps socket alive
                ) as ws:
                    print(f"[{now()}] 🟢 {tag} CONNECTED")
                    await asyncio.sleep(1)  # drain backlog
                    attempt = 0

                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.BINARY:
                            buf = msg.data
                            if base64.b64encode(buf).decode() == HEARTBEAT_B64:
                                continue
                            await handle_frame(buf, account)

                        elif msg.type == aiohttp.WSMsgType.TEXT:
                            await handle_frame(msg.data.encode(), account)

                        elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING):
                            print(f"[{now()}] 🔴 {tag} WS closed — reconnecting in {backoff}s")
                            break

                        elif msg.type == aiohttp.WSMsgType.ERROR:
                            print(f"[{now()}] ❌ {tag} WS error: {ws.exception()} — reconnecting in {backoff}s")
                            break

        except asyncio.TimeoutError:
            print(f"[{now()}] ⏱ {tag} No data for 90s — reconnecting in {backoff}s")
        except Exception as e:
            print(f"[{now()}] ❌ {tag} {type(e).__name__}: {e} — reconnecting in {backoff}s")

        await asyncio.sleep(backoff)

# ============================================================
# ENTRY POINT — return_exceptions=True prevents silent death
# ============================================================

async def main():
    results = await asyncio.gather(
        monitor(ACCOUNT1),
        monitor(ACCOUNT2),
        return_exceptions=True,
    )
    for i, r in enumerate(results, 1):
        if isinstance(r, Exception):
            print(f"[{now()}] 💀 Account {i} died: {r}")

if __name__ == "__main__":
    asyncio.run(main())
