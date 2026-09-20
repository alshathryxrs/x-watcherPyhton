import asyncio
import struct
import base64
import json
import httpx
import aiohttp
from datetime import datetime

# ==================== ACCOUNT CREDENTIALS ====================
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

NTFY_TOPIC = "JamilaActivatedHerXAccount"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) "
    "Gecko/20100101 Firefox/155.0"
)

HEARTBEAT_B64 = "DAACDAACAAAA"

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
    }.get(sender_id, f"User {sender_id}")

# ============================================================
# NTFY
# ============================================================

async def send_ntfy(title: str, message: str, retries: int = 3) -> None:
    rfc2047 = "=?UTF-8?B?" + base64.b64encode(title.encode()).decode() + "?="
    for attempt in range(1, retries + 1):
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                r = await client.post(
                    f"https://ntfy.sh/{NTFY_TOPIC}",
                    content=message.encode(),
                    headers={"Content-Type": "text/plain; charset=utf-8", "Title": rfc2047},
                )
            if r.is_success:
                if attempt > 1:
                    print(f"[{now()}] ✅ ntfy ok on attempt {attempt}")
                return
            print(f"[{now()}] ntfy HTTP {r.status_code} attempt {attempt}/{retries}")
        except Exception as e:
            print(f"[{now()}] ntfy failed attempt {attempt}/{retries}: {e}")
        if attempt < retries:
            await asyncio.sleep(2 * attempt)
    print(f"[{now()}] ❌ ntfy gave up — {title!r}")

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
        if not f12: return None
        if not f12.get(1) or not f12.get(2): return None
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

_typing_flags  = {}
_typing_timers = {}

async def on_typing(label: str, key: str, acct_label: str) -> None:
    loop = asyncio.get_event_loop()
    if not _typing_flags.get(key):
        _typing_flags[key] = True
        print(f"⌨️  [{now()}] [Acc{acct_label}] {label} is TYPING...")
        await send_ntfy(f"{label} {acct_label} ⌨️", f"{label} is typing...")
    old = _typing_timers.get(key)
    if old: old.cancel()
    def stop():
        _typing_flags[key] = False
        print(f"⏹️  [{now()}] [Acc{acct_label}] {label} STOPPED TYPING.\n" + "--"*25)
    _typing_timers[key] = loop.call_later(4.0, stop)

# ============================================================
# HANDLE FRAME
# ============================================================

async def handle_frame(buf: bytes, account: dict) -> None:
    tag   = f"[Acc{account['LABEL']}]"
    lbl   = account["LABEL"]
    my_id = account["MY_USER_ID"]

    seen = try_parse_seen(buf)
    if seen:
        if seen["reader_id"] == my_id: return
        name = get_label(seen["reader_id"])
        print(f"👁️  [{now()}] {tag} {name} SEEN your message!")
        await send_ntfy(f"{name} {lbl} 👁️", f"{name} has seen your message!")
        print("--"*25); return

    msg = try_parse_message(buf)
    if msg:
        sid = msg["sender_id"]
        if sid == my_id:
            print(f"↩️  [{now()}] {tag} OUTBOUND IGNORED"); return
        if my_id not in msg["conv_id"].split(":"):
            print(f"⚠️  [{now()}] {tag} Not a participant."); return
        name = get_label(sid)
        print(f"💬 [{now()}] {tag} {name} sent a MESSAGE!")
        await send_ntfy(f"{name} {lbl} 💬", f"{name} sent you a message!")
        print("--"*25); return

    try:
        cleaned = "".join(c if 0x20 <= ord(c) <= 0x7E else " "
                          for c in buf.decode("utf-8", errors="replace")).strip()
        typer_id = cleaned.split()[1] if len(cleaned.split()) > 1 else ""
    except: return

    if not typer_id or not typer_id.isdigit() or not (6 <= len(typer_id) <= 20): return
    if typer_id == my_id: return
    await on_typing(get_label(typer_id), typer_id, lbl)

# ============================================================
# FETCH WS TOKEN
# ============================================================

async def fetch_ws_url(account: dict) -> str:
    print(f"[{now()}] 🔄 [Acc{account['LABEL']}] Requesting fresh WS token...")
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
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
    data  = r.json()
    token = (
        (data.get("data") or {}).get("user_get_x_chat_auth_token", {}).get("token")
        or data.get("user_get_x_chat_auth_token", {}).get("token")
    )
    if not token:
        raise RuntimeError(f"Token not found: {str(data)[:200]}")
    return f"wss://chat-ws.x.com/ws?token={token}"

# ============================================================
# MONITOR — uses aiohttp WebSocket (stable API, no version drama)
# ============================================================

async def monitor(account: dict) -> None:
    tag     = f"[Acc{account['LABEL']}]"
    attempt = 0

    while True:
        attempt += 1
        backoff = min(1 * (2 ** (attempt - 1)), 60)

        try:
            ws_url = await fetch_ws_url(account)
            print(f"[{now()}] ✅ {tag} Token acquired! Connecting...")

            headers = {
                "User-Agent": USER_AGENT,
                "Origin":     "https://x.com",
                "Cookie":     f"auth_token={account['AUTH_TOKEN']}; ct0={account['CT0']};",
            }

            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(
                    ws_url,
                    headers=headers,
                    heartbeat=25,        # aiohttp sends ping every 25s — keeps Railway alive
                    
                ) as ws:
                    print(f"[{now()}] 🟢 {tag} ONLINE: Clearing backlog (1s)...")
                    await asyncio.sleep(1)
                    attempt = 0
                    print(f"⚡ {tag} NOW LISTENING\n")

                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.BINARY:
                            buf = msg.data
                            if base64.b64encode(buf).decode() == HEARTBEAT_B64:
                                continue
                            await handle_frame(buf, account)

                        elif msg.type == aiohttp.WSMsgType.TEXT:
                            buf = msg.data.encode()
                            await handle_frame(buf, account)

                        elif msg.type == aiohttp.WSMsgType.CLOSED:
                            print(f"[{now()}] 🔴 {tag} WS closed. Reconnecting in {backoff}s...")
                            break

                        elif msg.type == aiohttp.WSMsgType.ERROR:
                            print(f"[{now()}] ❌ {tag} WS error: {ws.exception()}")
                            break

        except Exception as e:
            print(f"[{now()}] ❌ {tag} Error: {e}. Retrying in {backoff}s...")

        await asyncio.sleep(backoff)

# ============================================================
# ENTRY POINT
# ============================================================

async def main():
    await asyncio.gather(
        monitor(ACCOUNT1),
        monitor(ACCOUNT2),
    )

if __name__ == "__main__":
    asyncio.run(main())
