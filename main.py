import asyncio
import struct
import base64
import time
import json
import httpx
import websockets
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

# ==================== NTFY ====================
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
# NTFY — async, 3 retries, exponential backoff
# ============================================================

async def send_ntfy(title: str, message: str, retries: int = 3) -> None:
    rfc2047 = (
        "=?UTF-8?B?"
        + base64.b64encode(title.encode()).decode()
        + "?="
    )
    for attempt in range(1, retries + 1):
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                r = await client.post(
                    f"https://ntfy.sh/{NTFY_TOPIC}",
                    content=message.encode(),
                    headers={
                        "Content-Type": "text/plain; charset=utf-8",
                        "Title":        rfc2047,
                    },
                )
            if r.is_success:
                if attempt > 1:
                    print(f"[{now()}] ✅ ntfy succeeded on attempt {attempt}")
                return
            print(f"[{now()}] ntfy HTTP {r.status_code} attempt {attempt}/{retries}")
        except Exception as e:
            print(f"[{now()}] ntfy failed attempt {attempt}/{retries}: {e}")

        if attempt < retries:
            await asyncio.sleep(2 * attempt)  # 2s, 4s

    print(f"[{now()}] ❌ ntfy gave up after {retries} attempts — {title!r}")

# ============================================================
# THRIFT BINARY PARSER
# ============================================================

def parse_thrift(buf: bytes, offset: int) -> tuple[dict, int]:
    fields: dict = {}

    while offset < len(buf):
        if offset + 3 > len(buf):
            break

        type_id = buf[offset]
        field   = struct.unpack_from(">H", buf, offset + 1)[0]
        offset += 3

        if type_id == 0:
            break

        # STRING
        if type_id == 11:
            if offset + 4 > len(buf):
                break
            length = struct.unpack_from(">I", buf, offset)[0]
            offset += 4
            if offset + length > len(buf):
                break
            fields[field] = buf[offset:offset + length].decode("utf-8", errors="replace")
            offset += length

        # STRUCT
        elif type_id == 12:
            inner, offset = parse_thrift(buf, offset)
            fields[field] = inner

        # LIST
        elif type_id == 15:
            if offset + 5 > len(buf):
                break
            elem_type = buf[offset]
            offset += 1
            count = struct.unpack_from(">I", buf, offset)[0]
            offset += 4
            lst = []
            for _ in range(count):
                if elem_type == 12:
                    inner, offset = parse_thrift(buf, offset)
                    lst.append(inner)
                elif elem_type == 11:
                    if offset + 4 > len(buf):
                        break
                    length = struct.unpack_from(">I", buf, offset)[0]
                    offset += 4
                    if offset + length > len(buf):
                        break
                    lst.append(buf[offset:offset + length].decode("utf-8", errors="replace"))
                    offset += length
                else:
                    break
            fields[field] = lst

        # I64
        elif type_id == 10:
            if offset + 8 > len(buf):
                break
            hi, lo = struct.unpack_from(">II", buf, offset)
            fields[field] = hi * 4_294_967_296 + lo
            offset += 8

        # I32
        elif type_id == 8:
            if offset + 4 > len(buf):
                break
            fields[field] = struct.unpack_from(">i", buf, offset)[0]
            offset += 4

        # BOOL
        elif type_id == 2:
            if offset >= len(buf):
                break
            fields[field] = buf[offset]
            offset += 1

        else:
            break

    return fields, offset

# ============================================================
# FRAME PARSERS
# ============================================================

def try_parse_seen(buf: bytes) -> dict | None:
    try:
        root, _ = parse_thrift(buf, 0)
        outer = root.get(1)
        if not outer:
            return None

        reader_id = str(outer.get(3, ""))
        if not reader_id or not reader_id.isdigit() or not (6 <= len(reader_id) <= 20):
            return None

        conv_id = str(outer.get(4, ""))
        if ":" not in conv_id:
            return None

        f7 = outer.get(7)
        if not f7:
            return None
        f12 = f7.get(12)
        if not f12:
            return None

        seen_msg_id = f12.get(1)
        seen_at     = f12.get(2)
        if not seen_msg_id or not seen_at:
            return None

        return {
            "reader_id":    reader_id,
            "conv_id":      conv_id,
            "seen_msg_id":  str(seen_msg_id),
            "seen_at":      seen_at,
        }
    except Exception:
        return None


def try_parse_message(buf: bytes) -> dict | None:
    try:
        root, _ = parse_thrift(buf, 0)
        outer = root.get(1)
        if not outer:
            return None

        sender_id = str(outer.get(3, ""))
        if not sender_id or not sender_id.isdigit() or not (6 <= len(sender_id) <= 20):
            return None

        conv_id = str(outer.get(4, ""))
        if ":" not in conv_id:
            return None

        f7 = outer.get(7)
        if not f7:
            return None
        f1 = f7.get(1)
        if not f1:
            return None
        if f1.get(102) != 1:
            return None

        msg_id = outer.get(1)
        sent_at = f1.get(104)
        if not msg_id or not sent_at:
            return None

        return {
            "sender_id": sender_id,
            "conv_id":   conv_id,
            "msg_id":    str(msg_id),
            "sent_at":   sent_at,
        }
    except Exception:
        return None

# ============================================================
# TYPING STATE (shared, protected by asyncio single-thread)
# ============================================================

class TypingState:
    def __init__(self):
        self.flags:  dict[str, bool]               = {}
        self.timers: dict[str, asyncio.TimerHandle] = {}

    def is_typing(self, key: str) -> bool:
        return self.flags.get(key, False)

    def set_typing(self, key: str, value: bool):
        self.flags[key] = value

    def get_timer(self, key: str):
        return self.timers.get(key)

    def set_timer(self, key: str, handle):
        self.timers[key] = handle

typing = TypingState()

async def on_typing(label: str, key: str, acct_label: str) -> None:
    loop = asyncio.get_event_loop()

    if not typing.is_typing(key):
        typing.set_typing(key, True)
        print(f"⌨️  [{now()}] [Acc{acct_label}] {label} is TYPING...")
        await send_ntfy(f"{label} {acct_label} ⌨️", f"{label} is typing...")

    old = typing.get_timer(key)
    if old:
        old.cancel()

    def stop():
        typing.set_typing(key, False)
        print(
            f"⏹️  [{now()}] [Acc{acct_label}] {label} STOPPED TYPING.\n"
            + "--" * 25
        )

    typing.set_timer(key, loop.call_later(4.0, stop))

# ============================================================
# HANDLE INCOMING FRAME
# ============================================================

async def handle_frame(buf: bytes, account: dict) -> None:
    tag   = f"[Acc{account['LABEL']}]"
    label = account["LABEL"]
    my_id = account["MY_USER_ID"]

    # ── READ RECEIPT ─────────────────────────────────────────
    seen = try_parse_seen(buf)
    if seen:
        if seen["reader_id"] == my_id:
            return
        name = get_label(seen["reader_id"])
        print(f"👁️  [{now()}] {tag} {name} SEEN your message!")
        await send_ntfy(f"{name} {label} 👁️", f"{name} has seen your message!")
        print("--" * 25)
        return

    # ── NEW MESSAGE ───────────────────────────────────────────
    msg = try_parse_message(buf)
    if msg:
        sender_id = msg["sender_id"]

        if sender_id == my_id:
            print(f"↩️  [{now()}] {tag} OUTBOUND IGNORED (sender={sender_id})")
            return

        participants = msg["conv_id"].split(":")
        if my_id not in participants:
            print(f"⚠️  [{now()}] {tag} Message ignored — not a participant.")
            return

        name = get_label(sender_id)
        print(f"💬 [{now()}] {tag} {name} sent you a MESSAGE! (id={msg['msg_id']})")
        await send_ntfy(f"{name} {label} 💬", f"{name} sent you a message!")
        print("--" * 25)
        return

    # ── TYPING ────────────────────────────────────────────────
    try:
        raw     = buf.decode("utf-8", errors="replace")
        cleaned = "".join(c if 0x20 <= ord(c) <= 0x7E else " " for c in raw).strip()
        parts   = cleaned.split()
        typer_id = parts[1] if len(parts) > 1 else ""
    except Exception:
        return

    if not typer_id or not typer_id.isdigit() or not (6 <= len(typer_id) <= 20):
        return
    if typer_id == my_id:
        return

    key  = typer_id
    name = get_label(typer_id)
    await on_typing(name, key, label)

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
        raise RuntimeError(f"Token not found in response: {str(data)[:200]}")

    return f"wss://chat-ws.x.com/ws?token={token}"

# ============================================================
# MONITOR ONE ACCOUNT
# ============================================================

async def monitor(account: dict) -> None:
    tag     = f"[Acc{account['LABEL']}]"
    attempt = 0

    while True:
        attempt += 1
        backoff = min(1 * (2 ** (attempt - 1)), 60)  # 1s, 2s, 4s … 60s

        try:
            ws_url = await fetch_ws_url(account)
            print(f"[{now()}] ✅ {tag} Token acquired! Connecting...")

            headers = {
                "User-Agent": USER_AGENT,
                "Origin":     "https://x.com",
                "Cookie":     f"auth_token={account['AUTH_TOKEN']}; ct0={account['CT0']};",
            }

            async with websockets.connect(
                ws_url,
                extra_headers=headers,
                ping_interval=25,      # sends WS ping every 25s — keeps Railway alive
                ping_timeout=10,
                open_timeout=15,
            ) as ws:
                print(f"[{now()}] 🟢 {tag} ONLINE: Clearing backlog (1s)...")
                await asyncio.sleep(1)
                attempt = 0            # reset backoff on successful connect
                print(f"⚡ {tag} NOW LISTENING\n")

                async for raw in ws:
                    buf = raw if isinstance(raw, bytes) else raw.encode()

                    # Heartbeat — ignore
                    if base64.b64encode(buf).decode() == HEARTBEAT_B64:
                        continue

                    await handle_frame(buf, account)

        except websockets.exceptions.ConnectionClosed as e:
            print(
                f"[{now()}] 🔴 {tag} Disconnected "
                f"(code={e.code}, reason={e.reason or 'none'}). "
                f"Reconnecting in {backoff}s..."
            )
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
