#!/usr/bin/env python3
"""Pookie - secure multi-user WhatsApp AI assistant (replacement for assistant.py).

Run the bot:           python assistant.py            (same as: python assistant.py run)
One-time setup:        python assistant.py init
Per-user Gemini key:   python assistant.py set-key friend1      (hidden prompt)
Other private tools:   remove-key LABEL | rebind LABEL | check-model | backup | agents
"""

import argparse
import getpass
import logging
import os
import signal
import stat
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

try:
    from dotenv import load_dotenv
    load_dotenv(BASE_DIR / ".env")
except ImportError:  # python-dotenv is optional at import time
    pass

import pookie_features as fx
from pookie_app import Pookie
from pookie_config import load_agent_specs
from pookie_db import LABEL_RE, Database, KeyVault, SecretRedactor, VaultError
from pookie_runner import AgentRunner, Supervisor

# ---------------- CONFIGURATION ----------------

OWNER_LABEL = os.environ.get("POOKIE_OWNER_LABEL", "owner").strip().lower()
DB_PATH = Path(os.environ.get("POOKIE_DB") or BASE_DIR / "pookie.db")
KEY_FILE = BASE_DIR / ".pookie.key"
DOWNLOAD_DIR = BASE_DIR / "downloads"          # same folder as the original script

log = logging.getLogger("pookie")
redactor = SecretRedactor()


def setup_logging():
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", "%H:%M:%S"))
    handler.addFilter(redactor)                 # masks tokens/keys in EVERY log line
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def register_secrets():
    for name, value in os.environ.items():
        if name.startswith("POOKIE_TOKEN_") or name in (
            "WHATSAPP_AGENT_TOKEN", "GEMINI_API_KEY", "BRAVE_API_KEY",
            "YOUTUBE_API_KEY", "POOKIE_MASTER_KEY",
        ):
            redactor.add(value.strip())


def warn_permissions():
    for path in (BASE_DIR / ".env", KEY_FILE, DB_PATH):
        try:
            if path.exists() and stat.S_IMODE(path.stat().st_mode) & 0o077:
                log.warning("%s is readable by other users. Run: chmod 600 %s", path.name, path.name)
        except OSError:
            pass


def open_database():
    vault = KeyVault(KEY_FILE)
    return Database(DB_PATH, vault), vault


# ---------------- WHATSAPP GLUE ----------------

def identity_from_ctx(ctx):
    """Sender id and agent id exactly as the API delivered them (whagent
    Message.sender and Update.agent_id). Missing attributes give None, in which
    case only the per-agent token mapping is used."""
    message = getattr(ctx, "message", None)
    update = getattr(ctx, "update", None)
    return getattr(message, "sender", None), getattr(update, "agent_id", None)


def send_out(ctx, out):
    if out.preview:
        client = getattr(ctx, "client", None)
        message = getattr(ctx, "message", None)
        sender = getattr(message, "sender", None)
        if client is not None and sender:
            try:
                client.send_text(sender, out.text, preview_url=True,
                                 reply_to=getattr(message, "id", None) or None)
                return
            except Exception as exc:  # noqa: BLE001 - fall back to a normal reply
                log.warning("Preview send failed (%s); using plain reply", type(exc).__name__)
    try:
        ctx.reply(str(out.text)[:3500])
    except Exception as exc:  # noqa: BLE001
        log.warning("Reply error: %s", type(exc).__name__)


def build_agent(spec, app):
    """One Agent per token. The handler closes over this agent's label, so a
    message can only ever act with the permissions of the account that
    received it."""
    from whagent import Agent, FileOffsetStore

    agent = Agent(spec.token, offset_store=FileOffsetStore(str(spec.offset_path)))
    label = spec.label
    warned = []

    @agent.on_text
    def handle_message(ctx):
        started = time.perf_counter()
        sender, agent_id = identity_from_ctx(ctx)
        if sender is None and not warned:
            warned.append(True)
            log.warning("[%s] ctx exposes no sender id; identity binding is OFF for this agent "
                        "(token-per-agent mapping still applies).", label)
        out = app.handle(label, ctx.text or "", sender=sender, agent_id=agent_id)
        if out is not None:
            send_out(ctx, out)
        log.info("[%s] handled in %.2fs", label, time.perf_counter() - started)  # no content logged

    return agent


# ---------------- COMMANDS ----------------

def cmd_run(_args):
    setup_logging()
    register_secrets()
    specs, skipped = load_agent_specs(os.environ, BASE_DIR, OWNER_LABEL)
    if not any(s.is_owner for s in specs):
        raise SystemExit("API key missing. Set WHATSAPP_AGENT_TOKEN in .env first.")
    for label, reason in skipped:
        log.warning("Skipped agent '%s': %s", label, reason)

    db, vault = open_database()
    for spec in specs:
        db.ensure_user(spec.label, spec.is_owner)
    DOWNLOAD_DIR.mkdir(exist_ok=True)
    warn_permissions()
    if not vault.available:
        log.warning("Key encryption unavailable (%s): per-user Gemini keys cannot be stored.",
                    vault.problem)
    if vault.permission_warning:
        log.warning(vault.permission_warning)
    if not (os.environ.get("GEMINI_API_KEY") or "").strip():
        log.warning("GEMINI_API_KEY not set: admin /ai will not work.")

    from whagent.errors import AuthenticationError, InvalidRequestError, PollReplacedError
    fatal = (AuthenticationError, InvalidRequestError, PollReplacedError)

    app = Pookie(db, OWNER_LABEL, os.environ, DOWNLOAD_DIR, redactor=redactor)
    runners = [AgentRunner(spec, lambda s: build_agent(s, app), fatal) for spec in specs]
    supervisor = Supervisor(runners)
    app.status_provider = supervisor.statuses

    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    log.info("Pookie starting with %d agent(s): %s", len(specs), ", ".join(s.label for s in specs))
    log.info("Downloads folder: %s", DOWNLOAD_DIR)
    log.info("WhatsApp par /help bhej kar test karo. Stop karne ke liye Ctrl+C dabao.")
    supervisor.start()

    interrupted = False
    try:
        while supervisor.any_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        interrupted = True
        log.info("Shutting down (can take up to ~25s while polls finish)...")
    finally:
        supervisor.stop(timeout=30)
        db.close()
    if not interrupted:
        log.error("All agents have stopped. Check statuses above (revoked token or duplicate poller?).")
        sys.exit(1)
    log.info("Stopped cleanly.")


def _db_with_users():
    setup_logging()
    register_secrets()
    db, vault = open_database()
    specs, _ = load_agent_specs(os.environ, BASE_DIR, OWNER_LABEL)
    for spec in specs:
        db.ensure_user(spec.label, spec.is_owner)
    return db, vault


def _need_label(db, label):
    label = (label or "").lower()
    user = db.get_user(label) if LABEL_RE.match(label) else None
    if user is None:
        raise SystemExit(f"Unknown user '{label}'. Configure its POOKIE_TOKEN_<LABEL> in .env first.")
    return user


def cmd_init(_args):
    setup_logging()
    if os.environ.get("POOKIE_MASTER_KEY"):
        print("Master key comes from POOKIE_MASTER_KEY (not creating a file).")
    elif KEY_FILE.exists():
        print(f"{KEY_FILE.name} already exists - left untouched.")
    else:
        try:
            KeyVault.create_key_file(KEY_FILE)
            print(f"Created {KEY_FILE.name} (permissions 600). BACK IT UP somewhere safe:")
            print("without it, stored user keys cannot be decrypted.")
        except ImportError:
            print("'cryptography' is not installed: user keys cannot be stored. See SETUP.md.")
    db, vault = open_database()
    print("Database:", db.health()[1], "-", DB_PATH.name)
    print("Key encryption:", "active" if vault.available else f"unavailable ({vault.problem})")
    db.close()


def cmd_set_key(args):
    db, vault = _db_with_users()
    user = _need_label(db, args.label)
    if user["role"] == "admin":
        raise SystemExit("The admin uses GEMINI_API_KEY from .env; nothing to store.")
    if not vault.available:
        raise SystemExit(f"Cannot store keys: encryption unavailable ({vault.problem}).")
    key = getpass.getpass(f"Gemini API key for '{user['label']}' (input hidden): ").strip()
    if not (20 <= len(key) <= 256) or any(c.isspace() for c in key):
        raise SystemExit("That does not look like an API key. Nothing saved.")
    try:
        db.set_api_key(user["label"], key, "cli")
    except VaultError as exc:
        raise SystemExit(f"Not saved: {exc}")
    print(f"Saved (encrypted) for '{user['label']}'. Active immediately for a running Pookie.")
    if not user["ai_enabled"]:
        print(f"Reminder: AI is still OFF for them. In WhatsApp (admin): /ai {user['label']} on")


def cmd_remove_key(args):
    db, _vault = _db_with_users()
    user = _need_label(db, args.label)
    print("Removed." if db.delete_api_key(user["label"], "cli") else "No key was stored.")


def cmd_rebind(args):
    db, _vault = _db_with_users()
    user = _need_label(db, args.label)
    db.rebind(user["label"], "cli")
    print(f"Identity binding cleared for '{user['label']}'; it re-binds on the next message.")


def cmd_check_model(_args):
    setup_logging()
    register_secrets()
    key = (os.environ.get("GEMINI_API_KEY") or "").strip()
    model = os.environ.get("GEMINI_MODEL") or fx.DEFAULT_GEMINI_MODEL
    if not key:
        raise SystemExit("GEMINI_API_KEY is not set in .env.")
    ok, message = fx.check_gemini_model(key, model)
    print(("OK: " if ok else "PROBLEM: ") + message)
    sys.exit(0 if ok else 1)


def cmd_backup(_args):
    setup_logging()
    db, _vault = open_database()
    print("Backup written:", db.backup().name)
    db.close()


def cmd_agents(_args):
    specs, skipped = load_agent_specs(os.environ, BASE_DIR, OWNER_LABEL)
    for spec in specs:
        print(f"{spec.label:12} {'owner/admin' if spec.is_owner else 'user':12} offset: {spec.offset_path.name}")
    for label, reason in skipped:
        print(f"SKIPPED {label}: {reason}")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="assistant.py", description="Pookie WhatsApp assistant")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("run", help="start the bot (default)").set_defaults(func=cmd_run)
    sub.add_parser("init", help="create master key + database").set_defaults(func=cmd_init)
    for name, func, help_text in (
        ("set-key", cmd_set_key, "store a user's Gemini key (hidden prompt)"),
        ("remove-key", cmd_remove_key, "delete a user's stored key"),
        ("rebind", cmd_rebind, "clear a user's WhatsApp identity binding"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("label")
        p.set_defaults(func=func)
    sub.add_parser("check-model", help="verify GEMINI_MODEL with the API").set_defaults(func=cmd_check_model)
    sub.add_parser("backup", help="write a database backup").set_defaults(func=cmd_backup)
    sub.add_parser("agents", help="list configured agents (no tokens shown)").set_defaults(func=cmd_agents)
    args = parser.parse_args(argv)
    (args.func if args.command else cmd_run)(args)


if __name__ == "__main__":
    main()
