"""pookie_app.py - Pookie's brain: parsing, permissions, admin and user commands.

`Pookie.handle(label, text, sender, agent_id)` is the ONLY entry point. `label`
comes from the per-agent closure created in assistant.py (it identifies which
authenticated token received the message) - never from message text.

Every command passes through check_access() before it executes, and again
right before a queued expensive task starts, so a block / AI-off / kill switch
takes effect immediately and also cancels work that was waiting in the queue.
"""

import logging
import os
import re
import threading
import time
from dataclasses import dataclass

import requests

import pookie_features as fx
from pookie_db import FEATURES, DEFAULT_DAILY_LIMIT, RateLimiter

log = logging.getLogger("pookie.app")

MAX_REPLY = 3500            # same cap as the original script
USERS_PER_PAGE = 8
CONFIRM_TTL = 60            # seconds to confirm /remove-user

ALIASES = {"start": "/start", "hello": "/start", "hi": "/start", "help": "/help", "ping": "/ping"}

FEATURE_CMDS = {
    "/ai": "ai", "/search": "search", "/youtube": "youtube", "/play": "play",
    "/weather": "weather", "/calc": "calc", "/scrape": "scrape",
    "/download": "download", "/ytdl": "ytdl",
}
# Requests that cost network/CPU and count towards the daily limit.
COUNTED = {"ai", "search", "youtube", "play", "weather", "scrape", "download", "ytdl"}

ADMIN_COMMANDS = {
    "/admin", "/users", "/user", "/features", "/block", "/unblock",
    "/stats", "/health", "/audit", "/setlimit", "/remove-user",
}

USAGE = {
    "/ai": "Use: /ai apna sawal likho",
    "/search": "Use: /search your query   (phir /search 2 detail ke liye)",
    "/youtube": "Use: /youtube video search query",
    "/play": "Use: /play query   ya   /play 2 (pichli list se)",
    "/weather": "Use: /weather Lahore",
    "/calc": "Use: /calc (25*4)+10",
    "/scrape": "Use: /scrape https://example.com",
    "/download": "Use: /download https://example.com/file.pdf",
    "/ytdl": "Use: /ytdl VIDEO_URL",
}

HELP_LINES = {
    "ai": "/ai QUESTION - Ask Gemini AI",
    "search": "/search QUERY - Web search (then /search 2)",
    "youtube": "/youtube QUERY - YouTube search",
    "play": "/play QUERY or /play N - Pick a YouTube result",
    "weather": "/weather CITY - Current weather",
    "calc": "/calc EXPRESSION - Calculator",
    "scrape": "/scrape URL - Extract webpage text",
    "download": "/download URL - Download direct file (max 50 MB)",
    "ytdl": "/ytdl URL - Supported video download (max 50 MB)",
}

ADMIN_HELP = (
    "👑 ADMIN COMMANDS\n"
    "/admin - Dashboard\n"
    "/users [page] - List users\n"
    "/user ID - User profile\n"
    "/ai ID on|off - AI for one user\n"
    "/ai all off - EMERGENCY AI kill switch (/ai all on lifts it)\n"
    "/features ID [name on|off] - Feature permissions\n"
    "/block ID  |  /unblock ID\n"
    "/setlimit ID N - Daily request limit\n"
    "/remove-user ID - Disable user (asks to confirm)\n"
    "/stats  |  /health  |  /audit [N]"
)

MSG_UNKNOWN = "Unknown command. Available commands ke liye /help bhejo."
MSG_NOT_REGISTERED = "Yeh account Pookie mein registered/authorized nahi hai. Admin se rabta karo."
MSG_BLOCKED = "🚫 Aap ka account block hai. Admin se rabta karo."
MSG_REMOVED = "Yeh account ab active nahi hai. Admin se rabta karo."
MSG_IDENTITY = ("⚠️ Yeh chat registered account se match nahi karti. "
                "Admin ko account re-bind karna hoga.")
MSG_BUSY = "Server abhi busy hai. Thori dair baad dobara try karo."
MSG_NETWORK = "Network error hua. Internet connection check karke dobara try karo."
MSG_GENERIC = "Command complete nahi ho saki. Thori dair baad try karo."
MSG_KEY_IN_CHAT = ("⚠️ Is message mein API key lagti hai. Chat mein kabhi keys share na karo - "
                   "message delete kar do. Maine isay save ya use nahi kiya.")

KEY_LIKE = re.compile(r"AIza[0-9A-Za-z_\-]{30,}")
ADMIN_AI_RE = re.compile(r"^(\S+)\s+(on|off)$", re.IGNORECASE)


@dataclass
class Out:
    text: str
    preview: bool = False   # ask WhatsApp for a link preview (single-link messages)


@dataclass
class Decision:
    ok: bool
    message: str = ""


def _fmt_ts(ts):
    return (ts or "")[5:16].replace("T", " ")


class Pookie:
    def __init__(self, db, owner_label="owner", environ=None, download_dir=None,
                 max_concurrent=3, user_rate=(12, 60), global_rate=(120, 60),
                 limiter=None, selections=None, status_provider=None,
                 gemini_model=None, redactor=None, queue_wait=60):
        self.db = db
        self.owner_label = owner_label
        self.environ = os.environ if environ is None else environ
        self.download_dir = download_dir
        self.limiter = limiter or RateLimiter()
        self.user_rate = user_rate
        self.global_rate = global_rate
        self.selections = selections or fx.Selections()
        self.status_provider = status_provider
        self.model = (gemini_model or self.environ.get("GEMINI_MODEL")
                      or fx.DEFAULT_GEMINI_MODEL)
        self.redactor = redactor
        self._sem = threading.BoundedSemaphore(max_concurrent)
        self._queue_wait = queue_wait
        self._pending = {}
        self._pending_lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Identity and permissions
    # ------------------------------------------------------------------ #

    def is_admin(self, label):
        """Re-validated against the database on EVERY call."""
        user = self.db.get_user(label)
        return bool(user and user["role"] == "admin" and user["status"] == "active"
                    and label == self.owner_label)

    def resolve_ai_key(self, label):
        """The key for THIS account only. Admin uses GEMINI_API_KEY; everybody
        else uses their own stored key. There is no fallback between the two."""
        user = self.db.get_user(label)
        if user is None or user["status"] != "active":
            return None
        if user["role"] == "admin" and label == self.owner_label:
            return (self.environ.get("GEMINI_API_KEY") or "").strip() or None
        return self.db.get_api_key(label)

    def check_access(self, label, feature):
        user = self.db.get_user(label)
        if user is None:
            return Decision(False, MSG_NOT_REGISTERED)
        if user["status"] == "blocked":
            return Decision(False, MSG_BLOCKED)
        if user["status"] == "removed":
            return Decision(False, MSG_REMOVED)
        if feature == "ai":
            if self.db.global_ai_off():
                return Decision(False, "🛑 AI abhi admin ne sab ke liye temporarily band kiya hua hai.")
            if not user["ai_enabled"]:
                return Decision(False, "🤖 AI aap ke account par enabled nahi hai. Admin se request karo.")
            if user["ai_self_off"]:
                return Decision(False, "Aap ne AI khud OFF kiya hua hai. /myai on se dobara chalao.")
            if self.resolve_ai_key(label) is None:
                if user["role"] == "admin":
                    return Decision(False, "GEMINI_API_KEY .env mein set nahi hai.")
                return Decision(False, (
                    "🔑 Admin ne AI enable kar diya hai, lekin aap ki apni Gemini API key "
                    "configure nahi hai.\n\n"
                    "Key chat mein MAT bhejo. Free key aistudio.google.com/apikey se banao aur "
                    "admin ko secure tareeqe se do - admin server par private command "
                    "(set-key) se hidden prompt mein save karega. /mykey se status dekho."))
        elif not self.db.feature_enabled(label, feature):
            return Decision(False, f"🚫 Yeh feature aap ke account par disabled hai (/{feature}). "
                                   "Admin se request karo.")
        return Decision(True)

    # ------------------------------------------------------------------ #
    # Entry point
    # ------------------------------------------------------------------ #

    def handle(self, label, text, sender=None, agent_id=None):
        text = (text or "").strip()
        if not text:
            return None
        user = self.db.get_user(label)
        if user is None:
            return Out(MSG_NOT_REGISTERED)
        if not self.db.bind_identity(label, sender, agent_id):
            log.warning("Identity mismatch on agent '%s'; message refused", label)
            return Out(MSG_IDENTITY)
        if user["status"] == "blocked":
            return Out(MSG_BLOCKED)
        if user["status"] == "removed":
            return Out(MSG_REMOVED)

        allowed, wait = self.limiter.allow(f"user:{label}", *self.user_rate)
        if allowed:
            allowed, wait = self.limiter.allow("global", *self.global_rate)
        if not allowed:
            return Out(f"⏳ Bohat tez messages. {wait} second baad try karo.")

        if KEY_LIKE.search(text):
            return Out(MSG_KEY_IN_CHAT)

        parts = text.split(maxsplit=1)
        command = ALIASES.get(parts[0].lower(), parts[0].lower())
        argument = parts[1].strip() if len(parts) > 1 else ""

        try:
            out = self._dispatch(label, command, argument)
        except Exception as exc:  # noqa: BLE001 - never leak details to chat
            log.error("Handler error (%s) for command %s", type(exc).__name__, command[:20])
            out = Out(MSG_GENERIC)
        out.text = out.text[:MAX_REPLY]
        return out

    def _dispatch(self, label, command, argument):
        admin = self.is_admin(label)

        if command in ADMIN_COMMANDS:
            if not admin:
                self.db.audit(label, "admin_denied", None, command)
                return Out(MSG_UNKNOWN)          # same reply as any unknown command
            return Out(self._admin_command(label, command, argument))

        if command == "/ai" and admin:
            match = ADMIN_AI_RE.match(argument)
            if match:
                target = match.group(1).lower()
                if target == "all" or self.db.get_user(target):
                    return Out(self._admin_ai(label, target, match.group(2).lower()))

        if command == "/start":
            return Out("Assalam-o-Alaikum! 👋\nMain Pookie hoon, aap ka WhatsApp assistant.\n"
                       "Available commands ke liye /help bhejo.")
        if command == "/help":
            return Out(self._help(label, admin))
        if command == "/ping":
            return Out("Pong! ✅ Connection working.")
        if command == "/about":
            return Out("Pookie - a Python WhatsApp assistant.\n"
                       "Har user ke permissions admin control karta hai.\n"
                       "Yeh tab tak chalta hai jab tak Termux script chal rahi hai.")
        if command == "/myai":
            return Out(self._myai(label, argument))
        if command == "/mykey":
            return Out(self._mykey(label, argument))

        feature = FEATURE_CMDS.get(command)
        if feature is None:
            return Out(MSG_UNKNOWN)
        return self._feature_command(label, command, feature, argument, admin)

    # ------------------------------------------------------------------ #
    # Feature commands (central permission + limit + concurrency path)
    # ------------------------------------------------------------------ #

    def _feature_command(self, label, command, feature, argument, admin):
        decision = self.check_access(label, feature)
        if not decision.ok:
            return Out(decision.message)
        if not argument:
            return Out(USAGE[command])

        if command in ("/search", "/play") and argument.isdigit():
            return self._select(label, command, int(argument))   # no quota, no network

        if feature == "calc":                                     # local and cheap
            try:
                return Out(f"🧮 Result: {fx.calculate(argument)}")
            except (ValueError, SyntaxError, ZeroDivisionError, OverflowError) as exc:
                return Out(f"Input error: {exc}")

        user = self.db.get_user(label)
        allowed, _used = self.db.consume(
            label, feature, None if admin else user["daily_limit"])
        if not allowed:
            return Out(f"📊 Aap ki daily limit ({user['daily_limit']} requests) poori ho gayi. "
                       "Kal 00:00 UTC (subah ~5 baje PKT) reset hogi.")

        if not self._sem.acquire(timeout=self._queue_wait):
            return Out(MSG_BUSY)
        try:
            # A task that waited in the queue must not run if access was revoked meanwhile.
            again = self.check_access(label, feature)
            if not again.ok:
                return Out("Aap ka access beech mein change ho gaya.\n" + again.message)
            return self._execute(label, feature, argument)
        finally:
            self._sem.release()

    def _execute(self, label, feature, argument):
        try:
            if feature == "ai":
                key = self.resolve_ai_key(label)
                if key is None:
                    return Out(self.check_access(label, "ai").message)
                if self.redactor:
                    self.redactor.add(key)
                return Out(fx.ask_gemini(key, argument, model=self.model))

            if feature == "search":
                items = fx.search_items(fx.web_search(argument, environ=self.environ))
                self.selections.put(label, "search", items)
                return Out(fx.format_search(argument, items))

            if feature in ("youtube", "play"):
                items = fx.youtube_search(argument, environ=self.environ)
                self.selections.put(label, "youtube", items)
                return Out(fx.format_youtube(argument, items))

            if feature == "weather":
                return Out(fx.get_weather(argument))
            if feature == "scrape":
                return Out(fx.scrape_page(argument))
            if feature == "download":
                return Out(fx.direct_download(argument, self._user_dir(label)))
            if feature == "ytdl":
                return Out(fx.youtube_download(argument, self._user_dir(label)))
            return Out(MSG_UNKNOWN)

        except fx.GeminiError as exc:
            self.db.record_error(label, feature)
            return Out(fx.GEMINI_USER_MESSAGES.get(exc.kind, MSG_GENERIC))
        except fx.UserFacingError as exc:
            return Out(str(exc))
        except requests.RequestException as exc:
            self.db.record_error(label, feature)
            log.warning("Network error in %s: %s", feature, type(exc).__name__)  # no URL/body
            return Out(MSG_NETWORK)
        except ValueError as exc:
            if feature in ("weather", "ai"):
                return Out(f"Input error: {exc}")          # these messages are ours and safe
            self.db.record_error(label, feature)
            return Out(MSG_GENERIC)
        except Exception as exc:  # noqa: BLE001
            self.db.record_error(label, feature)
            log.error("Error in %s: %s", feature, type(exc).__name__)
            return Out(MSG_GENERIC)

    def _user_dir(self, label):
        if self.download_dir is None:
            raise RuntimeError("download directory not configured")
        return self.download_dir / label

    def _select(self, label, command, number):
        kind = "youtube" if command == "/play" else "search"
        items = self.selections.get(label, kind)
        if not items:
            hint = "/youtube ya /play QUERY" if kind == "youtube" else "/search QUERY"
            return Out(f"Koi active list nahi hai (ya expire ho gayi). Pehle {hint} se search karo.")
        if not 1 <= number <= len(items):
            return Out(f"1 se {len(items)} ke beech ka number do.")
        item = items[number - 1]
        if kind == "youtube":
            return Out(fx.format_play(item), preview=True)
        return Out(fx.format_search_detail(item, number))

    # ------------------------------------------------------------------ #
    # Help and self-service
    # ------------------------------------------------------------------ #

    def _help(self, label, admin):
        enabled = self.db.get_features(label)
        user = self.db.get_user(label)
        lines = ["🤖 POOKIE COMMANDS", "", "/start - Welcome", "/help - Commands list",
                 "/ping - Connection test", "/about - About Pookie"]
        for feature in ("ai", "search", "youtube", "play", "weather", "calc",
                        "scrape", "download", "ytdl"):
            if feature == "ai":
                if user["ai_enabled"]:
                    lines.append(HELP_LINES["ai"])
            elif enabled.get(feature):
                lines.append(HELP_LINES[feature])
        lines += ["/myai on|off - Apna AI switch", "/mykey - Key status (/mykey remove)"]
        if admin:
            lines += ["", ADMIN_HELP]
        return "\n".join(lines)

    def _myai(self, label, argument):
        user = self.db.get_user(label)
        choice = argument.lower()
        if choice in ("on", "off"):
            self.db.set_ai_self_off(label, choice == "off")
            user = self.db.get_user(label)
        lines = [f"Aap ka AI switch: {'OFF' if user['ai_self_off'] else 'ON'}",
                 f"Admin permission: {'enabled' if user['ai_enabled'] else 'disabled'}"]
        if self.db.global_ai_off():
            lines.append("Global AI kill switch: ACTIVE")
        lines.append("Use: /myai on  ya  /myai off")
        return "\n".join(lines)

    def _mykey(self, label, argument):
        user = self.db.get_user(label)
        if user["role"] == "admin":
            return "Admin ki key server ki .env (GEMINI_API_KEY) se aati hai. Chat se change nahi hoti."
        if argument.lower() == "remove":
            removed = self.db.delete_api_key(label, label)
            return "🗑️ Aap ki Gemini key hata di gayi." if removed else "Aap ki koi key saved nahi thi."
        state = "configured ✅" if user["has_key"] else "NOT configured ❌"
        return (f"Gemini key: {state}\n\n"
                "Key chat mein kabhi na bhejo. Set/rotate karne ke liye admin server par "
                "private command chalata hai (hidden input).\n"
                "Key hatani ho to: /mykey remove")

    # ------------------------------------------------------------------ #
    # Admin commands - authorisation is re-checked inside every action
    # ------------------------------------------------------------------ #

    def _admin_command(self, actor, command, argument):
        if not self.is_admin(actor):             # defence in depth, per action
            return MSG_UNKNOWN
        args = argument.split()
        handler = {
            "/admin": self._a_dashboard, "/users": self._a_users, "/user": self._a_user,
            "/features": self._a_features, "/block": self._a_block, "/unblock": self._a_unblock,
            "/stats": self._a_stats, "/health": self._a_health, "/audit": self._a_audit,
            "/setlimit": self._a_setlimit, "/remove-user": self._a_remove,
        }[command]
        return handler(actor, args)

    def _target(self, args):
        """Returns (user_row, error_message)."""
        if not args:
            return None, "Use: USER_ID dena zaroori hai (/users se dekho)."
        user = self.db.get_user(args[0].lower())
        if user is None:
            return None, "Aisa koi user nahi mila. /users se list dekho."
        return user, None

    def _a_dashboard(self, actor, args):
        stats = self.db.stats()
        status = stats["users_by_status"]
        today = sum(c for c, _e in stats["today"].values())
        return (
            "👑 Pookie ADMIN\n"
            f"Users: {sum(status.values())} (active {status.get('active', 0)}, "
            f"blocked {status.get('blocked', 0)}, removed {status.get('removed', 0)})\n"
            f"Requests today: {today}\n"
            f"Global AI: {'🛑 OFF (kill switch)' if self.db.global_ai_off() else '✅ allowed'}\n\n"
            + ADMIN_HELP
        )

    def _a_users(self, actor, args):
        page = int(args[0]) if args and args[0].isdigit() and int(args[0]) > 0 else 1
        total = self.db.count_users()
        rows = self.db.list_users((page - 1) * USERS_PER_PAGE, USERS_PER_PAGE)
        if not rows:
            return f"Page {page} khali hai. Total users: {total}."
        lines = [f"👥 Users {(page - 1) * USERS_PER_PAGE + 1}-"
                 f"{(page - 1) * USERS_PER_PAGE + len(rows)} of {total}"]
        for row in rows:
            lines.append(f"• {row['label']} · {row['role']} · {row['status']} · "
                         f"AI {'on' if row['ai_enabled'] else 'off'}")
        if page * USERS_PER_PAGE < total:
            lines.append(f"Next: /users {page + 1}")
        lines.append("Detail: /user ID")
        return "\n".join(lines)

    def _a_user(self, actor, args):
        user, error = self._target(args)
        if error:
            return error
        label = user["label"]
        features = self.db.get_features(label)
        on = ", ".join(f for f in FEATURES if features.get(f)) or "none"
        sender = user["sender_id"] or ""
        return (
            f"👤 {label}\nRole: {user['role']} · Status: {user['status']}\n"
            f"WhatsApp id: {('…' + sender[-4:]) if sender else 'not bound yet'}\n"
            f"AI: admin {'on' if user['ai_enabled'] else 'off'}, "
            f"self {'off' if user['ai_self_off'] else 'on'}, "
            f"own key {'set' if user['has_key'] else 'missing'}\n"
            f"Daily limit: {user['daily_limit']} (used today {self.db.usage_today(label)})\n"
            f"Features on: {on}\nCreated: {_fmt_ts(user['created_at'])} UTC"
        )

    def _a_features(self, actor, args):
        user, error = self._target(args)
        if error:
            return error
        label = user["label"]
        if len(args) == 1:
            features = self.db.get_features(label)
            lines = [f"🧩 Features: {label}",
                     f"{'✅' if user['ai_enabled'] else '❌'} ai (same as /ai {label} on|off)"]
            lines += [f"{'✅' if features.get(f) else '❌'} {f}" for f in FEATURES]
            lines.append(f"Change: /features {label} NAME on|off")
            return "\n".join(lines)
        if len(args) != 3 or args[2].lower() not in ("on", "off"):
            return f"Use: /features {label} NAME on|off"
        name, enabled = args[1].lower(), args[2].lower() == "on"
        if name == "ai":
            self.db.set_ai_enabled(label, enabled, actor)
        elif name in FEATURES:
            self.db.set_feature(label, name, enabled, actor)
        else:
            return "Feature ka naam: ai, " + ", ".join(FEATURES)
        return f"{'✅' if enabled else '🚫'} {name} for {label}: {'on' if enabled else 'off'}"

    def _admin_ai(self, actor, target, state):
        if not self.is_admin(actor):
            return MSG_UNKNOWN
        on = state == "on"
        if target == "all":
            self.db.set_global_ai_off(not on, actor)
            return ("✅ Global AI kill switch hata diya. Ab per-user settings lagu hain." if on else
                    "🛑 Global AI kill switch ON: AI sab ke liye (admin samet) band. "
                    "Wapas: /ai all on")
        self.db.set_ai_enabled(target, on, actor)
        note = ""
        user = self.db.get_user(target)
        if on and user["role"] != "admin" and not user["has_key"]:
            note = "\n⚠️ Is user ki apni key abhi set nahi - key set hone tak AI nahi chalega."
        return f"{'✅' if on else '🚫'} AI for {target}: {state}{note}"

    def _a_block(self, actor, args):
        user, error = self._target(args)
        if error:
            return error
        if user["role"] == "admin" or user["label"] == self.owner_label:
            return "Admin account ko block nahi kiya ja sakta."
        self.db.set_status(user["label"], "blocked", actor)
        self.selections.clear(user["label"])
        return f"🚫 {user['label']} blocked. Naye aur queued requests foran ruk jayenge."

    def _a_unblock(self, actor, args):
        user, error = self._target(args)
        if error:
            return error
        self.db.set_status(user["label"], "active", actor)
        return f"✅ {user['label']} dobara active hai."

    def _a_stats(self, actor, args):
        stats = self.db.stats()
        lines = ["📊 Stats (UTC din)"]
        if stats["today"]:
            for feature, (count, errors) in sorted(stats["today"].items()):
                lines.append(f"• {feature}: {count} requests, {errors} errors")
        else:
            lines.append("Aaj abhi koi usage nahi.")
        lines.append(f"Last 7 days: {stats['week_requests']} requests, {stats['week_errors']} errors")
        return "\n".join(lines)

    def _a_health(self, actor, args):
        ok, detail = self.db.health()
        vault = self.db.vault
        lines = ["🩺 Health",
                 f"Database: {'✅' if ok else '❌'} {detail}",
                 "Key encryption: " + ("✅ active" if vault and vault.available else
                                       f"❌ unavailable ({vault.problem if vault else 'no vault'})"),
                 f"Global AI: {'🛑 OFF' if self.db.global_ai_off() else '✅ allowed'}",
                 "Admin Gemini key: " + ("set" if (self.environ.get('GEMINI_API_KEY') or '').strip()
                                         else "MISSING"),
                 f"AI model: {self.model}"]
        if self.status_provider:
            lines.append("Agents:")
            for name, info in sorted(self.status_provider().items()):
                extra = f" ({info['last_error']})" if info.get("last_error") else ""
                lines.append(f"• {name}: {info['status']}{extra}")
        return "\n".join(lines)

    def _a_audit(self, actor, args):
        count = int(args[0]) if args and args[0].isdigit() else 10
        rows = self.db.recent_audit(min(count, 25))
        if not rows:
            return "Audit log khali hai."
        lines = ["📜 Recent admin actions"]
        for row in rows:
            tail = " ".join(x for x in (row["target"], row["detail"]) if x)
            lines.append(f"{_fmt_ts(row['ts'])} {row['actor']}: {row['action']} {tail}".strip())
        return "\n".join(lines)

    def _a_setlimit(self, actor, args):
        user, error = self._target(args)
        if error:
            return error
        if len(args) != 2 or not args[1].isdigit() or not 0 <= int(args[1]) <= 100000:
            return "Use: /setlimit USER_ID N   (N = 0..100000 requests per din)"
        self.db.set_limit(user["label"], int(args[1]), actor)
        return f"📊 {user['label']} ki daily limit ab {int(args[1])} hai."

    def _a_remove(self, actor, args):
        user, error = self._target(args)
        if error:
            return error
        label = user["label"]
        if user["role"] == "admin" or label == self.owner_label:
            return "Admin account remove nahi ho sakta."
        confirmed = len(args) > 1 and args[1].lower() == "confirm"
        now = time.monotonic()
        with self._pending_lock:
            expiry = self._pending.get((actor, label))
            if confirmed and expiry and now <= expiry:
                del self._pending[(actor, label)]
            elif confirmed:
                return f"Confirmation expire ho gayi. Pehle /remove-user {label} bhejo."
            else:
                self._pending[(actor, label)] = now + CONFIRM_TTL
                return (f"⚠️ {label} ko disable karke uski Gemini key delete ho jayegi "
                        f"(history rahegi).\nConfirm: /remove-user {label} confirm "
                        f"({CONFIRM_TTL}s ke andar)")
        self.db.remove_user(label, actor)
        self.selections.clear(label)
        return f"🗑️ {label} remove (disabled) kar diya gaya. /unblock {label} se wapas active hoga."
