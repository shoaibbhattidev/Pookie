"""pookie_db.py - persistent state for Pookie.

Contains:
  * KeyVault      - authenticated encryption (Fernet) for per-user Gemini keys
  * Database      - SQLite schema, migrations, users, permissions, usage, audit
  * RateLimiter   - in-memory sliding-window limiter
  * SecretRedactor - logging filter that masks known secrets

No secret (WhatsApp token, Gemini key, master key) is ever written to logs,
audit rows or exception messages by this module.
"""

import logging
import os
import re
import sqlite3
import stat
import threading
import time
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger("pookie.db")

SCHEMA_VERSION = 1
LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")

# Features that can be switched per user. "ai" is NOT in this list: it is
# stored in users.ai_enabled so there is exactly one source of truth for it.
FEATURES = ("search", "youtube", "play", "weather", "calc", "scrape", "download", "ytdl")
# Safe, cheap features that are ON by default for normal users.
# scrape / download / ytdl (risky or expensive) are OFF until the admin enables them.
DEFAULT_ON_FOR_USERS = frozenset({"search", "youtube", "play", "weather", "calc"})

DEFAULT_DAILY_LIMIT = 50


def utc_now():
    return datetime.now(timezone.utc)


def _iso(dt=None):
    return (dt or utc_now()).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today():
    return utc_now().strftime("%Y-%m-%d")


# --------------------------------------------------------------------------- #
# Encryption vault
# --------------------------------------------------------------------------- #

class VaultError(Exception):
    """Raised for vault problems. Messages never contain key material."""


class KeyVault:
    """Encrypts secrets at rest with Fernet (AES-128-CBC + HMAC-SHA256).

    The master key is NOT stored in the database. It is read from the
    POOKIE_MASTER_KEY environment variable or from a private key file.
    If the `cryptography` package or the master key is missing, the vault is
    unavailable and user keys are REFUSED (never stored in plaintext).
    """

    def __init__(self, key_file=None, env_name="POOKIE_MASTER_KEY", environ=None):
        self._fernet = None
        self.problem = None
        self.permission_warning = None
        environ = os.environ if environ is None else environ
        key_file = Path(key_file) if key_file else None

        try:
            from cryptography.fernet import Fernet
        except ImportError:
            self.problem = "the 'cryptography' package is not installed"
            return

        raw = (environ.get(env_name) or "").strip()
        if not raw and key_file and key_file.exists():
            try:
                raw = key_file.read_text().strip()
                mode = stat.S_IMODE(key_file.stat().st_mode)
                if mode & 0o077:
                    self.permission_warning = (
                        f"{key_file.name} is readable by other users; run: chmod 600 {key_file.name}"
                    )
            except OSError:
                self.problem = "master key file could not be read"
                return
        if not raw:
            self.problem = "no master key (run: python assistant.py init)"
            return
        try:
            self._fernet = Fernet(raw.encode())
        except Exception:  # noqa: BLE001 - never echo the key
            self.problem = "master key is invalid"

    @property
    def available(self):
        return self._fernet is not None

    def encrypt(self, plaintext):
        if not self._fernet:
            raise VaultError("encryption unavailable: " + (self.problem or "unknown"))
        return self._fernet.encrypt(plaintext.encode("utf-8"))

    def decrypt(self, blob):
        if not self._fernet:
            raise VaultError("encryption unavailable: " + (self.problem or "unknown"))
        try:
            return self._fernet.decrypt(bytes(blob)).decode("utf-8")
        except Exception as exc:  # noqa: BLE001
            raise VaultError("could not decrypt (wrong master key or corrupted data)") from exc

    @staticmethod
    def create_key_file(path):
        """Create a new master key file with 0600 permissions. Never overwrites."""
        from cryptography.fernet import Fernet

        path = Path(path)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(Fernet.generate_key().decode() + "\n")
        return path


# --------------------------------------------------------------------------- #
# Rate limiter
# --------------------------------------------------------------------------- #

class RateLimiter:
    """Sliding-window limiter. allow() returns (allowed, retry_after_seconds)."""

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._hits = {}
        self._lock = threading.Lock()

    def allow(self, key, limit, window):
        now = self._clock()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= window:
                hits.popleft()
            if len(hits) >= limit:
                return False, max(1, int(window - (now - hits[0])) + 1)
            hits.append(now)
            return True, 0


# --------------------------------------------------------------------------- #
# Log redaction
# --------------------------------------------------------------------------- #

class SecretRedactor(logging.Filter):
    """Replaces registered secrets (and Google-style API keys) in log output."""

    _PATTERNS = (
        re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),
        re.compile(r"(?i)(x-goog-api-key|authorization|bearer)\s*[:=]?\s*\S+"),
        re.compile(r"(?i)([?&]key=)[^&\s]+"),
    )

    def __init__(self):
        super().__init__()
        self._secrets = set()
        self._lock = threading.Lock()

    def add(self, secret):
        if secret and len(secret) >= 8:
            with self._lock:
                self._secrets.add(secret)

    def scrub(self, text):
        with self._lock:
            secrets = list(self._secrets)
        for secret in secrets:
            text = text.replace(secret, "[REDACTED]")
        for pattern in self._PATTERNS:
            text = pattern.sub(lambda m: (m.group(1) if m.lastindex else "") + "[REDACTED]", text)
        return text

    def filter(self, record):
        try:
            record.msg = self.scrub(record.getMessage())
            record.args = ()
        except Exception:  # noqa: BLE001 - logging must never crash the bot
            pass
        return True


# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #

_MIGRATIONS = {
    1: [
        """CREATE TABLE users (
            label       TEXT PRIMARY KEY,
            role        TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin','user')),
            status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','blocked','removed')),
            sender_id   TEXT,
            agent_id    TEXT,
            ai_enabled  INTEGER NOT NULL DEFAULT 0,
            ai_self_off INTEGER NOT NULL DEFAULT 0,
            daily_limit INTEGER NOT NULL DEFAULT 50,
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        )""",
        """CREATE TABLE features (
            label   TEXT NOT NULL REFERENCES users(label) ON DELETE CASCADE,
            feature TEXT NOT NULL,
            enabled INTEGER NOT NULL,
            PRIMARY KEY (label, feature)
        )""",
        """CREATE TABLE api_keys (
            label      TEXT PRIMARY KEY REFERENCES users(label) ON DELETE CASCADE,
            ciphertext BLOB NOT NULL,
            updated_at TEXT NOT NULL
        )""",
        """CREATE TABLE usage (
            label   TEXT NOT NULL,
            day     TEXT NOT NULL,
            feature TEXT NOT NULL,
            count   INTEGER NOT NULL DEFAULT 0,
            errors  INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (label, day, feature)
        )""",
        """CREATE TABLE audit (
            id     INTEGER PRIMARY KEY AUTOINCREMENT,
            ts     TEXT NOT NULL,
            actor  TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            detail TEXT
        )""",
        """CREATE TABLE settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )""",
        "CREATE INDEX idx_usage_day ON usage(day)",
        "CREATE INDEX idx_audit_id ON audit(id DESC)",
    ],
}


class Database:
    """Thread-safe SQLite wrapper. All access is serialised by one RLock and
    related changes happen inside explicit BEGIN IMMEDIATE transactions.
    Every statement is parameterised."""

    def __init__(self, path, vault=None):
        self.path = Path(path)
        self.vault = vault
        self._lock = threading.RLock()
        existed = self.path.exists()
        self._conn = sqlite3.connect(
            str(self.path), check_same_thread=False, isolation_level=None, timeout=15
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA busy_timeout = 15000")
        self._migrate(existed)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # -- plumbing ----------------------------------------------------------- #

    @contextmanager
    def _tx(self):
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def _query(self, sql, params=()):
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def _migrate(self, existed):
        with self._lock:
            version = self._conn.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"Database schema v{version} is newer than this script (v{SCHEMA_VERSION})."
                )
            if version == SCHEMA_VERSION:
                return
            if existed and version > 0:
                backup = self.backup(reason="pre-migrate")
                log.info("Database backed up to %s before migration", backup.name)
            for target in range(version + 1, SCHEMA_VERSION + 1):
                with self._tx() as conn:
                    for statement in _MIGRATIONS[target]:
                        conn.execute(statement)
                    conn.execute(f"PRAGMA user_version = {int(target)}")
            log.info("Database schema ready (v%s)", SCHEMA_VERSION)

    def backup(self, reason="manual"):
        """Online backup to a NEW file next to the database. Never overwrites."""
        stamp = utc_now().strftime("%Y%m%d-%H%M%S")
        dest = self.path.with_name(f"{self.path.name}.{reason}-{stamp}.bak")
        counter = 1
        while dest.exists():
            dest = self.path.with_name(f"{self.path.name}.{reason}-{stamp}-{counter}.bak")
            counter += 1
        target = sqlite3.connect(str(dest))
        try:
            with self._lock:
                self._conn.backup(target)
        finally:
            target.close()
        try:
            os.chmod(dest, 0o600)
        except OSError:
            pass
        return dest

    def close(self):
        with self._lock:
            self._conn.close()

    def health(self):
        try:
            self._query("SELECT 1")
            version = self._query("PRAGMA user_version")[0][0]
            return True, f"ok (schema v{version})"
        except Exception as exc:  # noqa: BLE001
            return False, f"error: {type(exc).__name__}"

    # -- audit --------------------------------------------------------------- #

    @staticmethod
    def _audit(conn, actor, action, target=None, detail=None):
        conn.execute(
            "INSERT INTO audit (ts, actor, action, target, detail) VALUES (?,?,?,?,?)",
            (_iso(), actor, action, target, (detail or "")[:200] or None),
        )

    def audit(self, actor, action, target=None, detail=None):
        with self._tx() as conn:
            self._audit(conn, actor, action, target, detail)

    def recent_audit(self, limit=10):
        limit = max(1, min(int(limit), 50))
        return [dict(r) for r in self._query("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]

    # -- users --------------------------------------------------------------- #

    def ensure_user(self, label, is_owner=False):
        """Create the user (and default feature rows) if missing. Enforces roles:
        only the configured owner can ever hold the 'admin' role."""
        now = _iso()
        with self._tx() as conn:
            created = conn.execute(
                """INSERT INTO users (label, role, status, ai_enabled, daily_limit, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?) ON CONFLICT(label) DO NOTHING""",
                (
                    label,
                    "admin" if is_owner else "user",
                    "active",
                    1 if is_owner else 0,
                    DEFAULT_DAILY_LIMIT,
                    now,
                    now,
                ),
            ).rowcount
            for feature in FEATURES:
                default = 1 if (is_owner or feature in DEFAULT_ON_FOR_USERS) else 0
                conn.execute(
                    "INSERT INTO features (label, feature, enabled) VALUES (?,?,?) "
                    "ON CONFLICT(label, feature) DO NOTHING",
                    (label, feature, default),
                )
            wanted = "admin" if is_owner else "user"
            changed = conn.execute(
                "UPDATE users SET role=?, updated_at=? WHERE label=? AND role<>?",
                (wanted, now, label, wanted),
            ).rowcount
            if created:
                self._audit(conn, "system", "user_registered", label, wanted)
            if changed:
                self._audit(conn, "system", "role_corrected", label, wanted)
        return bool(created)

    def get_user(self, label):
        rows = self._query("SELECT * FROM users WHERE label=?", (label,))
        if not rows:
            return None
        user = dict(rows[0])
        user["has_key"] = bool(
            self._query("SELECT 1 FROM api_keys WHERE label=?", (label,))
        )
        return user

    def count_users(self):
        return self._query("SELECT COUNT(*) FROM users")[0][0]

    def list_users(self, offset=0, limit=8):
        rows = self._query(
            "SELECT label, role, status, ai_enabled FROM users ORDER BY role, label LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [dict(r) for r in rows]

    def set_status(self, label, status, actor):
        if status not in ("active", "blocked", "removed"):
            raise ValueError("bad status")
        with self._tx() as conn:
            changed = conn.execute(
                "UPDATE users SET status=?, updated_at=? WHERE label=?", (status, _iso(), label)
            ).rowcount
            if changed:
                self._audit(conn, actor, f"status_{status}", label)
        return bool(changed)

    def remove_user(self, label, actor):
        """Safe removal: disable the account, revoke AI, delete the stored key.
        The row, usage and audit history are kept."""
        with self._tx() as conn:
            changed = conn.execute(
                "UPDATE users SET status='removed', ai_enabled=0, updated_at=? WHERE label=?",
                (_iso(), label),
            ).rowcount
            conn.execute("DELETE FROM api_keys WHERE label=?", (label,))
            if changed:
                self._audit(conn, actor, "user_removed", label)
        return bool(changed)

    def set_ai_enabled(self, label, enabled, actor):
        with self._tx() as conn:
            changed = conn.execute(
                "UPDATE users SET ai_enabled=?, updated_at=? WHERE label=?",
                (1 if enabled else 0, _iso(), label),
            ).rowcount
            if changed:
                self._audit(conn, actor, "ai_on" if enabled else "ai_off", label)
        return bool(changed)

    def set_ai_self_off(self, label, off):
        with self._tx() as conn:
            conn.execute(
                "UPDATE users SET ai_self_off=?, updated_at=? WHERE label=?",
                (1 if off else 0, _iso(), label),
            )
            self._audit(conn, label, "self_ai_off" if off else "self_ai_on", label)

    def set_limit(self, label, limit, actor):
        with self._tx() as conn:
            changed = conn.execute(
                "UPDATE users SET daily_limit=?, updated_at=? WHERE label=?",
                (int(limit), _iso(), label),
            ).rowcount
            if changed:
                self._audit(conn, actor, "set_limit", label, str(int(limit)))
        return bool(changed)

    # -- features ------------------------------------------------------------ #

    def get_features(self, label):
        rows = self._query("SELECT feature, enabled FROM features WHERE label=?", (label,))
        return {r["feature"]: bool(r["enabled"]) for r in rows}

    def feature_enabled(self, label, feature):
        rows = self._query(
            "SELECT enabled FROM features WHERE label=? AND feature=?", (label, feature)
        )
        return bool(rows and rows[0]["enabled"])

    def set_feature(self, label, feature, enabled, actor):
        if feature not in FEATURES:
            raise ValueError("unknown feature")
        with self._tx() as conn:
            changed = conn.execute(
                "UPDATE features SET enabled=? WHERE label=? AND feature=?",
                (1 if enabled else 0, label, feature),
            ).rowcount
            if changed:
                self._audit(conn, actor, "feature_on" if enabled else "feature_off", label, feature)
        return bool(changed)

    # -- global settings ----------------------------------------------------- #

    def global_ai_off(self):
        rows = self._query("SELECT value FROM settings WHERE key='global_ai_off'")
        return bool(rows and rows[0]["value"] == "1")

    def set_global_ai_off(self, off, actor):
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('global_ai_off', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                ("1" if off else "0",),
            )
            self._audit(conn, actor, "global_ai_off" if off else "global_ai_on")

    # -- identity binding ---------------------------------------------------- #

    def bind_identity(self, label, sender_id, agent_id):
        """Trust-on-first-use binding of the verified WhatsApp sender id and
        agent id (both come from the API payload, never from message text).
        Returns False if either differs from what was bound before."""
        with self._tx() as conn:
            row = conn.execute(
                "SELECT sender_id, agent_id FROM users WHERE label=?", (label,)
            ).fetchone()
            if row is None:
                return False
            for column, value in (("sender_id", sender_id), ("agent_id", agent_id)):
                if not value:
                    continue
                current = row[column]
                if current is None:
                    conn.execute(f"UPDATE users SET {column}=? WHERE label=?", (value, label))
                elif current != value:
                    self._audit(conn, "system", "identity_mismatch", label, column)
                    return False
        return True

    def rebind(self, label, actor):
        with self._tx() as conn:
            changed = conn.execute(
                "UPDATE users SET sender_id=NULL, agent_id=NULL, updated_at=? WHERE label=?",
                (_iso(), label),
            ).rowcount
            if changed:
                self._audit(conn, actor, "identity_rebind", label)
        return bool(changed)

    # -- usage --------------------------------------------------------------- #

    def consume(self, label, feature, limit):
        """Atomically check the daily limit and count one request.
        limit=None counts without limiting. Returns (allowed, used_before)."""
        today = _today()
        with self._tx() as conn:
            used = conn.execute(
                "SELECT COALESCE(SUM(count),0) FROM usage WHERE label=? AND day=?", (label, today)
            ).fetchone()[0]
            if limit is not None and used >= limit:
                return False, used
            conn.execute(
                """INSERT INTO usage (label, day, feature, count) VALUES (?,?,?,1)
                   ON CONFLICT(label, day, feature) DO UPDATE SET count = count + 1""",
                (label, today, feature),
            )
            return True, used

    def record_error(self, label, feature):
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO usage (label, day, feature, count, errors) VALUES (?,?,?,0,1)
                   ON CONFLICT(label, day, feature) DO UPDATE SET errors = errors + 1""",
                (label, _today(), feature),
            )

    def usage_today(self, label):
        rows = self._query(
            "SELECT COALESCE(SUM(count),0) FROM usage WHERE label=? AND day=?", (label, _today())
        )
        return rows[0][0]

    def stats(self):
        today = _today()
        week_start = (utc_now() - timedelta(days=6)).strftime("%Y-%m-%d")
        by_status = {r["status"]: r["n"] for r in self._query(
            "SELECT status, COUNT(*) AS n FROM users GROUP BY status")}
        today_rows = self._query(
            "SELECT feature, SUM(count) AS c, SUM(errors) AS e FROM usage WHERE day=? GROUP BY feature",
            (today,),
        )
        week = self._query(
            "SELECT COALESCE(SUM(count),0), COALESCE(SUM(errors),0) FROM usage WHERE day>=?",
            (week_start,),
        )[0]
        return {
            "users_by_status": by_status,
            "today": {r["feature"]: (r["c"], r["e"]) for r in today_rows},
            "week_requests": week[0],
            "week_errors": week[1],
        }

    # -- Gemini keys (encrypted) --------------------------------------------- #

    def set_api_key(self, label, plaintext, actor):
        if not self.vault or not self.vault.available:
            raise VaultError(
                "cannot store key: encryption unavailable ("
                + (self.vault.problem if self.vault else "no vault")
                + ")"
            )
        blob = self.vault.encrypt(plaintext)
        with self._tx() as conn:
            if conn.execute("SELECT 1 FROM users WHERE label=?", (label,)).fetchone() is None:
                raise KeyError("unknown user")
            conn.execute(
                """INSERT INTO api_keys (label, ciphertext, updated_at) VALUES (?,?,?)
                   ON CONFLICT(label) DO UPDATE SET ciphertext=excluded.ciphertext,
                                                    updated_at=excluded.updated_at""",
                (label, blob, _iso()),
            )
            self._audit(conn, actor, "key_set", label)  # never the key itself

    def get_api_key(self, label):
        """Return the decrypted key for exactly this label, or None."""
        rows = self._query("SELECT ciphertext FROM api_keys WHERE label=?", (label,))
        if not rows or not self.vault or not self.vault.available:
            return None
        try:
            return self.vault.decrypt(rows[0]["ciphertext"])
        except VaultError:
            log.error("Stored key for '%s' could not be decrypted", label)
            return None

    def delete_api_key(self, label, actor):
        with self._tx() as conn:
            removed = conn.execute("DELETE FROM api_keys WHERE label=?", (label,)).rowcount
            if removed:
                self._audit(conn, actor, "key_removed", label)
        return bool(removed)
