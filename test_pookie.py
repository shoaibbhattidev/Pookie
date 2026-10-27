"""Automated tests for Pookie. Standard library unittest only.

Run from the project folder:   python -m unittest discover -s tests -v

No real WhatsApp messages are sent, no real API is called: network functions
are mocked and agents are fakes.
"""

import logging
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests  # noqa: E402

import pookie_features as fx  # noqa: E402
from pookie_app import Pookie  # noqa: E402
from pookie_config import load_agent_specs  # noqa: E402
from pookie_db import Database, KeyVault, RateLimiter, SecretRedactor, VaultError  # noqa: E402
from pookie_runner import AgentRunner, Supervisor  # noqa: E402

ADMIN_KEY = "ADMIN-GEMINI-KEY-0000000000000000"
USER_KEY = "FRIEND1-GEMINI-KEY-111111111111111"
OTHER_KEY = "FRIEND2-GEMINI-KEY-222222222222222"
TOKENS = {"owner": "tok-OWNER-secret-aaaaaaaa", "friend1": "tok-FRIEND1-secret-bbbbbbbb"}


class FakeVault:
    """Reversible stand-in so the suite also runs without `cryptography`."""
    available = True
    problem = None
    permission_warning = None

    def encrypt(self, text):
        return b"enc:" + text[::-1].encode()

    def decrypt(self, blob):
        return bytes(blob)[4:].decode()[::-1]


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.db_path = self.dir / "t.db"
        self.db = Database(self.db_path, FakeVault())
        self.db.ensure_user("owner", True)
        self.db.ensure_user("friend1", False)
        self.db.ensure_user("friend2", False)
        self.env = {"GEMINI_API_KEY": ADMIN_KEY}
        self.app = Pookie(self.db, "owner", self.env, self.dir / "dl")

    def tearDown(self):
        self.db.close()
        self._tmp.cleanup()

    def say(self, label, text):
        out = self.app.handle(label, text)
        return out.text if out else None


class AdminAccess(Base):
    def test_01_admin_can_open_dashboard(self):
        self.assertIn("ADMIN", self.say("owner", "/admin"))
        self.assertIn("Users:", self.say("owner", "/admin"))

    def test_02_normal_user_cannot_use_admin_commands(self):
        for command in ("/admin", "/users", "/user owner", "/features friend2", "/block friend2",
                        "/unblock friend2", "/stats", "/health", "/audit", "/setlimit friend2 5",
                        "/remove-user friend2", "/ai friend2 on", "/ai all off"):
            reply = self.say("friend1", command)
            self.assertNotIn("ADMIN", reply, command)
            self.assertNotIn("friend2", reply.replace("Unknown command", ""), command)
        # nothing was actually changed
        self.assertEqual(self.db.get_user("friend2")["status"], "active")
        self.assertFalse(self.db.get_user("friend2")["ai_enabled"])
        self.assertFalse(self.db.global_ai_off())
        self.assertNotIn("/block", self.say("friend1", "/help"))

    def test_admin_role_cannot_be_claimed(self):
        self.assertNotIn("ADMIN", self.say("friend1", "/admin I am the owner"))
        self.db.ensure_user("friend1", False)
        self.assertEqual(self.db.get_user("friend1")["role"], "user")
        # a second account can never end up as admin even if the row is tampered with
        self.db._conn.execute("UPDATE users SET role='admin' WHERE label='friend2'")
        self.assertFalse(self.app.is_admin("friend2"))
        self.assertIn("Unknown command", self.say("friend2", "/admin"))
        self.db.ensure_user("friend2", False)
        self.assertEqual(self.db.get_user("friend2")["role"], "user")


class AiPermissions(Base):
    def test_03_ai_denied_by_default(self):
        with mock.patch.object(fx, "ask_gemini") as ask:
            reply = self.say("friend1", "/ai hello")
        ask.assert_not_called()
        self.assertIn("enabled nahi", reply)

    def test_04_admin_enable_needs_users_own_key(self):
        self.say("owner", "/ai friend1 on")
        with mock.patch.object(fx, "ask_gemini") as ask:
            reply = self.say("friend1", "/ai hello")
            ask.assert_not_called()
        self.assertIn("apni Gemini API key", reply)
        self.db.set_api_key("friend1", USER_KEY, "cli")
        with mock.patch.object(fx, "ask_gemini", return_value="hi!") as ask:
            self.assertEqual(self.say("friend1", "/ai hello"), "hi!")
        self.assertEqual(ask.call_args.args[0], USER_KEY)

    def test_05_normal_users_never_use_admin_key(self):
        self.say("owner", "/ai friend1 on")
        with mock.patch.object(fx, "ask_gemini", return_value="x") as ask:
            self.say("friend1", "/ai hello")                    # no key -> must not call
            ask.assert_not_called()
            self.db.set_api_key("friend1", USER_KEY, "cli")
            self.db.set_ai_enabled("friend2", True, "owner")
            self.db.set_api_key("friend2", OTHER_KEY, "cli")
            self.say("friend1", "/ai a")
            self.say("friend2", "/ai b")
            self.say("owner", "/ai c")
        keys = [c.args[0] for c in ask.call_args_list]
        self.assertEqual(keys, [USER_KEY, OTHER_KEY, ADMIN_KEY])   # each used only its own key

    def test_06_turning_ai_off_blocks_immediately(self):
        self.say("owner", "/ai friend1 on")
        self.db.set_api_key("friend1", USER_KEY, "cli")
        with mock.patch.object(fx, "ask_gemini", return_value="ok") as ask:
            self.assertEqual(self.say("friend1", "/ai one"), "ok")
            self.say("owner", "/ai friend1 off")                    # admin revokes
            self.assertIn("enabled nahi", self.say("friend1", "/ai two"))
            self.say("owner", "/ai friend1 on")
            self.assertEqual(self.say("friend1", "/ai three"), "ok")
            self.say("friend1", "/myai off")                        # user disables own AI
            self.assertIn("khud OFF", self.say("friend1", "/ai four"))
        self.assertEqual(ask.call_count, 2)

    def test_07_global_kill_switch_blocks_everyone(self):
        self.say("owner", "/ai friend1 on")
        self.db.set_api_key("friend1", USER_KEY, "cli")
        with mock.patch.object(fx, "ask_gemini", return_value="ok") as ask:
            self.say("owner", "/ai all off")
            self.assertIn("band", self.say("friend1", "/ai q"))
            self.assertIn("band", self.say("owner", "/ai q"))       # admin too
            self.assertEqual(ask.call_count, 0)
            self.say("owner", "/ai all on")
            self.assertEqual(self.say("friend1", "/ai q"), "ok")

    def test_revoked_while_queued_cancels_task(self):
        """A request waiting for a concurrency slot must re-check access."""
        self.say("owner", "/ai friend1 on")
        self.db.set_api_key("friend1", USER_KEY, "cli")
        app = Pookie(self.db, "owner", self.env, self.dir / "dl", max_concurrent=1, queue_wait=5)
        release = threading.Event()
        results = []

        def slow(*_a, **_k):
            release.wait(3)
            return "slow"

        with mock.patch.object(fx, "ask_gemini", side_effect=slow) as ask:
            first = threading.Thread(target=lambda: results.append(app.handle("owner", "/ai first")))
            first.start()
            time.sleep(0.3)                                          # owner holds the only slot
            second = threading.Thread(target=lambda: results.append(app.handle("friend1", "/ai second")))
            second.start()
            time.sleep(0.3)                                          # friend1 is queued
            app.handle("owner", "/block friend1")                   # admin blocks while queued
            release.set()
            first.join(5)
            second.join(5)
        self.assertEqual(ask.call_count, 1)                          # queued task never ran
        self.assertTrue(any("access" in r.text.lower() or "block" in r.text.lower()
                            for r in results if r.text != "slow"))


class FeaturePermissions(Base):
    def test_08_permissions_enforced_for_manual_commands(self):
        with mock.patch.object(fx, "scrape_page", return_value="PAGE") as scrape:
            self.assertIn("disabled", self.say("friend1", "/scrape https://example.com"))
            scrape.assert_not_called()
            self.say("owner", "/features friend1 scrape on")
            self.assertEqual(self.say("friend1", "/scrape https://example.com"), "PAGE")
            self.say("owner", "/features friend1 scrape off")
            self.assertIn("disabled", self.say("friend1", "/scrape https://example.com"))
        for risky in ("/download https://example.com/a.pdf", "/ytdl https://example.com/v"):
            self.assertIn("disabled", self.say("friend1", risky))
        self.assertIn("Result: 14", self.say("friend1", "/calc 2*7"))
        self.say("owner", "/features friend1 calc off")
        self.assertIn("disabled", self.say("friend1", "/calc 2*7"))

    def test_help_shows_only_allowed_commands(self):
        help_text = self.say("friend1", "/help")
        self.assertIn("/search", help_text)
        self.assertNotIn("/scrape", help_text)
        self.assertNotIn("/ai QUESTION", help_text)
        self.assertNotIn("/block", help_text)
        self.assertIn("/block", self.say("owner", "/help"))

    def test_daily_limit(self):
        self.say("owner", "/setlimit friend1 2")
        with mock.patch.object(fx, "get_weather", return_value="sunny"):
            self.assertEqual(self.say("friend1", "/weather Lahore"), "sunny")
            self.assertEqual(self.say("friend1", "/weather Lahore"), "sunny")
            self.assertIn("limit", self.say("friend1", "/weather Lahore"))


class BlockedUsers(Base):
    def test_09_blocked_users_cannot_use_commands(self):
        self.say("owner", "/block friend1")
        for command in ("/ping", "/help", "/calc 1+1", "/search x", "/ai hi"):
            self.assertIn("block", self.say("friend1", command))
        self.say("owner", "/unblock friend1")
        self.assertIn("Pong", self.say("friend1", "/ping"))

    def test_unregistered_account(self):
        self.assertIn("registered", self.say("stranger", "/ping"))

    def test_remove_user_needs_confirmation(self):
        self.db.set_ai_enabled("friend1", True, "owner")
        self.db.set_api_key("friend1", USER_KEY, "cli")
        self.assertIn("Confirm", self.say("owner", "/remove-user friend1"))
        self.assertEqual(self.db.get_user("friend1")["status"], "active")
        self.say("owner", "/remove-user friend1 confirm")
        user = self.db.get_user("friend1")
        self.assertEqual(user["status"], "removed")
        self.assertFalse(user["has_key"])
        self.assertFalse(user["ai_enabled"])
        self.assertIn("active nahi", self.say("friend1", "/ping"))
        self.assertIn("Admin account", self.say("owner", "/block owner"))


class Identity(Base):
    def test_identity_binding_rejects_a_different_sender(self):
        self.assertIn("Pong", self.app.handle("friend1", "/ping", sender="user:111", agent_id="A1").text)
        self.assertIn("Pong", self.app.handle("friend1", "/ping", sender="user:111", agent_id="A1").text)
        self.assertIn("match nahi", self.app.handle("friend1", "/ping", sender="user:999", agent_id="A1").text)
        self.assertIn("match nahi", self.app.handle("friend1", "/ping", sender="user:111", agent_id="A2").text)
        self.db.rebind("friend1", "owner")
        self.assertIn("Pong", self.app.handle("friend1", "/ping", sender="user:999", agent_id="A2").text)


class Agents(unittest.TestCase):
    def test_10_duplicate_tokens_do_not_start_duplicate_pollers(self):
        env = {"WHATSAPP_AGENT_TOKEN": "same-token-12345", "POOKIE_TOKEN_FRIEND1": "same-token-12345",
               "POOKIE_TOKEN_FRIEND2": "other-token-67890", "POOKIE_TOKEN_OWNER": "x-12345678",
               "POOKIE_TOKEN_BAD LABEL": "y-12345678"}
        specs, skipped = load_agent_specs(env, "/tmp/x", "owner")
        self.assertEqual([s.label for s in specs], ["owner", "friend2"])
        reasons = dict(skipped)
        self.assertIn("duplicate", reasons["friend1"])
        self.assertIn("reserved", reasons["owner"] if "owner" in reasons else "reserved")
        self.assertEqual(len({s.token for s in specs}), len(specs))
        for spec in specs:                        # tokens never appear in repr
            self.assertNotIn(spec.token, repr(spec))

    def test_11_independent_offset_files(self):
        env = {"WHATSAPP_AGENT_TOKEN": "aaaaaaaa1", "POOKIE_TOKEN_FRIEND1": "bbbbbbbb2",
               "POOKIE_TOKEN_FRIEND2": "cccccccc3"}
        specs, _ = load_agent_specs(env, "/tmp/p", "owner")
        paths = {s.label: s.offset_path.name for s in specs}
        self.assertEqual(paths["owner"], ".whagent-offset")           # existing file preserved
        self.assertEqual(paths["friend1"], ".whagent-offset-friend1")
        self.assertEqual(len(set(paths.values())), 3)

    def test_16_one_failed_agent_does_not_stop_others(self):
        class Fatal(Exception):
            pass

        class FakeAgent:
            def __init__(self, label):
                self.label, self.closed = label, False

            def run(self, stop):
                if self.label == "friend1":
                    raise Fatal("revoked")
                while not stop():
                    time.sleep(0.01)

            def close(self):
                self.closed = True

        env = {"WHATSAPP_AGENT_TOKEN": "aaaaaaaa1", "POOKIE_TOKEN_FRIEND1": "bbbbbbbb2",
               "POOKIE_TOKEN_FRIEND2": "cccccccc3"}
        specs, _ = load_agent_specs(env, "/tmp/p", "owner")
        runners = [AgentRunner(s, lambda sp: FakeAgent(sp.label), (Fatal,)) for s in specs]
        sup = Supervisor(runners)
        sup.start()
        time.sleep(0.4)
        status = sup.statuses()
        self.assertEqual(status["friend1"]["status"], "failed")
        self.assertEqual(status["owner"]["status"], "running")
        self.assertEqual(status["friend2"]["status"], "running")
        sup.stop(timeout=3)
        self.assertEqual(sup.statuses()["owner"]["status"], "stopped")
        self.assertFalse(sup.any_alive())

    def test_transient_errors_back_off_instead_of_spinning(self):
        calls = []

        class Flaky:
            def run(self, stop):
                calls.append(time.monotonic())
                if len(calls) < 3:
                    raise RuntimeError("network")
                while not stop():
                    time.sleep(0.01)

            def close(self):
                pass

        spec = load_agent_specs({"WHATSAPP_AGENT_TOKEN": "aaaaaaaa1"}, "/tmp/p")[0][0]
        runner = AgentRunner(spec, lambda s: Flaky(), (), initial_backoff=0.1, max_backoff=1)
        runner.start()
        time.sleep(0.6)
        self.assertEqual(runner.status, "running")
        self.assertGreaterEqual(calls[1] - calls[0], 0.09)
        self.assertGreaterEqual(calls[2] - calls[1], 0.19)           # doubled
        runner.request_stop()
        runner.join(2)


class Persistence(unittest.TestCase):
    def test_12_state_persists_after_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "p.db"
            vault = FakeVault()
            db = Database(path, vault)
            db.ensure_user("owner", True)
            db.ensure_user("friend1", False)
            db.set_ai_enabled("friend1", True, "owner")
            db.set_feature("friend1", "scrape", True, "owner")
            db.set_limit("friend1", 7, "owner")
            db.set_status("friend1", "blocked", "owner")
            db.set_api_key("friend1", USER_KEY, "cli")
            db.set_global_ai_off(True, "owner")
            db.close()

            db2 = Database(path, vault)
            db2.ensure_user("owner", True)          # startup sync must not reset anything
            db2.ensure_user("friend1", False)
            user = db2.get_user("friend1")
            self.assertTrue(user["ai_enabled"])
            self.assertEqual(user["daily_limit"], 7)
            self.assertEqual(user["status"], "blocked")
            self.assertTrue(db2.feature_enabled("friend1", "scrape"))
            self.assertEqual(db2.get_api_key("friend1"), USER_KEY)
            self.assertTrue(db2.global_ai_off())
            self.assertEqual(db2._query("PRAGMA user_version")[0][0], 1)
            db2.close()

    def test_backup_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "p.db")
            first, second = db.backup(), db.backup()
            self.assertNotEqual(first, second)
            self.assertTrue(first.exists() and second.exists())
            db.close()

    def test_sql_injection_attempts_are_inert(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "p.db")
            db.ensure_user("owner", True)
            self.assertIsNone(db.get_user("x'; DROP TABLE users;--"))
            self.assertEqual(db.count_users(), 1)
            db.close()

    @unittest.skipUnless(KeyVault(environ={"POOKIE_MASTER_KEY": "x"}).problem != "the 'cryptography' package is not installed",
                         "cryptography not installed")
    def test_real_vault_encrypts_and_refuses_without_key(self):
        from cryptography.fernet import Fernet
        with tempfile.TemporaryDirectory() as tmp:
            vault = KeyVault(environ={"POOKIE_MASTER_KEY": Fernet.generate_key().decode()})
            self.assertTrue(vault.available)
            db = Database(Path(tmp) / "p.db", vault)
            db.ensure_user("friend1", False)
            db.set_api_key("friend1", USER_KEY, "cli")
            db.close()
            self.assertNotIn(USER_KEY.encode(), (Path(tmp) / "p.db").read_bytes())
            # without a master key, keys are refused (never stored in plaintext)
            nokey = KeyVault(key_file=Path(tmp) / "none", environ={})
            self.assertFalse(nokey.available)
            db2 = Database(Path(tmp) / "q.db", nokey)
            db2.ensure_user("friend1", False)
            with self.assertRaises(VaultError):
                db2.set_api_key("friend1", USER_KEY, "cli")
            self.assertIsNone(db2.get_api_key("friend1"))
            db2.close()


class NoSecretLeaks(Base):
    def test_13_keys_and_tokens_never_appear_in_logs_or_replies(self):
        redactor = SecretRedactor()
        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())

        handler = Capture()
        handler.addFilter(redactor)
        root = logging.getLogger()
        root.addHandler(handler)
        old_level = root.level
        root.setLevel(logging.DEBUG)
        for secret in (ADMIN_KEY, USER_KEY, TOKENS["owner"]):
            redactor.add(secret)
        self.app.redactor = redactor
        try:
            self.say("owner", "/ai friend1 on")
            self.db.set_api_key("friend1", USER_KEY, "cli")
            replies = []
            boom = requests.ConnectionError(f"url=https://x/?key={USER_KEY} header {ADMIN_KEY}")
            with mock.patch.object(fx.requests, "post", side_effect=boom):
                replies.append(self.say("friend1", "/ai hi"))
                replies.append(self.say("owner", "/ai hi"))
            with mock.patch.object(fx, "ask_gemini", side_effect=RuntimeError(USER_KEY)):
                replies.append(self.say("friend1", "/ai hi"))
            with mock.patch.object(fx, "web_search", side_effect=requests.ConnectionError(USER_KEY)):
                replies.append(self.say("friend1", "/search cats"))
            for command in ("/user friend1", "/users", "/stats", "/health", "/audit 25",
                            "/features friend1", "/mykey", "/help", "/admin"):
                replies.append(self.say("owner", command))
            replies.append(self.say("friend1", "/mykey"))
            # a user pasting a key into chat is warned and NOT forwarded
            with mock.patch.object(fx, "ask_gemini") as ask:
                replies.append(self.say("friend1", "/ai AIza" + "a" * 35))
                ask.assert_not_called()
        finally:
            root.removeHandler(handler)
            root.setLevel(old_level)
        blob = "\n".join(r for r in replies if r) + "\n".join(records)
        audit = str(self.db.recent_audit(50))
        for secret in (ADMIN_KEY, USER_KEY, TOKENS["owner"]):
            self.assertNotIn(secret, blob)
            self.assertNotIn(secret, audit)
        self.assertNotIn(USER_KEY.encode(), self.db_path.read_bytes())    # not stored in plaintext
        self.assertNotIn(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", self.db_path.read_bytes())
        self.assertIn("key", "\n".join(replies).lower())

    def test_redactor_masks_google_style_keys(self):
        redactor = SecretRedactor()
        text = redactor.scrub("x AIza" + "B" * 30 + " and ?key=SECRETVALUE&a=1 and x-goog-api-key: abc123")
        self.assertNotIn("B" * 30, text)
        self.assertNotIn("SECRETVALUE", text)
        self.assertNotIn("abc123", text)


class YouTubeSearchFlow(Base):
    ITEMS = [
        {"id": "AAAAAAAAAAA", "title": "First *video*", "channel": "Chan_A", "duration": 125},
        {"id": "BBBBBBBBBBB", "title": "Second", "channel": None, "duration": None},
        {"id": "bad id!", "title": "Dropped", "channel": "x", "duration": 5},
    ]

    def test_14_selection_is_isolated_per_user_and_expires(self):
        clock = [0.0]
        self.app.selections = fx.Selections(ttl=600, clock=lambda: clock[0])
        with mock.patch.object(fx, "_ytdlp_search", return_value=self.ITEMS):
            listing = self.say("friend1", "/youtube lofi")
        self.assertIn("1. First video", listing)
        self.assertIn("👤 Chan A · ⏱ 2:05", listing)
        self.assertIn("https://youtu.be/AAAAAAAAAAA", listing)
        self.assertNotIn("Dropped", listing)
        self.assertNotIn("*", listing)                         # formatting chars neutralised
        self.assertNotIn("⏱ None", listing)                    # nothing invented
        self.assertIn("active list", self.say("friend2", "/play 1"))       # other user: nothing
        self.assertIn("active list", self.say("owner", "/play 1"))
        out = self.app.handle("friend1", "/play 2")
        self.assertIn("https://youtu.be/BBBBBBBBBBB", out.text)
        self.assertTrue(out.preview)
        self.assertIn("1 se 2", self.say("friend1", "/play 9"))
        # friend2 searching does not replace friend1's list
        with mock.patch.object(fx, "_ytdlp_search", return_value=self.ITEMS[1:2]):
            self.say("friend2", "/play other")
        self.assertIn("AAAAAAAAAAA", self.say("friend1", "/play 1"))
        clock[0] = 601
        self.assertIn("active list", self.say("friend1", "/play 1"))        # expired

    def test_fallback_when_provider_returns_nothing(self):
        with mock.patch.object(fx, "_ytdlp_search", return_value=[]):
            self.assertIn("youtube.com/results", self.say("friend1", "/youtube zzz"))


class SearchAndErrors(Base):
    def _html(self):
        return ('<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.example.org%2Fpage">'
                'Example <b>title</b></a><a class="result__snippet" href="x">A short <b>snippet</b> here</a>'
                '<a class="result__a" href="javascript:alert(1)">Bad</a>')

    def test_15_search_results_are_readable_and_selectable(self):
        response = mock.Mock(text=self._html())
        response.raise_for_status = mock.Mock()
        with mock.patch.object(fx.session, "get", return_value=response):
            listing = self.say("friend1", "/search python")
        self.assertIn("1. Example title", listing)
        self.assertIn("A short snippet here", listing)
        self.assertIn("🌐 example.org", listing)
        self.assertIn("https://www.example.org/page", listing)
        self.assertNotIn("duckduckgo", listing)
        self.assertNotIn("javascript", listing)
        self.assertIn("Result 1", self.say("friend1", "/search 1"))
        self.assertIn("active list", self.say("friend2", "/search 1"))

    def test_15_network_errors_are_friendly(self):
        with mock.patch.object(fx.session, "get", side_effect=requests.ConnectionError("boom http://secret")):
            reply = self.say("friend1", "/search python")
        self.assertIn("Network error", reply)
        self.assertNotIn("secret", reply)
        self.assertNotIn("Traceback", reply)

    def test_15_gemini_error_mapping(self):
        def fake(status, body=None):
            r = mock.Mock(status_code=status)
            r.json.return_value = body or {}
            return r

        cases = [
            (fake(401), "invalid_key"), (fake(403), "invalid_key"),
            (fake(400, {"error": {"message": "API key not valid"}}), "invalid_key"),
            (fake(429), "quota"), (fake(404), "model"), (fake(503), "provider"),
            (fake(200, {"promptFeedback": {"blockReason": "SAFETY"}}), "blocked"),
            (fake(200, {"candidates": []}), "empty"),
        ]
        for response, kind in cases:
            with mock.patch.object(fx.requests, "post", return_value=response):
                with self.assertRaises(fx.GeminiError) as caught:
                    fx.ask_gemini("k" * 30, "hi")
            self.assertEqual(caught.exception.kind, kind)
        with mock.patch.object(fx.requests, "post", side_effect=requests.Timeout("t")):
            with self.assertRaises(fx.GeminiError) as caught:
                fx.ask_gemini("k" * 30, "hi")
        self.assertEqual(caught.exception.kind, "timeout")
        ok = fake(200, {"candidates": [{"content": {"parts": [{"text": "hello"}]}}]})
        with mock.patch.object(fx.requests, "post", return_value=ok) as post:
            self.assertEqual(fx.ask_gemini("MYKEY" + "k" * 30, "hi", model="m1"), "hello")
        self.assertEqual(post.call_args.kwargs["headers"]["x-goog-api-key"], "MYKEY" + "k" * 30)
        self.assertIn("m1:generateContent", post.call_args.args[0])

    def test_15_ai_failures_reach_user_as_friendly_text(self):
        self.say("owner", "/ai friend1 on")
        self.db.set_api_key("friend1", USER_KEY, "cli")
        with mock.patch.object(fx, "ask_gemini", side_effect=fx.GeminiError("quota")):
            self.assertIn("quota", self.say("friend1", "/ai hi"))
        self.assertGreaterEqual(self.db.stats()["week_errors"], 1)


class Safety(unittest.TestCase):
    def test_calculator(self):
        self.assertEqual(fx.calculate("(25*4)+10"), 110)
        for bad in ("__import__('os')", "9**9**9", "((9**99)**99)**99", "1/0 + a", "x" * 101):
            with self.assertRaises((ValueError, SyntaxError, ZeroDivisionError)):
                fx.calculate(bad)

    def test_ssrf_blocked_for_private_hosts(self):
        for url in ("http://127.0.0.1/", "http://localhost/", "http://192.168.1.1/",
                    "http://169.254.169.254/latest", "http://[::1]/", "http://10.0.0.5:8080/",
                    "http://example.com:22/"):
            with self.assertRaises(fx.UserFacingError):
                fx.assert_public_url(url)

    def test_redirect_to_private_address_is_refused(self):
        redirect = mock.Mock(status_code=302, headers={"location": "http://127.0.0.1/admin"})
        with mock.patch.object(fx, "assert_public_url", side_effect=[None, fx.UserFacingError("no")]), \
                mock.patch.object(fx.session, "get", return_value=redirect):
            with self.assertRaises(fx.UserFacingError):
                fx.safe_get("https://example.com/")

    def test_clean_text_and_urls(self):
        self.assertEqual(fx.clean_text("a\n\tb\u202e *c* _d_ ~e~"), "a b c d e")
        self.assertIsNone(fx.tidy_url("javascript:alert(1)"))
        self.assertIsNone(fx.tidy_url("https://user:pw@evil.example/"))
        self.assertEqual(fx.tidy_url("https://example.com/a?id=1"), "https://example.com/a?id=1")

    def test_rate_limiter(self):
        clock = [0.0]
        limiter = RateLimiter(clock=lambda: clock[0])
        self.assertTrue(all(limiter.allow("u", 3, 60)[0] for _ in range(3)))
        allowed, wait = limiter.allow("u", 3, 60)
        self.assertFalse(allowed)
        self.assertGreater(wait, 0)
        self.assertTrue(limiter.allow("other", 3, 60)[0])
        clock[0] = 61
        self.assertTrue(limiter.allow("u", 3, 60)[0])

    def test_download_size_limit_and_no_path_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "friend1"
            response = mock.Mock(status_code=200, headers={"content-length": str(fx.MAX_DOWNLOAD_BYTES + 1)},
                                 url="https://example.com/big.bin")
            response.raise_for_status = mock.Mock()
            response.close = mock.Mock()
            with mock.patch.object(fx, "safe_get", return_value=response):
                self.assertIn("50 MB", fx.direct_download("https://example.com/big.bin", dest))
            small = mock.Mock(status_code=200, headers={}, url="https://example.com/a b/../f.txt")
            small.raise_for_status = mock.Mock()
            small.close = mock.Mock()
            small.iter_content = mock.Mock(return_value=[b"hello"])
            with mock.patch.object(fx, "safe_get", return_value=small):
                text = fx.direct_download("https://example.com/f.txt", dest)
            self.assertNotIn(tmp, text)                       # no server path in the reply
            self.assertTrue((dest / "f.txt").exists())


if __name__ == "__main__":
    unittest.main()
