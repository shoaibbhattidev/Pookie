# Pookie – setup, commands, limitations

Files: `assistant.py` (entry + CLI), `pookie_app.py` (permissions + commands), `pookie_db.py` (SQLite, encryption, rate limiter, log redaction), `pookie_features.py` (search, YouTube, Gemini, scrape…), `pookie_config.py` (tokens/offsets), `pookie_runner.py` (agent threads), `tests/test_pookie.py`, `.env.example`, `.gitignore`.

## 1. Back up, then install (Termux)

```bash
cd ~
cp -a myassistant myassistant-backup-$(date +%Y%m%d-%H%M)     # full backup incl. .env and .whagent-offset
cd myassistant && source .venv/bin/activate
# copy the delivered files into ~/myassistant (assistant.py replaces the old one; the backup keeps it)
pip install requests python-dotenv cryptography
chmod 600 .env
```

If `pip install cryptography` fails on Termux (it may need to compile), try `pkg install rust binutils build-essential openssl libffi` and retry. Without it Pookie still runs, but **per-user Gemini keys cannot be stored** (they are refused, never saved in plaintext).

Add extra agents to `.env` (see `.env.example`). Each friend must create **their own** WhatsApp agent and give you its token.

```bash
python assistant.py init        # creates .pookie.key (chmod 600) + pookie.db. BACK UP .pookie.key separately
python assistant.py agents      # shows labels / offset files / skipped duplicates (no tokens)
python assistant.py check-model # asks Google whether GEMINI_MODEL exists for your key
```

## 2. Checks and tests

```bash
python -m py_compile assistant.py pookie_*.py && echo "syntax OK"
python -m unittest discover -s tests -v          # 38 tests, mocks only, no messages sent, no API cost
```

## 3. Start and test manually

```bash
python assistant.py
```

1. From your owner chat: `/admin`, `/users`, `/health` → admin dashboard works.
2. From a friend's chat: `/admin` → "Unknown command"; `/help` shows no admin lines; `/ai hi` → "AI not enabled".
3. Friend's key (hidden prompt, in Termux — never in WhatsApp): `python assistant.py set-key friend1`
4. Owner: `/ai friend1 on` → friend: `/ai hello` works with **friend1's own key**.
5. Owner: `/features friend1 scrape on`, `/setlimit friend1 20`, `/block friend1`, `/unblock friend1`.
6. Emergency: `/ai all off` (everyone incl. admin) → `/ai all on` to lift.
7. `/youtube lofi` → `/play 2`; `/search python` → `/search 2`.

Stop with Ctrl+C (up to ~25 s while long polls finish). New tokens in `.env` need a restart.

## 4. Command reference

**Everyone (if enabled for them):** `/start` `/help` `/ping` `/about` · `/search QUERY` then `/search N` · `/youtube QUERY` · `/play QUERY` or `/play N` · `/weather CITY` · `/calc EXPR` · `/ai QUESTION` · `/scrape URL` · `/download URL` · `/ytdl URL` · `/myai on|off` · `/mykey` / `/mykey remove`
Defaults for new users: search, youtube, play, weather, calc **on**; AI, scrape, download, ytdl **off**. Daily limit 50 counted requests (AI, search, YouTube, weather, scrape, downloads). Selection lists expire after 10 minutes and are per user.

**Admin only (owner token):** `/admin` · `/users [page]` · `/user ID` · `/ai ID on|off` · `/ai all off|on` · `/features ID` · `/features ID NAME on|off` (NAME = ai, search, youtube, play, weather, calc, scrape, download, ytdl) · `/block ID` · `/unblock ID` (also restores removed users) · `/setlimit ID N` · `/remove-user ID` then `/remove-user ID confirm` (60 s) · `/stats` · `/health` · `/audit [N]`
`ID` = the label (owner, friend1…). Admin `/ai friend1 on` is treated as a control command only when the first word is an existing label or `all`; anything else is a normal AI question.

**Server CLI (private, in Termux):** `set-key LABEL` · `remove-key LABEL` · `rebind LABEL` · `check-model` · `backup` · `agents` · `init` · `run`

## 5. Security model (what is actually implemented)

- Admin = the agent whose token is `WHATSAPP_AGENT_TOKEN` (label from `POOKIE_OWNER_LABEL`). Each agent has its own handler closure; the label never comes from message text. Admin role is re-checked on every admin action.
- First message from a chat binds the API-delivered sender id and agent id; later mismatches are refused (`rebind` clears it). Requires `ctx.message.sender` / `ctx.update.agent_id` (see limitations).
- Gemini: `ask_gemini()` receives the key as an argument and never reads the environment; admin → `GEMINI_API_KEY`, others → only their own stored key, otherwise denied. AI needs: active account, admin AI on, global switch off, user's own switch on, own key, within limit. Access is re-checked after queueing, so blocks/AI-off also cancel waiting requests.
- User keys: Fernet (AES + HMAC) encrypted in SQLite; master key in `.pookie.key` or `POOKIE_MASTER_KEY`, never in the DB. Keys are never logged, shown, or put in audit rows; log lines pass a redaction filter; pasted `AIza…` keys in chat are not forwarded or stored.
- SQLite: parameterised queries, WAL, transactions, schema version (`PRAGMA user_version`), automatic backup before migrations, backups never overwrite.
- Scrape/download/ytdl: public hosts only (private, loopback, link-local and CGNAT ranges refused, every redirect hop checked), ports 80/443/8080/8443, 50 MB cap, 500 MB per-user folder, no server paths in replies, no shell.
- Message text is not logged.

## 6. Limitations and honest notes

- **One agent = one WhatsApp user.** whagent's API only lets an agent message its creator (`ForbiddenError` 131005), so "multi-user" means one agent token per friend.
- **Context attributes not verified:** the source of `whagent`'s `Context` class was not available. The code uses `ctx.text` and `ctx.reply` (as your original did) and reads `ctx.message.sender`, `ctx.update.agent_id`, `ctx.client` via `getattr` (they match how `Agent.dispatch` builds `Context`). If missing, Pookie logs one warning per agent, identity binding is skipped, and link previews fall back to plain replies; token-per-agent mapping still isolates users.
- **No buttons / in-chat playback:** `SENDABLE_TYPES` has no interactive messages, so selection is numbered text. `/play N` sends a clean `youtu.be` link with a preview request (`preview_url=True`); whether WhatsApp renders a thumbnail is up to WhatsApp. Pookie does not download or redistribute YouTube videos for `/youtube` and `/play`. `/ytdl` (disabled by default) remains from your original; use it only for content you may download.
- **Search providers:** DuckDuckGo's HTML page (unofficial, can break or rate-limit) unless `BRAVE_API_KEY` is set (official). YouTube: yt-dlp metadata (unofficial) unless `YOUTUBE_API_KEY` is set (official Data API). Missing titles/durations are omitted, never invented.
- **Gemini model:** `gemini-3.5-flash-lite` is kept from your script; I could only confirm it from third-party reseller docs, not from Google. Run `python assistant.py check-model` and set `GEMINI_MODEL` if it reports a problem.
- **Giving friends' keys to the admin** happens outside WhatsApp (in person/secure channel); the admin types it into a hidden prompt. There is no safe in-chat entry flow.
- **Residual SSRF risk:** DNS rebinding between the check and the connection is not pinned; yt-dlp follows its own redirects after the first check. Keep `scrape`, `download`, `ytdl` off for people you do not trust.
- Rate limits: 12 commands/min per user, 120/min overall. Because each agent has exactly one user, "per-agent" equals "per-user".
- A removed/blocked user's agent keeps polling and answers "not active"; delete their `POOKIE_TOKEN_…` line and restart to stop it.
- Changed from the original: download replies no longer show server paths; `/play` is now a selector; command names are no longer printed in logs; messages that were Roman-Urdu stay Roman-Urdu.
- Tested here with mocks and a stub `whagent` (no real WhatsApp or Gemini traffic). Do a live test with your real agents before relying on it.
