"""pookie_features.py - the actual command implementations.

Preserved from the original assistant.py: calculator, weather, scrape, direct
download, yt-dlp download, DuckDuckGo search parser, Gemini generateContent.
Changed: SSRF protection, size limits, per-user download folders, clean
formatting, numbered selection for /search, /youtube and /play, and a Gemini
function that receives the API key as an argument (it never reads the
environment, so it cannot fall back to the admin key by accident).

Nothing here logs message text, URLs or keys.
"""

import ast
import html
import ipaddress
import json
import logging
import math
import operator
import os
import re
import socket
import subprocess
import sys
import threading
import time
from contextlib import closing
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests

log = logging.getLogger("pookie.features")

HTTP_TIMEOUT = 15
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024  # 50 MB (unchanged from the original)
MAX_USER_DISK_BYTES = 500 * 1024 * 1024  # per-user download folder cap
MAX_REDIRECTS = 4
ALLOWED_PORTS = {None, 80, 443, 8080, 8443}

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; PythonPersonalAssistant/1.0)"})


class UserFacingError(Exception):
    """Message is safe to show to the WhatsApp user."""


# --------------------------------------------------------------------------- #
# Text / URL helpers
# --------------------------------------------------------------------------- #

_FORMAT_CHARS = str.maketrans({"*": "", "~": "", "`": "'", "_": " "})


def clean_text(value, limit=200):
    """Make untrusted text safe for a chat message: collapse whitespace, drop
    control / zero-width / bidi characters and WhatsApp formatting markers."""
    import unicodedata

    text = " ".join(str(value or "").split())
    text = "".join(ch for ch in text if ch == " " or unicodedata.category(ch)[0] != "C")
    text = " ".join(text.translate(_FORMAT_CHARS).split())
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def valid_url(value):
    try:
        value = value.strip()
        parsed = urlparse(value)
        return (
            parsed.scheme in ("http", "https")
            and bool(parsed.netloc)
            and "@" not in parsed.netloc
            and not any(c.isspace() for c in value)
            and len(value) <= 2000
        )
    except Exception:  # noqa: BLE001
        return False


def tidy_url(url, maxlen=110):
    """Return a compact clickable URL or None. Drops query/fragment only when the
    URL is long (so short links with ?id= keep working)."""
    if not valid_url(url):
        return None
    if len(url) > maxlen:
        parsed = urlparse(url)
        url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return url if len(url) <= 200 else None


def domain_of(url):
    host = urlparse(url).hostname or ""
    return host[4:] if host.startswith("www.") else host


def assert_public_url(url):
    """SSRF guard: only public internet hosts on normal web ports."""
    try:
        parsed = urlparse(url)
        port = parsed.port
        host = parsed.hostname
    except ValueError:
        raise UserFacingError("Yeh URL valid nahi hai.")
    if not host or port not in ALLOWED_PORTS:
        raise UserFacingError("Yeh URL ya port allowed nahi hai.")
    try:
        infos = socket.getaddrinfo(
            host, port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP
        )
    except socket.gaierror:
        raise UserFacingError("Website ka address resolve nahi ho saka.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global:
            raise UserFacingError("Local/private network addresses allowed nahi hain.")


def safe_get(url):
    """GET with manual redirect handling so every hop is SSRF-checked.
    (Residual risk: DNS rebinding between check and connect - see SETUP.md.)"""
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        if not valid_url(current):
            raise UserFacingError("Valid http:// ya https:// URL bhejo.")
        assert_public_url(current)
        response = session.get(current, timeout=HTTP_TIMEOUT, stream=True, allow_redirects=False)
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("location")
            response.close()
            if not location:
                raise UserFacingError("Website ne galat redirect diya.")
            current = urljoin(current, location)
            continue
        return response
    raise UserFacingError("Bohat zyada redirects hain.")


def read_limited(response, max_bytes):
    chunks, total = [], 0
    for chunk in response.iter_content(16 * 1024):
        if not chunk:
            continue
        total += len(chunk)
        chunks.append(chunk)
        if total >= max_bytes:
            break
    return b"".join(chunks)[:max_bytes]


# --------------------------------------------------------------------------- #
# Safe calculator (original, plus a cost guard on huge powers)
# --------------------------------------------------------------------------- #

BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
UNARY_OPS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def calculate(expression):
    if len(expression) > 100:
        raise ValueError("Expression too long.")
    tree = ast.parse(expression, mode="eval")

    def evaluate(node):
        if isinstance(node, ast.Expression):
            return evaluate(node.body)
        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in BIN_OPS:
            left = evaluate(node.left)
            right = evaluate(node.right)
            if isinstance(node.op, ast.Pow):
                if abs(right) > 100:
                    raise ValueError("Exponent too large.")
                # Refuse before computing something enormous like ((9**99)**99)**99.
                if abs(left) > 1 and abs(right) * math.log2(abs(left)) > 400:
                    raise ValueError("Result too large.")
            result = BIN_OPS[type(node.op)](left, right)
            if isinstance(result, (int, float)) and abs(result) > 1e100:
                raise ValueError("Result too large.")
            return result
        if isinstance(node, ast.UnaryOp) and type(node.op) in UNARY_OPS:
            return UNARY_OPS[type(node.op)](evaluate(node.operand))
        raise ValueError("Only basic arithmetic is supported.")

    return evaluate(tree)


# --------------------------------------------------------------------------- #
# Web search
# --------------------------------------------------------------------------- #

def _unwrap_ddg(href):
    if href.startswith("//"):
        href = "https:" + href
    parsed = urlparse(href)
    if (parsed.hostname or "").endswith("duckduckgo.com") and parsed.path.startswith("/l/"):
        target = parse_qs(parsed.query).get("uddg")
        return target[0] if target else None
    return href


class SearchParser(HTMLParser):
    """Parses DuckDuckGo's HTML endpoint: titles (a.result__a) and snippets."""

    def __init__(self):
        super().__init__()
        self.results = []
        self._title = False
        self._snippet_tag = None
        self._buf = ""
        self._href = ""

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        classes = attrs.get("class", "") or ""
        if tag == "a" and "result__a" in classes:
            self._title, self._buf, self._href = True, "", attrs.get("href", "") or ""
        elif "result__snippet" in classes and self.results:
            self._snippet_tag, self._buf = tag, ""

    def handle_data(self, data):
        if self._title or self._snippet_tag:
            self._buf += data

    def handle_endtag(self, tag):
        if self._title and tag == "a":
            title = " ".join(self._buf.split())
            url = _unwrap_ddg(self._href)
            if title and url:
                self.results.append({"title": title, "url": url, "snippet": ""})
            self._title = False
        elif self._snippet_tag and tag == self._snippet_tag:
            self.results[-1]["snippet"] = " ".join(self._buf.split())
            self._snippet_tag = None


def _ddg_search(query, count):
    response = session.get(
        "https://html.duckduckgo.com/html/", params={"q": query}, timeout=HTTP_TIMEOUT
    )
    response.raise_for_status()
    parser = SearchParser()
    parser.feed(response.text[:1_000_000])
    return parser.results[:count]


def _brave_search(query, api_key, count):
    response = session.get(
        "https://api.search.brave.com/res/v1/web/search",
        params={"q": query, "count": count},
        headers={"X-Subscription-Token": api_key, "Accept": "application/json"},
        timeout=HTTP_TIMEOUT,
    )
    response.raise_for_status()
    items = (response.json().get("web") or {}).get("results") or []
    out = []
    for item in items[:count]:
        snippet = html.unescape(re.sub(r"<[^>]+>", "", item.get("description") or ""))
        out.append({"title": item.get("title") or "", "url": item.get("url") or "", "snippet": snippet})
    return out


def web_search(query, count=5, environ=None):
    """Returns a list of {title, url, snippet}. Uses Brave Search API when
    BRAVE_API_KEY is set (official), otherwise falls back to DuckDuckGo's HTML
    page (unofficial; may break or be rate limited)."""
    environ = os.environ if environ is None else environ
    key = (environ.get("BRAVE_API_KEY") or "").strip()
    if key:
        try:
            results = _brave_search(query, key, count)
            if results:
                return results
        except (requests.RequestException, ValueError) as exc:
            log.warning("Brave search failed (%s); falling back", type(exc).__name__)
    return _ddg_search(query, count)


def search_items(raw_results):
    """Normalise + sanitise provider output. Untrusted text is cleaned here."""
    items = []
    for raw in raw_results:
        url = tidy_url(raw.get("url") or "")
        title = clean_text(raw.get("title"), 90)
        if not url or not title:
            continue
        items.append({
            "title": title,
            "url": url,
            "snippet": clean_text(raw.get("snippet"), 160),
            "domain": clean_text(domain_of(url), 60),
        })
    return items


def format_search(query, items):
    if not items:
        return (
            "Search results nahi milay. Direct search link:\n"
            f"https://www.google.com/search?q={requests.utils.quote(query)}"
        )
    lines = [f"🔎 Results: {clean_text(query, 60)}"]
    for index, item in enumerate(items, 1):
        block = [f"{index}. {item['title']}"]
        if item["snippet"]:
            block.append(f"   {item['snippet']}")
        block.append(f"   🌐 {item['domain']}")
        block.append(f"   {item['url']}")
        lines.append("\n".join(block))
    lines.append("Details ke liye: /search N (e.g. /search 2)")
    return "\n\n".join(lines)


def format_search_detail(item, number):
    parts = [f"🔎 Result {number}", item["title"]]
    if item["snippet"]:
        parts.append(item["snippet"])
    parts.append(f"🌐 {item['domain']}\n{item['url']}")
    parts.append("Page ka text dekhna ho to /scrape ke saath yeh link bhejo (agar enabled hai).")
    return "\n\n".join(parts)


# --------------------------------------------------------------------------- #
# YouTube (search metadata only - Pookie never downloads here)
# --------------------------------------------------------------------------- #

YT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{11}$")
_ISO_DURATION = re.compile(r"^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$")


def fmt_duration(seconds):
    if not isinstance(seconds, (int, float)) or seconds <= 0:
        return None
    seconds = int(seconds)
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes}:{secs:02d}"


def _iso_duration_seconds(value):
    match = _ISO_DURATION.match(value or "")
    if not match:
        return None
    hours, minutes, secs = (int(g or 0) for g in match.groups())
    return hours * 3600 + minutes * 60 + secs


def _youtube_api_search(query, api_key, count):
    """Official YouTube Data API v3 (search.list + videos.list)."""
    response = session.get(
        "https://www.googleapis.com/youtube/v3/search",
        params={"part": "snippet", "type": "video", "maxResults": count, "q": query,
                "safeSearch": "moderate", "key": api_key},
        timeout=HTTP_TIMEOUT,
    )
    response.raise_for_status()
    found = []
    for item in response.json().get("items", []):
        video_id = (item.get("id") or {}).get("videoId")
        snippet = item.get("snippet") or {}
        if video_id:
            found.append({"id": video_id, "title": snippet.get("title"),
                          "channel": snippet.get("channelTitle"), "duration": None})
    if found:
        details = session.get(
            "https://www.googleapis.com/youtube/v3/videos",
            params={"part": "contentDetails", "id": ",".join(v["id"] for v in found), "key": api_key},
            timeout=HTTP_TIMEOUT,
        )
        if details.ok:
            lengths = {
                d.get("id"): _iso_duration_seconds((d.get("contentDetails") or {}).get("duration"))
                for d in details.json().get("items", [])
            }
            for video in found:
                video["duration"] = lengths.get(video["id"])
    return found


def _ytdlp_search(query, count):
    """Metadata-only search through yt-dlp (unofficial fallback)."""
    result = subprocess.run(
        [sys.executable, "-m", "yt_dlp", "--ignore-config", "--flat-playlist",
         "--dump-single-json", "--skip-download", "--no-warnings", f"ytsearch{count}:{query}"],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return []
    found = []
    for entry in (json.loads(result.stdout).get("entries") or [])[:count]:
        found.append({
            "id": entry.get("id"),
            "title": entry.get("title"),
            "channel": entry.get("channel") or entry.get("uploader"),
            "duration": entry.get("duration"),
        })
    return found


def youtube_search(query, count=5, environ=None):
    """Returns sanitised items: {id, title, channel|None, duration|None, url}.
    Fields the provider did not supply stay None - nothing is invented."""
    environ = os.environ if environ is None else environ
    raw = []
    api_key = (environ.get("YOUTUBE_API_KEY") or "").strip()
    if api_key:
        try:
            raw = _youtube_api_search(query, api_key, count)
        except (requests.RequestException, ValueError) as exc:
            log.warning("YouTube API failed (%s); falling back", type(exc).__name__)
    if not raw:
        try:
            raw = _ytdlp_search(query, count)
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError, OSError) as exc:
            log.warning("yt-dlp search failed (%s)", type(exc).__name__)
    items = []
    for entry in raw:
        video_id = entry.get("id") or ""
        if not YT_ID_RE.match(video_id):
            continue
        items.append({
            "id": video_id,
            "title": clean_text(entry.get("title"), 90) or "Untitled video",
            "channel": clean_text(entry.get("channel"), 40) or None,
            "duration": fmt_duration(entry.get("duration")),
            "url": f"https://youtu.be/{video_id}",
        })
    return items


def format_youtube(query, items):
    if not items:
        search_url = "https://www.youtube.com/results?" + urlencode({"search_query": query})
        return f"Is search ka koi result nahi mila. YouTube par dekho:\n{search_url}"
    lines = [f"▶️ YouTube: {clean_text(query, 60)}"]
    for index, item in enumerate(items, 1):
        meta = " · ".join(
            part for part in (
                f"👤 {item['channel']}" if item["channel"] else None,
                f"⏱ {item['duration']}" if item["duration"] else None,
            ) if part
        )
        block = [f"{index}. {item['title']}"]
        if meta:
            block.append(f"   {meta}")
        block.append(f"   {item['url']}")
        lines.append("\n".join(block))
    lines.append("Kholne ke liye: /play N (e.g. /play 2)")
    return "\n\n".join(lines)


def format_play(item):
    meta = " · ".join(
        part for part in (
            f"👤 {item['channel']}" if item["channel"] else None,
            f"⏱ {item['duration']}" if item["duration"] else None,
        ) if part
    )
    text = f"▶️ {item['title']}"
    if meta:
        text += f"\n{meta}"
    return text + f"\n{item['url']}\n(Link tap karo - YouTube/app mein khulega.)"


# --------------------------------------------------------------------------- #
# Per-user selection state with expiry
# --------------------------------------------------------------------------- #

class Selections:
    """Remembers the last result list per (user label, kind). Expires."""

    def __init__(self, ttl=600, clock=time.monotonic):
        self.ttl = ttl
        self._clock = clock
        self._data = {}
        self._lock = threading.Lock()

    def put(self, label, kind, items):
        with self._lock:
            self._data[(label, kind)] = (self._clock(), list(items))

    def get(self, label, kind):
        with self._lock:
            entry = self._data.get((label, kind))
            if not entry:
                return None
            if self._clock() - entry[0] > self.ttl:
                del self._data[(label, kind)]
                return None
            return entry[1]

    def clear(self, label):
        with self._lock:
            for key in [k for k in self._data if k[0] == label]:
                del self._data[key]


# --------------------------------------------------------------------------- #
# Weather
# --------------------------------------------------------------------------- #

def get_weather(city):
    city = " ".join(city.split())
    if not city or len(city) > 60 or not re.match(r"^[\w\s.,'\-]+$", city):
        raise ValueError("City ka naam sahi likho (e.g. Lahore).")
    response = session.get(
        f"https://wttr.in/{requests.utils.quote(city)}",
        params={"format": "j1"},
        timeout=HTTP_TIMEOUT,
    )
    response.raise_for_status()
    data = response.json()
    current = data["current_condition"][0]
    description = current["weatherDesc"][0]["value"]
    return (
        f"🌦️ Weather: {clean_text(city, 60)}\n"
        f"Condition: {clean_text(description, 60)}\n"
        f"Temperature: {current['temp_C']}°C\n"
        f"Feels like: {current['FeelsLikeC']}°C\n"
        f"Humidity: {current['humidity']}%\n"
        f"Wind: {current['windspeedKmph']} km/h"
    )


# --------------------------------------------------------------------------- #
# Web page text (scrape)
# --------------------------------------------------------------------------- #

class TextParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title_parts, self.text_parts = [], []
        self.in_title = False
        self.skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self.in_title = True
        if tag in ("script", "style", "noscript", "svg"):
            self.skip_depth += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        if tag in ("script", "style", "noscript", "svg") and self.skip_depth:
            self.skip_depth -= 1

    def handle_data(self, data):
        clean = " ".join(data.split())
        if not clean:
            return
        if self.in_title:
            self.title_parts.append(clean)
        if not self.skip_depth:
            self.text_parts.append(clean)


def scrape_page(url):
    if not valid_url(url):
        return "Valid http:// ya https:// URL bhejo."
    with closing(safe_get(url)) as response:
        response.raise_for_status()
        content_type = response.headers.get("content-type", "").lower()
        if "html" not in content_type and "text" not in content_type:
            return "Yeh HTML/text webpage nahi lagta."
        body = read_limited(response, 1_000_000)
        encoding = response.encoding
        if not encoding or encoding.lower() == "iso-8859-1":
            encoding = "utf-8"
        final_url = response.url
    parser = TextParser()
    parser.feed(body.decode(encoding, errors="replace"))
    title = clean_text(" ".join(parser.title_parts), 120) or "No page title"
    text = clean_text(" ".join(parser.text_parts), 2200) or "Page se readable text nahi mil saka."
    shown = tidy_url(final_url) or domain_of(final_url)
    # Page content is DATA shown to the user. It is never fed to the AI or executed.
    return f"🌐 {title}\n\n{text}\n\nSource: {shown}"


# --------------------------------------------------------------------------- #
# Downloads (per-user folder, size limits, SSRF-safe)
# --------------------------------------------------------------------------- #

def _folder_size(folder):
    total = 0
    for path in folder.rglob("*"):
        try:
            if path.is_file():
                total += path.stat().st_size
        except OSError:
            continue
    return total


def direct_download(url, dest_dir):
    if not valid_url(url):
        return "Valid http:// ya https:// file URL bhejo."
    dest_dir.mkdir(parents=True, exist_ok=True)
    if _folder_size(dest_dir) >= MAX_USER_DISK_BYTES:
        return "Aap ka download folder full hai (500 MB limit). Admin se kaho purani files hataye."

    with closing(safe_get(url)) as response:
        response.raise_for_status()
        length = response.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_DOWNLOAD_BYTES:
            return "File 50 MB se bari hai; download cancel kar diya."

        filename = os.path.basename(urlparse(response.url).path)
        filename = re.sub(r"[^A-Za-z0-9._-]", "_", filename)[:100]
        if not filename or filename in (".", ".."):
            filename = "downloaded_file"
        destination = dest_dir / filename
        if destination.exists():
            destination = dest_dir / f"{int(time.time())}_{filename}"

        total = 0
        try:
            with open(destination, "wb") as handle:
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise OverflowError
                    handle.write(chunk)
        except OverflowError:
            destination.unlink(missing_ok=True)
            return "File 50 MB se bari nikli; download cancel kar diya."
        except BaseException:
            destination.unlink(missing_ok=True)
            raise

    return (
        "✅ Download complete!\n"
        f"File: {destination.name}\n"
        f"Size: {total / (1024 * 1024):.2f} MB\n"
        f"Folder: downloads/{dest_dir.name}/"
    )


def youtube_download(url, dest_dir):
    """yt-dlp download. Disabled by default; only for content the admin has the
    right to download. Arguments are a list (no shell)."""
    if not valid_url(url):
        return "Valid video URL bhejo."
    assert_public_url(url)
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "yt_dlp", "--ignore-config", "--no-playlist",
             "--max-filesize", "50M", "--no-warnings", "--restrict-filenames",
             "-P", str(dest_dir), "-o", "%(title).80s.%(ext)s", "--", url],
            capture_output=True, text=True, timeout=240,
        )
    except subprocess.TimeoutExpired:
        return "Download mein 4 minutes se zyada lag gaye; command stop kar di."
    except (FileNotFoundError, OSError):
        return "Download start nahi ho saka. yt-dlp installation check karo."
    if result.returncode == 0:
        return f"✅ Download command complete.\nFolder: downloads/{dest_dir.name}/"
    log.warning("yt-dlp exited with code %s", result.returncode)  # no URL / stderr logged
    return ("Download fail hua. Video unavailable ho sakti hai, ya website download support "
            "nahi karti.")


# --------------------------------------------------------------------------- #
# Gemini
# --------------------------------------------------------------------------- #

DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite"  # same model name as the original script
GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"
MAX_PROMPT_CHARS = 2000


class GeminiError(Exception):
    """kind: invalid_key | quota | model | timeout | provider | blocked | empty | network.
    Never contains the key, the prompt or the provider's response body."""

    def __init__(self, kind):
        super().__init__(kind)
        self.kind = kind


def ask_gemini(api_key, prompt, model=DEFAULT_GEMINI_MODEL):
    """Call generateContent with EXACTLY the key passed in. Never reads env."""
    if not api_key:
        raise GeminiError("invalid_key")
    prompt = prompt.strip()
    if not prompt:
        raise ValueError("Use: /ai apna sawal yahan likho")
    if len(prompt) > MAX_PROMPT_CHARS:
        raise ValueError(f"Sawal bohat lamba hai (max {MAX_PROMPT_CHARS} characters).")

    try:
        response = requests.post(
            f"{GEMINI_BASE}/models/{model}:generateContent",
            headers={"Content-Type": "application/json", "x-goog-api-key": api_key},
            json={"contents": [{"parts": [{"text": prompt}]}],
                  "generationConfig": {"maxOutputTokens": 700}},
            timeout=(15, 90),
        )
    except requests.Timeout:
        raise GeminiError("timeout") from None
    except requests.RequestException:
        raise GeminiError("network") from None  # `from None`: no URL/headers in traceback chain

    status = response.status_code
    if status >= 400:
        message = ""
        try:
            message = (response.json().get("error") or {}).get("message", "")
        except ValueError:
            pass
        if status in (401, 403) or (status == 400 and "api key" in message.lower()):
            raise GeminiError("invalid_key")
        if status == 429:
            raise GeminiError("quota")
        if status == 404:
            raise GeminiError("model")
        raise GeminiError("provider")

    try:
        data = response.json()
    except ValueError:
        raise GeminiError("provider") from None
    if (data.get("promptFeedback") or {}).get("blockReason"):
        raise GeminiError("blocked")
    candidates = data.get("candidates") or []
    if not candidates:
        raise GeminiError("empty")
    parts = (candidates[0].get("content") or {}).get("parts") or []
    answer = "\n".join(p["text"] for p in parts if p.get("text")).strip()
    if not answer:
        raise GeminiError("empty")
    return answer


def check_gemini_model(api_key, model=DEFAULT_GEMINI_MODEL):
    """Ask the API itself whether `model` exists and supports generateContent.
    Returns (ok, message)."""
    try:
        response = requests.get(
            f"{GEMINI_BASE}/models", params={"pageSize": 1000},
            headers={"x-goog-api-key": api_key}, timeout=(15, 30),
        )
    except requests.RequestException:
        return False, "Network error while listing models."
    if response.status_code != 200:
        return False, f"Model list request failed (HTTP {response.status_code})."
    for entry in response.json().get("models", []):
        if entry.get("name") == f"models/{model}":
            if "generateContent" in (entry.get("supportedGenerationMethods") or []):
                return True, f"Model '{model}' is available and supports generateContent."
            return False, f"Model '{model}' exists but does not support generateContent."
    return False, f"Model '{model}' was not found for this key. Set GEMINI_MODEL in .env."


GEMINI_USER_MESSAGES = {
    "invalid_key": "Gemini API key invalid ya expired lagti hai. Admin se kaho key update kare.",
    "quota": "Gemini ki quota/rate limit poori ho gayi. Thori dair baad try karo.",
    "model": "AI model abhi available nahi hai. Admin ko batao.",
    "timeout": "AI ne waqt par jawab nahi diya. Dobara try karo.",
    "network": "AI service tak network error aaya. Dobara try karo.",
    "provider": "AI service mein masla hai. Thori dair baad try karo.",
    "blocked": "Gemini ne yeh sawal safety ki wajah se block kar diya.",
    "empty": "AI abhi jawab nahi de saka. Thori dair baad try karo.",
}
