"""pookie_config.py - which WhatsApp agents to run.

Tokens come from the environment (your private .env):
    WHATSAPP_AGENT_TOKEN=...        -> the owner/admin agent (label from POOKIE_OWNER_LABEL, default "owner")
    POOKIE_TOKEN_FRIEND1=...        -> label "friend1"
    POOKIE_TOKEN_FRIEND2=...        -> label "friend2"

Rules enforced here:
  * labels are lowercase [a-z0-9_-], max 32 chars
  * duplicate tokens are skipped (a second poller on one token would knock the
    first one off with PollReplacedError)
  * every agent gets its own offset file; the owner keeps ".whagent-offset"
  * extra agents can never take the owner label
Token values are never returned in messages; only SHA-256 digests are compared.
"""

import hashlib
from dataclasses import dataclass
from pathlib import Path

from pookie_db import LABEL_RE

TOKEN_PREFIX = "POOKIE_TOKEN_"


@dataclass(frozen=True)
class AgentSpec:
    label: str
    token: str
    offset_path: Path
    is_owner: bool

    def __repr__(self):  # never print the token
        return f"AgentSpec(label={self.label!r}, owner={self.is_owner})"


def load_agent_specs(environ, base_dir, owner_label="owner"):
    """Returns (specs, skipped) where skipped is a list of (label, reason)."""
    base_dir = Path(base_dir)
    owner_label = owner_label.strip().lower()
    if not LABEL_RE.match(owner_label):
        raise ValueError("POOKIE_OWNER_LABEL must match [a-z0-9][a-z0-9_-]{0,31}")

    candidates = []
    owner_token = (environ.get("WHATSAPP_AGENT_TOKEN") or "").strip()
    if owner_token:
        candidates.append((owner_label, owner_token, True))
    for name in sorted(environ):
        if name.startswith(TOKEN_PREFIX):
            candidates.append((name[len(TOKEN_PREFIX):].lower(), (environ[name] or "").strip(), False))

    specs, skipped = [], []
    seen_labels, seen_tokens = set(), {}
    for label, token, is_owner in candidates:
        if not LABEL_RE.match(label):
            skipped.append((label, "invalid label"))
            continue
        if not is_owner and label == owner_label:
            skipped.append((label, "label reserved for the owner agent"))
            continue
        if label in seen_labels:
            skipped.append((label, "duplicate label"))
            continue
        if not token:
            skipped.append((label, "empty token"))
            continue
        digest = hashlib.sha256(token.encode()).hexdigest()
        if digest in seen_tokens:
            skipped.append((label, f"same token as '{seen_tokens[digest]}' (duplicate skipped)"))
            continue
        seen_labels.add(label)
        seen_tokens[digest] = label
        offset = base_dir / (".whagent-offset" if is_owner else f".whagent-offset-{label}")
        specs.append(AgentSpec(label=label, token=token, offset_path=offset, is_owner=is_owner))
    return specs, skipped
