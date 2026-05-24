"""Core redact() entry point."""

from __future__ import annotations

import hashlib
from typing import Literal

from .patterns import Patterns, luhn_ok

Mode = Literal["mask", "hash"]


def _short_hash(value: str, salt: str) -> str:
    """6-char hex tag, salted. Deterministic so repeated redactions cluster."""
    h = hashlib.sha256((salt + ":" + value).encode("utf-8")).hexdigest()
    return h[:6]


def redact(
    text: str,
    patterns: Patterns | None = None,
    mode: Mode = "mask",
    salt: str = "",
) -> str:
    """Scrub PII and secrets from a string.

    mode="mask" replaces matches with <label>.
    mode="hash" replaces matches with <label:hash> using sha256(salt+value)[:6].
    """
    if patterns is None:
        patterns = Patterns()
    if mode == "hash" and not salt:
        # Forcing a salt makes hashes non-trivial to reverse via rainbow tables.
        raise ValueError("mode='hash' requires a non-empty salt")

    # Find all matches across all patterns, then resolve overlaps by taking the
    # earliest match and the longest tie-break. This avoids double-wrapping when
    # two patterns hit the same span (for example sk-ant- could partially overlap
    # the generic sk- rule if we let them both fire).
    spans: list[tuple[int, int, str, str]] = []
    for regex, label in patterns.entries:
        for m in regex.finditer(text):
            value = m.group(0)
            if label == "credit-card" and patterns.luhn and not luhn_ok(value):
                continue
            spans.append((m.start(), m.end(), label, value))

    if not spans:
        return text

    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    chosen: list[tuple[int, int, str, str]] = []
    cursor = -1
    for start, end, label, value in spans:
        if start >= cursor:
            chosen.append((start, end, label, value))
            cursor = end

    out: list[str] = []
    last = 0
    for start, end, label, value in chosen:
        out.append(text[last:start])
        if mode == "hash":
            out.append(f"<{label}:{_short_hash(value, salt)}>")
        else:
            out.append(f"<{label}>")
        last = end
    out.append(text[last:])
    return "".join(out)
