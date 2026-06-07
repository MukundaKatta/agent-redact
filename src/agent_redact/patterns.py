"""Default regex patterns and the Patterns builder.

Each entry is (compiled_regex, label). Labels are stable and used in output
markers like <email> or <openai-key:a1b2c3>. Keep patterns conservative so we
do not turn benign log lines into a wall of redactions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Order matters. More specific provider keys are matched before generic shapes
# like AWS access keys, so a Stripe sk_live_ does not get caught by a looser
# pattern further down the list.
_BUILTINS: list[tuple[str, str]] = [
    # API keys (provider-prefixed, high precision)
    (r"sk-ant-[A-Za-z0-9_\-]{20,}", "anthropic-key"),
    (r"sk-proj-[A-Za-z0-9_\-]{20,}", "openai-key"),
    (r"sk-[A-Za-z0-9]{20,}", "openai-key"),
    (r"ghp_[A-Za-z0-9]{30,}", "github-token"),
    (r"gho_[A-Za-z0-9]{30,}", "github-token"),
    (r"ghs_[A-Za-z0-9]{30,}", "github-token"),
    (r"AIza[0-9A-Za-z_\-]{30,}", "google-key"),
    (r"AKIA[0-9A-Z]{16}", "aws-access-key"),
    (r"sk_live_[A-Za-z0-9]{20,}", "stripe-key"),
    (r"sk_test_[A-Za-z0-9]{20,}", "stripe-key"),
    (r"pk_live_[A-Za-z0-9]{20,}", "stripe-key"),
    (r"pk_test_[A-Za-z0-9]{20,}", "stripe-key"),
    (r"xox[baprs]-[A-Za-z0-9\-]{10,}", "slack-token"),
    # JWT (three base64url segments separated by dots, starts with eyJ)
    (r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "jwt"),
    # Personal info
    (r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", "email"),
    (r"\b\d(?:[ \-]?\d){12,18}\b", "credit-card"),  # 13-19 digit runs; Luhn optional
    (r"\b\d{3}-\d{2}-\d{4}\b", "ssn"),
    # Phone (US-friendly + simple international). Requires at least one
    # separator or a leading "+" so a bare 16-digit run does not get caught here.
    (
        r"(?:\+\d{1,3}[\s\-]\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4})"
        r"|(?:\(?\d{3}\)?[\s\-]\d{3}[\s\-]\d{4})",
        "phone",
    ),
]

_OPTIONAL: dict[str, tuple[str, str]] = {
    # IP addresses are often non-PII (server logs), so they are opt-in.
    "ipv4": (
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "ipv4",
    ),
    "ipv6": (
        r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b",
        "ipv6",
    ),
    # AWS secret key shape (40 chars base64-ish). High false-positive risk.
    "aws_secret": (
        r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
        "aws-secret",
    ),
}


def luhn_ok(digits: str) -> bool:
    """Standard Luhn check. Used to weed out random digit runs from card numbers."""
    s = [int(d) for d in digits if d.isdigit()]
    if len(s) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(s)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@dataclass
class Patterns:
    """Builder for the active pattern set. All default-on patterns are included
    on construction. Chain .add() or toggle methods to customize.
    """

    # `entries=None` means "use defaults". An empty list means "start empty".
    # We need that distinction so Patterns.empty() does not silently re-seed.
    entries: list[tuple[re.Pattern[str], str]] | None = None
    luhn: bool = False

    def __post_init__(self) -> None:
        if self.entries is None:
            self.entries = [(re.compile(p), label) for p, label in _BUILTINS]

    def add(self, pattern: str, label: str) -> "Patterns":
        self.entries.append((re.compile(pattern), label))
        return self

    def enable(self, name: str) -> "Patterns":
        if name not in _OPTIONAL:
            raise ValueError(f"unknown optional pattern: {name}")
        p, label = _OPTIONAL[name]
        self.entries.append((re.compile(p), label))
        return self

    def with_luhn(self, enabled: bool = True) -> "Patterns":
        self.luhn = enabled
        return self

    # Convenience toggles for the common case of starting from empty.
    @classmethod
    def empty(cls) -> "Patterns":
        return cls(entries=[])

    def email(self) -> "Patterns":
        return self.add(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", "email")

    def credit_card(self) -> "Patterns":
        return self.add(r"\b\d(?:[ \-]?\d){12,18}\b", "credit-card")
