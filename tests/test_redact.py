"""Tests for agent_redact. One assertion per intent so failures are easy to read."""

from __future__ import annotations

import pytest

from agent_redact import Patterns, redact


def test_email_redacted():
    out = redact("contact me at jane.doe@example.com please")
    assert out == "contact me at <email> please"


def test_openai_key_redacted():
    out = redact("key=sk-" + ("Z" * 40) + " end")
    assert "<openai-key>" in out
    assert "sk-Z" not in out


def test_anthropic_key_takes_precedence_over_generic_sk():
    out = redact("auth: sk-ant-" + ("Z" * 40) + " done")
    assert "<anthropic-key>" in out
    assert "<openai-key>" not in out


def test_aws_access_key_redacted():
    out = redact("aws key AKIA" + ("Z" * 16) + " here")
    assert "<aws-access-key>" in out


def test_github_token_redacted():
    out = redact("token ghp_" + ("Z" * 36) + " ok")
    assert "<github-token>" in out


def test_stripe_key_redacted():
    out = redact("billing sk_live_" + ("Z" * 24) + " done")
    assert "<stripe-key>" in out


def test_jwt_redacted():
    jwt = "eyJ" + ("A" * 20) + "." + ("B" * 20) + "." + ("C" * 20)
    out = redact(f"bearer {jwt}")
    assert "<jwt>" in out
    assert "eyJ" not in out


def test_ssn_redacted():
    out = redact("ssn 123-45-6789 on file")
    assert "<ssn>" in out


def test_credit_card_redacted_without_luhn():
    out = redact("card 4111 1111 1111 1111 expires soon")
    assert "<credit-card>" in out


def test_credit_card_luhn_filters_random_digits():
    text = "id 1234567890123456 here"
    # Default off: this looks like a card and gets redacted.
    assert "<credit-card>" in redact(text)
    # With Luhn on, a bogus digit run is left alone.
    patterns = Patterns().with_luhn(True)
    assert redact(text, patterns=patterns) == text


def test_phone_redacted():
    out = redact("call +1 (415) 555-0123 tomorrow")
    assert "<phone>" in out


def test_hash_mode_is_deterministic():
    a = redact("user@example.com", mode="hash", salt="s")
    b = redact("user@example.com", mode="hash", salt="s")
    assert a == b
    assert a.startswith("<email:")
    # Different salt -> different hash.
    c = redact("user@example.com", mode="hash", salt="other")
    assert a != c


def test_hash_mode_requires_salt():
    with pytest.raises(ValueError):
        redact("user@example.com", mode="hash")


def test_custom_pattern_via_add():
    patterns = Patterns().add(r"INTERNAL-\d{4}", "internal-id")
    out = redact("ticket INTERNAL-4242 escalated", patterns=patterns)
    assert "<internal-id>" in out


def test_empty_builder_skips_defaults():
    fake_aws = "AKIA" + ("Z" * 16)
    patterns = Patterns.empty().email()
    out = redact(f"user@example.com and {fake_aws}", patterns=patterns)
    assert "<email>" in out
    # AWS pattern not enabled, so it stays put.
    assert fake_aws in out


def test_optional_ipv4_pattern():
    patterns = Patterns().enable("ipv4")
    out = redact("from 192.168.1.42 today", patterns=patterns)
    assert "<ipv4>" in out


def test_no_match_returns_input_unchanged():
    text = "nothing sensitive here, just words"
    assert redact(text) == text
