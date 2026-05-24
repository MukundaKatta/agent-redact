# agent-redact

Zero-dep PII and secret scrubber for AI agent logs, traces, and audit output.

Your agent writes prompts, tool inputs, and tool outputs to disk. Those logs end up in S3, in a vector index for run search, in your error tracker, and sometimes in a Slack alert. Each hop is a place customer emails, API keys, and JWTs leak.

agent-redact is a single function that masks or hashes the common offenders before they cross any of those boundaries.

## Install

```bash
pip install agent-redact
```

Python 3.10+. Zero runtime dependencies.

## Use

```python
from agent_redact import redact

redact("user@example.com hit /charge with key sk-" + "Z" * 40)
# -> "<email> hit /charge with key <openai-key>"
```

Hash mode keeps identifiers distinguishable across log rows without leaking the value:

```python
redact("user@example.com retried 3 times", mode="hash", salt="rotate-monthly")
# -> "<email:a1b2c3> retried 3 times"
```

Custom patterns:

```python
from agent_redact import Patterns

patterns = (
    Patterns()
    .with_luhn(True)             # only redact card numbers that pass Luhn
    .add(r"INTERNAL-\d{4}", "internal-id")
)
redact("ticket INTERNAL-4242 from card 4111 1111 1111 1111", patterns=patterns)
# -> "ticket <internal-id> from card <credit-card>"
```

Start from an empty builder when you want strict opt-in:

```python
patterns = Patterns.empty().email()
redact("user@example.com and key sk-FAKEFAKEFAKE", patterns=patterns)
# -> "<email> and key sk-FAKEFAKEFAKE"
```

## What it catches by default

- email addresses
- credit card numbers (13-19 digit shape, optional Luhn check)
- US SSN
- phone numbers (US and basic international)
- OpenAI keys: `sk-`, `sk-proj-`
- Anthropic keys: `sk-ant-`
- AWS access keys: `AKIA...`
- GitHub tokens: `ghp_`, `gho_`, `ghs_`
- Google API keys: `AIza...`
- Stripe keys: `sk_live_`, `sk_test_`, `pk_live_`, `pk_test_`
- Slack tokens: `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`
- JWTs (`eyJ...` three-segment shape)

Opt-in via `.enable(name)`:

- `ipv4`, `ipv6`: usually server-only, off by default
- `aws_secret`: high false-positive rate on random base64-ish strings

## Compose with the agent stack

agent-redact pairs cleanly with the other small libs in the stack:

- **agenttrace**: pipe the JSONL export through `examples/integrate_with_agenttrace.py` before shipping it anywhere.
- **agentleash**: scrub the audit log so the money-cap proof you keep in S3 does not double as a customer-PII spill.
- **birddog**: redact scraped pages before they go to a downstream LLM.

See `examples/integrate_with_agenttrace.py` for a 30-line JSONL filter you can adapt.

## Design

- Pure stdlib (`re`, `hashlib`, `dataclasses`).
- Patterns are pre-compiled once.
- Overlap resolution: earliest match wins, longer match breaks ties. Prevents double-wrapping when two patterns hit the same span.
- Provider-specific keys are matched before generic shapes so an Anthropic key never falls through to the generic OpenAI rule.
- Deterministic output. Snapshot-friendly. Safe to run inline before every log line.

## License

MIT
