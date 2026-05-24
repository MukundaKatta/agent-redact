"""Redact an agent trace JSONL log before you hand it off for storage or review.

This works equally well for agenttrace, agentleash audit logs, langfuse exports,
or any line-delimited JSON where prompts and tool outputs land on disk.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from agent_redact import Patterns, redact


def scrub_line(line: str, patterns: Patterns) -> str:
    """Parse one JSONL row, scrub string fields recursively, re-serialize."""
    try:
        row = json.loads(line)
    except json.JSONDecodeError:
        # Not JSON. Scrub it as raw text and move on.
        return redact(line, patterns=patterns)

    def walk(node):
        if isinstance(node, str):
            return redact(node, patterns=patterns)
        if isinstance(node, list):
            return [walk(x) for x in node]
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items()}
        return node

    return json.dumps(walk(row), separators=(",", ":"))


def main(in_path: str, out_path: str) -> None:
    # Hash mode keeps unique identifiers distinguishable across rows
    # without leaking the underlying value. Use the same salt across the
    # batch so a single user maps to a single hash tag for analytics.
    patterns = Patterns().with_luhn(True)
    salt = "rotate-me-monthly"

    src = Path(in_path)
    dst = Path(out_path)
    with src.open("r") as fin, dst.open("w") as fout:
        for line in fin:
            line = line.rstrip("\n")
            if not line:
                continue
            scrubbed = scrub_line(line, patterns)
            # Apply hash-mode pass over the serialized form too, so any value
            # that survived parsing as a non-string still gets caught.
            fout.write(redact(scrubbed, patterns=patterns, mode="hash", salt=salt))
            fout.write("\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: integrate_with_agenttrace.py <in.jsonl> <out.jsonl>")
        raise SystemExit(2)
    main(sys.argv[1], sys.argv[2])
