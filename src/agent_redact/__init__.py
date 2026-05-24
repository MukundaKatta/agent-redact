"""agent-redact: zero-dep PII and secret scrubber for AI agent logs.

Public API:
    redact(text, patterns=None, mode="mask", salt="") -> str
    Patterns()  -> builder for the active pattern set
"""

from .patterns import Patterns
from .redact import redact

__all__ = ["redact", "Patterns"]
__version__ = "0.1.0"
