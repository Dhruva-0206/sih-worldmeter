"""Small text heuristics shared by regex-based SAST scanners."""
from __future__ import annotations

_LINE_COMMENT_PREFIXES = ("#", "//", "*", "/*")


def is_comment_line(line: str) -> bool:
    """True if `line`, stripped, looks like a comment line.

    Deliberately cheap (no tokenizer): catches the common case of a
    match landing inside a `#`/`//`/block-comment continuation line, which
    is the single biggest source of false positives for a regex scanner run
    over real source (docstrings, TODOs, and — recursively — a security
    scanner's own rule-documenting comments all contain rule-shaped text).
    Doesn't catch a trailing same-line comment (`code(); // hashlib.md5(...)`,
    would need real tokenization for that) — acceptable false-negative rate
    for a heuristic filter.
    """
    stripped = line.strip()
    return stripped.startswith(_LINE_COMMENT_PREFIXES)
