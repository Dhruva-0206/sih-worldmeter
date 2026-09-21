"""Hardcoded secret detection: known-format regexes + Shannon entropy on
credential-shaped assignments.

Design note: a naive "flag every high-entropy string literal" scanner is
useless on a codebase this size — minified vendor snippets, hex colors,
content hashes in generated filenames, and UUIDs all look high-entropy.
Entropy here is a *secondary* signal that upgrades confidence on a match
that a regex already flagged as credential-shaped (an assignment to a
variable named like `*_KEY`, `*_SECRET`, `*_TOKEN`, `password`, etc.), not a
standalone detector run over every string in the file. That keeps this
scanner usable against worldmonitor's real source instead of drowning real
findings (see fixture-app/app.py's hardcoded JWT_SECRET, which this catches
cleanly) in noise from a huge production monorepo.
"""
from __future__ import annotations

import math
import re
from pathlib import Path

from engine.common.fs_walk import iter_source_files
from engine.common.models import CodeLocation, Confidence, Finding, FindingSource, Severity
from engine.common.text_utils import is_comment_line

# --- High-confidence known secret formats -----------------------------------

_KNOWN_FORMAT_RULES: list[tuple[str, str, re.Pattern]] = [
    ("SEC-001", "AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("SEC-002", "GitHub personal access token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("SEC-003", "Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b")),
    ("SEC-004", "Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("SEC-005", "Stripe secret/publishable key", re.compile(r"\b[sp]k_(live|test)_[0-9A-Za-z]{16,}\b")),
    ("SEC-006", "PEM private key block", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("SEC-007", "Generic bearer/JWT-looking token literal",
     re.compile(r"[\"']eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}[\"']")),
]

# --- Credential-shaped assignment (regex catches the shape, entropy scores it) ---

_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    (?:^|[\s{,(;])                 # must look like an identifier position, not
                                    # text embedded inside a string literal —
                                    # otherwise "...user-api-key:..." inside an
                                    # unrelated string's own closing quote can be
                                    # misread as `key: '<value>'` (see module docstring)
    (
        api[_-]?key | apikey |
        secret[_-]?key | secret |
        access[_-]?token | auth[_-]?token | token |
        password | passwd | pwd |
        private[_-]?key |
        client[_-]?secret
    )\b
    [ \t]*[:=][ \t]*
    (?P<quote>['"`])
    (?P<value>[^'"`\n]{8,200})
    (?P=quote)
    """
)

_PLACEHOLDER_RE = re.compile(
    r"^(\s*|change[_-]?me|your[_-].*|xxx+|placeholder|example|test|dummy|"
    r"redacted|<.*>|\.\.\.|todo|fixme|null|none|undefined|fake)$",
    re.IGNORECASE,
)
_ENV_REFERENCE_RE = re.compile(
    r"process\.env\.|import\.meta\.env\.|os\.environ|getenv\(|\$\{.*\}|%\w+%"
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _looks_like_placeholder(value: str) -> bool:
    if _PLACEHOLDER_RE.match(value.strip()):
        return True
    if _ENV_REFERENCE_RE.search(value):
        return True
    # Repeated-character / sequential filler ("aaaaaaaa", "12345678")
    if len(set(value)) <= 2:
        return True
    return False


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _snippet(line: str, max_len: int = 160) -> str:
    line = line.strip()
    return line if len(line) <= max_len else line[:max_len] + "…"


def scan_file(path: Path, rel_display: str) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return []

    findings: list[Finding] = []
    lines = text.splitlines()

    for rule_id, title, pattern in _KNOWN_FORMAT_RULES:
        for m in pattern.finditer(text):
            line_no = _line_number(text, m.start())
            if line_no - 1 < len(lines) and is_comment_line(lines[line_no - 1]):
                continue
            findings.append(Finding(
                rule_id=rule_id,
                title=f"Hardcoded secret: {title}",
                description=(
                    f"A string matching the known format for {title} was found "
                    f"directly in source at {rel_display}:{line_no}."
                ),
                category="secrets",
                source=FindingSource.SAST,
                confidence=Confidence.FIRM,
                target="",  # filled in by caller
                severity=Severity.CRITICAL,
                code_location=CodeLocation(
                    file_path=rel_display,
                    line_number=line_no,
                    snippet=_snippet(lines[line_no - 1]) if line_no - 1 < len(lines) else None,
                ),
                remediation=(
                    "Revoke this credential immediately (assume it is compromised — it is in "
                    "version control history even if removed from HEAD), move it to an "
                    "environment variable or secrets manager, and rotate any systems it granted access to."
                ),
                business_impact="A leaked credential of this class typically grants direct account or service access to an attacker who reads the source.",
                tags=["secret", "hardcoded-credential"],
            ))

    for m in _ASSIGNMENT_RE.finditer(text):
        value = m.group("value")
        if _looks_like_placeholder(value):
            continue
        line_no = _line_number(text, m.start())
        if line_no - 1 < len(lines) and is_comment_line(lines[line_no - 1]):
            continue
        entropy = shannon_entropy(value)
        # Entropy threshold scales gently with length — short high-entropy
        # strings (e.g. 8-char hex) are common and not very secret-like.
        entropy_ok = entropy >= 3.0 and len(value) >= 12
        if not entropy_ok:
            continue
        confidence = Confidence.FIRM if entropy >= 4.0 else Confidence.TENTATIVE
        findings.append(Finding(
            rule_id="SEC-010",
            title="Possible hardcoded credential (high-entropy assignment)",
            description=(
                f"A variable named like a credential is assigned a literal string with "
                f"Shannon entropy {entropy:.2f} at {rel_display}:{line_no}, rather than "
                f"being read from an environment variable or secrets store."
            ),
            category="secrets",
            source=FindingSource.SAST,
            confidence=confidence,
            target="",
            severity=Severity.HIGH if confidence == Confidence.FIRM else Severity.MEDIUM,
            code_location=CodeLocation(
                file_path=rel_display,
                line_number=line_no,
                snippet=_snippet(lines[line_no - 1]) if line_no - 1 < len(lines) else None,
            ),
            remediation=(
                "Move this value to an environment variable / secrets manager and load it at "
                "runtime. If this is test/fixture data only, rename the variable away from "
                "credential-shaped names or add an explicit allowlist comment so scanners don't re-flag it."
            ),
            business_impact="If this value is a real credential, anyone with source access (including this repo's git history) has it.",
            tags=["secret", "entropy"],
            extra={"entropy": round(entropy, 3)},
        ))

    return findings


def run(source_paths: list[Path], target_name: str, max_findings: int = 200) -> list[Finding]:
    findings: list[Finding] = []
    for root in source_paths:
        root = Path(root)
        for f in iter_source_files(root, exclude_tests=True):
            try:
                rel = str(f.relative_to(root.parent))
            except ValueError:
                rel = str(f)
            for finding in scan_file(f, rel):
                finding.target = target_name
                findings.append(finding)
                if len(findings) >= max_findings:
                    return findings
    return findings
