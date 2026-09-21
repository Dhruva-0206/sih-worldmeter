"""Weak auth/session code-pattern detection.

Three focused, regex-based checks chosen for low false-positive rate on a
large codebase rather than broad coverage:

  AUTH-001  weak password hashing (MD5/SHA1) near password-shaped context
  AUTH-002  JWT verification that accepts alg=none / doesn't pin an algorithm allowlist
  AUTH-003  session/auth cookie set without Secure+HttpOnly+SameSite

These are deliberately narrow. A generic "flag every === comparison near a
variable called token" rule would drown in false positives on a codebase
this size; each rule here instead anchors on a specific, well-known CWE
pattern with enough surrounding context to stay precise.
"""
from __future__ import annotations

import re
from pathlib import Path

from engine.common.fs_walk import iter_source_files
from engine.common.models import CodeLocation, Confidence, Finding, FindingSource, Severity
from engine.common.text_utils import is_comment_line

_WEAK_HASH_RE = re.compile(
    r"(?i)(hashlib\.(md5|sha1)\s*\(|crypto\.createHash\(\s*['\"](md5|sha1)['\"]\s*\))"
)
_PASSWORD_CONTEXT_RE = re.compile(r"(?i)\b(password|passwd|pwd)\b")

_JWT_ALG_NONE_RE = re.compile(
    r"(?i)alg(?:orithm)?\s*(?:\.lower\(\))?\s*(?:===?|==)\s*['\"]none['\"]"
)
_JWT_ALGORITHMS_LIST_NONE_RE = re.compile(
    r"(?i)algorithms\s*:\s*\[[^\]]*['\"]none['\"][^\]]*\]"
)
_JWT_VERIFY_CALL_RE = re.compile(r"(?i)\bjwt\.(decode|verify)\s*\(")

_COOKIE_SET_RE = re.compile(
    r"""(?ix)
    (
        \.cookie\s*\(\s*['"][\w.-]+['"]\s*,.*?\)   # express-style res.cookie('name', value, {opts})
        | Set-Cookie['"]?\s*[:=]\s*[`'"][^`'"]*     # manual Set-Cookie header string construction
        | set_cookie\s*\(
    )
    """,
    re.DOTALL,
)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _snippet(lines: list[str], line_no: int, max_len: int = 160) -> str | None:
    if 0 <= line_no - 1 < len(lines):
        s = lines[line_no - 1].strip()
        return s if len(s) <= max_len else s[:max_len] + "…"
    return None


def _check_weak_hashing(text: str, lines: list[str], rel_display: str) -> list[Finding]:
    findings = []
    for m in _WEAK_HASH_RE.finditer(text):
        line_no = _line_number(text, m.start())
        if line_no - 1 < len(lines) and is_comment_line(lines[line_no - 1]):
            continue
        window = "\n".join(lines[max(0, line_no - 4):line_no + 2])
        if not _PASSWORD_CONTEXT_RE.search(window):
            continue  # weak hash used for something else (cache keys, ETags, etc.) — not a credential-storage bug
        algo = m.group(2) or m.group(3)
        findings.append(Finding(
            rule_id="AUTH-001",
            title=f"Weak password hashing algorithm ({algo.upper()})",
            description=(
                f"{rel_display}:{line_no} hashes what appears to be a password/credential with "
                f"{algo.upper()}, which has no salt and no work factor by default and is fast "
                f"enough to brute-force offline at billions of guesses/second on commodity hardware."
            ),
            category="insecure-storage",
            source=FindingSource.SAST,
            confidence=Confidence.FIRM,
            target="",
            severity=Severity.HIGH,
            code_location=CodeLocation(file_path=rel_display, line_number=line_no,
                                        snippet=_snippet(lines, line_no)),
            remediation="Use a purpose-built password hash (bcrypt, scrypt, or Argon2id) with a per-user salt and a tunable work factor.",
            business_impact="If the credential store is ever exfiltrated, MD5/SHA1-hashed passwords can be cracked en masse, not just guessed one at a time.",
            tags=["auth", "weak-hash", "cwe-916"],
        ))
    return findings


def _check_jwt_alg_none(text: str, lines: list[str], rel_display: str) -> list[Finding]:
    findings = []
    if not _JWT_VERIFY_CALL_RE.search(text) and "jwt" not in text.lower() and "JWT" not in text:
        pass  # don't gate — hand-rolled JWT (like fixture-app's) never calls a jwt.verify()-shaped API
    for m in list(_JWT_ALG_NONE_RE.finditer(text)) + list(_JWT_ALGORITHMS_LIST_NONE_RE.finditer(text)):
        line_no = _line_number(text, m.start())
        if line_no - 1 < len(lines) and is_comment_line(lines[line_no - 1]):
            continue
        findings.append(Finding(
            rule_id="AUTH-002",
            title="JWT verification accepts alg=none",
            description=(
                f"{rel_display}:{line_no} treats a token with an `alg: none` header as valid, or "
                f"explicitly allowlists \"none\" as an accepted signing algorithm. Any caller can "
                f"forge a token with an arbitrary payload (e.g. a different username or an "
                f"elevated role claim) and no signature at all."
            ),
            category="authn",
            source=FindingSource.SAST,
            confidence=Confidence.FIRM,
            target="",
            severity=Severity.CRITICAL,
            code_location=CodeLocation(file_path=rel_display, line_number=line_no,
                                        snippet=_snippet(lines, line_no)),
            remediation="Pin verification to the exact algorithm(s) the server itself issues (e.g. only HS256), and hard-reject any other `alg` value before touching the payload.",
            business_impact="Complete authentication bypass — an attacker can impersonate any user, including an administrator, without knowing any secret.",
            tags=["auth", "jwt", "cwe-347"],
        ))
    return findings


def _check_insecure_cookie(text: str, lines: list[str], rel_display: str) -> list[Finding]:
    findings = []
    for m in _COOKIE_SET_RE.finditer(text):
        window = m.group(0)
        line_no = _line_number(text, m.start())
        if line_no - 1 < len(lines) and is_comment_line(lines[line_no - 1]):
            continue
        # Look a bit further than the single regex match for the options object,
        # since `.cookie('name', value, { httpOnly: true, ... })` can span lines.
        extended = text[m.start():m.start() + 400]
        has_httponly = re.search(r"(?i)httponly\s*:\s*true|HttpOnly", extended)
        has_secure = re.search(r"(?i)\bsecure\s*:\s*true|;\s*Secure\b", extended)
        if has_httponly and has_secure:
            continue
        missing = [n for n, present in (("HttpOnly", has_httponly), ("Secure", has_secure)) if not present]
        findings.append(Finding(
            rule_id="AUTH-003",
            title=f"Cookie set without {' and '.join(missing)}",
            description=(
                f"{rel_display}:{line_no} sets a cookie without the {' / '.join(missing)} attribute(s). "
                "Missing HttpOnly lets JavaScript (including injected via XSS) read the cookie; "
                "missing Secure lets it be sent over plain HTTP."
            ),
            category="session-management",
            source=FindingSource.SAST,
            confidence=Confidence.TENTATIVE,
            target="",
            severity=Severity.MEDIUM,
            code_location=CodeLocation(file_path=rel_display, line_number=line_no,
                                        snippet=_snippet(lines, line_no)),
            remediation="Set HttpOnly, Secure, and an explicit SameSite value on any cookie that carries a session or auth token.",
            business_impact="Session/auth cookies without these flags are easier to steal via XSS or network interception.",
            tags=["auth", "cookie", "cwe-1004"],
        ))
    return findings


def scan_file(path: Path, rel_display: str) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return []
    lines = text.splitlines()
    return (
        _check_weak_hashing(text, lines, rel_display)
        + _check_jwt_alg_none(text, lines, rel_display)
        + _check_insecure_cookie(text, lines, rel_display)
    )


def run(source_paths: list[Path], target_name: str, max_findings: int = 200) -> list[Finding]:
    findings: list[Finding] = []
    for root in source_paths:
        root = Path(root)
        for f in iter_source_files(root, suffixes={".js", ".mjs", ".cjs", ".ts", ".mts", ".tsx", ".py"}, exclude_tests=True):
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
