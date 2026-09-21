"""Unsafe deserialization, string-concatenated SQL, and unescaped-output
patterns.

Three regex-based checks, each anchored on both a *query-building shape*
(f-string/concatenation/template-literal) AND a nearby SQL keyword or
dangerous-sink call name — a bare f-string or a bare "SELECT" substring
alone would be far too noisy on a real codebase (a log message, a docstring,
a GraphQL query all contain those individually).
"""
from __future__ import annotations

import re
from pathlib import Path

from engine.common.fs_walk import iter_source_files
from engine.common.models import CodeLocation, Confidence, Finding, FindingSource, Severity
from engine.common.text_utils import is_comment_line

# Full clause shapes, not bare keywords: a standalone "FROM" or "WHERE"
# matches ordinary English prose constantly ("drifted from", "handler
# missing from...") — caught as a wall of false positives against
# worldmonitor's real source (log/error message template literals) during
# development. Requiring the SELECT-FROM / INSERT-INTO / UPDATE-SET /
# DELETE-FROM clause pairing is specific enough to stay quiet on prose
# while still matching the fixture app's real
# `SELECT id, title FROM notes WHERE ...` query.
_SQL_KEYWORDS = r"(SELECT\b.{0,200}?\bFROM\b|INSERT\s+INTO\b|UPDATE\b.{0,200}?\bSET\b|DELETE\s+FROM\b)"

# Python f-string / .format() / % containing a SQL keyword and an interpolation.
# Uses a backreference ((?!\1).) rather than [^'"] to exclude only the SAME
# quote character that opened the string — a naive [^'"]* wrongly treats a
# SQL LIKE pattern's own embedded quotes (f"...WHERE title LIKE '%{q}%'...",
# a double-quoted f-string containing literal single quotes) as the end of
# the Python string literal, missing the match entirely (caught during
# development against the fixture app's actual vulnerable line).
_PY_FSTRING_SQL_RE = re.compile(
    rf"""(?i)f(['"])(?:(?!\1).)*?{_SQL_KEYWORDS}(?:(?!\1).)*?\{{[^}}]+\}}(?:(?!\1).)*?\1"""
)
_PY_CONCAT_SQL_RE = re.compile(
    # Backreferences are \1 and \3, not \1/\2: _SQL_KEYWORDS itself contains
    # a capturing group, so it consumes a group number between the two
    # quote groups (group 1 = first branch's quote, group 2 = the SQL-clause
    # match inside that branch, group 3 = second branch's quote).
    rf"""(?i)(['"])(?:(?!\1).)*?{_SQL_KEYWORDS}(?:(?!\1).)*?\1\s*\+\s*\w|"""
    rf"""\w[\w.\[\]]*\s*\+\s*(['"])(?:(?!\3).)*?{_SQL_KEYWORDS}(?:(?!\3).)*?\3"""
)

# JS/TS template literal containing a SQL keyword and a ${...} interpolation
_JS_TEMPLATE_SQL_RE = re.compile(
    rf"(?i)`[^`]*{_SQL_KEYWORDS}[^`]*\$\{{[^}}]+\}}[^`]*`"
)

_DESERIALIZATION_SINKS_RE = re.compile(
    # (?<!\.) excludes a preceding dot so this doesn't fire on `regex.exec(`
    # — JavaScript's ubiquitous, completely unrelated RegExp.exec() method —
    # which it did during development against worldmonitor's real source
    # (dozens of hits, none of them code execution). Same guard on eval(
    # for any future .eval(-style method some library might expose.
    r"(?i)\b(pickle\.loads|yaml\.load\((?!.*Loader=yaml\.SafeLoader)|marshal\.loads|"
    r"(?<!\.)\beval\(|(?<!\.)\bexec\(|new Function\(|child_process\.exec\()"
)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _snippet(lines: list[str], line_no: int, max_len: int = 160) -> str | None:
    if 0 <= line_no - 1 < len(lines):
        s = lines[line_no - 1].strip()
        return s if len(s) <= max_len else s[:max_len] + "…"
    return None


def _emit(rule_id: str, title: str, description: str, severity: Severity, category: str,
          rel_display: str, line_no: int, lines: list[str], remediation: str, tags: list[str]) -> Finding:
    return Finding(
        rule_id=rule_id, title=title, description=description, category=category,
        source=FindingSource.SAST, confidence=Confidence.FIRM, target="", severity=severity,
        code_location=CodeLocation(file_path=rel_display, line_number=line_no,
                                    snippet=_snippet(lines, line_no)),
        remediation=remediation, tags=tags,
    )


def scan_file(path: Path, rel_display: str) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return []
    lines = text.splitlines()
    findings: list[Finding] = []

    sql_patterns = []
    if path.suffix == ".py":
        sql_patterns = [_PY_FSTRING_SQL_RE, _PY_CONCAT_SQL_RE]
    elif path.suffix in (".js", ".mjs", ".cjs", ".ts", ".mts", ".tsx"):
        sql_patterns = [_JS_TEMPLATE_SQL_RE]

    for pattern in sql_patterns:
        for m in pattern.finditer(text):
            line_no = _line_number(text, m.start())
            if line_no - 1 < len(lines) and is_comment_line(lines[line_no - 1]):
                continue
            findings.append(_emit(
                "INJ-SAST-001", "String-concatenated/interpolated SQL query",
                f"{rel_display}:{line_no} builds a SQL query by interpolating a variable directly "
                f"into the query text instead of using a parameterized query/prepared statement.",
                Severity.HIGH, "injection", rel_display, line_no, lines,
                "Use parameterized queries (e.g. `cursor.execute(query, (param,))`) — never interpolate request-influenced values into SQL text.",
                ["injection", "sqli", "cwe-89"],
            ))

    for m in _DESERIALIZATION_SINKS_RE.finditer(text):
        sink = m.group(1)
        # yaml.load( without a safe-loader arg is a real anti-pattern in
        # Python (PyYAML) but not in JS/TS: js-yaml's yaml.load() is safe by
        # default (its unsafe equivalent is a differently-named function) —
        # scoping this specific alternative to .py avoided a wall of false
        # positives against worldmonitor's JS/TS source during development.
        if sink.startswith("yaml.load") and path.suffix != ".py":
            continue
        line_no = _line_number(text, m.start())
        if line_no - 1 < len(lines) and is_comment_line(lines[line_no - 1]):
            continue
        findings.append(Finding(
            rule_id="INJ-SAST-002", title=f"Unsafe deserialization/eval sink: {sink}",
            description=(
                f"{rel_display}:{line_no} calls {sink}, which can execute arbitrary code if its "
                f"input is influenced by an untrusted source. Regex-based detection can't tell a "
                f"real call from the same text appearing inside a string/regex literal (e.g. a "
                f"test asserting a Redis command matches /^eval(sha)?$/) — confirm this is an "
                f"actual call before treating it as a finding."
            ),
            category="injection", source=FindingSource.SAST, confidence=Confidence.TENTATIVE,
            target="", severity=Severity.HIGH,
            code_location=CodeLocation(file_path=rel_display, line_number=line_no,
                                        snippet=_snippet(lines, line_no)),
            remediation="Avoid pickle/marshal/eval/exec/new Function on untrusted input; use a safe serialization format (JSON) and a restrictive YAML loader (yaml.safe_load) instead.",
            tags=["injection", "deserialization", "cwe-502"],
        ))

    return findings


def run(source_paths: list[Path], target_name: str, max_findings: int = 200) -> list[Finding]:
    findings: list[Finding] = []
    for root in source_paths:
        root = Path(root)
        for f in iter_source_files(root, suffixes={".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".tsx"}, exclude_tests=True):
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
