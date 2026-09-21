"""Safe SQLi/NoSQLi/command-injection probing.

Three techniques, all using benign markers rather than destructive payloads
(no DROP/DELETE/UPDATE, no real filesystem or process side effects):

  INJ-001  boolean-based differential — a `' OR '1'='1`-style payload that
           should widen a result set is compared against a baseline query
           that should return few/no rows. A meaningfully larger result set
           under the injected payload is the signal.
  INJ-002  error-based — a lone quote/backslash provokes a syntax error;
           the response is scanned for a database error signature.
  INJ-003  time-based blind — multi-dialect payloads (MySQL/Postgres/MSSQL/
           SQLite-incompatible-by-design/shell) that each sleep a small,
           bounded delay (default 3s) if — and only if — the injected
           expression actually executes. A response taking meaningfully
           longer than baseline is the signal. Capped low deliberately:
           enough to distinguish from network jitter, not enough to be a
           meaningful DoS vector even run repeatedly.
"""
from __future__ import annotations

import re
import time

from engine.common.http_client import SafeClient
from engine.common.models import Confidence, Finding, FindingSource, HttpEvidence, Severity

_DB_ERROR_MARKERS = re.compile(
    r"(?i)(sql syntax|sqlite3\.OperationalError|unterminated string|"
    r"ORA-\d{5}|SQLSTATE\[|PostgreSQL.*ERROR|you have an error in your sql|"
    r"psycopg2\.|pymysql\.|System\.Data\.SqlClient|no such column|no such table)"
)

_BOOLEAN_PAYLOADS = ["' OR '1'='1", "1' OR '1'='1' -- -", "\" OR \"1\"=\"1"]
_ERROR_PAYLOADS = ["'", "\\", "''"]
_TIME_DELAY_SECONDS = 3
_TIME_PAYLOADS = [
    ("MySQL", f"' OR SLEEP({_TIME_DELAY_SECONDS})-- -"),
    ("PostgreSQL", f"'; SELECT pg_sleep({_TIME_DELAY_SECONDS})-- -"),
    ("MSSQL", f"'; WAITFOR DELAY '0:0:{_TIME_DELAY_SECONDS}'-- -"),
    ("shell command", f"; sleep {_TIME_DELAY_SECONDS}"),
    ("shell command (subshell)", f"$(sleep {_TIME_DELAY_SECONDS})"),
]
_BASELINE_QUERY = "wmsec-baseline-nonexistent-term"


def _get_len(client: SafeClient, path: str, param: str, value: str) -> tuple[int | None, float, str]:
    resp = client.get(path, params={param: value})
    if not resp.ok:
        return None, 0.0, ""
    return resp.status_code, resp.elapsed_seconds, resp.text


def run_boolean_based(client: SafeClient, target_name: str, path: str, param: str) -> list[Finding]:
    findings = []
    _, _, baseline_body = _get_len(client, path, param, _BASELINE_QUERY)
    for payload in _BOOLEAN_PAYLOADS:
        _, _, injected_body = _get_len(client, path, param, payload)
        if len(injected_body) > len(baseline_body) * 1.5 and len(injected_body) - len(baseline_body) > 20:
            findings.append(Finding(
                rule_id="INJ-001",
                title=f"Possible boolean-based SQL injection: {path}?{param}=...",
                description=(
                    f"GET {path}?{param}={_BASELINE_QUERY} (baseline, expected to match nothing) "
                    f"returned a {len(baseline_body)}-byte body; {path}?{param}={payload!r} returned "
                    f"a {len(injected_body)}-byte body — a payload that widens a SQL WHERE clause to "
                    f"match everything produced substantially more data."
                ),
                category="injection",
                source=FindingSource.DAST,
                confidence=Confidence.TENTATIVE,
                target=target_name,
                severity=Severity.HIGH,
                http_evidence=[HttpEvidence(method="GET", url=f"{path}?{param}={payload}",
                                             status_code=200, response_snippet=injected_body[:300])],
                remediation="Use parameterized queries/prepared statements; never interpolate request input directly into SQL text.",
                business_impact="An attacker can read data outside their intended access scope, and depending on the query context, potentially modify or exfiltrate the entire dataset.",
                tags=["injection", "sqli", "boolean-based", "cwe-89"],
            ))
            break  # one confirmation per path/param is enough signal
    return findings


def run_error_based(client: SafeClient, target_name: str, path: str, param: str) -> list[Finding]:
    findings = []
    for payload in _ERROR_PAYLOADS:
        resp = client.get(path, params={param: payload})
        if not resp.ok:
            continue
        m = _DB_ERROR_MARKERS.search(resp.text)
        if m:
            findings.append(Finding(
                rule_id="INJ-002",
                title=f"Database error reflected from injection probe: {path}?{param}=...",
                description=(
                    f"GET {path}?{param}={payload!r} produced a response containing a database "
                    f"error signature: \"{m.group(0)}\"."
                ),
                category="injection",
                source=FindingSource.DAST,
                confidence=Confidence.CONFIRMED,
                target=target_name,
                severity=Severity.HIGH,
                http_evidence=[HttpEvidence(method="GET", url=resp.url, status_code=resp.status_code,
                                             response_snippet=resp.text[:300])],
                remediation="Use parameterized queries; catch DB errors and return a generic message without the underlying error text.",
                business_impact="Confirms unsanitized input reaches a SQL query, and leaks schema/engine details useful for building a working exploit.",
                tags=["injection", "sqli", "error-based", "cwe-89"],
            ))
            break
    return findings


def run_time_based(client: SafeClient, target_name: str, path: str, param: str,
                    baseline_runs: int = 2) -> list[Finding]:
    findings = []
    baseline_times = []
    for _ in range(baseline_runs):
        _, elapsed, _ = _get_len(client, path, param, _BASELINE_QUERY)
        baseline_times.append(elapsed)
    baseline = max(baseline_times) if baseline_times else 0.5

    for dialect, payload in _TIME_PAYLOADS:
        _, elapsed, _ = _get_len(client, path, param, payload)
        if elapsed >= baseline + _TIME_DELAY_SECONDS - 1:  # 1s tolerance for network jitter
            findings.append(Finding(
                rule_id="INJ-003",
                title=f"Possible time-based blind injection ({dialect}): {path}?{param}=...",
                description=(
                    f"GET {path}?{param}=... with a {dialect} time-delay payload took {elapsed:.1f}s "
                    f"vs a {baseline:.1f}s baseline for a non-delaying query — consistent with the "
                    f"injected delay expression actually executing."
                ),
                category="injection",
                source=FindingSource.DAST,
                confidence=Confidence.TENTATIVE,
                target=target_name,
                severity=Severity.HIGH,
                http_evidence=[HttpEvidence(method="GET", url=f"{path}?{param}={payload}",
                                             notes=f"elapsed={elapsed:.2f}s, baseline={baseline:.2f}s")],
                remediation="Use parameterized queries (SQL) or avoid shelling out to an interpreter with unsanitized input (command injection).",
                business_impact="A working blind injection can be used to exfiltrate data one bit at a time even without any visible output difference.",
                tags=["injection", "time-based", dialect.lower().replace(" ", "-")],
            ))
            break  # one dialect confirming is enough; no need to also fire the delay for every other dialect
    return findings


def run(client: SafeClient, target_name: str, path: str, param: str) -> list[Finding]:
    findings = run_boolean_based(client, target_name, path, param)
    findings += run_error_based(client, target_name, path, param)
    if findings:
        # Boolean/error-based already confirmed injection on this param —
        # skip the (up to 5 x 3s) time-based probes, which exist to find
        # *blind* injection when there's no visible signal otherwise.
        return findings
    findings += run_time_based(client, target_name, path, param)
    return findings
