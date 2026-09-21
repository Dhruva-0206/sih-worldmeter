"""Generates a safe, minimal, reproducible PoC for each finding.

For a DAST finding (has http_evidence), the PoC is a curl command rebuilt
from the actual request that was sent and observed to trigger the finding —
not a hypothetical example, the literal reproduction.

The target is always a shell variable defaulting to the config-provided
base_url, which config.load_scan_config() already validated as
local/docker-scoped before this pipeline ever ran — so a generated PoC
cannot silently point at a real host even if someone copies it out of the
report and runs it unmodified.

For a SAST-only finding (no http_evidence — a source-code pattern with
nothing to send over HTTP), the "PoC" is a short set of review steps
pointing at the exact file/line instead of a fabricated request.
"""
from __future__ import annotations

import shlex

from engine.common.models import Finding, HttpEvidence


def _curl_for_evidence(ev: HttpEvidence, base_url_var: str = "TARGET_BASE_URL") -> str:
    parts = ["curl", "-s", "-i"]
    if ev.method and ev.method.upper() != "GET":
        parts += ["-X", ev.method.upper()]
    for k, v in ev.request_headers.items():
        parts += ["-H", shlex.quote(f"{k}: {v}")]
    if ev.request_body:
        parts += ["-d", shlex.quote(ev.request_body)]

    url = ev.url
    # Rewrite the concrete host back to the parameterized variable so the
    # PoC is portable to "wherever this run's target actually is" rather
    # than a copy-pasted literal localhost:PORT that drifts from config.
    from urllib.parse import urlparse
    parsed = urlparse(url)
    path_and_query = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    parts.append(f'"${{{base_url_var}}}{path_and_query}"')
    return " ".join(parts)


def generate_poc(finding: Finding) -> tuple[str, str]:
    """Returns (poc_text, poc_language)."""
    if finding.http_evidence:
        lines = [
            f"# {finding.title}",
            f"# Target must be set explicitly — defaults to nothing so this can never",
            f"# accidentally hit a real host. Point it at YOUR local/docker deployment:",
            f"export {'TARGET_BASE_URL'}=http://localhost:PORT   # e.g. http://localhost:3000",
            "",
        ]
        for i, ev in enumerate(finding.http_evidence, 1):
            if len(finding.http_evidence) > 1:
                lines.append(f"# Step {i}{f' — {ev.notes}' if ev.notes else ''}")
            lines.append(_curl_for_evidence(ev))
            lines.append("")
        if finding.category in ("injection",) or "bola" in finding.tags or "privilege-escalation" in finding.tags:
            lines.append("# Expected if vulnerable: response reflects data/access beyond what the")
            lines.append("# caller's own role/ownership should permit. Compare against a baseline")
            lines.append("# request without the payload/tampering to confirm the difference.")
        return "\n".join(lines), "bash"

    if finding.code_location:
        loc = finding.code_location
        lines = [
            f"# {finding.title}",
            f"# Source-only finding — no live request reproduces this on its own.",
            f"# Review steps:",
            f"1. Open {loc.file_path}" + (f", line {loc.line_number}" if loc.line_number else ""),
        ]
        if loc.snippet:
            lines.append(f"2. Confirm the flagged pattern:\n   {loc.snippet}")
        lines.append(f"3. {finding.remediation or 'Assess whether this pattern is reachable/exploitable in context.'}")
        return "\n".join(lines), "text"

    return f"# {finding.title}\n# No evidence captured to build a reproduction from.", "text"


def generate_pocs(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        poc_text, poc_lang = generate_poc(f)
        f.poc = poc_text
        f.poc_language = poc_lang
    return findings
