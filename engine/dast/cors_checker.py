"""CORS misconfiguration probing via origin reflection.

The only security-meaningful CORS bug this can find is a response that
REFLECTS an attacker-controlled Origin value back in
Access-Control-Allow-Origin while also setting
Access-Control-Allow-Credentials: true — that combination is what lets a
malicious page read a victim's authenticated response. A server that always
returns some fixed ACAO value regardless of the request's Origin is not
exploitable this way even if that fixed value looks odd, because a browser
only exposes the response to page JS when ACAO exactly equals the page's own
Origin. So every probe here compares the *returned* ACAO against the Origin
*we sent*, not against a hardcoded expectation of what the header "should"
say — that keeps this test accurate regardless of which layer (app code,
edge middleware, reverse proxy) actually produced the header.

Includes one target-specific regression probe: worldmonitor's own
api/_cors.js contains defenses against a Google-Translate-rewritten-origin
bypass (`evil--worldmonitor-app.translate.goog` decoding to
`evil-worldmonitor.app`, discovered as issue #6411 per their source
comments). Re-testing a fix that's already known to exist isn't redundant
for a DAST tool — it's exactly the kind of regression a future change could
silently reintroduce, and it's cheap to check every run.
"""
from __future__ import annotations

from engine.common.http_client import SafeClient
from engine.common.models import Confidence, Finding, FindingSource, HttpEvidence, Severity

_FOREIGN_ORIGIN = "https://evil-attacker.example"
_NULL_ORIGIN = "null"
_TRANSLATE_GOOG_BYPASS_ORIGIN = "https://evil--worldmonitor-app.translate.goog"

_PROBE_PATHS = ["/api/health?compact=1", "/api/version"]


def _probe_origin(client: SafeClient, path: str, origin: str) -> tuple[Finding | None, HttpEvidence]:
    resp = client.get(path, headers={"Origin": origin})
    evidence = HttpEvidence(
        method="GET", url=resp.url,
        request_headers={"Origin": origin},
        status_code=resp.status_code,
        response_headers={k: v for k, v in resp.headers.items() if k.lower().startswith("access-control")},
        notes=f"Origin sent: {origin}",
    )
    if not resp.ok:
        return None, evidence

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

    if acao == origin and acac:
        finding = Finding(
            rule_id="CORS-001",
            title=f"CORS reflects attacker-controlled Origin with credentials allowed: {path}",
            description=(
                f"Sending `Origin: {origin}` to {path} produced "
                f"`Access-Control-Allow-Origin: {acao}` (an exact echo of the request Origin) "
                f"together with `Access-Control-Allow-Credentials: true`. A page hosted at "
                f"{origin} could issue a credentialed request to this endpoint from a victim's "
                f"browser and read the response."
            ),
            category="cors",
            source=FindingSource.DAST,
            confidence=Confidence.CONFIRMED,
            target="",
            severity=Severity.HIGH,
            http_evidence=[evidence],
            remediation="Validate Origin against an explicit allowlist before echoing it, and never combine a reflected/wildcard origin with Allow-Credentials: true.",
            business_impact="Any authenticated user who visits a page at the attacker's origin can have their session silently used to read data from this API.",
            tags=["cors", "origin-reflection"],
        )
        return finding, evidence
    return None, evidence


def run(client: SafeClient, target_name: str, max_findings: int = 50) -> list[Finding]:
    findings: list[Finding] = []
    probes = [
        ("foreign origin", _FOREIGN_ORIGIN),
        ("null origin", _NULL_ORIGIN),
        ("translate.goog bypass attempt", _TRANSLATE_GOOG_BYPASS_ORIGIN),
    ]
    for path in _PROBE_PATHS:
        for label, origin in probes:
            finding, _ = _probe_origin(client, path, origin)
            if finding:
                finding.target = target_name
                finding.tags.append(label.replace(" ", "-"))
                findings.append(finding)
                if len(findings) >= max_findings:
                    return findings
    return findings
