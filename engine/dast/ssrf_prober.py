"""Safe SSRF probing against server-side URL-fetching proxy endpoints.

Every payload targets an address that is either non-routable from this test
run's perspective or requires no interaction beyond "did the target fetch
it" — no payload asks the target to read/write/delete real data anywhere.
Candidates: cloud-metadata IP (169.254.169.254, unreachable in this Docker
Desktop setup regardless — this only tests whether the *app* attempted and
disclosed the fetch outcome), internal docker-network service names,
loopback, and three classic SSRF-filter-bypass IP encodings (decimal, hex,
IPv6-mapped) to check the blocklist isn't purely string-matching
"127.0.0.1"/"localhost".

Detection: worldmonitor's own SSRF guard returns 403 with a distinctive
locked-down CSP (`sandbox; default-src 'none'; ...`) — verified empirically
against the live instance before writing this. A response that's 200 *and*
lacks that lockdown CSP is treated as a possible bypass; the finding
includes the raw evidence so it can be manually confirmed either way rather
than trusted blindly.
"""
from __future__ import annotations

from engine.common.http_client import SafeClient
from engine.common.models import Confidence, Finding, FindingSource, HttpEvidence, Severity

_SSRF_PAYLOADS = [
    ("cloud metadata IP", "http://169.254.169.254/latest/meta-data/"),
    ("internal docker service (redis)", "http://redis:6379/"),
    ("internal docker service (self)", "http://worldmonitor:8080/api/local-status"),
    ("loopback", "http://127.0.0.1:8080/api/local-status"),
    ("decimal-encoded loopback", "http://2130706433/"),
    ("hex-encoded loopback", "http://0x7f000001/"),
    ("IPv6-mapped loopback", "http://[::ffff:127.0.0.1]/"),
]

_LOCKDOWN_CSP_MARKER = "default-src 'none'"


def run(client: SafeClient, target_name: str, proxy_path: str = "/api/rss-proxy",
        param_name: str = "url") -> list[Finding]:
    findings: list[Finding] = []
    for label, payload in _SSRF_PAYLOADS:
        resp = client.get(proxy_path, params={param_name: payload})
        if not resp.ok:
            continue

        csp = resp.headers.get("Content-Security-Policy", resp.headers.get("content-security-policy", ""))
        looks_blocked = resp.status_code in (400, 403, 422, 502, 504) or _LOCKDOWN_CSP_MARKER in csp
        if looks_blocked:
            continue

        if resp.status_code == 200:
            evidence = HttpEvidence(
                method="GET", url=resp.url, status_code=resp.status_code,
                response_headers=dict(resp.headers), response_snippet=resp.text[:300],
                notes=f"Payload: {label} ({payload})",
            )
            findings.append(Finding(
                rule_id="SSRF-001",
                title=f"Possible SSRF via {proxy_path}?{param_name}=... ({label})",
                description=(
                    f"Requesting {proxy_path}?{param_name}={payload} returned 200 without the "
                    f"lockdown response this endpoint gives for other blocked SSRF targets. This "
                    f"needs manual confirmation — check whether the response body actually "
                    f"contains fetched content from {payload}, or if this is a different, benign "
                    f"code path (e.g. the URL failed validation for an unrelated reason)."
                ),
                category="ssrf",
                source=FindingSource.DAST,
                confidence=Confidence.TENTATIVE,
                target=target_name,
                severity=Severity.HIGH,
                http_evidence=[evidence],
                remediation="Validate/deny-list target URLs server-side against loopback, link-local, and private/internal address ranges, including alternate IP encodings, before the outbound fetch — not just against a literal string match on 'localhost'/'127.0.0.1'.",
                business_impact="A working SSRF can be used to reach internal-only services, cloud metadata endpoints, or bypass network-level access controls.",
                tags=["ssrf", label.replace(" ", "-")],
            ))
    return findings
