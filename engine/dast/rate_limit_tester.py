"""Rate-limit enforcement + client-controlled-header bypass testing.

Rather than assuming a specific threshold (thresholds vary by endpoint and
aren't always documented), this probes empirically and stays honest about
what it could and couldn't establish within a safe request budget:

  1. Send a bounded burst (`burst_size`, default 20 — small and gentle by
     design, this is a demonstration probe, not a load test) at one
     endpoint and see if a 429 appears.
  2. If a 429 appears: immediately retry a few more requests, each with a
     different spoofed X-Forwarded-For / X-Real-IP value. If the 429 goes
     away under a spoofed header, the limiter is keying off a
     client-controlled value — RATE-002, a real bypass.
  3. If no 429 appears in the burst: say so plainly (RATE-000, INFO) rather
     than silently reporting nothing, which would look identical to "rate
     limiting is broken" in a report. Absence of evidence within a small,
     safe burst is not evidence of absence.
"""
from __future__ import annotations

from engine.common.http_client import SafeClient
from engine.common.models import Confidence, Finding, FindingSource, HttpEvidence, Severity

_SPOOF_HEADER_NAMES = ["X-Forwarded-For", "X-Real-IP"]
_FAKE_IPS = ["203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13"]


def _fire(client: SafeClient, method: str, path: str, headers: dict[str, str] | None = None):
    return client.request(method, path, headers=headers or {})


def run(client: SafeClient, target_name: str, path: str = "/api/wm-session", method: str = "POST",
        burst_size: int = 20) -> list[Finding]:
    findings: list[Finding] = []
    responses = []
    for _ in range(burst_size):
        resp = _fire(client, method, path)
        responses.append(resp)
        if not resp.ok:
            break

    got_429 = any(r.status_code == 429 for r in responses)
    has_ratelimit_headers = any(
        any(h.lower().startswith("ratelimit") or h.lower().startswith("x-ratelimit") for h in r.headers)
        for r in responses
    )

    if not got_429:
        findings.append(Finding(
            rule_id="RATE-000",
            title=f"Rate limit not triggered within {burst_size} requests: {method} {path}",
            description=(
                f"Sent {len(responses)} requests to {method} {path} without receiving a 429. "
                f"This endpoint may have a higher threshold, a longer window, or a per-day cap "
                f"not practical to trigger in a bounded/safe test. "
                + ("IETF RateLimit-* headers were not observed on any response either."
                   if not has_ratelimit_headers else "RateLimit-* headers were present but no 429 occurred.")
            ),
            category="rate-limiting",
            source=FindingSource.DAST,
            confidence=Confidence.TENTATIVE,
            target=target_name,
            severity=Severity.INFO,
            http_evidence=[HttpEvidence(method=method, url=responses[-1].url if responses else path,
                                         status_code=responses[-1].status_code if responses else None,
                                         notes=f"{len(responses)} requests sent, no 429 observed")],
            tags=["rate-limiting", "inconclusive"],
        ))
        return findings

    # Got a 429 — now test whether a spoofed client-identity header resets it.
    bypassed = False
    bypass_evidence = None
    for i, fake_ip in enumerate(_FAKE_IPS):
        headers = {name: fake_ip for name in _SPOOF_HEADER_NAMES}
        resp = _fire(client, method, path, headers=headers)
        if resp.ok and resp.status_code != 429:
            bypassed = True
            bypass_evidence = HttpEvidence(
                method=method, url=resp.url, status_code=resp.status_code,
                request_headers=headers,
                notes=f"Request #{i+1} after triggering 429, with spoofed X-Forwarded-For/X-Real-IP={fake_ip}",
            )
            break

    if bypassed:
        findings.append(Finding(
            rule_id="RATE-002",
            title=f"Rate limit bypassed via spoofed client-IP header: {method} {path}",
            description=(
                f"{method} {path} returned 429 after {burst_size} requests, but a subsequent "
                f"request with a spoofed X-Forwarded-For/X-Real-IP header succeeded (non-429). "
                f"The limiter appears to key its bucket off a client-controlled header instead of "
                f"the connection's actual source address."
            ),
            category="rate-limiting",
            source=FindingSource.DAST,
            confidence=Confidence.CONFIRMED,
            target=target_name,
            severity=Severity.HIGH,
            http_evidence=[bypass_evidence] if bypass_evidence else [],
            remediation="Key rate-limit buckets off the connection's real source address (or a header only a trusted, configured reverse proxy can set), never an unauthenticated client-supplied header.",
            business_impact="Rate limiting is trivially bypassable by rotating a header value, defeating its purpose (abuse/cost control, brute-force slowdown).",
            tags=["rate-limiting", "bypass", "ip-spoofing"],
        ))
    else:
        findings.append(Finding(
            rule_id="RATE-001",
            title=f"Rate limit enforced and resists IP-spoofing header bypass: {method} {path}",
            description=(
                f"{method} {path} returned 429 after {burst_size} requests, and stayed 429 across "
                f"{len(_FAKE_IPS)} follow-up requests each with a different spoofed "
                f"X-Forwarded-For/X-Real-IP value — the limiter is not keying off those headers."
            ),
            category="rate-limiting",
            source=FindingSource.DAST,
            confidence=Confidence.CONFIRMED,
            target=target_name,
            severity=Severity.INFO,
            tags=["rate-limiting", "verified-control"],
        ))
    return findings
