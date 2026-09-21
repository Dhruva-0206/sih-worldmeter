"""Exposed debug/admin endpoints + verbose error / stack-trace leakage.

Two independent probes:

  INFO-001  a candidate sensitive path (generic admin/debug conventions,
            plus worldmonitor's documented `/api/local-*` administration
            routes, which SELF_HOSTING.md says must 403 in Docker mode)
            responds with 200 instead of a deny/not-found status.

  INFO-002  a request crafted to provoke an error (malformed JSON, an
            oversized/wrong-typed field) gets a response body containing
            what looks like a stack trace or an internal file path —
            leaking framework/library internals to an unauthenticated
            caller.

The candidate path list is intentionally generic (works against any target)
with the worldmonitor-specific `/api/local-*` paths folded in as additional
candidates — if a target doesn't have them, they just 404/pass through
cleanly and produce no finding.
"""
from __future__ import annotations

import re
import uuid

from engine.common.http_client import SafeClient
from engine.common.models import Confidence, Finding, FindingSource, HttpEvidence, Severity

_GENERIC_SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.git/config", "/.git/HEAD",
    "/api/debug", "/debug", "/api/admin", "/admin",
    "/api/_debug", "/server-status", "/actuator/health", "/api/internal",
]
# NOTE: /.well-known/security.txt is deliberately NOT on this list — it's an
# RFC 9116 file orgs are expected to publish (security contact info), so a
# 200 there is a good sign, not a finding. Caught during development when it
# showed up as worldmonitor's one "leak" — it was their real, intentional
# security.txt.

_WORLDMONITOR_LOCAL_ADMIN_PATHS = [
    "/api/local-status", "/api/local-traffic-log", "/api/local-debug-toggle",
    "/api/local-env-update", "/api/local-env-update-batch", "/api/local-validate-secret",
]

_STACK_TRACE_MARKERS = re.compile(
    r"(at\s+[\w.$<>]+\s+\([^)]*\.(?:js|ts|mjs):\d+:\d+\)|"
    r"node_modules[/\\][\w.@-]+|"
    r"Traceback \(most recent call last\)|"
    r"File \"[^\"]+\.py\", line \d+|"
    r"System\.\w+Exception|"
    r"at Object\.<anonymous>|"
    r"webpack-internal://)"
)

_MALFORMED_JSON_PROBES = [
    ("malformed JSON body", "{not valid json", "application/json"),
    ("wrong content-type with JSON-looking body", '{"a":1}', "text/plain"),
]


def _spa_fallback_signature(client: SafeClient) -> tuple[int, int, str]:
    """Fetch a guaranteed-nonexistent path to fingerprint a SPA's catch-all
    route (`try_files ... /dashboard.html`-style fallbacks serve 200 with
    the app shell for literally any unmatched path — without this baseline,
    every candidate in the sensitive-path list "succeeds" with 200 and the
    checker is just reporting the SPA's own routing behavior, not a real
    disclosure). Any candidate response matching this signature is noise.
    """
    probe_path = f"/__wmsec_baseline_probe_{uuid.uuid4().hex}__"
    resp = client.get(probe_path)
    return (resp.status_code, len(resp.text), resp.headers.get("content-type", ""))


def _check_sensitive_paths(client: SafeClient, target_name: str, paths: list[str],
                            expect_blocked: bool) -> list[Finding]:
    findings = []
    baseline = _spa_fallback_signature(client)
    for path in paths:
        resp = client.get(path)
        if not resp.ok:
            continue
        signature = (resp.status_code, len(resp.text), resp.headers.get("content-type", ""))
        if resp.status_code == 200 and signature == baseline:
            continue  # identical to the nonexistent-path baseline — SPA/catch-all fallback, not a real disclosure
        if resp.status_code == 200:
            evidence = HttpEvidence(
                method="GET", url=resp.url, status_code=resp.status_code,
                response_headers=dict(resp.headers),
                response_snippet=resp.text[:300],
            )
            findings.append(Finding(
                rule_id="INFO-001",
                title=f"Unexpected 200 on sensitive path: {path}",
                description=(
                    f"GET {path} returned 200 OK. " +
                    ("This path is documented as requiring administrator authentication "
                     "and returning 403 in self-hosted Docker mode." if path in _WORLDMONITOR_LOCAL_ADMIN_PATHS
                     else "This path matches a common sensitive/debug-endpoint convention.")
                ),
                category="info-disclosure",
                source=FindingSource.DAST,
                confidence=Confidence.CONFIRMED if expect_blocked else Confidence.TENTATIVE,
                target=target_name,
                severity=Severity.HIGH if path in _WORLDMONITOR_LOCAL_ADMIN_PATHS else Severity.MEDIUM,
                http_evidence=[evidence],
                remediation="Ensure this route enforces its access-control gate before returning a 200, and returns 403/404 for unauthenticated/unauthorized callers.",
                business_impact="Administrative or debug functionality reachable without authentication can expose internals or allow configuration changes.",
                tags=["info-disclosure", "exposed-endpoint"],
            ))
    return findings


def _check_verbose_errors(client: SafeClient, target_name: str, probe_paths: list[str]) -> list[Finding]:
    findings = []
    for path in probe_paths:
        for label, body, content_type in _MALFORMED_JSON_PROBES:
            resp = client.post(path, data=body, headers={"Content-Type": content_type})
            if not resp.ok:
                continue
            m = _STACK_TRACE_MARKERS.search(resp.text)
            if not m:
                continue
            evidence = HttpEvidence(
                method="POST", url=resp.url, status_code=resp.status_code,
                request_headers={"Content-Type": content_type}, request_body=body,
                response_snippet=resp.text[max(0, m.start() - 60):m.start() + 200],
                notes=label,
            )
            findings.append(Finding(
                rule_id="INFO-002",
                title=f"Verbose error / stack trace leaked from {path}",
                description=(
                    f"Sending a {label} to {path} produced a response containing what looks "
                    f"like a stack trace or internal file path: \"{m.group(0)[:120]}\"."
                ),
                category="info-disclosure",
                source=FindingSource.DAST,
                confidence=Confidence.CONFIRMED,
                target=target_name,
                severity=Severity.LOW,
                http_evidence=[evidence],
                remediation="Catch errors at the handler boundary and return a generic error body; log the full stack trace server-side only.",
                business_impact="Stack traces can reveal framework versions, file layout, and internal logic useful for crafting further attacks.",
                tags=["info-disclosure", "stack-trace"],
            ))
    return findings


def run(client: SafeClient, target_name: str, extra_sensitive_paths: list[str] | None = None,
        error_probe_paths: list[str] | None = None, include_worldmonitor_paths: bool = False) -> list[Finding]:
    candidate_paths = list(_GENERIC_SENSITIVE_PATHS)
    if include_worldmonitor_paths:
        candidate_paths += _WORLDMONITOR_LOCAL_ADMIN_PATHS
    if extra_sensitive_paths:
        candidate_paths += extra_sensitive_paths

    findings = _check_sensitive_paths(client, target_name, candidate_paths, expect_blocked=include_worldmonitor_paths)
    findings += _check_verbose_errors(client, target_name, error_probe_paths or ["/api/health"])
    return findings
