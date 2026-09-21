"""HTTP response security-header audit, graded A+ through F.

Methodology and header checklist are modeled on securityheaders.com's
public checklist (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy, Cross-Origin-*-Policy) — reimplemented
locally so the framework stays fully offline-capable and never sends a
target's headers to a third-party service. The weights/grade bands below are
this project's own reimplementation, not a claim of bit-for-bit parity with
securityheaders.com's (non-public) scoring algorithm.

CSP is checked at directive granularity rather than "present or absent" —
`script-src 'unsafe-inline'` and `style-src 'unsafe-inline'` are different
severities (inline script execution vs. inline style injection), and a page
can legitimately harden one directive while leaving another looser (see
module use against worldmonitor's real CSP: strict script-src with
nonces/hashes, but style-src still carries 'unsafe-inline').
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from engine.common.http_client import SafeClient
from engine.common.models import Confidence, Finding, FindingSource, HttpEvidence, Severity


@dataclass
class HeaderCheckResult:
    name: str
    weight: int
    earned: int
    detail: str
    finding_severity: Severity | None = None


def _split_csp(csp: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        directives[tokens[0].lower()] = tokens[1:]
    return directives


def _grade_from_ratio(ratio: float) -> str:
    if ratio >= 0.95:
        return "A+"
    if ratio >= 0.85:
        return "A"
    if ratio >= 0.70:
        return "B"
    if ratio >= 0.55:
        return "C"
    if ratio >= 0.40:
        return "D"
    return "F"


def evaluate_headers(headers: dict[str, str], scheme: str) -> tuple[list[HeaderCheckResult], str, int, int]:
    h = {k.lower(): v for k, v in headers.items()}
    results: list[HeaderCheckResult] = []

    # --- HSTS ---------------------------------------------------------
    hsts = h.get("strict-transport-security")
    if scheme != "https":
        results.append(HeaderCheckResult(
            "Strict-Transport-Security", 0, 0,
            "Not scored: this response was served over plain HTTP (local self-hosted deployment). "
            "HSTS is a browser instruction that only takes effect over HTTPS — check this again "
            "against the production TLS-terminated deployment.",
        ))
    elif not hsts:
        results.append(HeaderCheckResult("Strict-Transport-Security", 10, 0,
                                          "Missing entirely.", Severity.MEDIUM))
    else:
        max_age_ok = False
        for part in hsts.split(";"):
            part = part.strip()
            if part.startswith("max-age="):
                try:
                    max_age_ok = int(part.split("=", 1)[1]) >= 15552000  # 180 days
                except ValueError:
                    pass
        include_subdomains = "includesubdomains" in hsts.lower()
        preload = "preload" in hsts.lower()
        earned = 6 + (2 if max_age_ok else 0) + (1 if include_subdomains else 0) + (1 if preload else 0)
        detail = f"Present: max-age {'>=180d' if max_age_ok else '<180d (weak)'}, includeSubDomains={include_subdomains}, preload={preload}"
        results.append(HeaderCheckResult("Strict-Transport-Security", 10, earned, detail,
                                          None if earned >= 9 else Severity.LOW))

    # --- Content-Security-Policy ---------------------------------------
    csp = h.get("content-security-policy")
    if not csp:
        results.append(HeaderCheckResult("Content-Security-Policy", 25, 0, "Missing entirely.", Severity.HIGH))
    else:
        directives = _split_csp(csp)
        earned = 10  # base credit for having a CSP at all
        notes = []

        script_src = directives.get("script-src", directives.get("default-src", []))
        if "'unsafe-inline'" in script_src and "'strict-dynamic'" not in script_src:
            notes.append("script-src allows 'unsafe-inline' with no strict-dynamic/nonce/hash mitigation")
        elif "'unsafe-eval'" in script_src:
            notes.append("script-src allows 'unsafe-eval'")
        else:
            earned += 8
            notes.append("script-src has no unsafe-inline/unsafe-eval exposure")

        style_src = directives.get("style-src", directives.get("default-src", []))
        if "'unsafe-inline'" in style_src:
            notes.append("style-src allows 'unsafe-inline' (lower risk than script-src, but still widens the CSS-injection/exfiltration surface)")
        else:
            earned += 3

        if "object-src" in directives and "'none'" in directives["object-src"]:
            earned += 2
        else:
            notes.append("object-src is not restricted to 'none'")

        if "frame-ancestors" in directives:
            earned += 2
        else:
            notes.append("no frame-ancestors directive (clickjacking mitigation relies on X-Frame-Options alone)")

        results.append(HeaderCheckResult("Content-Security-Policy", 25, min(earned, 25),
                                          "; ".join(notes) if notes else "Strong policy: no unsafe-inline/unsafe-eval, object-src none, frame-ancestors set.",
                                          Severity.MEDIUM if notes else None))

    # --- X-Frame-Options / frame-ancestors already covered above -------
    xfo = h.get("x-frame-options")
    has_frame_ancestors = csp and "frame-ancestors" in _split_csp(csp)
    if not xfo and not has_frame_ancestors:
        results.append(HeaderCheckResult("X-Frame-Options", 10, 0,
                                          "Missing, and CSP has no frame-ancestors either — page is frameable.", Severity.MEDIUM))
    elif not xfo:
        results.append(HeaderCheckResult("X-Frame-Options", 10, 7,
                                          "Missing, but CSP frame-ancestors covers clickjacking protection in modern browsers.", None))
    else:
        results.append(HeaderCheckResult("X-Frame-Options", 10, 10, f"Present: {xfo}", None))

    # --- X-Content-Type-Options -----------------------------------------
    xcto = h.get("x-content-type-options", "")
    if xcto.lower() == "nosniff":
        results.append(HeaderCheckResult("X-Content-Type-Options", 8, 8, "Present: nosniff", None))
    else:
        results.append(HeaderCheckResult("X-Content-Type-Options", 8, 0, "Missing or not 'nosniff'.", Severity.LOW))

    # --- Referrer-Policy --------------------------------------------------
    rp = h.get("referrer-policy", "")
    strong_rp = rp.lower() in ("no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin")
    if strong_rp:
        results.append(HeaderCheckResult("Referrer-Policy", 7, 7, f"Present: {rp}", None))
    elif rp:
        results.append(HeaderCheckResult("Referrer-Policy", 7, 3, f"Present but permissive: {rp}", Severity.LOW))
    else:
        results.append(HeaderCheckResult("Referrer-Policy", 7, 0, "Missing.", Severity.LOW))

    # --- Permissions-Policy -----------------------------------------------
    pp = h.get("permissions-policy", "")
    if pp:
        results.append(HeaderCheckResult("Permissions-Policy", 7, 7, f"Present: {pp[:120]}", None))
    else:
        results.append(HeaderCheckResult("Permissions-Policy", 7, 0, "Missing.", Severity.LOW))

    # --- Cross-Origin-*-Policy trio -----------------------------------
    coop = h.get("cross-origin-opener-policy", "")
    coep = h.get("cross-origin-embedder-policy", "")
    corp = h.get("cross-origin-resource-policy", "")
    coop_ok = coop.lower() in ("same-origin", "same-origin-allow-popups")
    present_count = sum(1 for v in (coop, coep, corp) if v)
    earned = (4 if coop_ok else (2 if coop else 0)) + (3 if coep else 0) + (3 if corp else 0)
    detail = f"COOP={coop or '(missing)'}, COEP={coep or '(missing)'}, CORP={corp or '(missing)'}"
    results.append(HeaderCheckResult("Cross-Origin-*-Policy", 10, min(earned, 10), detail,
                                      Severity.LOW if present_count < 3 else None))

    total_possible = sum(r.weight for r in results)
    total_earned = sum(r.earned for r in results)
    ratio = (total_earned / total_possible) if total_possible else 1.0
    grade = _grade_from_ratio(ratio)
    return results, grade, total_earned, total_possible


def run(client: SafeClient, target_name: str, path: str = "/") -> list[Finding]:
    resp = client.get(path)
    if not resp.ok:
        return []

    scheme = urlparse(client.base_url).scheme
    results, grade, earned, possible = evaluate_headers(resp.headers, scheme)

    evidence = HttpEvidence(
        method="GET", url=resp.url, status_code=resp.status_code,
        response_headers=dict(resp.headers),
        notes=f"Security header grade: {grade} ({earned}/{possible} points)",
    )

    findings: list[Finding] = [Finding(
        rule_id="HEADERS-000",
        title=f"Security header grade: {grade} ({earned}/{possible})",
        description="Aggregate security-header posture for " + path + ", methodology modeled on securityheaders.com's checklist:\n" +
                    "\n".join(f"  - {r.name}: {r.earned}/{r.weight} — {r.detail}" for r in results),
        category="security-headers",
        source=FindingSource.DAST,
        confidence=Confidence.CONFIRMED,
        target=target_name,
        severity=Severity.INFO,
        http_evidence=[evidence],
        tags=["security-headers", "grade", grade],
        extra={"grade": grade, "points_earned": earned, "points_possible": possible,
               "breakdown": [{"name": r.name, "earned": r.earned, "weight": r.weight, "detail": r.detail} for r in results]},
    )]

    for r in results:
        if r.finding_severity is None:
            continue
        findings.append(Finding(
            rule_id="HEADERS-001",
            title=f"Weak or missing security header: {r.name}",
            description=r.detail,
            category="security-headers",
            source=FindingSource.DAST,
            confidence=Confidence.CONFIRMED,
            target=target_name,
            severity=r.finding_severity,
            http_evidence=[evidence],
            remediation=f"Set a strong {r.name} header on responses that serve HTML/browser-rendered content.",
            business_impact="Weak security headers widen the blast radius of an otherwise-unrelated bug (e.g. an XSS becomes exploitable without CSP; clickjacking becomes possible without frame protection).",
            tags=["security-headers", r.name.lower()],
        ))
    return findings
