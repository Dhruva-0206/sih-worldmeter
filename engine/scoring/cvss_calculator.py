"""CVSS 3.1 base score calculation.

Every rule_id this framework can emit has a hand-reasoned CVSS 3.1 vector
below — not a generic "severity -> score" lookup, but a vector built from
the actual exploitation shape of that specific bug class (does it need a
prior foothold? does it need user interaction? does it cross a privilege
boundary?). A dependency finding (DEP-001/DEP-002) is the one deliberate
exception: its real-world severity varies per-CVE, so it falls back to a
representative vector chosen from the advisory's own severity band
(critical/high/moderate/low) rather than one fixed vector for every package.
Any rule_id this table doesn't recognize also falls back that way, keyed off
whatever severity the emitting module already assigned — so scoring never
silently drops a finding, it just scores conservatively until someone adds
a proper vector for that rule.

Score computation itself is delegated to the `cvss` package (FIRST's
reference algorithm), not reimplemented here.
"""
from __future__ import annotations

from cvss import CVSS3

from engine.common.models import Finding, Severity

# rule_id -> CVSS 3.1 vector (metrics only, no "CVSS:3.1/" prefix)
RULE_CVSS_VECTORS: dict[str, str] = {
    # --- secrets ---
    "SEC-001": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",   # AWS key
    "SEC-002": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",   # GitHub token
    "SEC-003": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",   # Slack token
    "SEC-004": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",   # Google API key
    "SEC-005": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",   # Stripe key
    "SEC-006": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # PEM private key
    "SEC-007": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",   # JWT-looking literal
    "SEC-010": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",   # entropy-based generic (lower confidence -> higher AC)

    # --- auth patterns (SAST) ---
    "AUTH-001": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",  # weak password hash — needs a DB-read precursor
    "AUTH-002": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # JWT alg=none in source
    "AUTH-003": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",  # insecure cookie flags — needs XSS/MITM precursor

    # --- access control (SAST heuristics) ---
    "ACCESS-001": "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    "ACCESS-002": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",

    # --- injection patterns (SAST) ---
    "INJ-SAST-001": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # string-concatenated SQL in source
    # unsafe deserialization/eval sink — AC:H because this is "a dangerous
    # sink exists in source", not a confirmed exploit: whether it's actually
    # reachable with attacker-controlled input is unverified (TENTATIVE
    # confidence — regex detection can also mistake a string/regex-literal
    # containing "eval(" for a real call, see the module docstring), so a
    # CVSS:C:H/I:H/A:H vector was overstating it as Critical by default.
    "INJ-SAST-002": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",

    # --- CORS ---
    "CORS-001": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",  # victim must visit attacker page

    # --- security headers ---
    "HEADERS-001": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",

    # --- info disclosure ---
    "INFO-001": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # exposed admin/debug route
    "INFO-002": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # stack trace leak

    # --- rate limiting ---
    "RATE-002": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",  # bypass -> abuse/cost/availability

    # --- SSRF ---
    "SSRF-001": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",  # scope change: can reach internal network

    # --- BOLA / privilege escalation ---
    "BOLA-001": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
    "PRIVESC-001": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # unauth JWT forgery -> any role
    "PRIVESC-002": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",  # needs a low-priv account first

    # --- injection ---
    "INJ-001": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "INJ-002": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",   # error-based disclosure only, weaker than a proven read/write primitive
    "INJ-003": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",

    # --- OAuth / MCP ---
    "MCP-001": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "OAUTH-001": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",

    # --- session/auth DAST ---
    "AUTH-T-001": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",  # token predictability
    "AUTH-T-002": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",  # weak password policy — needs brute-force precursor
    "AUTH-T-003": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",  # logout non-invalidation — needs a stolen-token precursor

    # --- API fuzzing ---
    "APIFUZZ-001": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
}

# Fallback vectors keyed by the emitting module's own qualitative severity —
# used for DEP-001/DEP-002 (real severity varies per-CVE) and any future
# rule_id that hasn't been given a hand-built vector yet.
_SEVERITY_FALLBACK_VECTORS: dict[Severity, str] = {
    Severity.CRITICAL: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    Severity.HIGH:      "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    Severity.MEDIUM:    "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    Severity.LOW:       "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    Severity.INFO:      "AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
}


def vector_for(finding: Finding) -> str:
    return RULE_CVSS_VECTORS.get(finding.rule_id) or _SEVERITY_FALLBACK_VECTORS[finding.severity]


def score_finding(finding: Finding) -> Finding:
    """Mutates and returns `finding` with cvss_vector/cvss_score/severity set
    from the CVSS 3.1 base score (severity is re-derived from the score, so
    it stays consistent with the vector rather than whatever heuristic
    severity the emitting DAST/SAST module guessed)."""
    vector = vector_for(finding)
    c = CVSS3(f"CVSS:3.1/{vector}")
    score = c.base_score
    finding.cvss_vector = f"CVSS:3.1/{vector}"
    finding.cvss_score = score
    finding.severity = Severity.from_cvss_score(score)
    return finding


def score_findings(findings: list[Finding]) -> list[Finding]:
    return [score_finding(f) for f in findings]
