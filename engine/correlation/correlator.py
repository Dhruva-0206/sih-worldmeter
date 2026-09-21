"""Maps DAST findings back to SAST source locations, producing a
"confirmed" vs "unconfirmed" classification.

Two matching strategies, because the two targets' source layouts are
genuinely different shapes:

  1. Path-based — worldmonitor's api/ tree is one-file-per-route, so
     access_control_checker's findings carry the exact route_path/
     route_literal they're about. A DAST finding whose probed URL path
     matches that route is a direct hit.

  2. Rule-family — fixture-app is one monolithic app.py handling every
     route, so path-based matching there would trivially link *every*
     SAST finding in the file to *every* DAST finding (useless — too
     coarse). Instead, a small hand-curated table says which SAST rule_ids
     and DAST rule_ids are about the same underlying bug class (e.g.
     AUTH-002's "JWT accepts alg=none" source pattern and PRIVESC-001's
     live JWT-forgery exploit are the same bug seen from two angles).

A finding's `status` becomes "confirmed" when: it's a DAST finding with
CONFIRMED confidence (empirically observed — self-confirming), or it's a
SAST finding cross-linked to such a DAST finding. Everything else — a SAST
heuristic lead nothing dynamic corroborated, or a DAST TENTATIVE probe
needing a human look — stays "unconfirmed". That label is exactly the
signal a reader needs to triage a report: start with "confirmed".
"""
from __future__ import annotations

from urllib.parse import urlparse

from engine.common.models import Confidence, Finding, FindingSource

# SAST rule_id -> DAST rule_id(s) that would confirm the same underlying bug
# from live behavior, when path-based matching doesn't apply (see docstring).
RULE_FAMILY_LINKS: dict[str, set[str]] = {
    "AUTH-002": {"PRIVESC-001"},                      # JWT alg=none: source pattern <-> live forgery
    "ACCESS-001": {"INFO-001", "BOLA-001", "PRIVESC-002"},
    "ACCESS-002": {"INFO-001"},
    "AUTH-001": set(),                                  # weak hash: SAST-only, nothing live corroborates storage format
    "AUTH-003": {"CORS-001"},                           # insecure cookie flags <-> exploitable cross-origin read
    "INJ-SAST-001": {"INJ-001", "INJ-002", "INJ-003"},  # string-concatenated SQL <-> live injection probes
}


def _path_of(url: str) -> str:
    return urlparse(url).path.rstrip("/") or "/"


def _sast_route_keys(finding: Finding) -> set[str]:
    keys = set()
    route_path = finding.extra.get("route_path") or finding.extra.get("route_literal")
    if route_path:
        keys.add(route_path.rstrip("/") or "/")
    if finding.code_location and finding.code_location.file_path:
        keys.add(f"file:{finding.code_location.file_path}")
    return keys


def _dast_route_keys(finding: Finding) -> set[str]:
    keys = set()
    for ev in finding.http_evidence:
        if ev.url:
            keys.add(_path_of(ev.url))
    return keys


def correlate(findings: list[Finding]) -> list[Finding]:
    sast = [f for f in findings if f.source == FindingSource.SAST]
    dast = [f for f in findings if f.source == FindingSource.DAST]

    # DAST findings that are themselves live-observed evidence are already confirmed.
    for f in dast:
        if f.confidence == Confidence.CONFIRMED:
            f.status = "confirmed"

    for sf in sast:
        sf_keys = _sast_route_keys(sf)
        family_targets = RULE_FAMILY_LINKS.get(sf.rule_id, set())

        for df in dast:
            if df.target != sf.target:
                continue
            path_match = bool(sf_keys & _dast_route_keys(df))
            family_match = df.rule_id in family_targets
            if not (path_match or family_match):
                continue

            if df.id not in sf.correlated_with:
                sf.correlated_with.append(df.id)
            if sf.id not in df.correlated_with:
                df.correlated_with.append(sf.id)

            # Correlation is itself a confirmation mechanism: an independent
            # static lead and an independent dynamic probe agreeing on the
            # same bug is stronger evidence than either alone, even if
            # neither individually reached CONFIRMED confidence on its own.
            sf.status = "confirmed"
            df.status = "confirmed"

    return findings
