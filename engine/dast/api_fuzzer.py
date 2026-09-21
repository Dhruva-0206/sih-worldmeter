"""OpenAPI-spec-driven endpoint fuzzing.

Reads the target's own generated OpenAPI document (no hand-maintained route
list to fall out of sync) and, for a bounded, evenly-spaced sample of GET
endpoints:

  1. Fires a baseline request using each parameter's spec-provided
     `example` value (falling back to a generic placeholder by type when a
     required parameter has none).
  2. For each integer/number-typed parameter, fires a type-confusion
     variant (a non-numeric string in an integer slot) and checks for a 500.

A 401/403/400/422 is not a finding here — that's an endpoint correctly
requiring auth or rejecting bad input, which is exactly what should happen.
Only an unhandled-exception-shaped 500 (optionally corroborated by a
stack-trace marker in the body, reusing the same detector as
info_disclosure.py) is flagged: a public endpoint crashing on a
malformed-but-plausible parameter is a robustness/potential-DoS and
info-disclosure signal, not proof of a deeper exploit — reported as such.
"""
from __future__ import annotations

import re

import yaml

from engine.common.http_client import SafeClient
from engine.common.models import Confidence, Finding, FindingSource, HttpEvidence, Severity

_STACK_TRACE_MARKERS = re.compile(
    r"(at\s+[\w.$<>]+\s+\([^)]*\.(?:js|ts|mjs):\d+:\d+\)|node_modules[/\\][\w.@-]+)"
)

_TYPE_PLACEHOLDER = {"integer": 1, "number": 1.0, "boolean": True, "string": "wmsec-fuzz-probe"}
_TYPE_CONFUSION_VALUE = "wmsec-not-a-number"


def load_get_endpoints(spec_path: str) -> list[tuple[str, list[dict]]]:
    with open(spec_path, "r", encoding="utf-8") as f:
        spec = yaml.safe_load(f)
    endpoints = []
    for path, methods in (spec.get("paths") or {}).items():
        get_def = methods.get("get")
        if not get_def:
            continue
        endpoints.append((path, get_def.get("parameters", []) or []))
    return endpoints


def _sample_evenly(items: list, n: int) -> list:
    if n >= len(items):
        return items
    step = len(items) / n
    return [items[int(i * step)] for i in range(n)]


def _baseline_params(parameters: list[dict]) -> dict:
    params = {}
    for p in parameters:
        if p.get("in") != "query":
            continue
        name = p.get("name")
        if not name:
            continue
        if "example" in p:
            params[name] = p["example"]
        elif p.get("required"):
            schema_type = (p.get("schema") or {}).get("type", "string")
            params[name] = _TYPE_PLACEHOLDER.get(schema_type, "wmsec-fuzz-probe")
    return params


def _numeric_params(parameters: list[dict]) -> list[str]:
    return [
        p["name"] for p in parameters
        if p.get("in") == "query" and p.get("name")
        and (p.get("schema") or {}).get("type") in ("integer", "number")
    ]


def run(client: SafeClient, target_name: str, spec_path: str, max_endpoints: int = 25) -> list[Finding]:
    findings: list[Finding] = []
    try:
        endpoints = load_get_endpoints(spec_path)
    except (OSError, yaml.YAMLError) as exc:
        return [Finding(
            rule_id="APIFUZZ-000", title="Could not load OpenAPI spec for fuzzing",
            description=f"{spec_path}: {exc}", category="api-fuzzing",
            source=FindingSource.DAST, confidence=Confidence.TENTATIVE, target=target_name,
            severity=Severity.INFO, tags=["api-fuzzing", "skipped"],
        )]

    sample = _sample_evenly(endpoints, max_endpoints)

    for path, parameters in sample:
        baseline_params = _baseline_params(parameters)
        numeric_names = _numeric_params(parameters)

        for numeric_name in numeric_names:
            fuzz_params = dict(baseline_params)
            fuzz_params[numeric_name] = _TYPE_CONFUSION_VALUE
            resp = client.get(path, params=fuzz_params)
            if not resp.ok:
                continue
            if resp.status_code >= 500:
                trace_match = _STACK_TRACE_MARKERS.search(resp.text)
                findings.append(Finding(
                    rule_id="APIFUZZ-001",
                    title=f"Unhandled error (5xx) on malformed parameter: {path}?{numeric_name}=...",
                    description=(
                        f"GET {path} with `{numeric_name}={_TYPE_CONFUSION_VALUE}` (a non-numeric "
                        f"value in an integer/number parameter) returned HTTP {resp.status_code} "
                        f"instead of a 4xx validation error."
                        + (f" Response body contains a stack-trace marker: \"{trace_match.group(0)}\"."
                           if trace_match else "")
                    ),
                    category="api-fuzzing",
                    source=FindingSource.DAST,
                    confidence=Confidence.CONFIRMED if trace_match else Confidence.TENTATIVE,
                    target=target_name,
                    severity=Severity.MEDIUM,
                    http_evidence=[HttpEvidence(method="GET", url=resp.url, status_code=resp.status_code,
                                                 response_snippet=resp.text[:300])],
                    remediation="Validate query parameter types/ranges before use and return a 400/422 on mismatch instead of letting the handler throw.",
                    business_impact="An unhandled exception on attacker-influenced input is a robustness gap and potential low-cost DoS/info-disclosure vector across every affected endpoint.",
                    tags=["api-fuzzing", "type-confusion"],
                ))
            # one confirmed 5xx per endpoint is enough signal; move on
            break
    return findings
