"""Shared data model for the assessment pipeline.

Every module (SAST detector, DAST tester, correlator, scorer, PoC generator,
report generator) reads and writes `Finding` objects. Keeping one shape here
means the orchestrator can pass findings between stages without per-module
adapters.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __str__(self) -> str:
        # A plain `class X(str, Enum)` mixin still uses Enum.__str__ (giving
        # "Severity.CRITICAL") on this Python version rather than the str
        # value — caught because it silently broke CSS class matching
        # (`sev-{{ finding.severity }}` rendered as `sev-Severity.CRITICAL`,
        # matching no rule) and printed ugly reprs everywhere else this
        # enum gets interpolated. Overriding __str__ fixes every call site
        # at once instead of hunting down each `.value` omission.
        return self.value

    @classmethod
    def from_cvss_score(cls, score: float) -> "Severity":
        # CVSS 3.1 qualitative severity rating scale (first.org).
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


class Confidence(str, Enum):
    CONFIRMED = "confirmed"   # DAST reproduced it live, or SAST+DAST correlated
    FIRM = "firm"             # single strong signal (SAST pattern match or DAST probe)
    TENTATIVE = "tentative"   # heuristic / entropy-based / low-signal match

    def __str__(self) -> str:
        return self.value


class FindingSource(str, Enum):
    SAST = "sast"
    DAST = "dast"
    CORRELATED = "correlated"

    def __str__(self) -> str:
        return self.value


@dataclass
class CodeLocation:
    file_path: str
    line_number: Optional[int] = None
    end_line: Optional[int] = None
    snippet: Optional[str] = None
    function_name: Optional[str] = None


@dataclass
class HttpEvidence:
    method: str
    url: str
    role_used: Optional[str] = None
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    status_code: Optional[int] = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_snippet: Optional[str] = None
    notes: Optional[str] = None


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    category: str                     # e.g. "secrets", "authz", "cors", "ssrf", "injection"
    source: FindingSource
    confidence: Confidence
    target: str                       # target name from config, e.g. "worldmonitor" / "fixture-app"
    severity: Severity = Severity.INFO
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    code_location: Optional[CodeLocation] = None
    http_evidence: list[HttpEvidence] = field(default_factory=list)
    remediation: Optional[str] = None
    business_impact: Optional[str] = None
    poc: Optional[str] = None
    poc_language: Optional[str] = None
    correlated_with: list[str] = field(default_factory=list)  # other finding ids
    status: str = "unconfirmed"       # "confirmed" | "unconfirmed" (set by correlator)
    tags: list[str] = field(default_factory=list)
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    extra: dict[str, Any] = field(default_factory=dict)
    id: str = field(default="")

    def __post_init__(self):
        if not self.id:
            self.id = self._compute_id()

    def _compute_id(self) -> str:
        loc = ""
        if self.code_location:
            loc = f"{self.code_location.file_path}:{self.code_location.line_number}"
        elif self.http_evidence:
            loc = f"{self.http_evidence[0].method}:{self.http_evidence[0].url}"
        basis = f"{self.target}|{self.rule_id}|{loc}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["source"] = self.source.value
        d["confidence"] = self.confidence.value
        d["severity"] = self.severity.value
        return d


class FindingEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Enum):
            return o.value
        if hasattr(o, "to_dict"):
            return o.to_dict()
        return super().default(o)


def findings_to_json(findings: list[Finding], **kwargs) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2, default=str, **kwargs)
