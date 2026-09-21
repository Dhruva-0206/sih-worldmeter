"""Assembles the final structured report: JSON (raw), HTML, and PDF.

Findings are expected to already be correlated/scored/PoC'd (i.e. have gone
through engine.orchestrator.run_target) before reaching this module — it's
purely presentation, no detection or scoring logic lives here.
"""
from __future__ import annotations

import io
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from xhtml2pdf import pisa

from engine.common.models import Finding, Severity, findings_to_json

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

_TARGET_LABELS = {
    "worldmonitor": "Primary Target — worldmonitor (real production codebase)",
    "fixture-app": "Fixture Target — RBAC/BOLA/injection capability demonstration",
}
_TARGET_DESCRIPTIONS = {
    "worldmonitor": (
        "Self-hosted instance of github.com/koala73/worldmonitor. Findings here are real, from the "
        "actual production codebase and its live self-hosted deployment."
    ),
    "fixture-app": (
        "Small, deliberately-vulnerable app the framework ships with (docker/fixture-app), used to "
        "demonstrate BOLA/IDOR, privilege-escalation, and injection detection end-to-end — worldmonitor's "
        "self-hosted mode has no role-based/object-ownership model to exercise those modules against."
    ),
}

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _severity_counts(findings: list[Finding]) -> OrderedDict:
    counts = OrderedDict((s.value, 0) for s in _SEVERITY_ORDER)
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return OrderedDict((k, v) for k, v in counts.items() if v > 0) or counts


def _sort_key(f: Finding):
    sev_rank = _SEVERITY_ORDER.index(f.severity) if f.severity in _SEVERITY_ORDER else len(_SEVERITY_ORDER)
    return (sev_rank, -(f.cvss_score or 0))


def build_report_context(findings: list[Finding], report_title: str = "World Monitor Security Assessment") -> dict:
    targets = sorted({f.target for f in findings})
    findings_by_target = {t: sorted([f for f in findings if f.target == t], key=_sort_key) for t in targets}
    per_target_severity_counts = {t: _severity_counts(findings_by_target[t]) for t in targets}

    confirmed_count = sum(1 for f in findings if f.status == "confirmed")
    unconfirmed_count = len(findings) - confirmed_count

    return dict(
        report_title=report_title,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        targets=targets,
        findings=findings,
        findings_by_target=findings_by_target,
        severity_counts=_severity_counts(findings),
        per_target_severity_counts=per_target_severity_counts,
        confirmed_count=confirmed_count,
        unconfirmed_count=unconfirmed_count,
        target_labels=_TARGET_LABELS,
        target_descriptions=_TARGET_DESCRIPTIONS,
        executive_summary_note=(
            "\"Confirmed\" findings were independently corroborated by at least two of: live dynamic "
            "observation, static source analysis, and cross-correlation between the two. "
            "\"Unconfirmed\" findings are single-signal leads (a static pattern match or a single dynamic "
            "probe) included for completeness and flagged for manual review rather than treated as proven."
        ),
    )


def render_html(findings: list[Finding], report_title: str = "World Monitor Security Assessment") -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template("report.html.j2")
    return template.render(**build_report_context(findings, report_title))


def render_pdf(html: str) -> bytes:
    buf = io.BytesIO()
    result = pisa.CreatePDF(io.StringIO(html), dest=buf)
    if result.err:
        raise RuntimeError(f"PDF generation failed with {result.err} error(s)")
    return buf.getvalue()


def generate_report(findings: list[Finding], out_dir: Path, report_title: str = "World Monitor Security Assessment",
                     base_filename: str = "security_assessment_report") -> dict[str, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / f"{base_filename}.json"
    html_path = out_dir / f"{base_filename}.html"
    pdf_path = out_dir / f"{base_filename}.pdf"

    json_path.write_text(findings_to_json(findings), encoding="utf-8")

    html = render_html(findings, report_title)
    html_path.write_text(html, encoding="utf-8")

    try:
        pdf_bytes = render_pdf(html)
        pdf_path.write_bytes(pdf_bytes)
    except Exception as exc:  # PDF rendering is a nice-to-have; HTML/JSON must never be blocked by it
        print(f"[report_generator] PDF generation failed, HTML/JSON still written: {exc}")
        pdf_path = None

    return {"json": json_path, "html": html_path, "pdf": pdf_path}
