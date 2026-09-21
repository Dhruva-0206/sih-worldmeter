"""Outdated/vulnerable dependency scanning across every lockfile root in the
monorepo, via `npm audit --json` (Node deps) and `pip-audit` (Python deps).

Both tools need network access (npm registry / OSV.dev advisory data) to
produce a report. If that's unavailable the scanner emits one INFO-level
"scan skipped" finding per root explaining why, rather than failing the
whole pipeline — a dependency scan being unreachable shouldn't take down
the SAST+DAST run alongside it.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from engine.common.models import CodeLocation, Confidence, Finding, FindingSource, Severity

_NPM_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _run(cmd: list[str], cwd: Path, timeout: int = 180) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                               timeout=timeout, shell=False)
        return proc.returncode, proc.stdout, proc.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return -1, "", str(exc)


def _skip_finding(target_name: str, location: str, reason: str) -> Finding:
    return Finding(
        rule_id="DEP-000",
        title=f"Dependency scan skipped for {location}",
        description=reason,
        category="dependency",
        source=FindingSource.SAST,
        confidence=Confidence.TENTATIVE,
        target=target_name,
        severity=Severity.INFO,
        code_location=CodeLocation(file_path=location, line_number=None),
        tags=["dependency", "scan-skipped"],
    )


def _npm_audit_root(root: Path, target_name: str) -> list[Finding]:
    findings: list[Finding] = []
    lockfile = root / "package-lock.json"
    if not lockfile.exists():
        return findings

    # shutil.which resolves the .cmd wrapper on Windows; passing a bare "npm"
    # to subprocess.run(shell=False) fails to find it there (a well-known
    # Windows subprocess gotcha — CreateProcess doesn't do PATHEXT lookup the
    # way cmd.exe does for an extensionless name).
    npm_path = shutil.which("npm")
    if npm_path is None:
        findings.append(_skip_finding(target_name, str(root), "npm is not installed on the scanning host"))
        return findings

    code, out, err = _run([npm_path, "audit", "--json"], cwd=root)
    if not out.strip():
        findings.append(_skip_finding(
            target_name, str(root),
            f"npm audit produced no output (exit {code}): {err[:300] or 'no stderr'}"
        ))
        return findings

    try:
        report = json.loads(out)
    except json.JSONDecodeError:
        findings.append(_skip_finding(target_name, str(root),
                                       "npm audit output was not valid JSON (likely a registry/network error)"))
        return findings

    vulnerabilities = report.get("vulnerabilities", {})
    for pkg_name, info in vulnerabilities.items():
        severity = info.get("severity", "info")
        via = info.get("via", [])
        advisory_titles, advisory_urls = [], []
        for v in via:
            if isinstance(v, dict):
                if v.get("title"):
                    advisory_titles.append(v["title"])
                if v.get("url"):
                    advisory_urls.append(v["url"])
        title = advisory_titles[0] if advisory_titles else f"Vulnerable dependency: {pkg_name}"
        findings.append(Finding(
            rule_id="DEP-001",
            title=f"{pkg_name}: {title}",
            description=(
                f"npm audit reports a {severity}-severity issue in `{pkg_name}` "
                f"(lockfile: {lockfile}). " + (f"Advisory: {advisory_urls[0]}" if advisory_urls else "")
            ),
            category="dependency",
            source=FindingSource.SAST,
            confidence=Confidence.FIRM,
            target=target_name,
            severity=_NPM_SEVERITY_MAP.get(severity, Severity.MEDIUM),
            code_location=CodeLocation(file_path=str(lockfile), line_number=None),
            remediation=f"Run `npm audit fix` in {root}, or manually update `{pkg_name}` to a patched version.",
            business_impact="Severity-dependent — ranges from denial-of-service to remote code execution in the affected package's own code path.",
            tags=["dependency", "npm-audit", pkg_name],
            extra={"package": pkg_name, "npm_severity": severity, "advisory_urls": advisory_urls,
                   "lockfile_root": str(root)},
        ))
    return findings


def _pip_audit_requirements(req_file: Path, target_name: str) -> list[Finding]:
    findings: list[Finding] = []
    if not req_file.exists():
        return findings

    # Invoke pip-audit as a module of *this process's* interpreter (the
    # framework's own venv, where we installed it) rather than trusting a
    # bare "pip-audit" to be on PATH. req_file must be resolved to absolute
    # first — cwd is set to its parent, so a relative path would otherwise
    # be interpreted against that new cwd (self-referential, always 404s).
    code, out, err = _run([sys.executable, "-m", "pip_audit", "-r", str(req_file.resolve()), "--format", "json"],
                           cwd=req_file.parent)
    if not out.strip():
        findings.append(_skip_finding(
            target_name, str(req_file),
            f"pip-audit produced no output (exit {code}): {err[:300] or 'no stderr'}"
        ))
        return findings

    try:
        report = json.loads(out)
    except json.JSONDecodeError:
        findings.append(_skip_finding(target_name, str(req_file), "pip-audit output was not valid JSON"))
        return findings

    deps = report if isinstance(report, list) else report.get("dependencies", [])
    for dep in deps:
        name = dep.get("name")
        version = dep.get("version")
        for vuln in dep.get("vulns", []):
            vid = vuln.get("id", "unknown")
            fix_versions = vuln.get("fix_versions", [])
            findings.append(Finding(
                rule_id="DEP-002",
                title=f"{name}=={version}: {vid}",
                description=vuln.get("description") or f"{vid} affects {name} {version}.",
                category="dependency",
                source=FindingSource.SAST,
                confidence=Confidence.FIRM,
                target=target_name,
                severity=Severity.HIGH,  # pip-audit doesn't return a severity rating; default conservatively
                code_location=CodeLocation(file_path=str(req_file), line_number=None),
                remediation=(f"Upgrade {name} to {', '.join(fix_versions)}." if fix_versions
                             else f"No fixed version published yet for {vid} — track upstream."),
                business_impact="Severity-dependent on the specific CVE/GHSA advisory.",
                tags=["dependency", "pip-audit", name],
                extra={"package": name, "installed_version": version, "vuln_id": vid,
                       "fix_versions": fix_versions},
            ))
    return findings


def run(lockfile_roots: list[Path], target_name: str, requirements_files: list[Path] | None = None,
        max_findings: int = 200) -> list[Finding]:
    findings: list[Finding] = []
    for root in lockfile_roots:
        findings.extend(_npm_audit_root(Path(root), target_name))
        if len(findings) >= max_findings:
            return findings[:max_findings]
    for req in (requirements_files or []):
        findings.extend(_pip_audit_requirements(Path(req), target_name))
        if len(findings) >= max_findings:
            return findings[:max_findings]
    return findings[:max_findings]
