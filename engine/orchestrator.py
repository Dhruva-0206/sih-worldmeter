"""Runs the full pipeline for one target: SAST -> DAST -> correlate -> score
-> generate PoCs. Module dispatch is driven entirely by ScanConfig — which
modules run and what paths/params they use come from the target's YAML
(config/*.yaml), not from hardcoded per-target branches in here, so wiring
up a new target is a config change, not a code change.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

from engine.common.config import ScanConfig
from engine.common.http_client import SafeClient
from engine.common.models import Finding
from engine.correlation.correlator import correlate
from engine.poc.poc_generator import generate_pocs
from engine.scoring.cvss_calculator import score_findings

from engine.sast import (
    access_control_checker, auth_pattern_checker, dependency_scanner,
    injection_pattern_checker, secrets_scanner,
)
from engine.dast import (
    api_fuzzer, auth_tester, bola_tester, cors_checker, info_disclosure,
    injection_tester, oauth_mcp_checker, privilege_escalation, rate_limit_tester,
    security_headers_checker, ssrf_prober,
)


def log(msg: str) -> None:
    print(f"[orchestrator] {msg}", file=sys.stderr)


def run_sast(config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    target = config.target
    modules = config.modules
    max_f = config.safety.max_findings_per_module

    if modules.sast_enabled("secrets_scanner"):
        log("SAST: secrets_scanner")
        findings += secrets_scanner.run(target.source_paths, target.name, max_findings=max_f)

    if modules.sast_enabled("auth_pattern_checker"):
        log("SAST: auth_pattern_checker")
        findings += auth_pattern_checker.run(target.source_paths, target.name, max_findings=max_f)

    if modules.sast_enabled("access_control_checker"):
        log("SAST: access_control_checker")
        findings += access_control_checker.run(target.source_paths, target.name, max_findings=max_f)

    if modules.sast_enabled("injection_pattern_checker"):
        log("SAST: injection_pattern_checker")
        findings += injection_pattern_checker.run(target.source_paths, target.name, max_findings=max_f)

    if modules.sast_enabled("dependency_scanner"):
        log("SAST: dependency_scanner")
        requirements_files = [p / "requirements.txt" for p in target.source_paths
                               if (p / "requirements.txt").exists()]
        findings += dependency_scanner.run(target.lockfile_roots, target.name,
                                            requirements_files=requirements_files, max_findings=max_f)

    for f in findings:
        f.target = target.name
    return findings


def _make_client(config: ScanConfig) -> SafeClient:
    return SafeClient(config.target.base_url, max_requests_per_second=config.safety.max_requests_per_second,
                       timeout_seconds=config.safety.request_timeout_seconds)


def run_dast(config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    target = config.target
    modules = config.modules
    p = target.dast_params

    if not target.base_url:
        log("DAST: no base_url configured, skipping")
        return findings

    client = _make_client(config)
    auth_profile = target.auth_profile

    if modules.dast_enabled("cors_checker"):
        log("DAST: cors_checker")
        findings += cors_checker.run(client, target.name)

    if modules.dast_enabled("security_headers_checker"):
        log("DAST: security_headers_checker")
        findings += security_headers_checker.run(client, target.name,
                                                   path=p.get("security_headers_path", "/"))

    if modules.dast_enabled("info_disclosure"):
        log("DAST: info_disclosure")
        findings += info_disclosure.run(
            client, target.name,
            error_probe_paths=p.get("info_disclosure_error_probe_paths", ["/api/health"]),
            include_worldmonitor_paths=(auth_profile == "anonymous_session"),
        )

    if modules.dast_enabled("rate_limit_tester"):
        log("DAST: rate_limit_tester")
        findings += rate_limit_tester.run(
            client, target.name,
            path=p.get("rate_limit_path", "/"),
            method=p.get("rate_limit_method", "GET"),
        )

    if modules.dast_enabled("ssrf_prober"):
        log("DAST: ssrf_prober")
        findings += ssrf_prober.run(
            client, target.name,
            proxy_path=p.get("ssrf_proxy_path", "/api/rss-proxy"),
            param_name=p.get("ssrf_param_name", "url"),
        )

    if modules.dast_enabled("oauth_mcp_checker"):
        log("DAST: oauth_mcp_checker")
        findings += oauth_mcp_checker.run(client, target.name)

    if modules.dast_enabled("api_fuzzer") and target.openapi_spec:
        log("DAST: api_fuzzer")
        findings += api_fuzzer.run(client, target.name, str(target.openapi_spec),
                                    max_endpoints=p.get("api_fuzz_max_endpoints", 25))

    if modules.dast_enabled("auth_tester"):
        log("DAST: auth_tester")
        if auth_profile == "anonymous_session":
            findings += auth_tester.run_anonymous_session(
                client, target.name,
                session_issue_path=p.get("session_issue_path", "/api/wm-session"),
                cookie_name=p.get("session_cookie_name", "wm-session"),
            )
        elif auth_profile == "role_based":
            findings += auth_tester.run_role_based(
                client, target.name, target.accounts,
                login_path=p.get("login_path", "/api/login"),
                logout_path=p.get("logout_path", "/api/logout"),
                register_path=p.get("register_path", "/api/register"),
                protected_path=p.get("whoami_path", "/api/whoami"),
                token_field=p.get("token_field", "token"),
            )

    if modules.dast_enabled("bola_tester") and target.accounts:
        log("DAST: bola_tester")
        findings += bola_tester.run(
            client, target.name, target.accounts,
            login_path=p.get("login_path", "/api/login"),
            create_path=p.get("notes_create_path", "/api/notes"),
            object_path_template=p.get("notes_object_path_template", "/api/notes/{id}"),
            token_field=p.get("token_field", "token"),
        )

    if modules.dast_enabled("privilege_escalation") and target.accounts:
        log("DAST: privilege_escalation")
        findings += privilege_escalation.run(
            client, target.name, target.accounts,
            login_path=p.get("login_path", "/api/login"),
            protected_path=p.get("admin_path", "/api/admin/users"),
            profile_update_path=p.get("profile_update_path", "/api/profile"),
            whoami_path=p.get("whoami_path", "/api/whoami"),
            token_field=p.get("token_field", "token"),
            target_role=p.get("target_role", "admin"),
        )

    if modules.dast_enabled("injection_tester"):
        log("DAST: injection_tester")
        findings += injection_tester.run(
            client, target.name,
            path=p.get("search_path", "/api/search"),
            param=p.get("search_param_name", "q"),
        )

    for f in findings:
        f.target = target.name
    return findings


def run_target(config: ScanConfig, sast_only: bool = False, dast_only: bool = False) -> list[Finding]:
    t0 = time.time()
    findings: list[Finding] = []

    if not dast_only:
        findings += run_sast(config)
    if not sast_only:
        findings += run_dast(config)

    log(f"correlating {len(findings)} findings")
    findings = correlate(findings)

    log("scoring (CVSS 3.1)")
    findings = score_findings(findings)

    log("generating PoCs")
    findings = generate_pocs(findings)

    log(f"target '{config.target.name}' done in {time.time() - t0:.1f}s — {len(findings)} findings")
    return findings


def run_multi(configs: list[ScanConfig], sast_only: bool = False, dast_only: bool = False) -> list[Finding]:
    all_findings: list[Finding] = []
    for config in configs:
        all_findings += run_target(config, sast_only=sast_only, dast_only=dast_only)
    return all_findings
