"""Broken Object Level Authorization (BOLA/IDOR) probing.

Generic technique, not fixture-specific: log in as account A, create an
object it owns, log in as a *different* account B, then try to read A's
object by ID through B's session. If B succeeds, the endpoint isn't scoping
reads to the caller's own objects.

Needs a target with an object-ownership model to test at all — worldmonitor
(config: bola_tester disabled) has none in self-hosted mode; the fixture app
does (docker/fixture-app/app.py's GET /api/notes/<id>).
"""
from __future__ import annotations

from engine.common.config import AccountConfig
from engine.common.http_client import SafeClient
from engine.common.models import Confidence, Finding, FindingSource, HttpEvidence, Severity


def _login(client: SafeClient, login_path: str, account: AccountConfig, token_field: str) -> str | None:
    resp = client.post(login_path, json={"username": account.username, "password": account.password})
    if not resp.ok or resp.status_code != 200:
        return None
    try:
        return resp.json().get(token_field)
    except (ValueError, AttributeError):
        return None


def run(client: SafeClient, target_name: str, accounts: list[AccountConfig],
        login_path: str = "/api/login", create_path: str = "/api/notes",
        object_path_template: str = "/api/notes/{id}", token_field: str = "token",
        id_field: str = "id") -> list[Finding]:
    findings: list[Finding] = []
    if len(accounts) < 2:
        return findings

    owner, other = accounts[0], accounts[1]

    owner_token = _login(client, login_path, owner, token_field)
    if not owner_token:
        return findings

    create_resp = client.post(create_path, json={"title": "wmsec-bola-probe", "body": "probe object"},
                               headers={"Authorization": f"Bearer {owner_token}"})
    if not create_resp.ok or create_resp.status_code not in (200, 201):
        return findings
    try:
        object_id = create_resp.json().get(id_field)
    except (ValueError, AttributeError):
        return findings
    if object_id is None:
        return findings

    other_token = _login(client, login_path, other, token_field)
    if not other_token:
        return findings

    object_path = object_path_template.format(id=object_id)
    read_resp = client.get(object_path, headers={"Authorization": f"Bearer {other_token}"})
    if not read_resp.ok:
        return findings

    if read_resp.status_code == 200:
        findings.append(Finding(
            rule_id="BOLA-001",
            title=f"Broken object-level authorization: {object_path_template}",
            description=(
                f"Account '{owner.username}' ({owner.role}) created an object at "
                f"{create_path} (id={object_id}). Account '{other.username}' ({other.role}) — a "
                f"different user — was able to GET {object_path} and received HTTP 200 instead "
                f"of a 403/404."
            ),
            category="authz",
            source=FindingSource.DAST,
            confidence=Confidence.CONFIRMED,
            target=target_name,
            severity=Severity.HIGH,
            http_evidence=[
                HttpEvidence(method="POST", url=create_resp.url, role_used=owner.role,
                              status_code=create_resp.status_code, notes=f"created object id={object_id}"),
                HttpEvidence(method="GET", url=read_resp.url, role_used=other.role,
                              status_code=read_resp.status_code, response_snippet=read_resp.text[:300],
                              notes="cross-account read of another user's object"),
            ],
            remediation=f"Add an ownership check (e.g. `WHERE owner_id = current_user.id`) to the handler behind {object_path_template} before returning the object.",
            business_impact="Any authenticated user can read (and, if the same pattern applies to write/delete routes, modify or destroy) any other user's data by guessing or incrementing an ID.",
            tags=["authz", "bola", "idor", "cwe-639"],
        ))
    return findings
