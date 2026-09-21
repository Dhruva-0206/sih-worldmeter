"""Session/auth handling tests: token unpredictability, weak password
policy, and missing session invalidation on logout.

Scoped per auth_profile because the two targets' auth surfaces are genuinely
different shapes, not just different endpoints:

  anonymous_session (worldmonitor): there's no login/logout, no password,
  and per SELF_HOSTING.md only one route even treats the session as an
  authentication boundary — and that route returns the same shared,
  non-premium content regardless of whether the session validates. So the
  one externally-observable, safe-to-test property is whether issued
  session tokens are unpredictable (AUTH-T-001) — a tampered-token
  behavioral-difference test isn't meaningful here since there's no
  documented access difference to observe from outside.

  role_based (fixture-app, or any target configured this way): full
  surface — weak password policy on registration, and whether a token
  keeps working after the user "logs out".
"""
from __future__ import annotations

from engine.common.config import AccountConfig
from engine.common.http_client import SafeClient
from engine.common.models import Confidence, Finding, FindingSource, HttpEvidence, Severity


def _test_anonymous_session_unpredictability(client: SafeClient, target_name: str,
                                              session_issue_path: str, cookie_name: str) -> list[Finding]:
    findings = []
    tokens = []
    for _ in range(3):
        # Clear the jar first: SafeClient's underlying requests.Session persists
        # cookies like a real browser tab, so without this, call #2 would send
        # call #1's cookie back and we'd be testing session *renewal* behavior,
        # not independent-issuance uniqueness.
        client._session.cookies.clear()
        resp = client.post(session_issue_path)
        if not resp.ok:
            continue
        # Prefer the cookie jar (matches how a real browser would carry the
        # token), but worldmonitor's /api/wm-session also returns the token
        # directly in the JSON body — the cookie jar came back empty in
        # practice against a bare "localhost" host (a known Python
        # http.cookiejar edge case with dot-less domains), so fall back to
        # the body rather than falsely concluding no token was issued.
        token = resp.cookies.get(cookie_name)
        if not token:
            try:
                token = resp.json().get("token")
            except (ValueError, AttributeError):
                token = None
        if token:
            tokens.append(token)

    if len(tokens) < 2:
        return findings  # couldn't observe enough tokens to say anything

    if len(set(tokens)) < len(tokens):
        findings.append(Finding(
            rule_id="AUTH-T-001",
            title=f"Repeated session token issued by {session_issue_path}",
            description=f"Two of {len(tokens)} session-issuance calls to {session_issue_path} returned the identical token.",
            category="session-management",
            source=FindingSource.DAST,
            confidence=Confidence.CONFIRMED,
            target=target_name,
            severity=Severity.HIGH,
            http_evidence=[HttpEvidence(method="POST", url=session_issue_path, notes=f"{len(tokens)} tokens observed, {len(set(tokens))} unique")],
            remediation="Ensure every issued session includes a fresh, cryptographically random nonce.",
            business_impact="Predictable or reused session tokens make session fixation/prediction attacks viable.",
            tags=["session-management", "predictability"],
        ))
    else:
        findings.append(Finding(
            rule_id="AUTH-T-000",
            title=f"Session tokens from {session_issue_path} are unique across repeated issuance",
            description=f"{len(tokens)} calls to {session_issue_path} each returned a distinct token — no repetition observed.",
            category="session-management",
            source=FindingSource.DAST,
            confidence=Confidence.CONFIRMED,
            target=target_name,
            severity=Severity.INFO,
            tags=["session-management", "verified-control"],
        ))
    return findings


def _test_weak_password_policy(client: SafeClient, target_name: str, register_path: str) -> list[Finding]:
    findings = []
    trivial_password = "a"
    username = f"wmsec_probe_{id(client) % 100000}"
    resp = client.post(register_path, json={"username": username, "password": trivial_password})
    if not resp.ok:
        return findings
    if resp.status_code in (200, 201):
        findings.append(Finding(
            rule_id="AUTH-T-002",
            title=f"No password policy enforced on {register_path}",
            description=(
                f"POST {register_path} with a 1-character password (\"{trivial_password}\") "
                f"succeeded (HTTP {resp.status_code}) instead of being rejected."
            ),
            category="authn",
            source=FindingSource.DAST,
            confidence=Confidence.CONFIRMED,
            target=target_name,
            severity=Severity.MEDIUM,
            http_evidence=[HttpEvidence(method="POST", url=resp.url,
                                         request_body=f'{{"username":"{username}","password":"***"}}',
                                         status_code=resp.status_code)],
            remediation="Enforce a minimum length/complexity policy on registration and password-change endpoints.",
            business_impact="Trivial passwords are the first thing credential-stuffing and brute-force tooling tries.",
            tags=["authn", "weak-password-policy"],
        ))
    return findings


def _test_logout_invalidation(client: SafeClient, target_name: str, account: AccountConfig,
                               login_path: str, logout_path: str, protected_path: str,
                               token_field: str = "token") -> list[Finding]:
    findings = []
    login_resp = client.post(login_path, json={"username": account.username, "password": account.password})
    if not login_resp.ok or login_resp.status_code != 200:
        return findings
    try:
        token = login_resp.json().get(token_field)
    except ValueError:
        return findings
    if not token:
        return findings

    auth_header = {"Authorization": f"Bearer {token}"}
    pre_logout = client.get(protected_path, headers=auth_header)

    logout_resp = client.post(logout_path, headers=auth_header)
    if not logout_resp.ok:
        return findings

    post_logout = client.get(protected_path, headers=auth_header)

    if pre_logout.status_code == 200 and post_logout.status_code == 200:
        findings.append(Finding(
            rule_id="AUTH-T-003",
            title=f"Token remains valid after logout: {logout_path}",
            description=(
                f"After POST {logout_path}, the same bearer token used to log in still "
                f"authenticated a request to {protected_path} (HTTP {post_logout.status_code})."
            ),
            category="session-management",
            source=FindingSource.DAST,
            confidence=Confidence.CONFIRMED,
            target=target_name,
            severity=Severity.MEDIUM,
            http_evidence=[
                HttpEvidence(method="POST", url=login_resp.url, role_used=account.role, status_code=login_resp.status_code, notes="login"),
                HttpEvidence(method="POST", url=logout_resp.url, role_used=account.role, status_code=logout_resp.status_code, notes="logout"),
                HttpEvidence(method="GET", url=post_logout.url, role_used=account.role, status_code=post_logout.status_code, notes="reused token after logout"),
            ],
            remediation="Maintain a server-side revocation list (or use short-lived tokens plus refresh) so a token stops working immediately after logout.",
            business_impact="A stolen or shared token remains usable indefinitely across 'logout' events, undermining any incident response that assumes logout ends a session.",
            tags=["session-management", "logout", "cwe-613"],
        ))
    return findings


def run_anonymous_session(client: SafeClient, target_name: str, session_issue_path: str = "/api/wm-session",
                           cookie_name: str = "wm-session") -> list[Finding]:
    return _test_anonymous_session_unpredictability(client, target_name, session_issue_path, cookie_name)


def run_role_based(client: SafeClient, target_name: str, accounts: list[AccountConfig],
                    login_path: str = "/api/login", logout_path: str = "/api/logout",
                    register_path: str = "/api/register", protected_path: str = "/api/whoami",
                    token_field: str = "token") -> list[Finding]:
    findings = _test_weak_password_policy(client, target_name, register_path)
    if accounts:
        findings += _test_logout_invalidation(client, target_name, accounts[0], login_path, logout_path,
                                               protected_path, token_field=token_field)
    return findings
