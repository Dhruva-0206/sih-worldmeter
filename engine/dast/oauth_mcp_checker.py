"""OAuth/MCP grant-flow checks.

Two targeted probes, grounded against the live self-hosted instance before
writing thresholds (see comments):

  MCP-001  MCP tool *invocation* (`tools/call`) must require a valid
           X-WorldMonitor-Key. `tools/list` (pure discovery/metadata) is
           expected to work unauthenticated by this project's own design —
           tested empirically: it does, and *actually calling* a tool
           correctly 401s without a key. Only flag if invocation itself
           turns out to be reachable without auth.

  OAUTH-001  OAuth protected-resource metadata (RFC 9728) must not reflect
             a spoofed Host header into `resource`/`authorization_servers`
             — doing so would let an attacker get the server to vouch for
             an arbitrary origin as a valid OAuth resource identifier.
"""
from __future__ import annotations

from engine.common.http_client import SafeClient
from engine.common.models import Confidence, Finding, FindingSource, HttpEvidence, Severity


def check_mcp_tool_call_requires_auth(client: SafeClient, target_name: str,
                                       mcp_path: str = "/api/mcp",
                                       tool_name: str = "get_earthquakes") -> list[Finding]:
    findings = []
    resp = client.post(mcp_path, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": tool_name, "arguments": {}},
    }, headers={"Accept": "application/json, text/event-stream"})
    if not resp.ok:
        return findings
    if resp.status_code == 200:
        findings.append(Finding(
            rule_id="MCP-001",
            title=f"MCP tool invocation succeeded without authentication: {mcp_path}",
            description=(
                f"POST {mcp_path} with method=tools/call and no X-WorldMonitor-Key header "
                f"returned HTTP 200 instead of 401. Tool discovery (tools/list) is expected to "
                f"be unauthenticated by design; actual tool invocation is not."
            ),
            category="authn",
            source=FindingSource.DAST,
            confidence=Confidence.CONFIRMED,
            target=target_name,
            severity=Severity.HIGH,
            http_evidence=[HttpEvidence(method="POST", url=resp.url, status_code=resp.status_code,
                                         response_snippet=resp.text[:300])],
            remediation="Require and validate X-WorldMonitor-Key (or an OAuth bearer token) before dispatching tools/call.",
            business_impact="Unauthenticated callers could invoke tools/consume resources intended to be gated behind an API key.",
            tags=["authn", "mcp"],
        ))
    return findings


def check_oauth_metadata_host_spoofing(client: SafeClient, target_name: str,
                                        metadata_path: str = "/api/oauth-protected-resource",
                                        spoofed_host: str = "evil-attacker.example") -> list[Finding]:
    findings = []
    resp = client.get(metadata_path, headers={"Host": spoofed_host})
    if not resp.ok or resp.status_code != 200:
        return findings
    try:
        body = resp.json()
    except (ValueError, AttributeError):
        return findings

    resource = str(body.get("resource", ""))
    auth_servers = body.get("authorization_servers", [])
    if spoofed_host in resource or any(spoofed_host in str(a) for a in auth_servers):
        findings.append(Finding(
            rule_id="OAUTH-001",
            title=f"OAuth protected-resource metadata reflects spoofed Host: {metadata_path}",
            description=(
                f"Sending Host: {spoofed_host} to {metadata_path} produced a `resource`/"
                f"`authorization_servers` value containing that attacker-controlled host: "
                f"resource={resource!r}, authorization_servers={auth_servers!r}."
            ),
            category="authn",
            source=FindingSource.DAST,
            confidence=Confidence.CONFIRMED,
            target=target_name,
            severity=Severity.MEDIUM,
            http_evidence=[HttpEvidence(method="GET", url=resp.url, status_code=resp.status_code,
                                         request_headers={"Host": spoofed_host},
                                         response_snippet=resp.text[:300])],
            remediation="Derive the resource/authorization_servers origin from a fixed allowlist, never directly from the request Host header.",
            business_impact="A spoofed Host could get the server to publish OAuth metadata vouching for an attacker's origin, useful in phishing/relying-party-confusion attacks against OAuth clients.",
            tags=["authn", "oauth", "host-spoofing"],
        ))
    else:
        findings.append(Finding(
            rule_id="OAUTH-000",
            title=f"OAuth metadata origin resists Host-header spoofing: {metadata_path}",
            description=(
                f"Sending Host: {spoofed_host} to {metadata_path} did not change the returned "
                f"resource/authorization_servers origin (still {resource!r})."
            ),
            category="authn",
            source=FindingSource.DAST,
            confidence=Confidence.CONFIRMED,
            target=target_name,
            severity=Severity.INFO,
            tags=["authn", "oauth", "verified-control"],
        ))
    return findings


def run(client: SafeClient, target_name: str) -> list[Finding]:
    return (
        check_mcp_tool_call_requires_auth(client, target_name)
        + check_oauth_metadata_host_spoofing(client, target_name)
    )
