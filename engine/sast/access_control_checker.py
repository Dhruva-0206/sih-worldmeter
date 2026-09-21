"""Missing/broken authorization checks in route handlers.

Two complementary checks, because worldmonitor's `api/` tree mixes two
different access-control architectures:

  ACCESS-001  per-route heuristic — for the Vercel one-file-per-route
              convention (api/*.js/*.ts, mapped via code_parser). A route
              whose path/filename looks sensitive (admin, internal,
              webhook, billing, ...) is flagged if the file calls nothing
              that looks like an auth/session/entitlement check and has no
              inline Authorization/API-key header check.

  ACCESS-002  centralized-gate check — for files that dispatch multiple
              routes by string comparison inside one handler (e.g.
              src-tauri/sidecar/local-api-server.mjs's single
              `mode === 'docker'` gate covering every /api/local-* path).
              Flags a sensitive route-path literal that has no apparent
              mode/role gate *earlier in the same file*.

Both are heuristics (TENTATIVE confidence) — a static scanner can't prove a
route is unprotected, only that it found no recognizable protection. That's
exactly what the DAST correlator is for: info_disclosure.py's live probe of
the same route is what upgrades a TENTATIVE SAST lead to CONFIRMED.
"""
from __future__ import annotations

import re
from pathlib import Path

from engine.common.models import CodeLocation, Confidence, Finding, FindingSource, Severity
from engine.common.text_utils import is_comment_line
from engine.sast.code_parser import RouteHandler, parse_api_routes

SENSITIVE_PATH_KEYWORDS = [
    "admin", "internal", "delete", "invalidate", "purge", "mcp-grant",
    "user-api-key", "create-checkout", "customer-portal", "oauth",
    "notification-webhook", "cache-purge", "embed-key", "api-key",
    "webhook", "secret",
]

_AUTH_CALL_NAME_RE = re.compile(
    r"(?i)(session|entitlement|apikey|api_key|requirerole|checkrole|"
    r"verifysignature|verifywebhook|isadmin|requireadmin|authenticate|"
    r"authorize|validatesession|validaterequest|checkaccess|permission)"
)
_INLINE_AUTH_SIGNAL_RE = re.compile(
    r"(?i)(x-worldmonitor-key|worldmonitor_valid_keys|"
    r"headers\.get\(['\"]authorization['\"]\)|headers\.authorization|"
    r"bearer\s)"
)

_SENSITIVE_ROUTE_LITERAL_RE = re.compile(
    r"""['"](/api/(?:local-[\w-]+|admin(?:/[\w-]+)?|internal(?:/[\w-]+)?))['"]"""
)
_MODE_ROLE_GATE_RE = re.compile(
    r"(?i)(mode\s*===?\s*['\"]docker['\"]|LOCAL_API_MODE|"
    r"role\s*!==?\s*['\"]admin['\"]|requireAdmin|isAdmin\b|"
    r"LOCAL_API_TOKEN)"
)


def _route_is_sensitive(handler: RouteHandler) -> str | None:
    haystack = f"{handler.route_path} {handler.file_path}".lower()
    for kw in SENSITIVE_PATH_KEYWORDS:
        if kw in haystack:
            return kw
    return None


def _has_auth_signal(handler: RouteHandler) -> bool:
    if any(_AUTH_CALL_NAME_RE.search(name) for name in handler.called_names):
        return True
    return bool(_INLINE_AUTH_SIGNAL_RE.search(handler.source))


def check_per_route_heuristic(handlers: list[RouteHandler], target_name: str) -> list[Finding]:
    findings = []
    for h in handlers:
        if h.is_helper or h.parse_error:
            continue
        keyword = _route_is_sensitive(h)
        if keyword is None or _has_auth_signal(h):
            continue
        findings.append(Finding(
            rule_id="ACCESS-001",
            title=f"Sensitive-looking route with no detected authorization check: {h.route_path}",
            description=(
                f"{h.file_path} implements {h.route_path}, whose path matches the sensitivity "
                f"keyword \"{keyword}\". No call to a session/entitlement/API-key/role-check "
                f"function was found in the file, and no inline Authorization/API-key header "
                f"check was found either. This may be a false positive (the check could live in "
                f"shared middleware this scanner doesn't trace, or the route may genuinely be "
                f"public by design) — treat as a lead for manual/DAST confirmation, not a "
                f"confirmed finding on its own."
            ),
            category="authz",
            source=FindingSource.SAST,
            confidence=Confidence.TENTATIVE,
            target=target_name,
            severity=Severity.MEDIUM,
            code_location=CodeLocation(file_path=str(h.file_path), line_number=1,
                                        snippet=h.source.splitlines()[0] if h.source else None,
                                        function_name=None),
            remediation="Confirm whether this route should require authentication/authorization. If so, add an explicit check at the top of the handler before any side-effecting logic runs.",
            business_impact="An unauthenticated or unauthorized caller may be able to reach privileged functionality directly.",
            tags=["authz", "heuristic", h.route_path],
            extra={"route_path": h.route_path, "matched_keyword": keyword},
        ))
    return findings


_DISPATCHER_SUBDIRS = ("server", "src-tauri/sidecar", "convex")
_NON_DISPATCHER_MARKERS = (".test.", ".spec.")
_NON_DISPATCHER_DIRS = {"__tests__", "e2e", "tests", "node_modules", "dist", "src"}


def _looks_like_dispatcher_file(path: Path) -> bool:
    """Filter for "this file actually executes a route handler", as opposed
    to a file that merely mentions a route path as a string — frontend code
    calling fetch(), a test asserting on the path, or edge middleware making
    an unrelated (non-authz) routing decision like bot-gating. All three
    produced false positives during development on worldmonitor's real
    source (see module docstring): a frontend src/*.ts file has no business
    holding a server-side authz gate for a URL it merely calls, and
    middleware.ts's one match turned out to be bot-gating logic, not
    authorization — "does this file gate this path" was a category error
    there, not a real gap.
    """
    if any(marker in path.name for marker in _NON_DISPATCHER_MARKERS):
        return False
    if any(part in _NON_DISPATCHER_DIRS for part in path.parts):
        return False
    return True


def check_centralized_route_gates(source_paths: list[Path], target_name: str) -> list[Finding]:
    findings = []
    for root in source_paths:
        root = Path(root)
        if not root.exists():
            continue
        scan_roots = [root / d for d in _DISPATCHER_SUBDIRS if (root / d).exists()]
        candidate_files: list[Path] = []
        for scan_root in scan_roots:
            candidate_files.extend(
                p for p in scan_root.rglob("*")
                if p.is_file() and p.suffix.lower() in (".js", ".mjs", ".cjs", ".ts", ".mts")
            )

        for path in candidate_files:
            if not _looks_like_dispatcher_file(path):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue

            route_matches = list(_SENSITIVE_ROUTE_LITERAL_RE.finditer(text))
            if not route_matches:
                continue
            gate_matches = list(_MODE_ROLE_GATE_RE.finditer(text))
            lines = text.splitlines()

            earliest_gate_line = (
                min(text.count("\n", 0, g.start()) + 1 for g in gate_matches)
                if gate_matches else None
            )

            seen_routes: set[str] = set()
            for m in route_matches:
                route_literal = m.group(1)
                if route_literal in seen_routes:
                    continue
                seen_routes.add(route_literal)
                line_no = text.count("\n", 0, m.start()) + 1
                if line_no - 1 < len(lines) and is_comment_line(lines[line_no - 1]):
                    continue
                if earliest_gate_line is not None and earliest_gate_line <= line_no:
                    continue  # a mode/role gate precedes this route literal in the same file — looks guarded
                try:
                    rel = str(path.relative_to(root.parent))
                except ValueError:
                    rel = str(path)
                findings.append(Finding(
                    rule_id="ACCESS-002",
                    title=f"Sensitive route path with no preceding access gate in file: {route_literal}",
                    description=(
                        f"{rel}:{line_no} compares the request path against \"{route_literal}\" "
                        f"but this file has "
                        + ("no recognizable mode/role gate at all" if earliest_gate_line is None
                           else f"its earliest such gate at line {earliest_gate_line}, "
                                f"*after* this route check at line {line_no}")
                        + ". A route handled this way can execute before any centralized "
                          "protection in the file takes effect."
                    ),
                    category="authz",
                    source=FindingSource.SAST,
                    confidence=Confidence.TENTATIVE,
                    target=target_name,
                    severity=Severity.HIGH,
                    code_location=CodeLocation(file_path=rel, line_number=line_no,
                                                snippet=lines[line_no - 1].strip() if line_no - 1 < len(lines) else None),
                    remediation="Move the mode/role gate to before every sensitive route-path comparison in this file, or restructure so the gate can't be bypassed by handler ordering.",
                    business_impact="A misordered or missing centralized gate can expose every route it was meant to cover, not just one.",
                    tags=["authz", "centralized-gate", "heuristic"],
                    extra={"route_literal": route_literal},
                ))
    return findings


def run(source_paths: list[Path], target_name: str, max_findings: int = 200) -> list[Finding]:
    findings: list[Finding] = []
    for root in source_paths:
        root = Path(root)
        handlers = parse_api_routes(root)
        findings.extend(check_per_route_heuristic(handlers, target_name))
    findings.extend(check_centralized_route_gates(source_paths, target_name))
    return findings[:max_findings]
