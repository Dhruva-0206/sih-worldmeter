"""Config loading + safety-gate for target definitions.

Every target (worldmonitor, fixture-app, or any future target) is described by
one YAML file under config/. The safety gate here is load-bearing: DAST modules
must never be able to fire a probe at a host that isn't explicitly allow-listed
as local/docker-network, no matter what a config file says the base_url is.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import yaml

# Hosts a DAST probe is ever allowed to touch. This list is intentionally not
# configurable from scan_config.yaml — widening it requires editing source,
# which is the point: a malformed or malicious config can't silently redirect
# traffic at a real host.
_ALLOWED_HOST_PATTERNS = [
    re.compile(r"^localhost$"),
    re.compile(r"^127\.0\.0\.1$"),
    re.compile(r"^0\.0\.0\.0$"),
    re.compile(r"^\[::1\]$"),
    re.compile(r"^::1$"),
    # Docker Compose service names / internal docker networks only.
    re.compile(r"^[a-zA-Z0-9_-]+$"),  # bare service name, e.g. "worldmonitor", "fixture-app"
    re.compile(r"^host\.docker\.internal$"),
    re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),  # any literal IPv4 — see note below
]

_PRIVATE_IPV4_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                           "172.2", "172.30.", "172.31.", "192.168.", "127.")


class UnsafeTargetError(ValueError):
    """Raised when a config's base_url resolves to a host outside the local/docker allow-list."""


@dataclass
class AccountConfig:
    role: str
    username: str
    password: str
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class TargetConfig:
    name: str
    description: str
    auth_profile: str  # "none" | "anonymous_session" | "role_based"
    source_paths: list[Path] = field(default_factory=list)
    base_url: Optional[str] = None
    openapi_spec: Optional[Path] = None
    lockfile_roots: list[Path] = field(default_factory=list)
    accounts: list[AccountConfig] = field(default_factory=list)
    # Target-specific paths/params each DAST module needs (endpoint names,
    # field names) — kept in config rather than hardcoded in orchestrator.py
    # so a new target is wired up by editing YAML, not Python.
    dast_params: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModuleToggles:
    sast: dict[str, bool] = field(default_factory=dict)
    dast: dict[str, bool] = field(default_factory=dict)

    def sast_enabled(self, name: str) -> bool:
        return self.sast.get(name, False)

    def dast_enabled(self, name: str) -> bool:
        return self.dast.get(name, False)


@dataclass
class SafetyConfig:
    max_requests_per_second: float = 5.0
    request_timeout_seconds: float = 8.0
    max_findings_per_module: int = 200


@dataclass
class ScanConfig:
    target: TargetConfig
    modules: ModuleToggles
    safety: SafetyConfig
    config_path: Path


def _validate_base_url(base_url: str, config_path: Path) -> None:
    """Refuse to load a config whose base_url isn't local/docker-scoped.

    This is the guardrail that stops the framework from ever being pointed at
    a live/production host, including https://www.worldmonitor.app itself,
    even by accident (typo'd config) or a malicious config file.
    """
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeTargetError(
            f"{config_path}: base_url '{base_url}' has unsupported scheme '{parsed.scheme}'"
        )
    host = parsed.hostname or ""
    if not host:
        raise UnsafeTargetError(f"{config_path}: base_url '{base_url}' has no resolvable host")

    if any(p.match(host) for p in _ALLOWED_HOST_PATTERNS):
        # Bare-hostname pattern matches almost anything alnum, including real
        # domains like "worldmonitor.app" — so IPv4-shaped hosts are checked
        # for RFC1918/loopback ranges, and anything containing a dot that
        # ISN'T a private IP is rejected below.
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            if not host.startswith(_PRIVATE_IPV4_PREFIXES):
                raise UnsafeTargetError(
                    f"{config_path}: base_url host '{host}' is a public IP literal — "
                    "DAST targets must be localhost, a private/RFC1918 address, or a "
                    "bare docker-compose service name."
                )
            return
        if "." in host:
            raise UnsafeTargetError(
                f"{config_path}: base_url host '{host}' looks like a real domain, not a "
                "local/docker target. Refusing to scan — never point this tool at a live host."
            )
        return

    raise UnsafeTargetError(
        f"{config_path}: base_url host '{host}' is not in the local/docker allow-list."
    )


def load_scan_config(path: str | Path) -> ScanConfig:
    config_path = Path(path).resolve()
    with open(config_path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    base_dir = config_path.parent
    t = raw["target"]

    base_url = t.get("base_url")
    if base_url:
        _validate_base_url(base_url, config_path)

    source_paths = [
        (base_dir / p).resolve() for p in t.get("source_paths", [])
    ]
    lockfile_roots = [
        (base_dir / p).resolve() for p in t.get("lockfile_roots", [])
    ]
    openapi_spec = t.get("openapi_spec")
    if openapi_spec:
        openapi_spec = (base_dir / openapi_spec).resolve()

    accounts = [
        AccountConfig(role=a["role"], username=a["username"], password=a["password"],
                       extra={k: v for k, v in a.items() if k not in ("role", "username", "password")})
        for a in t.get("accounts", [])
    ]

    target = TargetConfig(
        name=t["name"],
        description=t.get("description", ""),
        auth_profile=t.get("auth_profile", "none"),
        source_paths=source_paths,
        base_url=base_url,
        openapi_spec=openapi_spec,
        lockfile_roots=lockfile_roots,
        accounts=accounts,
        dast_params=t.get("dast_params", {}),
    )

    modules_raw = raw.get("modules", {})
    modules = ModuleToggles(
        sast=modules_raw.get("sast", {}),
        dast=modules_raw.get("dast", {}),
    )

    safety_raw = raw.get("safety", {})
    safety = SafetyConfig(
        max_requests_per_second=safety_raw.get("max_requests_per_second", 5.0),
        request_timeout_seconds=safety_raw.get("request_timeout_seconds", 8.0),
        max_findings_per_module=safety_raw.get("max_findings_per_module", 200),
    )

    return ScanConfig(target=target, modules=modules, safety=safety, config_path=config_path)
