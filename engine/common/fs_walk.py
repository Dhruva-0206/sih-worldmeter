"""Shared source-tree walker for SAST modules.

worldmonitor is a large monorepo with generated/vendored content mixed in
(node_modules, dist, public/pro build output, localized asset bundles, lock
files). Every SAST scanner needs the same excludes, so they live here once
instead of drifting across secrets_scanner / auth_pattern_checker /
access_control_checker.
"""
from __future__ import annotations

from pathlib import Path

EXCLUDED_DIR_NAMES = {
    "node_modules", ".git", "dist", "build", ".next", ".turbo", ".venv",
    "venv", "__pycache__", "coverage", ".astro", "target", ".cache",
    ".vercel", ".output", "out", ".pytest_cache", "playwright-report",
    "test-results", ".husky",
}

# public/ holds built frontend assets (worldmonitor's Vite output + copied
# /pro bundle) — real source lives in src/, api/, server/, scripts/, convex/.
# public/**/*.md (docs-as-markdown mirrors) and public/data/* fixtures are
# noise for a source-code scanner, so public/ is excluded wholesale; nothing
# security-relevant lives only there.
EXCLUDED_TOP_LEVEL_DIR_NAMES = {"public"}

EXCLUDED_FILE_SUFFIXES = {
    ".min.js", ".map", ".lock", ".png", ".jpg", ".jpeg", ".webp", ".ico",
    ".svg", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz",
}

EXCLUDED_FILE_NAMES = {
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
}

SCANNABLE_SOURCE_SUFFIXES = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx",
    ".py", ".sh", ".yaml", ".yml", ".json", ".toml", ".env.example",
}

# Regex-heuristic scanners (secrets, auth patterns, injection patterns) are
# dominated by test-fixture noise if they walk test directories: synthetic
# secrets ("test-secret-change-me"), new Function() used as a test harness
# technique, eval/exec substrings inside regex-literal assertions. Confirmed
# empirically against worldmonitor's real tests/ tree during development —
# 172 of ~180 raw hits across secrets_scanner + injection_pattern_checker
# were test fixtures, not production code. Opt-in per caller (not baked into
# iter_source_files unconditionally) since a future consumer might
# legitimately want to walk tests too.
TEST_DIR_NAMES = {"__tests__", "tests", "test", "e2e"}
TEST_FILE_MARKERS = (".test.", ".spec.")


def is_test_path(path: Path) -> bool:
    if any(marker in path.name for marker in TEST_FILE_MARKERS):
        return True
    return any(part in TEST_DIR_NAMES for part in path.parts)


def _is_excluded_dir(dirpath: Path, root: Path) -> bool:
    if dirpath.name in EXCLUDED_DIR_NAMES:
        return True
    if dirpath.parent == root and dirpath.name in EXCLUDED_TOP_LEVEL_DIR_NAMES:
        return True
    return False


def iter_source_files(root: Path, suffixes: set[str] | None = None, exclude_tests: bool = False):
    """Yield every scannable file under `root`, honoring the shared excludes.

    `suffixes`, if given, restricts to those extensions (e.g. {'.js', '.ts'});
    otherwise every extension in SCANNABLE_SOURCE_SUFFIXES is included, plus
    extensionless files are skipped. `exclude_tests=True` additionally skips
    test files/directories (see TEST_DIR_NAMES/TEST_FILE_MARKERS above) —
    off by default so a caller that genuinely wants test coverage still gets
    it; the noise-prone regex-heuristic SAST scanners opt in.
    """
    root = Path(root)
    if not root.exists():
        return
    wanted = suffixes if suffixes is not None else SCANNABLE_SOURCE_SUFFIXES

    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except (PermissionError, FileNotFoundError):
            continue
        for entry in entries:
            if entry.is_dir():
                if exclude_tests and entry.name in TEST_DIR_NAMES:
                    continue
                if not _is_excluded_dir(entry, root):
                    stack.append(entry)
                continue
            if entry.name in EXCLUDED_FILE_NAMES:
                continue
            if any(entry.name.endswith(suf) for suf in EXCLUDED_FILE_SUFFIXES):
                continue
            if exclude_tests and is_test_path(entry):
                continue
            if entry.suffix.lower() in wanted or entry.name == ".env.example":
                yield entry
