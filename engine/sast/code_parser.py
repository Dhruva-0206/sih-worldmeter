"""AST-based mapping of route source files to URL paths + call-expression facts.

worldmonitor's `api/` directory follows the Vercel serverless convention: one
file = one route handler (confirmed during recon — `api/rss-proxy.js`,
`api/geo.js`, etc., each `export default` a single handler). That convention
means code_parser doesn't need to hunt for a handler function nested inside a
larger file — the file *is* the handler's scope, which is what
`RouteHandler.source` reflects.

Tree-sitter is used specifically for **call-expression extraction**: pulling
out the set of function names actually *called* in the file, as opposed to
identifiers that merely appear in a comment or a string literal. That
distinction is exactly what a regex-only approach gets wrong (e.g. a file
with `// TODO: call validateSessionToken() here` would regex-match but never
actually calls it) — auth_pattern_checker.py and access_control_checker.py
rely on `called_names` being real calls, not text matches, to keep false
positives down.

Cheaper structural facts (does the file export a default handler / named HTTP
method exports) are derived by regex over the source text — for those,
regex is robust enough and a full AST walk buys nothing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from tree_sitter import Node
from tree_sitter_language_pack import get_parser

_JS_EXTENSIONS = {".js", ".mjs", ".cjs"}
_TS_EXTENSIONS = {".ts", ".mts", ".cts"}
_TSX_EXTENSIONS = {".tsx", ".jsx"}
_ALL_ROUTE_EXTENSIONS = _JS_EXTENSIONS | _TS_EXTENSIONS | _TSX_EXTENSIONS

_ROUTE_EXCLUDE_PATTERNS = [
    re.compile(r".*\.test\.[cm]?[jt]sx?$"),
    re.compile(r".*\.d\.[cm]?ts$"),
]

_DEFAULT_EXPORT_RE = re.compile(r"export\s+default\s+(async\s+)?(function|\()")
_CJS_EXPORT_RE = re.compile(r"module\.exports\s*=")
_NAMED_HTTP_EXPORT_RE = re.compile(
    r"export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b"
)


def _parser_for(path: Path):
    suffix = path.suffix.lower()
    if suffix in _TSX_EXTENSIONS:
        return get_parser("tsx")
    if suffix in _TS_EXTENSIONS:
        return get_parser("typescript")
    return get_parser("javascript")


@dataclass
class RouteHandler:
    route_path: str
    file_path: Path
    is_helper: bool                        # "_"-prefixed: shared helper, not a route itself
    source: str
    line_count: int
    has_default_export: bool = False
    has_cjs_export: bool = False
    exported_http_methods: list[str] = field(default_factory=list)
    called_names: set[str] = field(default_factory=set)
    parse_error: str | None = None


def file_path_to_route(api_root: Path, file_path: Path) -> str:
    """Vercel-convention file->route mapping. `[id]` -> `:id`, `[...rest]` -> `*rest`."""
    rel = file_path.relative_to(api_root).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "index":
        parts = parts[:-1]
    segs = []
    for part in parts:
        if part.startswith("[...") and part.endswith("]"):
            segs.append("*" + part[4:-1])
        elif part.startswith("[") and part.endswith("]"):
            segs.append(":" + part[1:-1])
        else:
            segs.append(part)
    return "/api/" + "/".join(segs) if segs else "/api"


def _walk(node: Node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def _text(node: Node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _extract_called_names(tree_root: Node, source_bytes: bytes) -> set[str]:
    names: set[str] = set()
    for node in _walk(tree_root):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn is None:
            continue
        if fn.type == "identifier":
            names.add(_text(fn, source_bytes))
        elif fn.type == "member_expression":
            prop = fn.child_by_field_name("property")
            if prop is not None:
                names.add(_text(prop, source_bytes))
    return names


def parse_route_file(file_path: Path, api_root: Path) -> RouteHandler:
    source_bytes = file_path.read_bytes()
    source_text = source_bytes.decode("utf-8", errors="replace")

    called_names: set[str] = set()
    parse_error = None
    try:
        parser = _parser_for(file_path)
        tree = parser.parse(source_bytes)
        called_names = _extract_called_names(tree.root_node, source_bytes)
    except Exception as exc:  # tree-sitter grammar edge cases shouldn't kill the scan
        parse_error = f"{type(exc).__name__}: {exc}"

    return RouteHandler(
        route_path=file_path_to_route(api_root, file_path),
        file_path=file_path,
        is_helper=file_path.name.startswith("_"),
        source=source_text,
        line_count=source_text.count("\n") + 1,
        has_default_export=bool(_DEFAULT_EXPORT_RE.search(source_text)),
        has_cjs_export=bool(_CJS_EXPORT_RE.search(source_text)),
        exported_http_methods=[m.upper() for m in _NAMED_HTTP_EXPORT_RE.findall(source_text)
                                if isinstance(m, str)] or
                               [m[1] for m in _NAMED_HTTP_EXPORT_RE.findall(source_text)],
        called_names=called_names,
        parse_error=parse_error,
    )


def discover_route_files(api_root: Path) -> list[Path]:
    if not api_root.is_dir():
        return []
    files = []
    for p in api_root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in _ALL_ROUTE_EXTENSIONS:
            continue
        rel = str(p.relative_to(api_root))
        if any(pat.match(rel) for pat in _ROUTE_EXCLUDE_PATTERNS):
            continue
        files.append(p)
    return sorted(files)


def parse_api_routes(source_root: Path) -> list[RouteHandler]:
    """Entry point: parse every route file under <source_root>/api."""
    api_root = source_root / "api"
    return [parse_route_file(f, api_root) for f in discover_route_files(api_root)]
