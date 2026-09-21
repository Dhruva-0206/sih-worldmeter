# CLAUDE.md — orientation for future agents working on this repo

This is a White-Box Security Assessment Framework built for SIH 2026, Problem Statement
26163. Read this before making changes — several things here look like they could be
simplified or "fixed" and aren't bugs; the reasoning is below so you don't re-break them.

## What this actually is

A general-purpose, config-driven SAST+DAST engine (`engine/`) that runs against any
locally-deployed target described by a YAML file in `config/`. It is **not** hardcoded to
worldmonitor — module dispatch in `engine/orchestrator.py` reads entirely from
`ScanConfig.modules` toggles and `ScanConfig.target.dast_params`. Two targets exist today:

- `config/worldmonitor.yaml` — the real `github.com/koala73/worldmonitor` codebase,
  self-hosted via **its own** `docker-compose.yml` at `../target-src` (sibling directory,
  not inside this repo — clone it there). We wrap it, never modify it.
- `config/fixture.yaml` — `docker/fixture-app/`, a small Flask app we own, deliberately
  vulnerable, seeded with admin/standard_user/viewer roles.

## Why two targets (read this before "simplifying" to one)

worldmonitor's self-hosted Docker mode (`LOCAL_API_MODE=docker`) has **no Clerk/Convex
auth** — no login, no roles, just an anonymous HMAC session (`api/_session.js`). There is
no object-ownership or role model to test BOLA/privilege-escalation against on that
target. The fixture app exists solely to prove those specific modules
(`bola_tester.py`, `privilege_escalation.py`, `injection_tester.py`) work end-to-end. This
was a deliberate, discussed decision (see conversation/PR history), not a scope-creep
accident — don't collapse it back to one target without re-reading that reasoning.

## Running things

```bash
# Python env (3.11 — see "Python version" gotcha below)
py -3.11 -m venv .venv
./.venv/Scripts/pip install -r requirements.txt

# worldmonitor (sibling dir, its own compose)
cd ../target-src && docker compose up -d --build

# fixture-app (this repo's compose)
cd worldmonitor-security-framework
docker compose -f docker/docker-compose.fixture.yml up -d --build

# full pipeline
./.venv/Scripts/python.exe run_assessment.py \
  --target-config config/worldmonitor.yaml --target-config config/fixture.yaml
```

Output lands in `output/security_assessment_report.{json,html,pdf}`.

## Gotchas hit during development (don't rediscover these the hard way)

1. **Windows `core.autocrlf` corrupts worldmonitor's own build.** `.gitattributes` pins
   `.js/.ts/.mjs/etc.` to `eol=lf` but not `.md`. If this machine's git has
   `core.autocrlf=true` (common Windows default), `public/home.md` gets checked out with
   CRLF, and `pro-test/prerender.mjs`'s `agentContext.match(/^---\n.../)` regex (LF-only)
   fails to find frontmatter, breaking `npm run build:pro` inside the Docker build with
   `Error: Homepage agent context must have document metadata`. Fix in `target-src`:
   `git config core.autocrlf false && git rm --cached -r . -q && git checkout HEAD -- .`

2. **A full host disk corrupts Docker's WSL2 backend, not just fails the build.** If C:
   fills to 0 bytes free mid-build, Docker's `docker_data.vhdx` ext4 filesystem can get
   genuinely corrupted (journal abort, superblock write failure, `containerd` SIGBUS on
   every subsequent start). `docker compose up` retries won't fix this — the WSL2 distro
   needs to come back from a Docker Desktop update/reinstall, or from `wsl --unregister
   docker-desktop` + relaunch (destructive: wipes local image/build cache, not project
   files). Keep >20GB free before building; check `df -h /c` first if a build fails with
   `npm error code EIO`.

3. **`class Severity(str, Enum)` does not stringify to its value on this Python.**
   `str(Severity.CRITICAL)` returns `"Severity.CRITICAL"`, not `"critical"`, unless
   `__str__` is explicitly overridden (see `engine/common/models.py`). This silently broke
   Jinja2 template rendering (`sev-{{ finding.severity }}` → `sev-Severity.CRITICAL`,
   matching no CSS rule) — findings rendered with **no color coding at all**, easy to miss
   visually. All three enums in `models.py` (`Severity`, `Confidence`, `FindingSource`)
   have `__str__` overridden to return `.value`. If you add a new str-mixin enum anywhere
   findings get templated, give it the same override or test it explicitly — don't trust
   `str, Enum` to "just work" on interpolation.

4. **`dict(requests.Response.headers)` silently drops repeated headers.** worldmonitor's
   `/api/wm-session` sends two `Set-Cookie` headers on one response; converting
   `resp.headers` to a plain dict keeps only one. `engine/common/http_client.py`'s
   `SafeResponse` carries a separate `cookies` field from `resp.cookies.get_dict()` for
   this reason — don't reach for `resp.headers.get('set-cookie')` when you need every
   cookie a response set.

5. **Regex-based SAST scanners need a comment-line filter and a test-file filter, or they
   drown in their own reflexivity.** `secrets_scanner.py`'s own docstring literally
   containing `` `hashlib.md5(` `` as documentation matched its own rule. worldmonitor's
   `tests/` tree is full of synthetic secrets (`'test-secret-change-me'`) and legitimate
   `new Function(...)` test-harness patterns that look identical to real
   deserialization sinks. `engine/common/text_utils.py::is_comment_line` and
   `engine/common/fs_walk.py::iter_source_files(..., exclude_tests=True)` exist
   specifically for this — any new regex-heuristic SAST module should use both.

6. **`[^'"]*` in a regex is not the same as "match a Python string literal."** A
   double-quoted f-string containing a literal single quote (`f"...LIKE '%{q}%'..."`,
   ordinary SQL syntax) breaks a naive `[^'"]*` bound, which excludes *both* quote
   characters instead of just the one that opened the string. Use a backreference guard
   (`(['"])(?:(?!\1).)*?...\1`) instead. See `injection_pattern_checker.py`.

7. **A bare `exec\(` or `eval\(` regex matches JS's `RegExp.prototype.exec()`.** Wildly
   common, completely unrelated to code execution. Guard with a negative lookbehind for a
   preceding `.` (`(?<!\.)\bexec\(`) or you'll flag dozens of harmless `pattern.exec(str)`
   calls as deserialization sinks.

## Module map

- `engine/sast/` — `code_parser` (tree-sitter route/call-expression extraction, foundation
  for the others), `secrets_scanner`, `auth_pattern_checker` (weak hash/JWT
  alg=none/cookie flags), `access_control_checker` (per-route + centralized-gate
  heuristics), `injection_pattern_checker` (string-concat SQL, deserialization sinks),
  `dependency_scanner` (npm audit + pip-audit wrapper).
- `engine/dast/` — one module per concern (cors, security headers, info disclosure, rate
  limiting, SSRF, auth/session, BOLA, privilege escalation, injection, OAuth/MCP, OpenAPI
  fuzzing). Every module was empirically grounded against the live target before being
  written — check each module's docstring for the curl probes that validated its
  assumptions before changing detection logic.
- `engine/correlation/correlator.py` — path-based (worldmonitor's per-route-file
  convention) + rule-family (fixture's monolithic file) matching. Correlation *itself* is
  treated as confirmation: a cross-linked SAST+DAST pair both become `status="confirmed"`
  regardless of either finding's individual confidence.
- `engine/scoring/cvss_calculator.py` — hand-reasoned CVSS 3.1 vector per rule_id, not a
  generic severity→vector lookup. Severity-band fallback only for `DEP-001`/`DEP-002`
  (real severity varies per-CVE) and any future unmapped rule_id.
- `engine/poc/poc_generator.py` — rebuilds a curl command from actual captured
  `HttpEvidence`, target always a shell variable defaulting to nothing (never a literal
  host), per the "never silently point at a real host" guardrail.

## Known accepted residual noise

`INJ-SAST-002` still has ~2 false positives in worldmonitor's `scripts/seed-vpd-tracker.mjs`
(matching `'eval("var res = ['` as a *string content* needle, not a real call) — accepted
as TENTATIVE-confidence noise rather than chasing a 6th regex refinement. Don't be
surprised by it; it's documented, not forgotten.

## Safety invariant — do not weaken this

`engine/common/config.py::_validate_base_url` refuses to load any config whose
`base_url` isn't localhost/RFC1918/a bare docker-compose service name. This is the single
gate preventing the whole pipeline from ever firing a DAST probe at a real host, including
`www.worldmonitor.app` itself. Any change here needs to preserve that property.
