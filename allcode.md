# All Code — worldmonitor-security-framework

Full source dump of every file in this project (51 files). Generated for reference/archival — not meant to be edited here; edit the actual files under their real paths.

## File index

- [.gitignore](#gitignore)
- [CLAUDE.md](#claudemd)
- [DEMO_SCRIPT.md](#demoscriptmd)
- [HUMAN.md](#humanmd)
- [README.md](#readmemd)
- [config/fixture.yaml](#configfixtureyaml)
- [config/worldmonitor.yaml](#configworldmonitoryaml)
- [dashboard/__init__.py](#dashboardinitpy)
- [dashboard/app.py](#dashboardapppy)
- [docker/docker-compose.fixture.yml](#dockerdockercomposefixtureyml)
- [docker/fixture-app/Dockerfile](#dockerfixtureappdockerfile)
- [docker/fixture-app/app.py](#dockerfixtureappapppy)
- [docker/fixture-app/requirements.txt](#dockerfixtureapprequirementstxt)
- [engine/__init__.py](#engineinitpy)
- [engine/common/__init__.py](#enginecommoninitpy)
- [engine/common/config.py](#enginecommonconfigpy)
- [engine/common/fs_walk.py](#enginecommonfswalkpy)
- [engine/common/http_client.py](#enginecommonhttpclientpy)
- [engine/common/models.py](#enginecommonmodelspy)
- [engine/common/text_utils.py](#enginecommontextutilspy)
- [engine/correlation/__init__.py](#enginecorrelationinitpy)
- [engine/correlation/correlator.py](#enginecorrelationcorrelatorpy)
- [engine/dast/__init__.py](#enginedastinitpy)
- [engine/dast/api_fuzzer.py](#enginedastapifuzzerpy)
- [engine/dast/auth_tester.py](#enginedastauthtesterpy)
- [engine/dast/bola_tester.py](#enginedastbolatesterpy)
- [engine/dast/cors_checker.py](#enginedastcorscheckerpy)
- [engine/dast/info_disclosure.py](#enginedastinfodisclosurepy)
- [engine/dast/injection_tester.py](#enginedastinjectiontesterpy)
- [engine/dast/oauth_mcp_checker.py](#enginedastoauthmcpcheckerpy)
- [engine/dast/privilege_escalation.py](#enginedastprivilegeescalationpy)
- [engine/dast/rate_limit_tester.py](#enginedastratelimittesterpy)
- [engine/dast/security_headers_checker.py](#enginedastsecurityheaderscheckerpy)
- [engine/dast/ssrf_prober.py](#enginedastssrfproberpy)
- [engine/orchestrator.py](#engineorchestratorpy)
- [engine/poc/__init__.py](#enginepocinitpy)
- [engine/poc/poc_generator.py](#enginepocpocgeneratorpy)
- [engine/sast/__init__.py](#enginesastinitpy)
- [engine/sast/access_control_checker.py](#enginesastaccesscontrolcheckerpy)
- [engine/sast/auth_pattern_checker.py](#enginesastauthpatterncheckerpy)
- [engine/sast/code_parser.py](#enginesastcodeparserpy)
- [engine/sast/dependency_scanner.py](#enginesastdependencyscannerpy)
- [engine/sast/injection_pattern_checker.py](#enginesastinjectionpatterncheckerpy)
- [engine/sast/secrets_scanner.py](#enginesastsecretsscannerpy)
- [engine/scoring/__init__.py](#enginescoringinitpy)
- [engine/scoring/cvss_calculator.py](#enginescoringcvsscalculatorpy)
- [report/__init__.py](#reportinitpy)
- [report/report_generator.py](#reportreportgeneratorpy)
- [report/templates/report.html.j2](#reporttemplatesreporthtmlj2)
- [requirements.txt](#requirementstxt)
- [run_assessment.py](#runassessmentpy)

---

<a id="gitignore"></a>
## `.gitignore`

```
.venv/
__pycache__/
*.pyc
output/
.env
docker/fixture-app/fixture.db
*.log
.pytest_cache/
```

---

<a id="claudemd"></a>
## `CLAUDE.md`

```markdown
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
```

---

<a id="demoscriptmd"></a>
## `DEMO_SCRIPT.md`

```markdown
# 3-Minute Demo Script — SIH 2026, PS 26163

**Framing (0:00–0:25)**
"Problem Statement 26163 asks for a security assessment of World Monitor. We built something
broader than a one-off report: a general-purpose White-Box Security Assessment Framework —
SAST plus DAST, correlated, CVSS-scored, with safe PoCs, config-driven so it runs against any
locally-deployed target, not just this one.

Recon on the real codebase surfaced a mismatch worth calling out up front: worldmonitor's
self-hosted Docker mode has no login, no roles — just an anonymous session. There's nothing to
run BOLA or privilege-escalation tests against. So the framework runs against **two** targets:
worldmonitor itself for everything that's real and testable there, and a small app we built
specifically to prove the role-based/BOLA/injection modules work end-to-end."

**Architecture (0:25–0:55)**
Show the README architecture diagram. One sentence per stage:
"Config drives everything — which target, which modules, safety limits. SAST walks the source:
secrets, weak auth patterns, missing authz checks, unsafe SQL, vulnerable dependencies. DAST
hits the live instance: CORS, headers, SSRF, injection, auth flows. The correlator cross-links
a static lead with a live probe into one 'confirmed' finding. Everything gets a real CVSS 3.1
vector, a safe reproduction, and lands in one report."

**Live run (0:55–1:50)**
```bash
python run_assessment.py --target-config config/worldmonitor.yaml --target-config config/fixture.yaml
```
While it runs (~3 min in reality — have it pre-run, show the tail of the log + the finished
report): point out the module log lines scrolling — SAST modules, then DAST modules, then
"correlating N findings", "scoring (CVSS 3.1)", "generating PoCs".

**The report — worldmonitor section (1:50–2:30)**
Open `output/security_assessment_report.html`. Scroll to worldmonitor:
- "29 real dependency vulnerabilities from `npm audit` across all 6 npm workspaces in the
  monorepo — real CVEs, real advisories, not synthetic."
- "The framework also verified several controls are working correctly — CORS resists a
  reflected-origin attack, SSRF probing against cloud metadata and internal docker services is
  blocked, OAuth metadata resists Host-header spoofing. A security report that only lists
  what's broken and never says what's confirmed *working* isn't trustworthy — this one does
  both."
- Point at the one ACCESS-001 lead (`/api/oauth-protected-resource`) flagged TENTATIVE: "The
  tool flagged this as a candidate — on inspection it's a deliberately public RFC 9728 metadata
  endpoint. That's the tool doing its job: surface a lead, don't assert a false certainty."

**The report — fixture section (2:30–2:55)**
Scroll to fixture-app: "Here's the same engine, pointed at a target that *does* have roles and
ownership. BOLA confirmed — one user reads another's private note. Privilege escalation
confirmed two ways — a forged JWT with `alg: none`, and mass-assignment role tampering. SQL
injection confirmed. Every one of these has a CVSS score, a curl PoC built from the actual
captured request, and is cross-linked to the exact source line that caused it."

**Close (2:55–3:00)**
"One engine, two targets, two different auth models, adapting what it tests — config-driven,
not hardcoded. That's the framework, not just the findings."

---

## Fallback if live network/Docker is flaky during the actual demo

Everything above works from the **already-generated** `output/security_assessment_report.html`
— the live `run_assessment.py` invocation is for color/credibility, not a hard dependency. If
Docker isn't cooperating on demo day, skip straight to the report and the architecture diagram.
```

---

<a id="humanmd"></a>
## `HUMAN.md`

```markdown
# What this project is, in plain English

## The assignment

Smart India Hackathon 2026 gave us Problem Statement 26163: "Security Assessment of the
World Monitor Application." The brief asked for a **white-box security assessment
framework** — meaning a tool that has access to the source code (not just poking at it
from outside), and that combines two classic kinds of security testing:

- **SAST** (Static Application Security Testing) — reading the source code looking for
  dangerous patterns: hardcoded passwords, weak encryption, SQL queries built by pasting
  strings together, missing permission checks, outdated libraries with known bugs.
- **DAST** (Dynamic Application Security Testing) — actually running the app and poking at
  it over the network: trying to log in as one person and read another person's data,
  trying to trick it into fetching an internal server it shouldn't be able to reach,
  sending malformed input and seeing if it crashes or leaks an error message with
  internal details in it.

The ask wasn't "write us a report." It was "build a *tool* that produces the report" —
something reusable, that scores what it finds using an industry-standard severity scale
(CVSS), and that proves each finding with a safe, working demonstration rather than just
an assertion.

## The target: World Monitor

World Monitor (worldmonitor.app) is a real, live product — a global intelligence
dashboard that aggregates news, conflict data, market data, military tracking, weather
disasters, and dozens of other live data feeds into one map-based dashboard. It's open
source on GitHub, actively developed (commits landing hours before we started), and it's
a serious piece of software — tens of thousands of files, a real paying customer base, a
Discord community, the works.

## The twist we found

We expected — reasonably, going in — that "assess World Monitor's security" would mean
something like: there are user accounts (maybe admin, regular user, guest), there's a
database, and the job is to check whether one user can see another user's data, whether
passwords are stored safely, whether an attacker can inject SQL, and so on. That's the
classic shape of a web app security assessment, and it's clearly what the problem
statement's phrasing (roles, access control, injection) was written expecting.

When we actually pulled down World Monitor's code and read how it works, we found
something different. The self-hosted version of World Monitor — the version anyone can
run on their own laptop via Docker, which is the only version we're allowed to test
against (testing the real, live production site is off-limits, and rightly so) — **doesn't
have user accounts at all**. No login. No admin/user/guest roles. Just a browser visiting
the site gets an anonymous, cryptographically-signed pass so the app can rate-limit it. The
"real" login system, with actual user accounts, lives in the cloud version, tied to a paid
subscription service World Monitor doesn't let you self-host.

So the specific vulnerability class the assignment implicitly assumed — "can user A see
user B's private data" — literally does not exist to test, on the only version of the app
we're allowed to test.

## What we did about it

Rather than quietly ignoring that mismatch (or worse, pretending to test something that
isn't there), we built the framework to run against **two targets**:

1. **World Monitor itself** — real code, real running instance, on our own laptop, no
   internet-facing testing at all. We run every check that's actually meaningful for how
   this app is really built: are there hardcoded secrets anywhere in the code, are any
   dependencies out of date with known security bugs, does the app correctly refuse to let
   a malicious website read its data, does it correctly refuse to be tricked into fetching
   an internal address it shouldn't be able to reach, does it leak stack traces when
   something goes wrong, are the security-related HTTP headers configured well.

2. **A tiny app we built ourselves** — on purpose, deliberately vulnerable, with actual
   user accounts (admin / regular user / guest) and actual private data one user owns.
   Its only job is to prove that the parts of our tool built for "can user A see user B's
   data" and "can a regular user promote themselves to admin" actually work, correctly,
   end to end — since World Monitor itself gave us no way to prove that.

This means our final report has two sections, clearly labeled: real findings from a real
production app, and a demonstration against a small app we built to show the tool's full
range of capability. We think that's more honest — and more useful — than either skipping
those checks entirely, or quietly testing something that doesn't apply and hoping nobody
notices.

## What the tool actually found

**Against the real World Monitor codebase:**
- ~30 real, known security vulnerabilities in its third-party dependencies (out-of-date
  libraries with published CVEs) — found by asking `npm audit` to check all six separate
  package manifests in their codebase (it's a monorepo with several sub-projects, each
  with its own dependency list).
- Several things we tried to break that turned out to already be solid: cross-site
  request forgery protection, protection against being tricked into fetching internal
  servers, session-token handling, and their OAuth metadata endpoint resisting a
  Host-header spoofing trick they specifically documented defending against in their own
  code comments. We report these too — a security report that only ever lists bad news
  and never confirms what's working properly isn't trustworthy.
- One "maybe" that we chased down and explained: an endpoint our tool flagged as
  "looks like it might be missing a login check" that, on inspection, turned out to be a
  deliberately public metadata file (the kind of thing that's *supposed* to be
  unauthenticated by design). We kept that in the report too, labeled clearly as a false
  positive we investigated — that's what a responsible read of an automated tool's output
  looks like.

**Against our own small demo app:**
- Confirmed that one user can read another user's private notes (the classic "IDOR" bug).
- Confirmed two different ways to trick the app into treating you as an administrator —
  one by forging a login token with no valid signature at all, one by simply asking the
  app to change your own account's role field, which it foolishly allowed.
- Confirmed a working SQL injection.

Every one of these came with an automatically-generated, safe way to reproduce it (a
`curl` command you can actually run against your own local copy), a calculated severity
score using the same CVSS standard real security teams use, and a plain-English
explanation of what's wrong and how to fix it.

## Why this is a "framework" and not just a report

The whole thing is driven by configuration files, not hardcoded logic. Pointing it at a
brand new target — a different app entirely — means writing one new YAML file describing
where its source code lives, what web address it runs on locally, and what kind of login
system (if any) it has. No code changes. The same engine that tested World Monitor's
anonymous-session model and our demo app's full-blown user-role model would, with a new
config file, adapt to test a third app with yet another kind of login system. That
adaptability — reading a target's shape from config and adjusting which tests even make
sense to run — is the actual "smart automation" idea behind this project, more than any
individual bug it found.

## Where to look

- `output/security_assessment_report.html` — the actual report, open it in a browser.
- `README.md` — the technical setup/usage instructions.
- `DEMO_SCRIPT.md` — a 3-minute walkthrough script for presenting this.
- `docker/fixture-app/app.py` — the small demo app, heavily commented explaining each bug.
```

---

<a id="readmemd"></a>
## `README.md`

```markdown
# World Monitor Security Assessment Framework

A **White-Box Security Assessment Framework** built for Smart India Hackathon 2026,
Problem Statement 26163 ("Security Assessment of the World Monitor Application", NTRO,
Software category, Smart Automation theme).

This is a general-purpose, config-driven SAST + DAST tool — not a one-off report. Point it
at any locally-deployed target via a YAML config, and it walks the source, probes the
running instance, correlates what it found across both, scores every finding with CVSS
3.1, generates a safe reproduction for each one, and produces a structured report
(JSON + HTML + PDF).

## Why two targets

The problem statement's assumed threat model (seeded admin/user/viewer accounts, BOLA,
privilege escalation) doesn't map cleanly onto the real target. worldmonitor's self-hosted
Docker mode (confirmed during recon, see `SELF_HOSTING.md` in the target repo) has **no
Clerk/Convex auth backend** — no login, no roles, just an anonymous HMAC-signed session.
Real multi-user auth is a cloud-only SaaS dependency this framework will never stand up or
test against (out of scope, and against the "local targets only" guardrail).

So this framework runs against **two targets** from the same engine:

1. **`worldmonitor`** (primary) — the real production codebase, self-hosted via its own
   `docker-compose.yml` (unmodified — we wrap it, not replace it). Full SAST across every
   npm workspace in the monorepo, plus every DAST module that's actually meaningful for an
   anonymous-session, no-SQL-database, Vercel-style-serverless-functions target: CORS,
   security headers, SSRF-safe proxy probing, session handling, rate-limiting, info
   disclosure, OAuth/MCP grant-flow checks, and OpenAPI-spec-driven fuzzing.

2. **`fixture-app`** (secondary) — a small, deliberately-vulnerable Flask app this repo
   ships (`docker/fixture-app`), seeded with admin/standard_user/viewer accounts and
   per-user-owned objects. Its only purpose is proving the BOLA/IDOR, privilege-escalation,
   and SQL-injection modules work end-to-end when a target actually has the auth model the
   original problem statement assumed. Every vulnerability in it is intentional and
   documented inline in `app.py`.

One engine, two auth models (`auth_profile: anonymous_session` vs `role_based` in each
target's YAML config), each module adapting what it tests based on that profile — that
adaptability is the actual "Smart Automation" story here, not a workaround.

## Architecture

```
                         ┌─────────────────────────┐
                         │   config/*.yaml          │
                         │   (target + module        │
                         │    toggles + safety)      │
                         └────────────┬─────────────┘
                                      │
                         ┌────────────▼─────────────┐
                         │   engine/orchestrator.py   │
                         └──┬─────────────────────┬──┘
                  ┌─────────▼──────────┐  ┌────────▼──────────┐
                  │   engine/sast/      │  │   engine/dast/      │
                  │  code_parser         │  │  cors_checker        │
                  │  secrets_scanner     │  │  security_headers     │
                  │  auth_pattern_checker│  │  info_disclosure      │
                  │  access_control_     │  │  rate_limit_tester    │
                  │    checker           │  │  ssrf_prober          │
                  │  injection_pattern_  │  │  auth_tester           │
                  │    checker           │  │  bola_tester           │
                  │  dependency_scanner  │  │  privilege_escalation  │
                  │                      │  │  injection_tester      │
                  │                      │  │  oauth_mcp_checker     │
                  │                      │  │  api_fuzzer            │
                  └──────────┬───────────┘  └──────────┬────────────┘
                             │       Finding objects    │
                             └────────────┬─────────────┘
                                          │
                    ┌─────────────────────▼─────────────────────┐
                    │   engine/correlation/correlator.py          │
                    │   path-based + rule-family matching ->       │
                    │   "confirmed" vs "unconfirmed"                │
                    └─────────────────────┬─────────────────────┘
                                          │
                    ┌─────────────────────▼─────────────────────┐
                    │   engine/scoring/cvss_calculator.py          │
                    │   per-rule CVSS 3.1 vector -> score + severity│
                    └─────────────────────┬─────────────────────┘
                                          │
                    ┌─────────────────────▼─────────────────────┐
                    │   engine/poc/poc_generator.py                │
                    │   safe curl repro from captured evidence      │
                    └─────────────────────┬─────────────────────┘
                                          │
                    ┌─────────────────────▼─────────────────────┐
                    │   report/report_generator.py                 │
                    │   -> output/*.json / *.html / *.pdf            │
                    └───────────────────────────────────────────┘
```

**Workflow:** Source Code → Isolated Docker Env → SAST + DAST → Correlation → CVSS Scoring
→ PoC Generation → Structured Report.

## Guardrails

- Every target's `base_url` is validated by `engine/common/config.py` before any DAST
  module can run — only `localhost`/`127.0.0.1`/RFC1918/docker-compose-service-name hosts
  are accepted. A config pointed at a real host (including `www.worldmonitor.app` itself)
  is **refused at load time**, not silently scanned.
- No destructive payloads anywhere. Injection testing uses boolean-differential,
  error-signature, and small bounded time-delay (3s) probes only — never a
  data-modifying statement.
- SSRF probing targets addresses that are safe by construction (cloud-metadata IP,
  internal docker-network names, loopback/obfuscated-loopback encodings) — never a real
  external host.
- The fixture app's credentials are synthetic, documented in `config/fixture.yaml`, and
  never hardcoded in source outside that one deliberately-vulnerable demo app.

## Setup

### 1. Python environment

```bash
py -3.11 -m venv .venv
./.venv/Scripts/pip install -r requirements.txt      # Windows
# source .venv/bin/activate && pip install -r requirements.txt   # macOS/Linux
```

### 2. Bring up worldmonitor (primary target)

Clone `github.com/koala73/worldmonitor` as a sibling directory (`../target-src` relative
to this repo, matching `config/worldmonitor.yaml`'s `source_paths`), then follow its own
`SELF_HOSTING.md`:

```bash
cd ../target-src
echo "RELAY_SHARED_SECRET=$(openssl rand -hex 32)" >> .env
echo "REDIS_PASSWORD=$(openssl rand -hex 32)"      >> .env
echo "REDIS_TOKEN=$(openssl rand -hex 32)"         >> .env
echo "WM_SESSION_SECRET=$(openssl rand -hex 32)"   >> .env
docker compose up -d --build
```

> **Windows note:** if `npm run build:pro` fails inside the Docker build with
> `Error: Homepage agent context must have document metadata`, your git checkout has
> CRLF-converted `public/home.md` (a Windows `core.autocrlf` default corrupting a file
> `.gitattributes` doesn't pin to LF). Fix: `git config core.autocrlf false && git rm
> --cached -r . -q && git checkout HEAD -- .` in the target-src repo, then rebuild.

### 3. Bring up the fixture app (secondary target)

```bash
cd worldmonitor-security-framework
docker compose -f docker/docker-compose.fixture.yml up -d --build
```

## Usage

```bash
# Full pipeline against both targets
python run_assessment.py --target-config config/worldmonitor.yaml --target-config config/fixture.yaml

# One target only
python run_assessment.py --target-config config/worldmonitor.yaml

# SAST only (no live target needed) / DAST only
python run_assessment.py --target-config config/worldmonitor.yaml --sast-only
python run_assessment.py --target-config config/worldmonitor.yaml --dast-only

# Custom output directory / report title
python run_assessment.py --target-config config/fixture.yaml --out-dir output/fixture-only --report-title "Fixture Demo Run"
```

Output: `output/security_assessment_report.{json,html,pdf}`.

## Adding a new target

1. Add a `config/<name>.yaml` — `target.base_url`, `target.auth_profile`
   (`none`/`anonymous_session`/`role_based`), `target.source_paths`/`lockfile_roots` for
   SAST, `target.accounts` if role-based, `target.dast_params` for any endpoint paths a
   DAST module needs (see the two existing configs for the full param list per module).
2. Toggle which SAST/DAST modules apply under `modules:`.
3. `python run_assessment.py --target-config config/<name>.yaml`.

No orchestrator code changes required — module dispatch reads entirely from the config.

## Project layout

```
worldmonitor-security-framework/
├── docker/
│   ├── docker-compose.fixture.yml   # standalone compose for the fixture app
│   └── fixture-app/                 # deliberately-vulnerable Flask demo app
├── engine/
│   ├── common/          # shared Finding model, config loader + safety gate, HTTP client
│   ├── sast/             # 6 static analysis modules
│   ├── dast/              # 11 dynamic analysis modules
│   ├── correlation/       # SAST<->DAST matching, confirmed/unconfirmed classification
│   ├── scoring/            # CVSS 3.1 vector table + score computation
│   ├── poc/                 # safe PoC/reproduction generator
│   └── orchestrator.py       # per-target pipeline, config-driven module dispatch
├── report/
│   ├── templates/report.html.j2
│   └── report_generator.py
├── config/
│   ├── worldmonitor.yaml
│   └── fixture.yaml
├── run_assessment.py      # CLI entry point
└── requirements.txt
```

## Sample findings

See `output/security_assessment_report.html` for a full run against both targets,
generated from this exact codebase. Highlights:

- **worldmonitor**: real dependency vulnerabilities (via `npm audit` across all 6 npm
  workspaces), plus verified-clean results for CORS, SSRF, session handling, and OAuth
  metadata Host-spoofing resistance — the codebase turned out to be unusually
  well-hardened, and the report documents what was checked and confirmed working, not
  just what was broken.
- **fixture-app**: confirmed BOLA/IDOR, JWT `alg=none` privilege escalation, mass-assignment
  privilege escalation, and SQL injection — each with a SAST lead, an independent DAST
  probe, and the correlator cross-linking both into a single "confirmed" finding.
```

---

<a id="configfixtureyaml"></a>
## `config/fixture.yaml`

```yaml
# Secondary target: our own small intentionally-vulnerable app
# (docker/fixture-app), seeded with admin/standard_user/viewer accounts and
# per-user-owned objects. Exists purely to prove the BOLA, privilege-
# escalation, and injection DAST modules work end-to-end — worldmonitor
# itself has no role model or object-ownership model to exercise them
# against (see config/worldmonitor.yaml).
#
# Every vulnerability this target has is intentional and documented in
# docker/fixture-app/app.py.

target:
  name: fixture-app
  description: >
    Deliberately-vulnerable Flask API (docker/fixture-app) with seeded
    admin/standard_user/viewer accounts and per-user-owned notes. Used to
    demonstrate BOLA/IDOR, JWT alg=none privilege escalation, mass-assignment
    role tampering, and SQL injection detection end-to-end.
  auth_profile: role_based
  base_url: "http://localhost:5001"

  source_paths:
    - "../docker/fixture-app"
  lockfile_roots: []  # requirements.txt is scanned by dependency_scanner directly

  accounts:
    - role: admin
      username: admin
      password: "AdminPass123!"
    - role: standard_user
      username: alice
      password: "AlicePass123!"
    - role: viewer
      username: bob
      password: "BobPass123!"

  dast_params:
    login_path: /api/login
    logout_path: /api/logout
    register_path: /api/register
    whoami_path: /api/whoami
    profile_update_path: /api/profile
    admin_path: /api/admin/users
    notes_create_path: /api/notes
    notes_object_path_template: /api/notes/{id}
    search_path: /api/search
    search_param_name: q
    token_field: token
    target_role: admin
    security_headers_path: /api/health

modules:
  sast:
    secrets_scanner: true
    auth_pattern_checker: true
    access_control_checker: true
    injection_pattern_checker: true
    dependency_scanner: true

  dast:
    auth_tester: true              # weak password policy, logout non-invalidation
    bola_tester: true               # GET /api/notes/<id> ownership bypass
    privilege_escalation: true      # JWT alg=none + PATCH /api/profile mass assignment
    injection_tester: true          # GET /api/search SQLi (safe boolean/error markers)
    cors_checker: true
    ssrf_prober: false               # fixture has no outbound-fetch endpoints
    rate_limit_tester: false         # fixture has no rate limiting to probe
    info_disclosure: true            # SQL error message reflection on /api/search
    security_headers_checker: true
    oauth_mcp_checker: false         # fixture has no OAuth/MCP surface
    api_fuzzer: false                # no OpenAPI spec for the fixture; routes are DAST-probed directly

safety:
  max_requests_per_second: 10
  request_timeout_seconds: 5
  max_findings_per_module: 200
```

---

<a id="configworldmonitoryaml"></a>
## `config/worldmonitor.yaml`

```yaml
# Primary target: the real worldmonitor codebase (github.com/koala73/worldmonitor),
# run self-hosted via its own docker-compose.yml (LOCAL_API_MODE=docker).
#
# auth_profile: anonymous_session — self-hosted Docker mode has no Clerk/Convex
# backend. There are no admin/user/viewer accounts to seed; the app only issues
# an anonymous HMAC-signed `wms_` session cookie. BOLA/privilege-escalation
# modules are intentionally left disabled below — there is no object-ownership
# or role model on this target to exercise them against. See fixture.yaml for
# the target that demonstrates those modules.

target:
  name: worldmonitor
  description: >
    Self-hosted instance of github.com/koala73/worldmonitor (Vite/React SPA +
    Vercel-style serverless API handlers + Redis), run from the project's own
    docker-compose.yml with LOCAL_API_MODE=docker.
  auth_profile: anonymous_session
  base_url: "http://localhost:3000"

  # Every npm workspace root in the monorepo, each with its own lockfile.
  source_paths:
    - "../../target-src"
  lockfile_roots:
    - "../../target-src"
    - "../../target-src/blog-site"
    - "../../target-src/cli"
    - "../../target-src/pro-test"
    - "../../target-src/consumer-prices-core"
    - "../../target-src/scripts"

  openapi_spec: "../../target-src/docs/api/worldmonitor.openapi.yaml"

  accounts: []  # none — anonymous_session profile

  # Endpoint names/params each DAST module targets. Every value here was
  # verified by hand against the live self-hosted instance before being
  # wired into the orchestrator — see the DAST module docstrings for the
  # specific curl probes that grounded each one.
  dast_params:
    session_issue_path: /api/wm-session
    session_cookie_name: wm-session
    ssrf_proxy_path: /api/rss-proxy
    ssrf_param_name: url
    mcp_path: /api/mcp
    mcp_tool_name: get_earthquakes
    oauth_metadata_path: /api/oauth-protected-resource
    rate_limit_path: /api/wm-session
    rate_limit_method: POST
    security_headers_path: /
    info_disclosure_error_probe_paths:
      - /api/wm-session
    api_fuzz_max_endpoints: 40

modules:
  sast:
    secrets_scanner: true
    auth_pattern_checker: true
    access_control_checker: true
    injection_pattern_checker: true
    dependency_scanner: true

  dast:
    auth_tester: true              # wms_ session replay/fixation/expiry
    bola_tester: false             # no object-ownership model on this target
    privilege_escalation: false    # no role model on this target
    injection_tester: true         # safe-marker probes on query params
    cors_checker: true             # allowlist + translate.goog bypass edge cases
    ssrf_prober: true              # safe probes on rss-proxy/geo/reverse-geocode
    rate_limit_tester: true        # trusted-proxy / IP-spoof bypass, IETF headers
    info_disclosure: true          # /api/local-* should 403 in docker mode
    security_headers_checker: true # HSTS/CSP/X-Frame-Options/etc, graded A+-F
    oauth_mcp_checker: true        # OAuth + MCP grant flow checks
    api_fuzzer: true               # driven by docs/api/worldmonitor.openapi.yaml

safety:
  max_requests_per_second: 5
  request_timeout_seconds: 8
  max_findings_per_module: 200
```

---

<a id="dashboardinitpy"></a>
## `dashboard/__init__.py`

```python

```

---

<a id="dashboardapppy"></a>
## `dashboard/app.py`

```python
"""Minimal local dashboard: trigger scans, browse the latest report.

    uvicorn dashboard.app:app --reload --port 8787

Deliberately plain HTML/JS (no build step) rather than a React app — this is
a local operator tool for the demo, not a product surface, and every extra
build step is one more thing that can break five minutes before a live demo.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.common.config import UnsafeTargetError, load_scan_config  # noqa: E402
from engine.orchestrator import run_multi  # noqa: E402
from report.report_generator import generate_report  # noqa: E402

app = FastAPI(title="World Monitor Security Assessment Dashboard")

CONFIG_DIR = ROOT / "config"
OUTPUT_DIR = ROOT / "output"

_scan_state = {"status": "idle", "detail": "", "findings_count": None}
_scan_lock = threading.Lock()


class ScanRequest(BaseModel):
    configs: list[str]  # filenames under config/, e.g. ["worldmonitor.yaml", "fixture.yaml"]
    sast_only: bool = False
    dast_only: bool = False


def _run_scan_background(config_names: list[str], sast_only: bool, dast_only: bool) -> None:
    with _scan_lock:
        _scan_state.update(status="running", detail="loading configs", findings_count=None)
    try:
        configs = [load_scan_config(CONFIG_DIR / name) for name in config_names]
        with _scan_lock:
            _scan_state["detail"] = f"running pipeline for {len(configs)} target(s)"
        findings = run_multi(configs, sast_only=sast_only, dast_only=dast_only)
        generate_report(findings, OUTPUT_DIR)
        with _scan_lock:
            _scan_state.update(status="done", detail="report written to output/", findings_count=len(findings))
    except Exception as exc:  # surfaced to the dashboard UI, not swallowed
        with _scan_lock:
            _scan_state.update(status="error", detail=str(exc), findings_count=None)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    configs = sorted(p.name for p in CONFIG_DIR.glob("*.yaml"))
    options = "".join(f'<option value="{c}">{c}</option>' for c in configs)
    return f"""<!DOCTYPE html>
<html><head><title>World Monitor Security Assessment</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; max-width: 720px; margin: 40px auto; color: #1a1a2e; }}
  h1 {{ font-size: 22px; }}
  select, button {{ font-size: 14px; padding: 6px 10px; margin: 4px 4px 4px 0; }}
  #status {{ margin-top: 16px; padding: 10px; border-radius: 4px; background: #f4f5f7; white-space: pre-wrap; }}
  .link-row a {{ margin-right: 12px; }}
</style></head>
<body>
  <h1>World Monitor Security Assessment Framework</h1>
  <p>Select target config(s), choose a mode, and run the pipeline.</p>
  <div>
    <label>Targets:</label><br>
    <select id="configs" multiple size="4">{options}</select>
  </div>
  <div>
    <label><input type="radio" name="mode" value="full" checked> Full (SAST+DAST)</label>
    <label><input type="radio" name="mode" value="sast"> SAST only</label>
    <label><input type="radio" name="mode" value="dast"> DAST only</label>
  </div>
  <button onclick="runScan()">Run Assessment</button>
  <button onclick="pollStatus()">Refresh Status</button>
  <div id="status">idle</div>
  <div class="link-row" style="margin-top:16px;">
    <a href="/report/html" target="_blank">View latest HTML report</a>
    <a href="/report/pdf" target="_blank">Download latest PDF</a>
    <a href="/report/json" target="_blank">Raw JSON</a>
  </div>
<script>
function selectedConfigs() {{
  return Array.from(document.getElementById('configs').selectedOptions).map(o => o.value);
}}
function mode() {{
  return document.querySelector('input[name=mode]:checked').value;
}}
async function runScan() {{
  const configs = selectedConfigs();
  if (!configs.length) {{ alert('Select at least one target config'); return; }}
  const m = mode();
  const body = {{ configs, sast_only: m === 'sast', dast_only: m === 'dast' }};
  await fetch('/api/scan', {{ method: 'POST', headers: {{'Content-Type':'application/json'}}, body: JSON.stringify(body) }});
  pollStatus();
}}
async function pollStatus() {{
  const r = await fetch('/api/scan/status');
  const j = await r.json();
  document.getElementById('status').textContent = JSON.stringify(j, null, 2);
  if (j.status === 'running') setTimeout(pollStatus, 2000);
}}
</script>
</body></html>"""


@app.post("/api/scan")
def start_scan(req: ScanRequest) -> JSONResponse:
    with _scan_lock:
        if _scan_state["status"] == "running":
            raise HTTPException(409, "A scan is already running")
    thread = threading.Thread(target=_run_scan_background, args=(req.configs, req.sast_only, req.dast_only), daemon=True)
    thread.start()
    return JSONResponse({"started": True})


@app.get("/api/scan/status")
def scan_status() -> dict:
    with _scan_lock:
        return dict(_scan_state)


@app.get("/report/html")
def report_html():
    path = OUTPUT_DIR / "security_assessment_report.html"
    if not path.exists():
        raise HTTPException(404, "No report yet — run a scan first")
    return FileResponse(path, media_type="text/html")


@app.get("/report/pdf")
def report_pdf():
    path = OUTPUT_DIR / "security_assessment_report.pdf"
    if not path.exists():
        raise HTTPException(404, "No PDF report yet — run a scan first")
    return FileResponse(path, media_type="application/pdf")


@app.get("/report/json")
def report_json():
    path = OUTPUT_DIR / "security_assessment_report.json"
    if not path.exists():
        raise HTTPException(404, "No report yet — run a scan first")
    return FileResponse(path, media_type="application/json")
```

---

<a id="dockerdockercomposefixtureyml"></a>
## `docker/docker-compose.fixture.yml`

```yaml
# Standalone compose file for the fixture app only. Run alongside (not merged
# with) worldmonitor's own docker-compose.yml — the two targets are
# independent and reachable from the host at different ports:
#
#   worldmonitor: http://localhost:3000  (started from ../../target-src)
#   fixture-app:  http://localhost:5001  (started from this file)
#
# Usage:
#   docker compose -f docker/docker-compose.fixture.yml up -d --build
#
# fixture.db is ephemeral (container-local /data volume) and reseeded fresh
# from app.py's init_db() on every container start.

services:
  fixture-app:
    build:
      context: ./fixture-app
    image: worldmonitor-security-fixture:latest
    container_name: wmsec-fixture-app
    ports:
      - "127.0.0.1:5001:5001"
    volumes:
      - fixture-data:/data
    restart: unless-stopped

volumes:
  fixture-data:
```

---

<a id="dockerfixtureappdockerfile"></a>
## `docker/fixture-app/Dockerfile`

```dockerfile
# fixture-app: small deliberately-vulnerable Flask API used only to prove out
# the BOLA/privilege-escalation/SQLi DAST modules end-to-end. Never expose
# this outside an isolated local Docker network.
FROM python:3.12-slim

WORKDIR /app
RUN useradd -m fixture && mkdir -p /data && chown fixture:fixture /data
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
USER fixture

EXPOSE 5001
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--workers", "2", "app:app"]
```

---

<a id="dockerfixtureappapppy"></a>
## `docker/fixture-app/app.py`

```python
"""fixture-app: a small, deliberately-vulnerable Flask API.

Purpose: worldmonitor's self-hosted Docker mode has no role-based auth (no
admin/user/viewer accounts, no per-user-owned objects — see
config/worldmonitor.yaml). This app exists solely so the framework's
BOLA/IDOR, privilege-escalation, and SQL-injection DAST modules have a real,
role-based, object-owning target to prove themselves against end to end.

Every bug below is intentional and documented inline with the CWE it
represents. Nothing here is obfuscated — a human or the SAST engine should be
able to find each one by reading the code.

NOT for exposure outside an isolated local Docker network. Seeded accounts
and data are synthetic.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sqlite3
import time
from dataclasses import dataclass

from flask import Flask, g, jsonify, request

app = Flask(__name__)

# CWE-798-adjacent: a real secret shouldn't live in source, but this is our
# own intentionally-vulnerable fixture, and the value is used only to make
# app.py's decode_jwt() bug (below) reachable in a controlled demo — SAST's
# secrets_scanner is expected to flag this line.
JWT_SECRET = "fixture-dev-secret-do-not-use-in-prod"

DB_PATH = "/data/fixture.db" if __name__ != "__main__" else "fixture.db"


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def md5_hash(password: str) -> str:
    # CWE-327 / CWE-916: MD5 has no place hashing credentials — no salt, no
    # work factor, trivially reversible via rainbow tables. Kept unsalted and
    # un-iterated on purpose so SAST's auth_pattern_checker has a clean,
    # unambiguous match (`hashlib.md5(` on a variable named `password`).
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS notes;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        );
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        );
        """
    )
    seed_users = [
        (1, "admin", md5_hash("AdminPass123!"), "admin"),
        (2, "alice", md5_hash("AlicePass123!"), "standard_user"),
        (3, "bob", md5_hash("BobPass123!"), "viewer"),
    ]
    conn.executemany(
        "INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
        seed_users,
    )
    seed_notes = [
        (1, 1, "Admin runbook", "Rotate fixture secrets before every demo run."),
        (2, 2, "Alice's private note", "Meeting notes for Q3 budget review — confidential."),
        (3, 3, "Bob's shopping list", "milk, eggs, bread"),
    ]
    conn.executemany(
        "INSERT INTO notes (id, owner_id, title, body) VALUES (?, ?, ?, ?)",
        seed_notes,
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Hand-rolled JWT (deliberately minimal — no external dependency) with a
# classic verification bug: CWE-347 (Improper Verification of Cryptographic
# Signature). See decode_jwt().
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def issue_jwt(username: str, role: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": username, "role": role, "iat": int(time.time())}
    header_b64 = _b64url_encode(json.dumps(header).encode())
    payload_b64 = _b64url_encode(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(sig)}"


def decode_jwt(token: str) -> dict | None:
    """Decode + verify a fixture JWT.

    VULNERABLE (CWE-347): trusts the caller-supplied `alg` header instead of
    pinning to the algorithm the server itself issues. A token with
    `{"alg": "none"}` and an empty/missing signature segment is accepted
    without any cryptographic check, so any client can forge a token for any
    username/role once it knows this endpoint exists — no secret required.
    This is the same bug class as CVE-2015-9235 (node-jsonwebtoken) and
    numerous hand-rolled JWT verifiers since.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))

        alg = header.get("alg", "")
        if alg.lower() == "none":
            # BUG: signature is never checked for alg=none. Should be a hard
            # reject (`alg not in ALLOWED_ALGS -> 401`), not a silent accept.
            return payload

        signing_input = f"{header_b64}.{payload_b64}".encode()
        expected_sig = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
        provided_sig = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected_sig, provided_sig):
            return None
        return payload
    except Exception:
        return None


# Logout does not maintain a revocation list — tokens are stateless and
# remain valid until natural expiry (there isn't one here). CWE-613:
# Insufficient Session Expiration. auth_tester.py's logout-invalidation check
# is expected to catch this: call /api/logout, then reuse the same token
# against a protected route and observe it still works.
REVOKED_TOKENS: set[str] = set()  # present but intentionally never populated by /api/logout


def current_user() -> dict | None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[len("Bearer "):]
    if token in REVOKED_TOKENS:
        return None
    return decode_jwt(token)


def require_auth():
    user = current_user()
    if user is None:
        return None, (jsonify(error="unauthorized"), 401)
    return user, None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify(status="ok", app="fixture-app")


@app.route("/api/register", methods=["POST"])
def register():
    # CWE-521: No password policy — a 1-character password is accepted.
    # auth_tester.py's weak-password-policy check registers with a trivial
    # password and expects this to be rejected; it isn't.
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    if not username or not password:
        return jsonify(error="username and password required"), 400
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, md5_hash(password), "viewer"),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="username taken"), 409
    return jsonify(status="registered", username=username, role="viewer"), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None or row["password_hash"] != md5_hash(password):
        return jsonify(error="invalid credentials"), 401
    token = issue_jwt(row["username"], row["role"])
    return jsonify(token=token, role=row["role"])


@app.route("/api/logout", methods=["POST"])
def logout():
    # See REVOKED_TOKENS note above — this is a no-op by design (the bug).
    return jsonify(status="logged out")


@app.route("/api/whoami", methods=["GET"])
def whoami():
    user, err = require_auth()
    if err:
        return err
    return jsonify(username=user.get("sub"), role=user.get("role"))


@app.route("/api/profile", methods=["PATCH"])
def update_profile():
    # CWE-915: Improperly Controlled Modification of Dynamically-Determined
    # Object Attributes ("mass assignment"). Any authenticated user can PATCH
    # their own `role` field directly — there's no allowlist of client-
    # writable fields and no check that only an admin may change roles. A
    # "viewer" can self-promote to "admin" in one request.
    user, err = require_auth()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username = ?", (user["sub"],)).fetchone()
    if row is None:
        return jsonify(error="user not found"), 404
    new_role = data.get("role", row["role"])
    db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, row["id"]))
    db.commit()
    new_token = issue_jwt(row["username"], new_role)
    return jsonify(status="updated", role=new_role, token=new_token)


@app.route("/api/notes", methods=["GET"])
def list_own_notes():
    # Correctly scoped — included as a contrast/control next to the broken
    # /api/notes/<id> route below, so the report can show "this route does it
    # right" next to "this route doesn't."
    user, err = require_auth()
    if err:
        return err
    db = get_db()
    owner = db.execute("SELECT id FROM users WHERE username = ?", (user["sub"],)).fetchone()
    if owner is None:
        return jsonify(notes=[])
    rows = db.execute("SELECT id, title, body FROM notes WHERE owner_id = ?", (owner["id"],)).fetchall()
    return jsonify(notes=[dict(r) for r in rows])


@app.route("/api/notes", methods=["POST"])
def create_note():
    user, err = require_auth()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    title = str(data.get("title", ""))
    body = str(data.get("body", ""))
    db = get_db()
    owner = db.execute("SELECT id FROM users WHERE username = ?", (user["sub"],)).fetchone()
    cur = db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (owner["id"], title, body),
    )
    db.commit()
    return jsonify(id=cur.lastrowid, title=title, body=body), 201


@app.route("/api/notes/<int:note_id>", methods=["GET"])
def get_note(note_id: int):
    # CWE-639: Authorization Bypass Through User-Controlled Key (BOLA/IDOR).
    # Any authenticated user can read any other user's note by guessing/
    # incrementing `note_id` — there is no `WHERE owner_id = ?` clause.
    user, err = require_auth()
    if err:
        return err
    db = get_db()
    row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    return jsonify(id=row["id"], owner_id=row["owner_id"], title=row["title"], body=row["body"])


@app.route("/api/search", methods=["GET"])
def search_notes():
    # CWE-89: SQL Injection via string concatenation instead of a
    # parameterized query. Reachable unauthenticated. injection_tester.py
    # uses safe boolean-based markers only (e.g. `' OR '1'='1` to widen a
    # result set, or a lone `'` to trigger a benign SQL syntax error) — never
    # a destructive payload.
    q = request.args.get("q", "")
    db = get_db()
    query = f"SELECT id, title FROM notes WHERE title LIKE '%{q}%'"
    try:
        rows = db.execute(query).fetchall()
    except sqlite3.OperationalError as exc:
        # Verbose DB error reflected to the client — also an info-disclosure
        # signal (CWE-209) that injection_tester.py's error-based probe uses.
        return jsonify(error="query failed", detail=str(exc)), 500
    return jsonify(results=[dict(r) for r in rows])


@app.route("/api/admin/users", methods=["GET"])
def admin_list_users():
    # "Protected" by a role check — but current_user() trusts decode_jwt(),
    # which trusts a client-supplied alg=none token (see decode_jwt above).
    # So this check is real code that is nonetheless bypassable end-to-end;
    # it's a good example for the correlator: SAST sees "role check present"
    # and would call this fine in isolation, DAST proves it's bypassable, and
    # the correlated finding explains why (the auth primitive underneath is
    # broken, not this route's authz check itself).
    user, err = require_auth()
    if err:
        return err
    if user.get("role") != "admin":
        return jsonify(error="forbidden"), 403
    db = get_db()
    rows = db.execute("SELECT id, username, password_hash, role FROM users").fetchall()
    # CWE-359 bonus: exposes password_hash values to the caller.
    return jsonify(users=[dict(r) for r in rows])


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5001)
else:
    init_db()
```

---

<a id="dockerfixtureapprequirementstxt"></a>
## `docker/fixture-app/requirements.txt`

```text
flask==3.0.3
gunicorn==22.0.0
```

---

<a id="engineinitpy"></a>
## `engine/__init__.py`

```python

```

---

<a id="enginecommoninitpy"></a>
## `engine/common/__init__.py`

```python

```

---

<a id="enginecommonconfigpy"></a>
## `engine/common/config.py`

```python
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
```

---

<a id="enginecommonfswalkpy"></a>
## `engine/common/fs_walk.py`

```python
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
```

---

<a id="enginecommonhttpclientpy"></a>
## `engine/common/http_client.py`

```python
"""Shared, rate-limited HTTP client for every DAST module.

Centralizing this means the `safety.max_requests_per_second` /
`request_timeout_seconds` config values apply uniformly, and — more
importantly — every probe goes through the same base_url that
config.load_scan_config() already validated as local/docker-scoped. No DAST
module constructs its own requests.Session pointed at an arbitrary host.
"""
from __future__ import annotations

import json as _json
import time
from dataclasses import dataclass, field
from typing import Any

import requests


@dataclass
class SafeResponse:
    status_code: int
    headers: dict[str, str]
    text: str
    elapsed_seconds: float
    url: str
    error: str | None = None
    # Parsed from requests' cookie jar, not from `headers['Set-Cookie']` —
    # a plain dict(resp.headers) collapses multiple Set-Cookie response
    # headers down to whichever one wins the key collision, silently
    # dropping the others (a real bug caught during development: worldmonitor
    # sends a session cookie AND a separate pro-key-clearing cookie on the
    # same response, and dict(headers) kept only the latter).
    cookies: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.error is None

    def json(self) -> Any:
        return _json.loads(self.text)


class RateLimiter:
    def __init__(self, max_requests_per_second: float):
        self._min_interval = 1.0 / max_requests_per_second if max_requests_per_second > 0 else 0.0
        self._last_call = 0.0

    def wait(self) -> None:
        if self._min_interval <= 0:
            return
        now = time.monotonic()
        delta = now - self._last_call
        if delta < self._min_interval:
            time.sleep(self._min_interval - delta)
        self._last_call = time.monotonic()


class SafeClient:
    """Thin wrapper over `requests` scoped to one base_url, rate-limited,
    never following redirects automatically (each DAST module decides
    whether a 3xx matters to it and inspects Location itself)."""

    def __init__(self, base_url: str, max_requests_per_second: float = 5.0,
                 timeout_seconds: float = 8.0, extra_headers: dict[str, str] | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout_seconds
        self._limiter = RateLimiter(max_requests_per_second)
        self._session = requests.Session()
        if extra_headers:
            self._session.headers.update(extra_headers)

    def _full_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            # Still enforce same-origin: a module must not be able to pivot
            # this client at an arbitrary host via a crafted `path`.
            if not path.startswith(self.base_url):
                raise ValueError(f"Refusing cross-origin request from SafeClient scoped to {self.base_url}: {path}")
            return path
        return f"{self.base_url}/{path.lstrip('/')}"

    def request(self, method: str, path: str, **kwargs: Any) -> SafeResponse:
        self._limiter.wait()
        url = self._full_url(path)
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", False)
        try:
            resp = self._session.request(method, url, **kwargs)
            return SafeResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text=resp.text,
                elapsed_seconds=resp.elapsed.total_seconds(),
                url=resp.url,
                cookies=resp.cookies.get_dict(),
            )
        except requests.RequestException as exc:
            return SafeResponse(status_code=-1, headers={}, text="", elapsed_seconds=0.0,
                                 url=url, error=str(exc))

    def get(self, path: str, **kwargs: Any) -> SafeResponse:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> SafeResponse:
        return self.request("POST", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> SafeResponse:
        return self.request("PATCH", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> SafeResponse:
        return self.request("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> SafeResponse:
        return self.request("DELETE", path, **kwargs)
```

---

<a id="enginecommonmodelspy"></a>
## `engine/common/models.py`

```python
"""Shared data model for the assessment pipeline.

Every module (SAST detector, DAST tester, correlator, scorer, PoC generator,
report generator) reads and writes `Finding` objects. Keeping one shape here
means the orchestrator can pass findings between stages without per-module
adapters.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __str__(self) -> str:
        # A plain `class X(str, Enum)` mixin still uses Enum.__str__ (giving
        # "Severity.CRITICAL") on this Python version rather than the str
        # value — caught because it silently broke CSS class matching
        # (`sev-{{ finding.severity }}` rendered as `sev-Severity.CRITICAL`,
        # matching no rule) and printed ugly reprs everywhere else this
        # enum gets interpolated. Overriding __str__ fixes every call site
        # at once instead of hunting down each `.value` omission.
        return self.value

    @classmethod
    def from_cvss_score(cls, score: float) -> "Severity":
        # CVSS 3.1 qualitative severity rating scale (first.org).
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


class Confidence(str, Enum):
    CONFIRMED = "confirmed"   # DAST reproduced it live, or SAST+DAST correlated
    FIRM = "firm"             # single strong signal (SAST pattern match or DAST probe)
    TENTATIVE = "tentative"   # heuristic / entropy-based / low-signal match

    def __str__(self) -> str:
        return self.value


class FindingSource(str, Enum):
    SAST = "sast"
    DAST = "dast"
    CORRELATED = "correlated"

    def __str__(self) -> str:
        return self.value


@dataclass
class CodeLocation:
    file_path: str
    line_number: Optional[int] = None
    end_line: Optional[int] = None
    snippet: Optional[str] = None
    function_name: Optional[str] = None


@dataclass
class HttpEvidence:
    method: str
    url: str
    role_used: Optional[str] = None
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    status_code: Optional[int] = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_snippet: Optional[str] = None
    notes: Optional[str] = None


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    category: str                     # e.g. "secrets", "authz", "cors", "ssrf", "injection"
    source: FindingSource
    confidence: Confidence
    target: str                       # target name from config, e.g. "worldmonitor" / "fixture-app"
    severity: Severity = Severity.INFO
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    code_location: Optional[CodeLocation] = None
    http_evidence: list[HttpEvidence] = field(default_factory=list)
    remediation: Optional[str] = None
    business_impact: Optional[str] = None
    poc: Optional[str] = None
    poc_language: Optional[str] = None
    correlated_with: list[str] = field(default_factory=list)  # other finding ids
    status: str = "unconfirmed"       # "confirmed" | "unconfirmed" (set by correlator)
    tags: list[str] = field(default_factory=list)
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    extra: dict[str, Any] = field(default_factory=dict)
    id: str = field(default="")

    def __post_init__(self):
        if not self.id:
            self.id = self._compute_id()

    def _compute_id(self) -> str:
        loc = ""
        if self.code_location:
            loc = f"{self.code_location.file_path}:{self.code_location.line_number}"
        elif self.http_evidence:
            loc = f"{self.http_evidence[0].method}:{self.http_evidence[0].url}"
        basis = f"{self.target}|{self.rule_id}|{loc}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["source"] = self.source.value
        d["confidence"] = self.confidence.value
        d["severity"] = self.severity.value
        return d


class FindingEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Enum):
            return o.value
        if hasattr(o, "to_dict"):
            return o.to_dict()
        return super().default(o)


def findings_to_json(findings: list[Finding], **kwargs) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2, default=str, **kwargs)
```

---

<a id="enginecommontextutilspy"></a>
## `engine/common/text_utils.py`

```python
"""Small text heuristics shared by regex-based SAST scanners."""
from __future__ import annotations

_LINE_COMMENT_PREFIXES = ("#", "//", "*", "/*")


def is_comment_line(line: str) -> bool:
    """True if `line`, stripped, looks like a comment line.

    Deliberately cheap (no tokenizer): catches the common case of a
    match landing inside a `#`/`//`/block-comment continuation line, which
    is the single biggest source of false positives for a regex scanner run
    over real source (docstrings, TODOs, and — recursively — a security
    scanner's own rule-documenting comments all contain rule-shaped text).
    Doesn't catch a trailing same-line comment (`code(); // hashlib.md5(...)`,
    would need real tokenization for that) — acceptable false-negative rate
    for a heuristic filter.
    """
    stripped = line.strip()
    return stripped.startswith(_LINE_COMMENT_PREFIXES)
```

---

<a id="enginecorrelationinitpy"></a>
## `engine/correlation/__init__.py`

```python

```

---

<a id="enginecorrelationcorrelatorpy"></a>
## `engine/correlation/correlator.py`

```python
"""Maps DAST findings back to SAST source locations, producing a
"confirmed" vs "unconfirmed" classification.

Two matching strategies, because the two targets' source layouts are
genuinely different shapes:

  1. Path-based — worldmonitor's api/ tree is one-file-per-route, so
     access_control_checker's findings carry the exact route_path/
     route_literal they're about. A DAST finding whose probed URL path
     matches that route is a direct hit.

  2. Rule-family — fixture-app is one monolithic app.py handling every
     route, so path-based matching there would trivially link *every*
     SAST finding in the file to *every* DAST finding (useless — too
     coarse). Instead, a small hand-curated table says which SAST rule_ids
     and DAST rule_ids are about the same underlying bug class (e.g.
     AUTH-002's "JWT accepts alg=none" source pattern and PRIVESC-001's
     live JWT-forgery exploit are the same bug seen from two angles).

A finding's `status` becomes "confirmed" when: it's a DAST finding with
CONFIRMED confidence (empirically observed — self-confirming), or it's a
SAST finding cross-linked to such a DAST finding. Everything else — a SAST
heuristic lead nothing dynamic corroborated, or a DAST TENTATIVE probe
needing a human look — stays "unconfirmed". That label is exactly the
signal a reader needs to triage a report: start with "confirmed".
"""
from __future__ import annotations

from urllib.parse import urlparse

from engine.common.models import Confidence, Finding, FindingSource

# SAST rule_id -> DAST rule_id(s) that would confirm the same underlying bug
# from live behavior, when path-based matching doesn't apply (see docstring).
RULE_FAMILY_LINKS: dict[str, set[str]] = {
    "AUTH-002": {"PRIVESC-001"},                      # JWT alg=none: source pattern <-> live forgery
    "ACCESS-001": {"INFO-001", "BOLA-001", "PRIVESC-002"},
    "ACCESS-002": {"INFO-001"},
    "AUTH-001": set(),                                  # weak hash: SAST-only, nothing live corroborates storage format
    "AUTH-003": {"CORS-001"},                           # insecure cookie flags <-> exploitable cross-origin read
    "INJ-SAST-001": {"INJ-001", "INJ-002", "INJ-003"},  # string-concatenated SQL <-> live injection probes
}


def _path_of(url: str) -> str:
    return urlparse(url).path.rstrip("/") or "/"


def _sast_route_keys(finding: Finding) -> set[str]:
    keys = set()
    route_path = finding.extra.get("route_path") or finding.extra.get("route_literal")
    if route_path:
        keys.add(route_path.rstrip("/") or "/")
    if finding.code_location and finding.code_location.file_path:
        keys.add(f"file:{finding.code_location.file_path}")
    return keys


def _dast_route_keys(finding: Finding) -> set[str]:
    keys = set()
    for ev in finding.http_evidence:
        if ev.url:
            keys.add(_path_of(ev.url))
    return keys


def correlate(findings: list[Finding]) -> list[Finding]:
    sast = [f for f in findings if f.source == FindingSource.SAST]
    dast = [f for f in findings if f.source == FindingSource.DAST]

    # DAST findings that are themselves live-observed evidence are already confirmed.
    for f in dast:
        if f.confidence == Confidence.CONFIRMED:
            f.status = "confirmed"

    for sf in sast:
        sf_keys = _sast_route_keys(sf)
        family_targets = RULE_FAMILY_LINKS.get(sf.rule_id, set())

        for df in dast:
            if df.target != sf.target:
                continue
            path_match = bool(sf_keys & _dast_route_keys(df))
            family_match = df.rule_id in family_targets
            if not (path_match or family_match):
                continue

            if df.id not in sf.correlated_with:
                sf.correlated_with.append(df.id)
            if sf.id not in df.correlated_with:
                df.correlated_with.append(sf.id)

            # Correlation is itself a confirmation mechanism: an independent
            # static lead and an independent dynamic probe agreeing on the
            # same bug is stronger evidence than either alone, even if
            # neither individually reached CONFIRMED confidence on its own.
            sf.status = "confirmed"
            df.status = "confirmed"

    return findings
```

---

<a id="enginedastinitpy"></a>
## `engine/dast/__init__.py`

```python

```

---

<a id="enginedastapifuzzerpy"></a>
## `engine/dast/api_fuzzer.py`

```python
"""OpenAPI-spec-driven endpoint fuzzing.

Reads the target's own generated OpenAPI document (no hand-maintained route
list to fall out of sync) and, for a bounded, evenly-spaced sample of GET
endpoints:

  1. Fires a baseline request using each parameter's spec-provided
     `example` value (falling back to a generic placeholder by type when a
     required parameter has none).
  2. For each integer/number-typed parameter, fires a type-confusion
     variant (a non-numeric string in an integer slot) and checks for a 500.

A 401/403/400/422 is not a finding here — that's an endpoint correctly
requiring auth or rejecting bad input, which is exactly what should happen.
Only an unhandled-exception-shaped 500 (optionally corroborated by a
stack-trace marker in the body, reusing the same detector as
info_disclosure.py) is flagged: a public endpoint crashing on a
malformed-but-plausible parameter is a robustness/potential-DoS and
info-disclosure signal, not proof of a deeper exploit — reported as such.
"""
from __future__ import annotations

import re

import yaml

from engine.common.http_client import SafeClient
from engine.common.models import Confidence, Finding, FindingSource, HttpEvidence, Severity

_STACK_TRACE_MARKERS = re.compile(
    r"(at\s+[\w.$<>]+\s+\([^)]*\.(?:js|ts|mjs):\d+:\d+\)|node_modules[/\\][\w.@-]+)"
)

_TYPE_PLACEHOLDER = {"integer": 1, "number": 1.0, "boolean": True, "string": "wmsec-fuzz-probe"}
_TYPE_CONFUSION_VALUE = "wmsec-not-a-number"


def load_get_endpoints(spec_path: str) -> list[tuple[str, list[dict]]]:
    with open(spec_path, "r", encoding="utf-8") as f:
        spec = yaml.safe_load(f)
    endpoints = []
    for path, methods in (spec.get("paths") or {}).items():
        get_def = methods.get("get")
        if not get_def:
            continue
        endpoints.append((path, get_def.get("parameters", []) or []))
    return endpoints


def _sample_evenly(items: list, n: int) -> list:
    if n >= len(items):
        return items
    step = len(items) / n
    return [items[int(i * step)] for i in range(n)]


def _baseline_params(parameters: list[dict]) -> dict:
    params = {}
    for p in parameters:
        if p.get("in") != "query":
            continue
        name = p.get("name")
        if not name:
            continue
        if "example" in p:
            params[name] = p["example"]
        elif p.get("required"):
            schema_type = (p.get("schema") or {}).get("type", "string")
            params[name] = _TYPE_PLACEHOLDER.get(schema_type, "wmsec-fuzz-probe")
    return params


def _numeric_params(parameters: list[dict]) -> list[str]:
    return [
        p["name"] for p in parameters
        if p.get("in") == "query" and p.get("name")
        and (p.get("schema") or {}).get("type") in ("integer", "number")
    ]


def run(client: SafeClient, target_name: str, spec_path: str, max_endpoints: int = 25) -> list[Finding]:
    findings: list[Finding] = []
    try:
        endpoints = load_get_endpoints(spec_path)
    except (OSError, yaml.YAMLError) as exc:
        return [Finding(
            rule_id="APIFUZZ-000", title="Could not load OpenAPI spec for fuzzing",
            description=f"{spec_path}: {exc}", category="api-fuzzing",
            source=FindingSource.DAST, confidence=Confidence.TENTATIVE, target=target_name,
            severity=Severity.INFO, tags=["api-fuzzing", "skipped"],
        )]

    sample = _sample_evenly(endpoints, max_endpoints)

    for path, parameters in sample:
        baseline_params = _baseline_params(parameters)
        numeric_names = _numeric_params(parameters)

        for numeric_name in numeric_names:
            fuzz_params = dict(baseline_params)
            fuzz_params[numeric_name] = _TYPE_CONFUSION_VALUE
            resp = client.get(path, params=fuzz_params)
            if not resp.ok:
                continue
            if resp.status_code >= 500:
                trace_match = _STACK_TRACE_MARKERS.search(resp.text)
                findings.append(Finding(
                    rule_id="APIFUZZ-001",
                    title=f"Unhandled error (5xx) on malformed parameter: {path}?{numeric_name}=...",
                    description=(
                        f"GET {path} with `{numeric_name}={_TYPE_CONFUSION_VALUE}` (a non-numeric "
                        f"value in an integer/number parameter) returned HTTP {resp.status_code} "
                        f"instead of a 4xx validation error."
                        + (f" Response body contains a stack-trace marker: \"{trace_match.group(0)}\"."
                           if trace_match else "")
                    ),
                    category="api-fuzzing",
                    source=FindingSource.DAST,
                    confidence=Confidence.CONFIRMED if trace_match else Confidence.TENTATIVE,
                    target=target_name,
                    severity=Severity.MEDIUM,
                    http_evidence=[HttpEvidence(method="GET", url=resp.url, status_code=resp.status_code,
                                                 response_snippet=resp.text[:300])],
                    remediation="Validate query parameter types/ranges before use and return a 400/422 on mismatch instead of letting the handler throw.",
                    business_impact="An unhandled exception on attacker-influenced input is a robustness gap and potential low-cost DoS/info-disclosure vector across every affected endpoint.",
                    tags=["api-fuzzing", "type-confusion"],
                ))
            # one confirmed 5xx per endpoint is enough signal; move on
            break
    return findings
```

---

<a id="enginedastauthtesterpy"></a>
## `engine/dast/auth_tester.py`

```python
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
```

---

<a id="enginedastbolatesterpy"></a>
## `engine/dast/bola_tester.py`

```python
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
```

---

<a id="enginedastcorscheckerpy"></a>
## `engine/dast/cors_checker.py`

```python
"""CORS misconfiguration probing via origin reflection.

The only security-meaningful CORS bug this can find is a response that
REFLECTS an attacker-controlled Origin value back in
Access-Control-Allow-Origin while also setting
Access-Control-Allow-Credentials: true — that combination is what lets a
malicious page read a victim's authenticated response. A server that always
returns some fixed ACAO value regardless of the request's Origin is not
exploitable this way even if that fixed value looks odd, because a browser
only exposes the response to page JS when ACAO exactly equals the page's own
Origin. So every probe here compares the *returned* ACAO against the Origin
*we sent*, not against a hardcoded expectation of what the header "should"
say — that keeps this test accurate regardless of which layer (app code,
edge middleware, reverse proxy) actually produced the header.

Includes one target-specific regression probe: worldmonitor's own
api/_cors.js contains defenses against a Google-Translate-rewritten-origin
bypass (`evil--worldmonitor-app.translate.goog` decoding to
`evil-worldmonitor.app`, discovered as issue #6411 per their source
comments). Re-testing a fix that's already known to exist isn't redundant
for a DAST tool — it's exactly the kind of regression a future change could
silently reintroduce, and it's cheap to check every run.
"""
from __future__ import annotations

from engine.common.http_client import SafeClient
from engine.common.models import Confidence, Finding, FindingSource, HttpEvidence, Severity

_FOREIGN_ORIGIN = "https://evil-attacker.example"
_NULL_ORIGIN = "null"
_TRANSLATE_GOOG_BYPASS_ORIGIN = "https://evil--worldmonitor-app.translate.goog"

_PROBE_PATHS = ["/api/health?compact=1", "/api/version"]


def _probe_origin(client: SafeClient, path: str, origin: str) -> tuple[Finding | None, HttpEvidence]:
    resp = client.get(path, headers={"Origin": origin})
    evidence = HttpEvidence(
        method="GET", url=resp.url,
        request_headers={"Origin": origin},
        status_code=resp.status_code,
        response_headers={k: v for k, v in resp.headers.items() if k.lower().startswith("access-control")},
        notes=f"Origin sent: {origin}",
    )
    if not resp.ok:
        return None, evidence

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

    if acao == origin and acac:
        finding = Finding(
            rule_id="CORS-001",
            title=f"CORS reflects attacker-controlled Origin with credentials allowed: {path}",
            description=(
                f"Sending `Origin: {origin}` to {path} produced "
                f"`Access-Control-Allow-Origin: {acao}` (an exact echo of the request Origin) "
                f"together with `Access-Control-Allow-Credentials: true`. A page hosted at "
                f"{origin} could issue a credentialed request to this endpoint from a victim's "
                f"browser and read the response."
            ),
            category="cors",
            source=FindingSource.DAST,
            confidence=Confidence.CONFIRMED,
            target="",
            severity=Severity.HIGH,
            http_evidence=[evidence],
            remediation="Validate Origin against an explicit allowlist before echoing it, and never combine a reflected/wildcard origin with Allow-Credentials: true.",
            business_impact="Any authenticated user who visits a page at the attacker's origin can have their session silently used to read data from this API.",
            tags=["cors", "origin-reflection"],
        )
        return finding, evidence
    return None, evidence


def run(client: SafeClient, target_name: str, max_findings: int = 50) -> list[Finding]:
    findings: list[Finding] = []
    probes = [
        ("foreign origin", _FOREIGN_ORIGIN),
        ("null origin", _NULL_ORIGIN),
        ("translate.goog bypass attempt", _TRANSLATE_GOOG_BYPASS_ORIGIN),
    ]
    for path in _PROBE_PATHS:
        for label, origin in probes:
            finding, _ = _probe_origin(client, path, origin)
            if finding:
                finding.target = target_name
                finding.tags.append(label.replace(" ", "-"))
                findings.append(finding)
                if len(findings) >= max_findings:
                    return findings
    return findings
```

---

<a id="enginedastinfodisclosurepy"></a>
## `engine/dast/info_disclosure.py`

```python
"""Exposed debug/admin endpoints + verbose error / stack-trace leakage.

Two independent probes:

  INFO-001  a candidate sensitive path (generic admin/debug conventions,
            plus worldmonitor's documented `/api/local-*` administration
            routes, which SELF_HOSTING.md says must 403 in Docker mode)
            responds with 200 instead of a deny/not-found status.

  INFO-002  a request crafted to provoke an error (malformed JSON, an
            oversized/wrong-typed field) gets a response body containing
            what looks like a stack trace or an internal file path —
            leaking framework/library internals to an unauthenticated
            caller.

The candidate path list is intentionally generic (works against any target)
with the worldmonitor-specific `/api/local-*` paths folded in as additional
candidates — if a target doesn't have them, they just 404/pass through
cleanly and produce no finding.
"""
from __future__ import annotations

import re
import uuid

from engine.common.http_client import SafeClient
from engine.common.models import Confidence, Finding, FindingSource, HttpEvidence, Severity

_GENERIC_SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.git/config", "/.git/HEAD",
    "/api/debug", "/debug", "/api/admin", "/admin",
    "/api/_debug", "/server-status", "/actuator/health", "/api/internal",
]
# NOTE: /.well-known/security.txt is deliberately NOT on this list — it's an
# RFC 9116 file orgs are expected to publish (security contact info), so a
# 200 there is a good sign, not a finding. Caught during development when it
# showed up as worldmonitor's one "leak" — it was their real, intentional
# security.txt.

_WORLDMONITOR_LOCAL_ADMIN_PATHS = [
    "/api/local-status", "/api/local-traffic-log", "/api/local-debug-toggle",
    "/api/local-env-update", "/api/local-env-update-batch", "/api/local-validate-secret",
]

_STACK_TRACE_MARKERS = re.compile(
    r"(at\s+[\w.$<>]+\s+\([^)]*\.(?:js|ts|mjs):\d+:\d+\)|"
    r"node_modules[/\\][\w.@-]+|"
    r"Traceback \(most recent call last\)|"
    r"File \"[^\"]+\.py\", line \d+|"
    r"System\.\w+Exception|"
    r"at Object\.<anonymous>|"
    r"webpack-internal://)"
)

_MALFORMED_JSON_PROBES = [
    ("malformed JSON body", "{not valid json", "application/json"),
    ("wrong content-type with JSON-looking body", '{"a":1}', "text/plain"),
]


def _spa_fallback_signature(client: SafeClient) -> tuple[int, int, str]:
    """Fetch a guaranteed-nonexistent path to fingerprint a SPA's catch-all
    route (`try_files ... /dashboard.html`-style fallbacks serve 200 with
    the app shell for literally any unmatched path — without this baseline,
    every candidate in the sensitive-path list "succeeds" with 200 and the
    checker is just reporting the SPA's own routing behavior, not a real
    disclosure). Any candidate response matching this signature is noise.
    """
    probe_path = f"/__wmsec_baseline_probe_{uuid.uuid4().hex}__"
    resp = client.get(probe_path)
    return (resp.status_code, len(resp.text), resp.headers.get("content-type", ""))


def _check_sensitive_paths(client: SafeClient, target_name: str, paths: list[str],
                            expect_blocked: bool) -> list[Finding]:
    findings = []
    baseline = _spa_fallback_signature(client)
    for path in paths:
        resp = client.get(path)
        if not resp.ok:
            continue
        signature = (resp.status_code, len(resp.text), resp.headers.get("content-type", ""))
        if resp.status_code == 200 and signature == baseline:
            continue  # identical to the nonexistent-path baseline — SPA/catch-all fallback, not a real disclosure
        if resp.status_code == 200:
            evidence = HttpEvidence(
                method="GET", url=resp.url, status_code=resp.status_code,
                response_headers=dict(resp.headers),
                response_snippet=resp.text[:300],
            )
            findings.append(Finding(
                rule_id="INFO-001",
                title=f"Unexpected 200 on sensitive path: {path}",
                description=(
                    f"GET {path} returned 200 OK. " +
                    ("This path is documented as requiring administrator authentication "
                     "and returning 403 in self-hosted Docker mode." if path in _WORLDMONITOR_LOCAL_ADMIN_PATHS
                     else "This path matches a common sensitive/debug-endpoint convention.")
                ),
                category="info-disclosure",
                source=FindingSource.DAST,
                confidence=Confidence.CONFIRMED if expect_blocked else Confidence.TENTATIVE,
                target=target_name,
                severity=Severity.HIGH if path in _WORLDMONITOR_LOCAL_ADMIN_PATHS else Severity.MEDIUM,
                http_evidence=[evidence],
                remediation="Ensure this route enforces its access-control gate before returning a 200, and returns 403/404 for unauthenticated/unauthorized callers.",
                business_impact="Administrative or debug functionality reachable without authentication can expose internals or allow configuration changes.",
                tags=["info-disclosure", "exposed-endpoint"],
            ))
    return findings


def _check_verbose_errors(client: SafeClient, target_name: str, probe_paths: list[str]) -> list[Finding]:
    findings = []
    for path in probe_paths:
        for label, body, content_type in _MALFORMED_JSON_PROBES:
            resp = client.post(path, data=body, headers={"Content-Type": content_type})
            if not resp.ok:
                continue
            m = _STACK_TRACE_MARKERS.search(resp.text)
            if not m:
                continue
            evidence = HttpEvidence(
                method="POST", url=resp.url, status_code=resp.status_code,
                request_headers={"Content-Type": content_type}, request_body=body,
                response_snippet=resp.text[max(0, m.start() - 60):m.start() + 200],
                notes=label,
            )
            findings.append(Finding(
                rule_id="INFO-002",
                title=f"Verbose error / stack trace leaked from {path}",
                description=(
                    f"Sending a {label} to {path} produced a response containing what looks "
                    f"like a stack trace or internal file path: \"{m.group(0)[:120]}\"."
                ),
                category="info-disclosure",
                source=FindingSource.DAST,
                confidence=Confidence.CONFIRMED,
                target=target_name,
                severity=Severity.LOW,
                http_evidence=[evidence],
                remediation="Catch errors at the handler boundary and return a generic error body; log the full stack trace server-side only.",
                business_impact="Stack traces can reveal framework versions, file layout, and internal logic useful for crafting further attacks.",
                tags=["info-disclosure", "stack-trace"],
            ))
    return findings


def run(client: SafeClient, target_name: str, extra_sensitive_paths: list[str] | None = None,
        error_probe_paths: list[str] | None = None, include_worldmonitor_paths: bool = False) -> list[Finding]:
    candidate_paths = list(_GENERIC_SENSITIVE_PATHS)
    if include_worldmonitor_paths:
        candidate_paths += _WORLDMONITOR_LOCAL_ADMIN_PATHS
    if extra_sensitive_paths:
        candidate_paths += extra_sensitive_paths

    findings = _check_sensitive_paths(client, target_name, candidate_paths, expect_blocked=include_worldmonitor_paths)
    findings += _check_verbose_errors(client, target_name, error_probe_paths or ["/api/health"])
    return findings
```

---

<a id="enginedastinjectiontesterpy"></a>
## `engine/dast/injection_tester.py`

```python
"""Safe SQLi/NoSQLi/command-injection probing.

Three techniques, all using benign markers rather than destructive payloads
(no DROP/DELETE/UPDATE, no real filesystem or process side effects):

  INJ-001  boolean-based differential — a `' OR '1'='1`-style payload that
           should widen a result set is compared against a baseline query
           that should return few/no rows. A meaningfully larger result set
           under the injected payload is the signal.
  INJ-002  error-based — a lone quote/backslash provokes a syntax error;
           the response is scanned for a database error signature.
  INJ-003  time-based blind — multi-dialect payloads (MySQL/Postgres/MSSQL/
           SQLite-incompatible-by-design/shell) that each sleep a small,
           bounded delay (default 3s) if — and only if — the injected
           expression actually executes. A response taking meaningfully
           longer than baseline is the signal. Capped low deliberately:
           enough to distinguish from network jitter, not enough to be a
           meaningful DoS vector even run repeatedly.
"""
from __future__ import annotations

import re
import time

from engine.common.http_client import SafeClient
from engine.common.models import Confidence, Finding, FindingSource, HttpEvidence, Severity

_DB_ERROR_MARKERS = re.compile(
    r"(?i)(sql syntax|sqlite3\.OperationalError|unterminated string|"
    r"ORA-\d{5}|SQLSTATE\[|PostgreSQL.*ERROR|you have an error in your sql|"
    r"psycopg2\.|pymysql\.|System\.Data\.SqlClient|no such column|no such table)"
)

_BOOLEAN_PAYLOADS = ["' OR '1'='1", "1' OR '1'='1' -- -", "\" OR \"1\"=\"1"]
_ERROR_PAYLOADS = ["'", "\\", "''"]
_TIME_DELAY_SECONDS = 3
_TIME_PAYLOADS = [
    ("MySQL", f"' OR SLEEP({_TIME_DELAY_SECONDS})-- -"),
    ("PostgreSQL", f"'; SELECT pg_sleep({_TIME_DELAY_SECONDS})-- -"),
    ("MSSQL", f"'; WAITFOR DELAY '0:0:{_TIME_DELAY_SECONDS}'-- -"),
    ("shell command", f"; sleep {_TIME_DELAY_SECONDS}"),
    ("shell command (subshell)", f"$(sleep {_TIME_DELAY_SECONDS})"),
]
_BASELINE_QUERY = "wmsec-baseline-nonexistent-term"


def _get_len(client: SafeClient, path: str, param: str, value: str) -> tuple[int | None, float, str]:
    resp = client.get(path, params={param: value})
    if not resp.ok:
        return None, 0.0, ""
    return resp.status_code, resp.elapsed_seconds, resp.text


def run_boolean_based(client: SafeClient, target_name: str, path: str, param: str) -> list[Finding]:
    findings = []
    _, _, baseline_body = _get_len(client, path, param, _BASELINE_QUERY)
    for payload in _BOOLEAN_PAYLOADS:
        _, _, injected_body = _get_len(client, path, param, payload)
        if len(injected_body) > len(baseline_body) * 1.5 and len(injected_body) - len(baseline_body) > 20:
            findings.append(Finding(
                rule_id="INJ-001",
                title=f"Possible boolean-based SQL injection: {path}?{param}=...",
                description=(
                    f"GET {path}?{param}={_BASELINE_QUERY} (baseline, expected to match nothing) "
                    f"returned a {len(baseline_body)}-byte body; {path}?{param}={payload!r} returned "
                    f"a {len(injected_body)}-byte body — a payload that widens a SQL WHERE clause to "
                    f"match everything produced substantially more data."
                ),
                category="injection",
                source=FindingSource.DAST,
                confidence=Confidence.TENTATIVE,
                target=target_name,
                severity=Severity.HIGH,
                http_evidence=[HttpEvidence(method="GET", url=f"{path}?{param}={payload}",
                                             status_code=200, response_snippet=injected_body[:300])],
                remediation="Use parameterized queries/prepared statements; never interpolate request input directly into SQL text.",
                business_impact="An attacker can read data outside their intended access scope, and depending on the query context, potentially modify or exfiltrate the entire dataset.",
                tags=["injection", "sqli", "boolean-based", "cwe-89"],
            ))
            break  # one confirmation per path/param is enough signal
    return findings


def run_error_based(client: SafeClient, target_name: str, path: str, param: str) -> list[Finding]:
    findings = []
    for payload in _ERROR_PAYLOADS:
        resp = client.get(path, params={param: payload})
        if not resp.ok:
            continue
        m = _DB_ERROR_MARKERS.search(resp.text)
        if m:
            findings.append(Finding(
                rule_id="INJ-002",
                title=f"Database error reflected from injection probe: {path}?{param}=...",
                description=(
                    f"GET {path}?{param}={payload!r} produced a response containing a database "
                    f"error signature: \"{m.group(0)}\"."
                ),
                category="injection",
                source=FindingSource.DAST,
                confidence=Confidence.CONFIRMED,
                target=target_name,
                severity=Severity.HIGH,
                http_evidence=[HttpEvidence(method="GET", url=resp.url, status_code=resp.status_code,
                                             response_snippet=resp.text[:300])],
                remediation="Use parameterized queries; catch DB errors and return a generic message without the underlying error text.",
                business_impact="Confirms unsanitized input reaches a SQL query, and leaks schema/engine details useful for building a working exploit.",
                tags=["injection", "sqli", "error-based", "cwe-89"],
            ))
            break
    return findings


def run_time_based(client: SafeClient, target_name: str, path: str, param: str,
                    baseline_runs: int = 2) -> list[Finding]:
    findings = []
    baseline_times = []
    for _ in range(baseline_runs):
        _, elapsed, _ = _get_len(client, path, param, _BASELINE_QUERY)
        baseline_times.append(elapsed)
    baseline = max(baseline_times) if baseline_times else 0.5

    for dialect, payload in _TIME_PAYLOADS:
        _, elapsed, _ = _get_len(client, path, param, payload)
        if elapsed >= baseline + _TIME_DELAY_SECONDS - 1:  # 1s tolerance for network jitter
            findings.append(Finding(
                rule_id="INJ-003",
                title=f"Possible time-based blind injection ({dialect}): {path}?{param}=...",
                description=(
                    f"GET {path}?{param}=... with a {dialect} time-delay payload took {elapsed:.1f}s "
                    f"vs a {baseline:.1f}s baseline for a non-delaying query — consistent with the "
                    f"injected delay expression actually executing."
                ),
                category="injection",
                source=FindingSource.DAST,
                confidence=Confidence.TENTATIVE,
                target=target_name,
                severity=Severity.HIGH,
                http_evidence=[HttpEvidence(method="GET", url=f"{path}?{param}={payload}",
                                             notes=f"elapsed={elapsed:.2f}s, baseline={baseline:.2f}s")],
                remediation="Use parameterized queries (SQL) or avoid shelling out to an interpreter with unsanitized input (command injection).",
                business_impact="A working blind injection can be used to exfiltrate data one bit at a time even without any visible output difference.",
                tags=["injection", "time-based", dialect.lower().replace(" ", "-")],
            ))
            break  # one dialect confirming is enough; no need to also fire the delay for every other dialect
    return findings


def run(client: SafeClient, target_name: str, path: str, param: str) -> list[Finding]:
    findings = run_boolean_based(client, target_name, path, param)
    findings += run_error_based(client, target_name, path, param)
    if findings:
        # Boolean/error-based already confirmed injection on this param —
        # skip the (up to 5 x 3s) time-based probes, which exist to find
        # *blind* injection when there's no visible signal otherwise.
        return findings
    findings += run_time_based(client, target_name, path, param)
    return findings
```

---

<a id="enginedastoauthmcpcheckerpy"></a>
## `engine/dast/oauth_mcp_checker.py`

```python
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
```

---

<a id="enginedastprivilegeescalationpy"></a>
## `engine/dast/privilege_escalation.py`

```python
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
```

---

<a id="enginedastratelimittesterpy"></a>
## `engine/dast/rate_limit_tester.py`

```python
"""Rate-limit enforcement + client-controlled-header bypass testing.

Rather than assuming a specific threshold (thresholds vary by endpoint and
aren't always documented), this probes empirically and stays honest about
what it could and couldn't establish within a safe request budget:

  1. Send a bounded burst (`burst_size`, default 20 — small and gentle by
     design, this is a demonstration probe, not a load test) at one
     endpoint and see if a 429 appears.
  2. If a 429 appears: immediately retry a few more requests, each with a
     different spoofed X-Forwarded-For / X-Real-IP value. If the 429 goes
     away under a spoofed header, the limiter is keying off a
     client-controlled value — RATE-002, a real bypass.
  3. If no 429 appears in the burst: say so plainly (RATE-000, INFO) rather
     than silently reporting nothing, which would look identical to "rate
     limiting is broken" in a report. Absence of evidence within a small,
     safe burst is not evidence of absence.
"""
from __future__ import annotations

from engine.common.http_client import SafeClient
from engine.common.models import Confidence, Finding, FindingSource, HttpEvidence, Severity

_SPOOF_HEADER_NAMES = ["X-Forwarded-For", "X-Real-IP"]
_FAKE_IPS = ["203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13"]


def _fire(client: SafeClient, method: str, path: str, headers: dict[str, str] | None = None):
    return client.request(method, path, headers=headers or {})


def run(client: SafeClient, target_name: str, path: str = "/api/wm-session", method: str = "POST",
        burst_size: int = 20) -> list[Finding]:
    findings: list[Finding] = []
    responses = []
    for _ in range(burst_size):
        resp = _fire(client, method, path)
        responses.append(resp)
        if not resp.ok:
            break

    got_429 = any(r.status_code == 429 for r in responses)
    has_ratelimit_headers = any(
        any(h.lower().startswith("ratelimit") or h.lower().startswith("x-ratelimit") for h in r.headers)
        for r in responses
    )

    if not got_429:
        findings.append(Finding(
            rule_id="RATE-000",
            title=f"Rate limit not triggered within {burst_size} requests: {method} {path}",
            description=(
                f"Sent {len(responses)} requests to {method} {path} without receiving a 429. "
                f"This endpoint may have a higher threshold, a longer window, or a per-day cap "
                f"not practical to trigger in a bounded/safe test. "
                + ("IETF RateLimit-* headers were not observed on any response either."
                   if not has_ratelimit_headers else "RateLimit-* headers were present but no 429 occurred.")
            ),
            category="rate-limiting",
            source=FindingSource.DAST,
            confidence=Confidence.TENTATIVE,
            target=target_name,
            severity=Severity.INFO,
            http_evidence=[HttpEvidence(method=method, url=responses[-1].url if responses else path,
                                         status_code=responses[-1].status_code if responses else None,
                                         notes=f"{len(responses)} requests sent, no 429 observed")],
            tags=["rate-limiting", "inconclusive"],
        ))
        return findings

    # Got a 429 — now test whether a spoofed client-identity header resets it.
    bypassed = False
    bypass_evidence = None
    for i, fake_ip in enumerate(_FAKE_IPS):
        headers = {name: fake_ip for name in _SPOOF_HEADER_NAMES}
        resp = _fire(client, method, path, headers=headers)
        if resp.ok and resp.status_code != 429:
            bypassed = True
            bypass_evidence = HttpEvidence(
                method=method, url=resp.url, status_code=resp.status_code,
                request_headers=headers,
                notes=f"Request #{i+1} after triggering 429, with spoofed X-Forwarded-For/X-Real-IP={fake_ip}",
            )
            break

    if bypassed:
        findings.append(Finding(
            rule_id="RATE-002",
            title=f"Rate limit bypassed via spoofed client-IP header: {method} {path}",
            description=(
                f"{method} {path} returned 429 after {burst_size} requests, but a subsequent "
                f"request with a spoofed X-Forwarded-For/X-Real-IP header succeeded (non-429). "
                f"The limiter appears to key its bucket off a client-controlled header instead of "
                f"the connection's actual source address."
            ),
            category="rate-limiting",
            source=FindingSource.DAST,
            confidence=Confidence.CONFIRMED,
            target=target_name,
            severity=Severity.HIGH,
            http_evidence=[bypass_evidence] if bypass_evidence else [],
            remediation="Key rate-limit buckets off the connection's real source address (or a header only a trusted, configured reverse proxy can set), never an unauthenticated client-supplied header.",
            business_impact="Rate limiting is trivially bypassable by rotating a header value, defeating its purpose (abuse/cost control, brute-force slowdown).",
            tags=["rate-limiting", "bypass", "ip-spoofing"],
        ))
    else:
        findings.append(Finding(
            rule_id="RATE-001",
            title=f"Rate limit enforced and resists IP-spoofing header bypass: {method} {path}",
            description=(
                f"{method} {path} returned 429 after {burst_size} requests, and stayed 429 across "
                f"{len(_FAKE_IPS)} follow-up requests each with a different spoofed "
                f"X-Forwarded-For/X-Real-IP value — the limiter is not keying off those headers."
            ),
            category="rate-limiting",
            source=FindingSource.DAST,
            confidence=Confidence.CONFIRMED,
            target=target_name,
            severity=Severity.INFO,
            tags=["rate-limiting", "verified-control"],
        ))
    return findings
```

---

<a id="enginedastsecurityheaderscheckerpy"></a>
## `engine/dast/security_headers_checker.py`

```python
"""HTTP response security-header audit, graded A+ through F.

Methodology and header checklist are modeled on securityheaders.com's
public checklist (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy, Cross-Origin-*-Policy) — reimplemented
locally so the framework stays fully offline-capable and never sends a
target's headers to a third-party service. The weights/grade bands below are
this project's own reimplementation, not a claim of bit-for-bit parity with
securityheaders.com's (non-public) scoring algorithm.

CSP is checked at directive granularity rather than "present or absent" —
`script-src 'unsafe-inline'` and `style-src 'unsafe-inline'` are different
severities (inline script execution vs. inline style injection), and a page
can legitimately harden one directive while leaving another looser (see
module use against worldmonitor's real CSP: strict script-src with
nonces/hashes, but style-src still carries 'unsafe-inline').
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from engine.common.http_client import SafeClient
from engine.common.models import Confidence, Finding, FindingSource, HttpEvidence, Severity


@dataclass
class HeaderCheckResult:
    name: str
    weight: int
    earned: int
    detail: str
    finding_severity: Severity | None = None


def _split_csp(csp: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        directives[tokens[0].lower()] = tokens[1:]
    return directives


def _grade_from_ratio(ratio: float) -> str:
    if ratio >= 0.95:
        return "A+"
    if ratio >= 0.85:
        return "A"
    if ratio >= 0.70:
        return "B"
    if ratio >= 0.55:
        return "C"
    if ratio >= 0.40:
        return "D"
    return "F"


def evaluate_headers(headers: dict[str, str], scheme: str) -> tuple[list[HeaderCheckResult], str, int, int]:
    h = {k.lower(): v for k, v in headers.items()}
    results: list[HeaderCheckResult] = []

    # --- HSTS ---------------------------------------------------------
    hsts = h.get("strict-transport-security")
    if scheme != "https":
        results.append(HeaderCheckResult(
            "Strict-Transport-Security", 0, 0,
            "Not scored: this response was served over plain HTTP (local self-hosted deployment). "
            "HSTS is a browser instruction that only takes effect over HTTPS — check this again "
            "against the production TLS-terminated deployment.",
        ))
    elif not hsts:
        results.append(HeaderCheckResult("Strict-Transport-Security", 10, 0,
                                          "Missing entirely.", Severity.MEDIUM))
    else:
        max_age_ok = False
        for part in hsts.split(";"):
            part = part.strip()
            if part.startswith("max-age="):
                try:
                    max_age_ok = int(part.split("=", 1)[1]) >= 15552000  # 180 days
                except ValueError:
                    pass
        include_subdomains = "includesubdomains" in hsts.lower()
        preload = "preload" in hsts.lower()
        earned = 6 + (2 if max_age_ok else 0) + (1 if include_subdomains else 0) + (1 if preload else 0)
        detail = f"Present: max-age {'>=180d' if max_age_ok else '<180d (weak)'}, includeSubDomains={include_subdomains}, preload={preload}"
        results.append(HeaderCheckResult("Strict-Transport-Security", 10, earned, detail,
                                          None if earned >= 9 else Severity.LOW))

    # --- Content-Security-Policy ---------------------------------------
    csp = h.get("content-security-policy")
    if not csp:
        results.append(HeaderCheckResult("Content-Security-Policy", 25, 0, "Missing entirely.", Severity.HIGH))
    else:
        directives = _split_csp(csp)
        earned = 10  # base credit for having a CSP at all
        notes = []

        script_src = directives.get("script-src", directives.get("default-src", []))
        if "'unsafe-inline'" in script_src and "'strict-dynamic'" not in script_src:
            notes.append("script-src allows 'unsafe-inline' with no strict-dynamic/nonce/hash mitigation")
        elif "'unsafe-eval'" in script_src:
            notes.append("script-src allows 'unsafe-eval'")
        else:
            earned += 8
            notes.append("script-src has no unsafe-inline/unsafe-eval exposure")

        style_src = directives.get("style-src", directives.get("default-src", []))
        if "'unsafe-inline'" in style_src:
            notes.append("style-src allows 'unsafe-inline' (lower risk than script-src, but still widens the CSS-injection/exfiltration surface)")
        else:
            earned += 3

        if "object-src" in directives and "'none'" in directives["object-src"]:
            earned += 2
        else:
            notes.append("object-src is not restricted to 'none'")

        if "frame-ancestors" in directives:
            earned += 2
        else:
            notes.append("no frame-ancestors directive (clickjacking mitigation relies on X-Frame-Options alone)")

        results.append(HeaderCheckResult("Content-Security-Policy", 25, min(earned, 25),
                                          "; ".join(notes) if notes else "Strong policy: no unsafe-inline/unsafe-eval, object-src none, frame-ancestors set.",
                                          Severity.MEDIUM if notes else None))

    # --- X-Frame-Options / frame-ancestors already covered above -------
    xfo = h.get("x-frame-options")
    has_frame_ancestors = csp and "frame-ancestors" in _split_csp(csp)
    if not xfo and not has_frame_ancestors:
        results.append(HeaderCheckResult("X-Frame-Options", 10, 0,
                                          "Missing, and CSP has no frame-ancestors either — page is frameable.", Severity.MEDIUM))
    elif not xfo:
        results.append(HeaderCheckResult("X-Frame-Options", 10, 7,
                                          "Missing, but CSP frame-ancestors covers clickjacking protection in modern browsers.", None))
    else:
        results.append(HeaderCheckResult("X-Frame-Options", 10, 10, f"Present: {xfo}", None))

    # --- X-Content-Type-Options -----------------------------------------
    xcto = h.get("x-content-type-options", "")
    if xcto.lower() == "nosniff":
        results.append(HeaderCheckResult("X-Content-Type-Options", 8, 8, "Present: nosniff", None))
    else:
        results.append(HeaderCheckResult("X-Content-Type-Options", 8, 0, "Missing or not 'nosniff'.", Severity.LOW))

    # --- Referrer-Policy --------------------------------------------------
    rp = h.get("referrer-policy", "")
    strong_rp = rp.lower() in ("no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin")
    if strong_rp:
        results.append(HeaderCheckResult("Referrer-Policy", 7, 7, f"Present: {rp}", None))
    elif rp:
        results.append(HeaderCheckResult("Referrer-Policy", 7, 3, f"Present but permissive: {rp}", Severity.LOW))
    else:
        results.append(HeaderCheckResult("Referrer-Policy", 7, 0, "Missing.", Severity.LOW))

    # --- Permissions-Policy -----------------------------------------------
    pp = h.get("permissions-policy", "")
    if pp:
        results.append(HeaderCheckResult("Permissions-Policy", 7, 7, f"Present: {pp[:120]}", None))
    else:
        results.append(HeaderCheckResult("Permissions-Policy", 7, 0, "Missing.", Severity.LOW))

    # --- Cross-Origin-*-Policy trio -----------------------------------
    coop = h.get("cross-origin-opener-policy", "")
    coep = h.get("cross-origin-embedder-policy", "")
    corp = h.get("cross-origin-resource-policy", "")
    coop_ok = coop.lower() in ("same-origin", "same-origin-allow-popups")
    present_count = sum(1 for v in (coop, coep, corp) if v)
    earned = (4 if coop_ok else (2 if coop else 0)) + (3 if coep else 0) + (3 if corp else 0)
    detail = f"COOP={coop or '(missing)'}, COEP={coep or '(missing)'}, CORP={corp or '(missing)'}"
    results.append(HeaderCheckResult("Cross-Origin-*-Policy", 10, min(earned, 10), detail,
                                      Severity.LOW if present_count < 3 else None))

    total_possible = sum(r.weight for r in results)
    total_earned = sum(r.earned for r in results)
    ratio = (total_earned / total_possible) if total_possible else 1.0
    grade = _grade_from_ratio(ratio)
    return results, grade, total_earned, total_possible


def run(client: SafeClient, target_name: str, path: str = "/") -> list[Finding]:
    resp = client.get(path)
    if not resp.ok:
        return []

    scheme = urlparse(client.base_url).scheme
    results, grade, earned, possible = evaluate_headers(resp.headers, scheme)

    evidence = HttpEvidence(
        method="GET", url=resp.url, status_code=resp.status_code,
        response_headers=dict(resp.headers),
        notes=f"Security header grade: {grade} ({earned}/{possible} points)",
    )

    findings: list[Finding] = [Finding(
        rule_id="HEADERS-000",
        title=f"Security header grade: {grade} ({earned}/{possible})",
        description="Aggregate security-header posture for " + path + ", methodology modeled on securityheaders.com's checklist:\n" +
                    "\n".join(f"  - {r.name}: {r.earned}/{r.weight} — {r.detail}" for r in results),
        category="security-headers",
        source=FindingSource.DAST,
        confidence=Confidence.CONFIRMED,
        target=target_name,
        severity=Severity.INFO,
        http_evidence=[evidence],
        tags=["security-headers", "grade", grade],
        extra={"grade": grade, "points_earned": earned, "points_possible": possible,
               "breakdown": [{"name": r.name, "earned": r.earned, "weight": r.weight, "detail": r.detail} for r in results]},
    )]

    for r in results:
        if r.finding_severity is None:
            continue
        findings.append(Finding(
            rule_id="HEADERS-001",
            title=f"Weak or missing security header: {r.name}",
            description=r.detail,
            category="security-headers",
            source=FindingSource.DAST,
            confidence=Confidence.CONFIRMED,
            target=target_name,
            severity=r.finding_severity,
            http_evidence=[evidence],
            remediation=f"Set a strong {r.name} header on responses that serve HTML/browser-rendered content.",
            business_impact="Weak security headers widen the blast radius of an otherwise-unrelated bug (e.g. an XSS becomes exploitable without CSP; clickjacking becomes possible without frame protection).",
            tags=["security-headers", r.name.lower()],
        ))
    return findings
```

---

<a id="enginedastssrfproberpy"></a>
## `engine/dast/ssrf_prober.py`

```python
"""Safe SSRF probing against server-side URL-fetching proxy endpoints.

Every payload targets an address that is either non-routable from this test
run's perspective or requires no interaction beyond "did the target fetch
it" — no payload asks the target to read/write/delete real data anywhere.
Candidates: cloud-metadata IP (169.254.169.254, unreachable in this Docker
Desktop setup regardless — this only tests whether the *app* attempted and
disclosed the fetch outcome), internal docker-network service names,
loopback, and three classic SSRF-filter-bypass IP encodings (decimal, hex,
IPv6-mapped) to check the blocklist isn't purely string-matching
"127.0.0.1"/"localhost".

Detection: worldmonitor's own SSRF guard returns 403 with a distinctive
locked-down CSP (`sandbox; default-src 'none'; ...`) — verified empirically
against the live instance before writing this. A response that's 200 *and*
lacks that lockdown CSP is treated as a possible bypass; the finding
includes the raw evidence so it can be manually confirmed either way rather
than trusted blindly.
"""
from __future__ import annotations

from engine.common.http_client import SafeClient
from engine.common.models import Confidence, Finding, FindingSource, HttpEvidence, Severity

_SSRF_PAYLOADS = [
    ("cloud metadata IP", "http://169.254.169.254/latest/meta-data/"),
    ("internal docker service (redis)", "http://redis:6379/"),
    ("internal docker service (self)", "http://worldmonitor:8080/api/local-status"),
    ("loopback", "http://127.0.0.1:8080/api/local-status"),
    ("decimal-encoded loopback", "http://2130706433/"),
    ("hex-encoded loopback", "http://0x7f000001/"),
    ("IPv6-mapped loopback", "http://[::ffff:127.0.0.1]/"),
]

_LOCKDOWN_CSP_MARKER = "default-src 'none'"


def run(client: SafeClient, target_name: str, proxy_path: str = "/api/rss-proxy",
        param_name: str = "url") -> list[Finding]:
    findings: list[Finding] = []
    for label, payload in _SSRF_PAYLOADS:
        resp = client.get(proxy_path, params={param_name: payload})
        if not resp.ok:
            continue

        csp = resp.headers.get("Content-Security-Policy", resp.headers.get("content-security-policy", ""))
        looks_blocked = resp.status_code in (400, 403, 422, 502, 504) or _LOCKDOWN_CSP_MARKER in csp
        if looks_blocked:
            continue

        if resp.status_code == 200:
            evidence = HttpEvidence(
                method="GET", url=resp.url, status_code=resp.status_code,
                response_headers=dict(resp.headers), response_snippet=resp.text[:300],
                notes=f"Payload: {label} ({payload})",
            )
            findings.append(Finding(
                rule_id="SSRF-001",
                title=f"Possible SSRF via {proxy_path}?{param_name}=... ({label})",
                description=(
                    f"Requesting {proxy_path}?{param_name}={payload} returned 200 without the "
                    f"lockdown response this endpoint gives for other blocked SSRF targets. This "
                    f"needs manual confirmation — check whether the response body actually "
                    f"contains fetched content from {payload}, or if this is a different, benign "
                    f"code path (e.g. the URL failed validation for an unrelated reason)."
                ),
                category="ssrf",
                source=FindingSource.DAST,
                confidence=Confidence.TENTATIVE,
                target=target_name,
                severity=Severity.HIGH,
                http_evidence=[evidence],
                remediation="Validate/deny-list target URLs server-side against loopback, link-local, and private/internal address ranges, including alternate IP encodings, before the outbound fetch — not just against a literal string match on 'localhost'/'127.0.0.1'.",
                business_impact="A working SSRF can be used to reach internal-only services, cloud metadata endpoints, or bypass network-level access controls.",
                tags=["ssrf", label.replace(" ", "-")],
            ))
    return findings
```

---

<a id="engineorchestratorpy"></a>
## `engine/orchestrator.py`

```python
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
```

---

<a id="enginepocinitpy"></a>
## `engine/poc/__init__.py`

```python

```

---

<a id="enginepocpocgeneratorpy"></a>
## `engine/poc/poc_generator.py`

```python
"""Generates a safe, minimal, reproducible PoC for each finding.

For a DAST finding (has http_evidence), the PoC is a curl command rebuilt
from the actual request that was sent and observed to trigger the finding —
not a hypothetical example, the literal reproduction.

The target is always a shell variable defaulting to the config-provided
base_url, which config.load_scan_config() already validated as
local/docker-scoped before this pipeline ever ran — so a generated PoC
cannot silently point at a real host even if someone copies it out of the
report and runs it unmodified.

For a SAST-only finding (no http_evidence — a source-code pattern with
nothing to send over HTTP), the "PoC" is a short set of review steps
pointing at the exact file/line instead of a fabricated request.
"""
from __future__ import annotations

import shlex

from engine.common.models import Finding, HttpEvidence


def _curl_for_evidence(ev: HttpEvidence, base_url_var: str = "TARGET_BASE_URL") -> str:
    parts = ["curl", "-s", "-i"]
    if ev.method and ev.method.upper() != "GET":
        parts += ["-X", ev.method.upper()]
    for k, v in ev.request_headers.items():
        parts += ["-H", shlex.quote(f"{k}: {v}")]
    if ev.request_body:
        parts += ["-d", shlex.quote(ev.request_body)]

    url = ev.url
    # Rewrite the concrete host back to the parameterized variable so the
    # PoC is portable to "wherever this run's target actually is" rather
    # than a copy-pasted literal localhost:PORT that drifts from config.
    from urllib.parse import urlparse
    parsed = urlparse(url)
    path_and_query = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    parts.append(f'"${{{base_url_var}}}{path_and_query}"')
    return " ".join(parts)


def generate_poc(finding: Finding) -> tuple[str, str]:
    """Returns (poc_text, poc_language)."""
    if finding.http_evidence:
        lines = [
            f"# {finding.title}",
            f"# Target must be set explicitly — defaults to nothing so this can never",
            f"# accidentally hit a real host. Point it at YOUR local/docker deployment:",
            f"export {'TARGET_BASE_URL'}=http://localhost:PORT   # e.g. http://localhost:3000",
            "",
        ]
        for i, ev in enumerate(finding.http_evidence, 1):
            if len(finding.http_evidence) > 1:
                lines.append(f"# Step {i}{f' — {ev.notes}' if ev.notes else ''}")
            lines.append(_curl_for_evidence(ev))
            lines.append("")
        if finding.category in ("injection",) or "bola" in finding.tags or "privilege-escalation" in finding.tags:
            lines.append("# Expected if vulnerable: response reflects data/access beyond what the")
            lines.append("# caller's own role/ownership should permit. Compare against a baseline")
            lines.append("# request without the payload/tampering to confirm the difference.")
        return "\n".join(lines), "bash"

    if finding.code_location:
        loc = finding.code_location
        lines = [
            f"# {finding.title}",
            f"# Source-only finding — no live request reproduces this on its own.",
            f"# Review steps:",
            f"1. Open {loc.file_path}" + (f", line {loc.line_number}" if loc.line_number else ""),
        ]
        if loc.snippet:
            lines.append(f"2. Confirm the flagged pattern:\n   {loc.snippet}")
        lines.append(f"3. {finding.remediation or 'Assess whether this pattern is reachable/exploitable in context.'}")
        return "\n".join(lines), "text"

    return f"# {finding.title}\n# No evidence captured to build a reproduction from.", "text"


def generate_pocs(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        poc_text, poc_lang = generate_poc(f)
        f.poc = poc_text
        f.poc_language = poc_lang
    return findings
```

---

<a id="enginesastinitpy"></a>
## `engine/sast/__init__.py`

```python

```

---

<a id="enginesastaccesscontrolcheckerpy"></a>
## `engine/sast/access_control_checker.py`

```python
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
```

---

<a id="enginesastauthpatterncheckerpy"></a>
## `engine/sast/auth_pattern_checker.py`

```python
"""Weak auth/session code-pattern detection.

Three focused, regex-based checks chosen for low false-positive rate on a
large codebase rather than broad coverage:

  AUTH-001  weak password hashing (MD5/SHA1) near password-shaped context
  AUTH-002  JWT verification that accepts alg=none / doesn't pin an algorithm allowlist
  AUTH-003  session/auth cookie set without Secure+HttpOnly+SameSite

These are deliberately narrow. A generic "flag every === comparison near a
variable called token" rule would drown in false positives on a codebase
this size; each rule here instead anchors on a specific, well-known CWE
pattern with enough surrounding context to stay precise.
"""
from __future__ import annotations

import re
from pathlib import Path

from engine.common.fs_walk import iter_source_files
from engine.common.models import CodeLocation, Confidence, Finding, FindingSource, Severity
from engine.common.text_utils import is_comment_line

_WEAK_HASH_RE = re.compile(
    r"(?i)(hashlib\.(md5|sha1)\s*\(|crypto\.createHash\(\s*['\"](md5|sha1)['\"]\s*\))"
)
_PASSWORD_CONTEXT_RE = re.compile(r"(?i)\b(password|passwd|pwd)\b")

_JWT_ALG_NONE_RE = re.compile(
    r"(?i)alg(?:orithm)?\s*(?:\.lower\(\))?\s*(?:===?|==)\s*['\"]none['\"]"
)
_JWT_ALGORITHMS_LIST_NONE_RE = re.compile(
    r"(?i)algorithms\s*:\s*\[[^\]]*['\"]none['\"][^\]]*\]"
)
_JWT_VERIFY_CALL_RE = re.compile(r"(?i)\bjwt\.(decode|verify)\s*\(")

_COOKIE_SET_RE = re.compile(
    r"""(?ix)
    (
        \.cookie\s*\(\s*['"][\w.-]+['"]\s*,.*?\)   # express-style res.cookie('name', value, {opts})
        | Set-Cookie['"]?\s*[:=]\s*[`'"][^`'"]*     # manual Set-Cookie header string construction
        | set_cookie\s*\(
    )
    """,
    re.DOTALL,
)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _snippet(lines: list[str], line_no: int, max_len: int = 160) -> str | None:
    if 0 <= line_no - 1 < len(lines):
        s = lines[line_no - 1].strip()
        return s if len(s) <= max_len else s[:max_len] + "…"
    return None


def _check_weak_hashing(text: str, lines: list[str], rel_display: str) -> list[Finding]:
    findings = []
    for m in _WEAK_HASH_RE.finditer(text):
        line_no = _line_number(text, m.start())
        if line_no - 1 < len(lines) and is_comment_line(lines[line_no - 1]):
            continue
        window = "\n".join(lines[max(0, line_no - 4):line_no + 2])
        if not _PASSWORD_CONTEXT_RE.search(window):
            continue  # weak hash used for something else (cache keys, ETags, etc.) — not a credential-storage bug
        algo = m.group(2) or m.group(3)
        findings.append(Finding(
            rule_id="AUTH-001",
            title=f"Weak password hashing algorithm ({algo.upper()})",
            description=(
                f"{rel_display}:{line_no} hashes what appears to be a password/credential with "
                f"{algo.upper()}, which has no salt and no work factor by default and is fast "
                f"enough to brute-force offline at billions of guesses/second on commodity hardware."
            ),
            category="insecure-storage",
            source=FindingSource.SAST,
            confidence=Confidence.FIRM,
            target="",
            severity=Severity.HIGH,
            code_location=CodeLocation(file_path=rel_display, line_number=line_no,
                                        snippet=_snippet(lines, line_no)),
            remediation="Use a purpose-built password hash (bcrypt, scrypt, or Argon2id) with a per-user salt and a tunable work factor.",
            business_impact="If the credential store is ever exfiltrated, MD5/SHA1-hashed passwords can be cracked en masse, not just guessed one at a time.",
            tags=["auth", "weak-hash", "cwe-916"],
        ))
    return findings


def _check_jwt_alg_none(text: str, lines: list[str], rel_display: str) -> list[Finding]:
    findings = []
    if not _JWT_VERIFY_CALL_RE.search(text) and "jwt" not in text.lower() and "JWT" not in text:
        pass  # don't gate — hand-rolled JWT (like fixture-app's) never calls a jwt.verify()-shaped API
    for m in list(_JWT_ALG_NONE_RE.finditer(text)) + list(_JWT_ALGORITHMS_LIST_NONE_RE.finditer(text)):
        line_no = _line_number(text, m.start())
        if line_no - 1 < len(lines) and is_comment_line(lines[line_no - 1]):
            continue
        findings.append(Finding(
            rule_id="AUTH-002",
            title="JWT verification accepts alg=none",
            description=(
                f"{rel_display}:{line_no} treats a token with an `alg: none` header as valid, or "
                f"explicitly allowlists \"none\" as an accepted signing algorithm. Any caller can "
                f"forge a token with an arbitrary payload (e.g. a different username or an "
                f"elevated role claim) and no signature at all."
            ),
            category="authn",
            source=FindingSource.SAST,
            confidence=Confidence.FIRM,
            target="",
            severity=Severity.CRITICAL,
            code_location=CodeLocation(file_path=rel_display, line_number=line_no,
                                        snippet=_snippet(lines, line_no)),
            remediation="Pin verification to the exact algorithm(s) the server itself issues (e.g. only HS256), and hard-reject any other `alg` value before touching the payload.",
            business_impact="Complete authentication bypass — an attacker can impersonate any user, including an administrator, without knowing any secret.",
            tags=["auth", "jwt", "cwe-347"],
        ))
    return findings


def _check_insecure_cookie(text: str, lines: list[str], rel_display: str) -> list[Finding]:
    findings = []
    for m in _COOKIE_SET_RE.finditer(text):
        window = m.group(0)
        line_no = _line_number(text, m.start())
        if line_no - 1 < len(lines) and is_comment_line(lines[line_no - 1]):
            continue
        # Look a bit further than the single regex match for the options object,
        # since `.cookie('name', value, { httpOnly: true, ... })` can span lines.
        extended = text[m.start():m.start() + 400]
        has_httponly = re.search(r"(?i)httponly\s*:\s*true|HttpOnly", extended)
        has_secure = re.search(r"(?i)\bsecure\s*:\s*true|;\s*Secure\b", extended)
        if has_httponly and has_secure:
            continue
        missing = [n for n, present in (("HttpOnly", has_httponly), ("Secure", has_secure)) if not present]
        findings.append(Finding(
            rule_id="AUTH-003",
            title=f"Cookie set without {' and '.join(missing)}",
            description=(
                f"{rel_display}:{line_no} sets a cookie without the {' / '.join(missing)} attribute(s). "
                "Missing HttpOnly lets JavaScript (including injected via XSS) read the cookie; "
                "missing Secure lets it be sent over plain HTTP."
            ),
            category="session-management",
            source=FindingSource.SAST,
            confidence=Confidence.TENTATIVE,
            target="",
            severity=Severity.MEDIUM,
            code_location=CodeLocation(file_path=rel_display, line_number=line_no,
                                        snippet=_snippet(lines, line_no)),
            remediation="Set HttpOnly, Secure, and an explicit SameSite value on any cookie that carries a session or auth token.",
            business_impact="Session/auth cookies without these flags are easier to steal via XSS or network interception.",
            tags=["auth", "cookie", "cwe-1004"],
        ))
    return findings


def scan_file(path: Path, rel_display: str) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return []
    lines = text.splitlines()
    return (
        _check_weak_hashing(text, lines, rel_display)
        + _check_jwt_alg_none(text, lines, rel_display)
        + _check_insecure_cookie(text, lines, rel_display)
    )


def run(source_paths: list[Path], target_name: str, max_findings: int = 200) -> list[Finding]:
    findings: list[Finding] = []
    for root in source_paths:
        root = Path(root)
        for f in iter_source_files(root, suffixes={".js", ".mjs", ".cjs", ".ts", ".mts", ".tsx", ".py"}, exclude_tests=True):
            try:
                rel = str(f.relative_to(root.parent))
            except ValueError:
                rel = str(f)
            for finding in scan_file(f, rel):
                finding.target = target_name
                findings.append(finding)
                if len(findings) >= max_findings:
                    return findings
    return findings
```

---

<a id="enginesastcodeparserpy"></a>
## `engine/sast/code_parser.py`

```python
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
```

---

<a id="enginesastdependencyscannerpy"></a>
## `engine/sast/dependency_scanner.py`

```python
"""Outdated/vulnerable dependency scanning across every lockfile root in the
monorepo, via `npm audit --json` (Node deps) and `pip-audit` (Python deps).

Both tools need network access (npm registry / OSV.dev advisory data) to
produce a report. If that's unavailable the scanner emits one INFO-level
"scan skipped" finding per root explaining why, rather than failing the
whole pipeline — a dependency scan being unreachable shouldn't take down
the SAST+DAST run alongside it.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from engine.common.models import CodeLocation, Confidence, Finding, FindingSource, Severity

_NPM_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _run(cmd: list[str], cwd: Path, timeout: int = 180) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                               timeout=timeout, shell=False)
        return proc.returncode, proc.stdout, proc.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return -1, "", str(exc)


def _skip_finding(target_name: str, location: str, reason: str) -> Finding:
    return Finding(
        rule_id="DEP-000",
        title=f"Dependency scan skipped for {location}",
        description=reason,
        category="dependency",
        source=FindingSource.SAST,
        confidence=Confidence.TENTATIVE,
        target=target_name,
        severity=Severity.INFO,
        code_location=CodeLocation(file_path=location, line_number=None),
        tags=["dependency", "scan-skipped"],
    )


def _npm_audit_root(root: Path, target_name: str) -> list[Finding]:
    findings: list[Finding] = []
    lockfile = root / "package-lock.json"
    if not lockfile.exists():
        return findings

    # shutil.which resolves the .cmd wrapper on Windows; passing a bare "npm"
    # to subprocess.run(shell=False) fails to find it there (a well-known
    # Windows subprocess gotcha — CreateProcess doesn't do PATHEXT lookup the
    # way cmd.exe does for an extensionless name).
    npm_path = shutil.which("npm")
    if npm_path is None:
        findings.append(_skip_finding(target_name, str(root), "npm is not installed on the scanning host"))
        return findings

    code, out, err = _run([npm_path, "audit", "--json"], cwd=root)
    if not out.strip():
        findings.append(_skip_finding(
            target_name, str(root),
            f"npm audit produced no output (exit {code}): {err[:300] or 'no stderr'}"
        ))
        return findings

    try:
        report = json.loads(out)
    except json.JSONDecodeError:
        findings.append(_skip_finding(target_name, str(root),
                                       "npm audit output was not valid JSON (likely a registry/network error)"))
        return findings

    vulnerabilities = report.get("vulnerabilities", {})
    for pkg_name, info in vulnerabilities.items():
        severity = info.get("severity", "info")
        via = info.get("via", [])
        advisory_titles, advisory_urls = [], []
        for v in via:
            if isinstance(v, dict):
                if v.get("title"):
                    advisory_titles.append(v["title"])
                if v.get("url"):
                    advisory_urls.append(v["url"])
        title = advisory_titles[0] if advisory_titles else f"Vulnerable dependency: {pkg_name}"
        findings.append(Finding(
            rule_id="DEP-001",
            title=f"{pkg_name}: {title}",
            description=(
                f"npm audit reports a {severity}-severity issue in `{pkg_name}` "
                f"(lockfile: {lockfile}). " + (f"Advisory: {advisory_urls[0]}" if advisory_urls else "")
            ),
            category="dependency",
            source=FindingSource.SAST,
            confidence=Confidence.FIRM,
            target=target_name,
            severity=_NPM_SEVERITY_MAP.get(severity, Severity.MEDIUM),
            code_location=CodeLocation(file_path=str(lockfile), line_number=None),
            remediation=f"Run `npm audit fix` in {root}, or manually update `{pkg_name}` to a patched version.",
            business_impact="Severity-dependent — ranges from denial-of-service to remote code execution in the affected package's own code path.",
            tags=["dependency", "npm-audit", pkg_name],
            extra={"package": pkg_name, "npm_severity": severity, "advisory_urls": advisory_urls,
                   "lockfile_root": str(root)},
        ))
    return findings


def _pip_audit_requirements(req_file: Path, target_name: str) -> list[Finding]:
    findings: list[Finding] = []
    if not req_file.exists():
        return findings

    # Invoke pip-audit as a module of *this process's* interpreter (the
    # framework's own venv, where we installed it) rather than trusting a
    # bare "pip-audit" to be on PATH. req_file must be resolved to absolute
    # first — cwd is set to its parent, so a relative path would otherwise
    # be interpreted against that new cwd (self-referential, always 404s).
    code, out, err = _run([sys.executable, "-m", "pip_audit", "-r", str(req_file.resolve()), "--format", "json"],
                           cwd=req_file.parent)
    if not out.strip():
        findings.append(_skip_finding(
            target_name, str(req_file),
            f"pip-audit produced no output (exit {code}): {err[:300] or 'no stderr'}"
        ))
        return findings

    try:
        report = json.loads(out)
    except json.JSONDecodeError:
        findings.append(_skip_finding(target_name, str(req_file), "pip-audit output was not valid JSON"))
        return findings

    deps = report if isinstance(report, list) else report.get("dependencies", [])
    for dep in deps:
        name = dep.get("name")
        version = dep.get("version")
        for vuln in dep.get("vulns", []):
            vid = vuln.get("id", "unknown")
            fix_versions = vuln.get("fix_versions", [])
            findings.append(Finding(
                rule_id="DEP-002",
                title=f"{name}=={version}: {vid}",
                description=vuln.get("description") or f"{vid} affects {name} {version}.",
                category="dependency",
                source=FindingSource.SAST,
                confidence=Confidence.FIRM,
                target=target_name,
                severity=Severity.HIGH,  # pip-audit doesn't return a severity rating; default conservatively
                code_location=CodeLocation(file_path=str(req_file), line_number=None),
                remediation=(f"Upgrade {name} to {', '.join(fix_versions)}." if fix_versions
                             else f"No fixed version published yet for {vid} — track upstream."),
                business_impact="Severity-dependent on the specific CVE/GHSA advisory.",
                tags=["dependency", "pip-audit", name],
                extra={"package": name, "installed_version": version, "vuln_id": vid,
                       "fix_versions": fix_versions},
            ))
    return findings


def run(lockfile_roots: list[Path], target_name: str, requirements_files: list[Path] | None = None,
        max_findings: int = 200) -> list[Finding]:
    findings: list[Finding] = []
    for root in lockfile_roots:
        findings.extend(_npm_audit_root(Path(root), target_name))
        if len(findings) >= max_findings:
            return findings[:max_findings]
    for req in (requirements_files or []):
        findings.extend(_pip_audit_requirements(Path(req), target_name))
        if len(findings) >= max_findings:
            return findings[:max_findings]
    return findings[:max_findings]
```

---

<a id="enginesastinjectionpatterncheckerpy"></a>
## `engine/sast/injection_pattern_checker.py`

```python
"""Unsafe deserialization, string-concatenated SQL, and unescaped-output
patterns.

Three regex-based checks, each anchored on both a *query-building shape*
(f-string/concatenation/template-literal) AND a nearby SQL keyword or
dangerous-sink call name — a bare f-string or a bare "SELECT" substring
alone would be far too noisy on a real codebase (a log message, a docstring,
a GraphQL query all contain those individually).
"""
from __future__ import annotations

import re
from pathlib import Path

from engine.common.fs_walk import iter_source_files
from engine.common.models import CodeLocation, Confidence, Finding, FindingSource, Severity
from engine.common.text_utils import is_comment_line

# Full clause shapes, not bare keywords: a standalone "FROM" or "WHERE"
# matches ordinary English prose constantly ("drifted from", "handler
# missing from...") — caught as a wall of false positives against
# worldmonitor's real source (log/error message template literals) during
# development. Requiring the SELECT-FROM / INSERT-INTO / UPDATE-SET /
# DELETE-FROM clause pairing is specific enough to stay quiet on prose
# while still matching the fixture app's real
# `SELECT id, title FROM notes WHERE ...` query.
_SQL_KEYWORDS = r"(SELECT\b.{0,200}?\bFROM\b|INSERT\s+INTO\b|UPDATE\b.{0,200}?\bSET\b|DELETE\s+FROM\b)"

# Python f-string / .format() / % containing a SQL keyword and an interpolation.
# Uses a backreference ((?!\1).) rather than [^'"] to exclude only the SAME
# quote character that opened the string — a naive [^'"]* wrongly treats a
# SQL LIKE pattern's own embedded quotes (f"...WHERE title LIKE '%{q}%'...",
# a double-quoted f-string containing literal single quotes) as the end of
# the Python string literal, missing the match entirely (caught during
# development against the fixture app's actual vulnerable line).
_PY_FSTRING_SQL_RE = re.compile(
    rf"""(?i)f(['"])(?:(?!\1).)*?{_SQL_KEYWORDS}(?:(?!\1).)*?\{{[^}}]+\}}(?:(?!\1).)*?\1"""
)
_PY_CONCAT_SQL_RE = re.compile(
    # Backreferences are \1 and \3, not \1/\2: _SQL_KEYWORDS itself contains
    # a capturing group, so it consumes a group number between the two
    # quote groups (group 1 = first branch's quote, group 2 = the SQL-clause
    # match inside that branch, group 3 = second branch's quote).
    rf"""(?i)(['"])(?:(?!\1).)*?{_SQL_KEYWORDS}(?:(?!\1).)*?\1\s*\+\s*\w|"""
    rf"""\w[\w.\[\]]*\s*\+\s*(['"])(?:(?!\3).)*?{_SQL_KEYWORDS}(?:(?!\3).)*?\3"""
)

# JS/TS template literal containing a SQL keyword and a ${...} interpolation
_JS_TEMPLATE_SQL_RE = re.compile(
    rf"(?i)`[^`]*{_SQL_KEYWORDS}[^`]*\$\{{[^}}]+\}}[^`]*`"
)

_DESERIALIZATION_SINKS_RE = re.compile(
    # (?<!\.) excludes a preceding dot so this doesn't fire on `regex.exec(`
    # — JavaScript's ubiquitous, completely unrelated RegExp.exec() method —
    # which it did during development against worldmonitor's real source
    # (dozens of hits, none of them code execution). Same guard on eval(
    # for any future .eval(-style method some library might expose.
    r"(?i)\b(pickle\.loads|yaml\.load\((?!.*Loader=yaml\.SafeLoader)|marshal\.loads|"
    r"(?<!\.)\beval\(|(?<!\.)\bexec\(|new Function\(|child_process\.exec\()"
)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _snippet(lines: list[str], line_no: int, max_len: int = 160) -> str | None:
    if 0 <= line_no - 1 < len(lines):
        s = lines[line_no - 1].strip()
        return s if len(s) <= max_len else s[:max_len] + "…"
    return None


def _emit(rule_id: str, title: str, description: str, severity: Severity, category: str,
          rel_display: str, line_no: int, lines: list[str], remediation: str, tags: list[str]) -> Finding:
    return Finding(
        rule_id=rule_id, title=title, description=description, category=category,
        source=FindingSource.SAST, confidence=Confidence.FIRM, target="", severity=severity,
        code_location=CodeLocation(file_path=rel_display, line_number=line_no,
                                    snippet=_snippet(lines, line_no)),
        remediation=remediation, tags=tags,
    )


def scan_file(path: Path, rel_display: str) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return []
    lines = text.splitlines()
    findings: list[Finding] = []

    sql_patterns = []
    if path.suffix == ".py":
        sql_patterns = [_PY_FSTRING_SQL_RE, _PY_CONCAT_SQL_RE]
    elif path.suffix in (".js", ".mjs", ".cjs", ".ts", ".mts", ".tsx"):
        sql_patterns = [_JS_TEMPLATE_SQL_RE]

    for pattern in sql_patterns:
        for m in pattern.finditer(text):
            line_no = _line_number(text, m.start())
            if line_no - 1 < len(lines) and is_comment_line(lines[line_no - 1]):
                continue
            findings.append(_emit(
                "INJ-SAST-001", "String-concatenated/interpolated SQL query",
                f"{rel_display}:{line_no} builds a SQL query by interpolating a variable directly "
                f"into the query text instead of using a parameterized query/prepared statement.",
                Severity.HIGH, "injection", rel_display, line_no, lines,
                "Use parameterized queries (e.g. `cursor.execute(query, (param,))`) — never interpolate request-influenced values into SQL text.",
                ["injection", "sqli", "cwe-89"],
            ))

    for m in _DESERIALIZATION_SINKS_RE.finditer(text):
        sink = m.group(1)
        # yaml.load( without a safe-loader arg is a real anti-pattern in
        # Python (PyYAML) but not in JS/TS: js-yaml's yaml.load() is safe by
        # default (its unsafe equivalent is a differently-named function) —
        # scoping this specific alternative to .py avoided a wall of false
        # positives against worldmonitor's JS/TS source during development.
        if sink.startswith("yaml.load") and path.suffix != ".py":
            continue
        line_no = _line_number(text, m.start())
        if line_no - 1 < len(lines) and is_comment_line(lines[line_no - 1]):
            continue
        findings.append(Finding(
            rule_id="INJ-SAST-002", title=f"Unsafe deserialization/eval sink: {sink}",
            description=(
                f"{rel_display}:{line_no} calls {sink}, which can execute arbitrary code if its "
                f"input is influenced by an untrusted source. Regex-based detection can't tell a "
                f"real call from the same text appearing inside a string/regex literal (e.g. a "
                f"test asserting a Redis command matches /^eval(sha)?$/) — confirm this is an "
                f"actual call before treating it as a finding."
            ),
            category="injection", source=FindingSource.SAST, confidence=Confidence.TENTATIVE,
            target="", severity=Severity.HIGH,
            code_location=CodeLocation(file_path=rel_display, line_number=line_no,
                                        snippet=_snippet(lines, line_no)),
            remediation="Avoid pickle/marshal/eval/exec/new Function on untrusted input; use a safe serialization format (JSON) and a restrictive YAML loader (yaml.safe_load) instead.",
            tags=["injection", "deserialization", "cwe-502"],
        ))

    return findings


def run(source_paths: list[Path], target_name: str, max_findings: int = 200) -> list[Finding]:
    findings: list[Finding] = []
    for root in source_paths:
        root = Path(root)
        for f in iter_source_files(root, suffixes={".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".tsx"}, exclude_tests=True):
            try:
                rel = str(f.relative_to(root.parent))
            except ValueError:
                rel = str(f)
            for finding in scan_file(f, rel):
                finding.target = target_name
                findings.append(finding)
                if len(findings) >= max_findings:
                    return findings
    return findings
```

---

<a id="enginesastsecretsscannerpy"></a>
## `engine/sast/secrets_scanner.py`

```python
"""Hardcoded secret detection: known-format regexes + Shannon entropy on
credential-shaped assignments.

Design note: a naive "flag every high-entropy string literal" scanner is
useless on a codebase this size — minified vendor snippets, hex colors,
content hashes in generated filenames, and UUIDs all look high-entropy.
Entropy here is a *secondary* signal that upgrades confidence on a match
that a regex already flagged as credential-shaped (an assignment to a
variable named like `*_KEY`, `*_SECRET`, `*_TOKEN`, `password`, etc.), not a
standalone detector run over every string in the file. That keeps this
scanner usable against worldmonitor's real source instead of drowning real
findings (see fixture-app/app.py's hardcoded JWT_SECRET, which this catches
cleanly) in noise from a huge production monorepo.
"""
from __future__ import annotations

import math
import re
from pathlib import Path

from engine.common.fs_walk import iter_source_files
from engine.common.models import CodeLocation, Confidence, Finding, FindingSource, Severity
from engine.common.text_utils import is_comment_line

# --- High-confidence known secret formats -----------------------------------

_KNOWN_FORMAT_RULES: list[tuple[str, str, re.Pattern]] = [
    ("SEC-001", "AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("SEC-002", "GitHub personal access token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("SEC-003", "Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b")),
    ("SEC-004", "Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("SEC-005", "Stripe secret/publishable key", re.compile(r"\b[sp]k_(live|test)_[0-9A-Za-z]{16,}\b")),
    ("SEC-006", "PEM private key block", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("SEC-007", "Generic bearer/JWT-looking token literal",
     re.compile(r"[\"']eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}[\"']")),
]

# --- Credential-shaped assignment (regex catches the shape, entropy scores it) ---

_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    (?:^|[\s{,(;])                 # must look like an identifier position, not
                                    # text embedded inside a string literal —
                                    # otherwise "...user-api-key:..." inside an
                                    # unrelated string's own closing quote can be
                                    # misread as `key: '<value>'` (see module docstring)
    (
        api[_-]?key | apikey |
        secret[_-]?key | secret |
        access[_-]?token | auth[_-]?token | token |
        password | passwd | pwd |
        private[_-]?key |
        client[_-]?secret
    )\b
    [ \t]*[:=][ \t]*
    (?P<quote>['"`])
    (?P<value>[^'"`\n]{8,200})
    (?P=quote)
    """
)

_PLACEHOLDER_RE = re.compile(
    r"^(\s*|change[_-]?me|your[_-].*|xxx+|placeholder|example|test|dummy|"
    r"redacted|<.*>|\.\.\.|todo|fixme|null|none|undefined|fake)$",
    re.IGNORECASE,
)
_ENV_REFERENCE_RE = re.compile(
    r"process\.env\.|import\.meta\.env\.|os\.environ|getenv\(|\$\{.*\}|%\w+%"
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _looks_like_placeholder(value: str) -> bool:
    if _PLACEHOLDER_RE.match(value.strip()):
        return True
    if _ENV_REFERENCE_RE.search(value):
        return True
    # Repeated-character / sequential filler ("aaaaaaaa", "12345678")
    if len(set(value)) <= 2:
        return True
    return False


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _snippet(line: str, max_len: int = 160) -> str:
    line = line.strip()
    return line if len(line) <= max_len else line[:max_len] + "…"


def scan_file(path: Path, rel_display: str) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return []

    findings: list[Finding] = []
    lines = text.splitlines()

    for rule_id, title, pattern in _KNOWN_FORMAT_RULES:
        for m in pattern.finditer(text):
            line_no = _line_number(text, m.start())
            if line_no - 1 < len(lines) and is_comment_line(lines[line_no - 1]):
                continue
            findings.append(Finding(
                rule_id=rule_id,
                title=f"Hardcoded secret: {title}",
                description=(
                    f"A string matching the known format for {title} was found "
                    f"directly in source at {rel_display}:{line_no}."
                ),
                category="secrets",
                source=FindingSource.SAST,
                confidence=Confidence.FIRM,
                target="",  # filled in by caller
                severity=Severity.CRITICAL,
                code_location=CodeLocation(
                    file_path=rel_display,
                    line_number=line_no,
                    snippet=_snippet(lines[line_no - 1]) if line_no - 1 < len(lines) else None,
                ),
                remediation=(
                    "Revoke this credential immediately (assume it is compromised — it is in "
                    "version control history even if removed from HEAD), move it to an "
                    "environment variable or secrets manager, and rotate any systems it granted access to."
                ),
                business_impact="A leaked credential of this class typically grants direct account or service access to an attacker who reads the source.",
                tags=["secret", "hardcoded-credential"],
            ))

    for m in _ASSIGNMENT_RE.finditer(text):
        value = m.group("value")
        if _looks_like_placeholder(value):
            continue
        line_no = _line_number(text, m.start())
        if line_no - 1 < len(lines) and is_comment_line(lines[line_no - 1]):
            continue
        entropy = shannon_entropy(value)
        # Entropy threshold scales gently with length — short high-entropy
        # strings (e.g. 8-char hex) are common and not very secret-like.
        entropy_ok = entropy >= 3.0 and len(value) >= 12
        if not entropy_ok:
            continue
        confidence = Confidence.FIRM if entropy >= 4.0 else Confidence.TENTATIVE
        findings.append(Finding(
            rule_id="SEC-010",
            title="Possible hardcoded credential (high-entropy assignment)",
            description=(
                f"A variable named like a credential is assigned a literal string with "
                f"Shannon entropy {entropy:.2f} at {rel_display}:{line_no}, rather than "
                f"being read from an environment variable or secrets store."
            ),
            category="secrets",
            source=FindingSource.SAST,
            confidence=confidence,
            target="",
            severity=Severity.HIGH if confidence == Confidence.FIRM else Severity.MEDIUM,
            code_location=CodeLocation(
                file_path=rel_display,
                line_number=line_no,
                snippet=_snippet(lines[line_no - 1]) if line_no - 1 < len(lines) else None,
            ),
            remediation=(
                "Move this value to an environment variable / secrets manager and load it at "
                "runtime. If this is test/fixture data only, rename the variable away from "
                "credential-shaped names or add an explicit allowlist comment so scanners don't re-flag it."
            ),
            business_impact="If this value is a real credential, anyone with source access (including this repo's git history) has it.",
            tags=["secret", "entropy"],
            extra={"entropy": round(entropy, 3)},
        ))

    return findings


def run(source_paths: list[Path], target_name: str, max_findings: int = 200) -> list[Finding]:
    findings: list[Finding] = []
    for root in source_paths:
        root = Path(root)
        for f in iter_source_files(root, exclude_tests=True):
            try:
                rel = str(f.relative_to(root.parent))
            except ValueError:
                rel = str(f)
            for finding in scan_file(f, rel):
                finding.target = target_name
                findings.append(finding)
                if len(findings) >= max_findings:
                    return findings
    return findings
```

---

<a id="enginescoringinitpy"></a>
## `engine/scoring/__init__.py`

```python

```

---

<a id="enginescoringcvsscalculatorpy"></a>
## `engine/scoring/cvss_calculator.py`

```python
"""CVSS 3.1 base score calculation.

Every rule_id this framework can emit has a hand-reasoned CVSS 3.1 vector
below — not a generic "severity -> score" lookup, but a vector built from
the actual exploitation shape of that specific bug class (does it need a
prior foothold? does it need user interaction? does it cross a privilege
boundary?). A dependency finding (DEP-001/DEP-002) is the one deliberate
exception: its real-world severity varies per-CVE, so it falls back to a
representative vector chosen from the advisory's own severity band
(critical/high/moderate/low) rather than one fixed vector for every package.
Any rule_id this table doesn't recognize also falls back that way, keyed off
whatever severity the emitting module already assigned — so scoring never
silently drops a finding, it just scores conservatively until someone adds
a proper vector for that rule.

Score computation itself is delegated to the `cvss` package (FIRST's
reference algorithm), not reimplemented here.
"""
from __future__ import annotations

from cvss import CVSS3

from engine.common.models import Finding, Severity

# rule_id -> CVSS 3.1 vector (metrics only, no "CVSS:3.1/" prefix)
RULE_CVSS_VECTORS: dict[str, str] = {
    # --- secrets ---
    "SEC-001": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",   # AWS key
    "SEC-002": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",   # GitHub token
    "SEC-003": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",   # Slack token
    "SEC-004": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",   # Google API key
    "SEC-005": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",   # Stripe key
    "SEC-006": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # PEM private key
    "SEC-007": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",   # JWT-looking literal
    "SEC-010": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",   # entropy-based generic (lower confidence -> higher AC)

    # --- auth patterns (SAST) ---
    "AUTH-001": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",  # weak password hash — needs a DB-read precursor
    "AUTH-002": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # JWT alg=none in source
    "AUTH-003": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",  # insecure cookie flags — needs XSS/MITM precursor

    # --- access control (SAST heuristics) ---
    "ACCESS-001": "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    "ACCESS-002": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",

    # --- injection patterns (SAST) ---
    "INJ-SAST-001": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # string-concatenated SQL in source
    # unsafe deserialization/eval sink — AC:H because this is "a dangerous
    # sink exists in source", not a confirmed exploit: whether it's actually
    # reachable with attacker-controlled input is unverified (TENTATIVE
    # confidence — regex detection can also mistake a string/regex-literal
    # containing "eval(" for a real call, see the module docstring), so a
    # CVSS:C:H/I:H/A:H vector was overstating it as Critical by default.
    "INJ-SAST-002": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",

    # --- CORS ---
    "CORS-001": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",  # victim must visit attacker page

    # --- security headers ---
    "HEADERS-001": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",

    # --- info disclosure ---
    "INFO-001": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # exposed admin/debug route
    "INFO-002": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # stack trace leak

    # --- rate limiting ---
    "RATE-002": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",  # bypass -> abuse/cost/availability

    # --- SSRF ---
    "SSRF-001": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",  # scope change: can reach internal network

    # --- BOLA / privilege escalation ---
    "BOLA-001": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
    "PRIVESC-001": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # unauth JWT forgery -> any role
    "PRIVESC-002": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",  # needs a low-priv account first

    # --- injection ---
    "INJ-001": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "INJ-002": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",   # error-based disclosure only, weaker than a proven read/write primitive
    "INJ-003": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",

    # --- OAuth / MCP ---
    "MCP-001": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "OAUTH-001": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",

    # --- session/auth DAST ---
    "AUTH-T-001": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",  # token predictability
    "AUTH-T-002": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",  # weak password policy — needs brute-force precursor
    "AUTH-T-003": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",  # logout non-invalidation — needs a stolen-token precursor

    # --- API fuzzing ---
    "APIFUZZ-001": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
}

# Fallback vectors keyed by the emitting module's own qualitative severity —
# used for DEP-001/DEP-002 (real severity varies per-CVE) and any future
# rule_id that hasn't been given a hand-built vector yet.
_SEVERITY_FALLBACK_VECTORS: dict[Severity, str] = {
    Severity.CRITICAL: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    Severity.HIGH:      "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    Severity.MEDIUM:    "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    Severity.LOW:       "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    Severity.INFO:      "AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
}


def vector_for(finding: Finding) -> str:
    return RULE_CVSS_VECTORS.get(finding.rule_id) or _SEVERITY_FALLBACK_VECTORS[finding.severity]


def score_finding(finding: Finding) -> Finding:
    """Mutates and returns `finding` with cvss_vector/cvss_score/severity set
    from the CVSS 3.1 base score (severity is re-derived from the score, so
    it stays consistent with the vector rather than whatever heuristic
    severity the emitting DAST/SAST module guessed)."""
    vector = vector_for(finding)
    c = CVSS3(f"CVSS:3.1/{vector}")
    score = c.base_score
    finding.cvss_vector = f"CVSS:3.1/{vector}"
    finding.cvss_score = score
    finding.severity = Severity.from_cvss_score(score)
    return finding


def score_findings(findings: list[Finding]) -> list[Finding]:
    return [score_finding(f) for f in findings]
```

---

<a id="reportinitpy"></a>
## `report/__init__.py`

```python

```

---

<a id="reportreportgeneratorpy"></a>
## `report/report_generator.py`

```python
"""Assembles the final structured report: JSON (raw), HTML, and PDF.

Findings are expected to already be correlated/scored/PoC'd (i.e. have gone
through engine.orchestrator.run_target) before reaching this module — it's
purely presentation, no detection or scoring logic lives here.
"""
from __future__ import annotations

import io
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from xhtml2pdf import pisa

from engine.common.models import Finding, Severity, findings_to_json

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

_TARGET_LABELS = {
    "worldmonitor": "Primary Target — worldmonitor (real production codebase)",
    "fixture-app": "Fixture Target — RBAC/BOLA/injection capability demonstration",
}
_TARGET_DESCRIPTIONS = {
    "worldmonitor": (
        "Self-hosted instance of github.com/koala73/worldmonitor. Findings here are real, from the "
        "actual production codebase and its live self-hosted deployment."
    ),
    "fixture-app": (
        "Small, deliberately-vulnerable app the framework ships with (docker/fixture-app), used to "
        "demonstrate BOLA/IDOR, privilege-escalation, and injection detection end-to-end — worldmonitor's "
        "self-hosted mode has no role-based/object-ownership model to exercise those modules against."
    ),
}

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _severity_counts(findings: list[Finding]) -> OrderedDict:
    counts = OrderedDict((s.value, 0) for s in _SEVERITY_ORDER)
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return OrderedDict((k, v) for k, v in counts.items() if v > 0) or counts


def _sort_key(f: Finding):
    sev_rank = _SEVERITY_ORDER.index(f.severity) if f.severity in _SEVERITY_ORDER else len(_SEVERITY_ORDER)
    return (sev_rank, -(f.cvss_score or 0))


def build_report_context(findings: list[Finding], report_title: str = "World Monitor Security Assessment") -> dict:
    targets = sorted({f.target for f in findings})
    findings_by_target = {t: sorted([f for f in findings if f.target == t], key=_sort_key) for t in targets}
    per_target_severity_counts = {t: _severity_counts(findings_by_target[t]) for t in targets}

    confirmed_count = sum(1 for f in findings if f.status == "confirmed")
    unconfirmed_count = len(findings) - confirmed_count

    return dict(
        report_title=report_title,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        targets=targets,
        findings=findings,
        findings_by_target=findings_by_target,
        severity_counts=_severity_counts(findings),
        per_target_severity_counts=per_target_severity_counts,
        confirmed_count=confirmed_count,
        unconfirmed_count=unconfirmed_count,
        target_labels=_TARGET_LABELS,
        target_descriptions=_TARGET_DESCRIPTIONS,
        executive_summary_note=(
            "\"Confirmed\" findings were independently corroborated by at least two of: live dynamic "
            "observation, static source analysis, and cross-correlation between the two. "
            "\"Unconfirmed\" findings are single-signal leads (a static pattern match or a single dynamic "
            "probe) included for completeness and flagged for manual review rather than treated as proven."
        ),
    )


def render_html(findings: list[Finding], report_title: str = "World Monitor Security Assessment") -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template("report.html.j2")
    return template.render(**build_report_context(findings, report_title))


def render_pdf(html: str) -> bytes:
    buf = io.BytesIO()
    result = pisa.CreatePDF(io.StringIO(html), dest=buf)
    if result.err:
        raise RuntimeError(f"PDF generation failed with {result.err} error(s)")
    return buf.getvalue()


def generate_report(findings: list[Finding], out_dir: Path, report_title: str = "World Monitor Security Assessment",
                     base_filename: str = "security_assessment_report") -> dict[str, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / f"{base_filename}.json"
    html_path = out_dir / f"{base_filename}.html"
    pdf_path = out_dir / f"{base_filename}.pdf"

    json_path.write_text(findings_to_json(findings), encoding="utf-8")

    html = render_html(findings, report_title)
    html_path.write_text(html, encoding="utf-8")

    try:
        pdf_bytes = render_pdf(html)
        pdf_path.write_bytes(pdf_bytes)
    except Exception as exc:  # PDF rendering is a nice-to-have; HTML/JSON must never be blocked by it
        print(f"[report_generator] PDF generation failed, HTML/JSON still written: {exc}")
        pdf_path = None

    return {"json": json_path, "html": html_path, "pdf": pdf_path}
```

---

<a id="reporttemplatesreporthtmlj2"></a>
## `report/templates/report.html.j2`

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{{ report_title }}</title>
<style>
  /* Kept to a CSS2.1-ish subset (no flexbox/grid) so the same markup renders
     correctly both in a browser and through xhtml2pdf for the PDF export. */
  body { font-family: 'Segoe UI', Arial, Helvetica, sans-serif; color: #1a1a2e; margin: 0; padding: 0; background: #f4f5f7; font-size: 13px; }
  .page { max-width: 960px; margin: 0 auto; padding: 24px; background: #ffffff; }
  h1 { font-size: 24px; margin: 0 0 4px 0; color: #0a0f0a; }
  h2 { font-size: 18px; margin: 28px 0 10px 0; padding-bottom: 6px; border-bottom: 2px solid #1f2937; color: #0a0f0a; }
  h3 { font-size: 14px; margin: 0; }
  .subtitle { color: #555; margin-bottom: 18px; font-size: 12px; }
  .meta-table { width: 100%; border-collapse: collapse; margin-bottom: 18px; }
  .meta-table td { padding: 4px 8px; border: 1px solid #ddd; font-size: 12px; }
  .summary-table { width: 100%; border-collapse: collapse; margin-bottom: 12px; }
  .summary-table th, .summary-table td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; font-size: 12px; }
  .summary-table th { background: #1f2937; color: #ffffff; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; color: #ffffff; }
  .sev-critical { background: #7f1d1d; }
  .sev-high { background: #b91c1c; }
  .sev-medium { background: #b45309; }
  .sev-low { background: #1d4ed8; }
  .sev-info { background: #6b7280; }
  .status-confirmed { background: #065f46; }
  .status-unconfirmed { background: #78716c; }
  .finding { border: 1px solid #ddd; border-radius: 4px; margin-bottom: 14px; padding: 12px 14px; page-break-inside: avoid; }
  .finding-title { font-size: 14px; font-weight: bold; margin-bottom: 6px; }
  .finding-meta { margin-bottom: 8px; }
  .finding-meta span { margin-right: 6px; }
  .field-label { font-weight: bold; color: #374151; margin-top: 8px; display: block; }
  .field-body { margin: 2px 0 6px 0; color: #1f2937; }
  pre { background: #0f172a; color: #e2e8f0; padding: 8px 10px; border-radius: 4px; overflow-x: auto; font-size: 11px; white-space: pre-wrap; word-wrap: break-word; }
  code { font-family: 'Consolas', 'Courier New', monospace; }
  .target-banner { background: #0a0f0a; color: #ffffff; padding: 10px 14px; border-radius: 4px; margin: 26px 0 12px 0; }
  .target-banner .role { color: #9ca3af; font-size: 11px; }
  .grade { font-size: 28px; font-weight: bold; }
  .toc { font-size: 12px; }
  .toc a { color: #1d4ed8; text-decoration: none; }
  .small { font-size: 11px; color: #666; }
  .footer { margin-top: 30px; padding-top: 10px; border-top: 1px solid #ddd; font-size: 11px; color: #777; }
</style>
</head>
<body>
<div class="page">

  <h1>{{ report_title }}</h1>
  <div class="subtitle">Generated {{ generated_at }} &middot; White-Box Security Assessment Framework (SIH 2026, PS 26163)</div>

  <table class="meta-table">
    <tr><td><strong>Targets assessed</strong></td><td>{{ targets|join(', ') }}</td></tr>
    <tr><td><strong>Total findings</strong></td><td>{{ findings|length }}</td></tr>
    <tr><td><strong>Confirmed</strong></td><td>{{ confirmed_count }}</td></tr>
    <tr><td><strong>Unconfirmed / needs review</strong></td><td>{{ unconfirmed_count }}</td></tr>
  </table>

  <h2>Executive Summary</h2>
  <table class="summary-table">
    <tr><th>Severity</th><th>Count</th></tr>
    {% for sev, count in severity_counts.items() %}
    <tr><td><span class="badge sev-{{ sev }}">{{ sev|upper }}</span></td><td>{{ count }}</td></tr>
    {% endfor %}
  </table>
  <p class="small">{{ executive_summary_note }}</p>

  {% for target in targets %}
  <div class="target-banner">
    <h3>{{ target_labels.get(target, target) }}</h3>
    <div class="role">{{ target_descriptions.get(target, '') }}</div>
  </div>

  <table class="summary-table">
    <tr><th>Severity</th><th>Count</th></tr>
    {% for sev, count in per_target_severity_counts[target].items() %}
    <tr><td><span class="badge sev-{{ sev }}">{{ sev|upper }}</span></td><td>{{ count }}</td></tr>
    {% endfor %}
  </table>

  {% for finding in findings_by_target[target] %}
  <div class="finding">
    <div class="finding-title">{{ finding.title }}</div>
    <div class="finding-meta">
      <span class="badge sev-{{ finding.severity }}">{{ finding.severity|upper }}</span>
      <span class="badge status-{{ finding.status }}">{{ finding.status|upper }}</span>
      <span class="small">{{ finding.rule_id }} &middot; {{ finding.category }} &middot; confidence: {{ finding.confidence }}</span>
    </div>

    <span class="field-label">CVSS 3.1</span>
    <div class="field-body">{{ finding.cvss_score }} &mdash; <code>{{ finding.cvss_vector }}</code></div>

    <span class="field-label">Description</span>
    <div class="field-body">{{ finding.description }}</div>

    {% if finding.code_location %}
    <span class="field-label">Affected component (source)</span>
    <div class="field-body">
      {{ finding.code_location.file_path }}{% if finding.code_location.line_number %}:{{ finding.code_location.line_number }}{% endif %}
      {% if finding.code_location.snippet %}<pre><code>{{ finding.code_location.snippet }}</code></pre>{% endif %}
    </div>
    {% endif %}

    {% if finding.http_evidence %}
    <span class="field-label">Affected component (endpoint)</span>
    <div class="field-body">
      {% for ev in finding.http_evidence %}
        {{ ev.method }} {{ ev.url }} {% if ev.status_code %}&rarr; {{ ev.status_code }}{% endif %}{% if ev.role_used %} (as {{ ev.role_used }}){% endif %}<br>
      {% endfor %}
    </div>
    {% endif %}

    {% if finding.poc %}
    <span class="field-label">Reproduction / PoC</span>
    <pre><code>{{ finding.poc }}</code></pre>
    {% endif %}

    {% if finding.business_impact %}
    <span class="field-label">Business impact</span>
    <div class="field-body">{{ finding.business_impact }}</div>
    {% endif %}

    {% if finding.remediation %}
    <span class="field-label">Remediation</span>
    <div class="field-body">{{ finding.remediation }}</div>
    {% endif %}

    {% if finding.correlated_with %}
    <span class="field-label">Correlation</span>
    <div class="field-body small">Cross-confirmed with finding id(s): {{ finding.correlated_with|join(', ') }}</div>
    {% endif %}
  </div>
  {% endfor %}
  {% endfor %}

  <div class="footer">
    Generated by the worldmonitor-security-framework White-Box Security Assessment Framework.
    All dynamic testing was performed exclusively against locally-deployed, isolated instances — never against any live/production host.
  </div>

</div>
</body>
</html>
```

---

<a id="requirementstxt"></a>
## `requirements.txt`

```text
PyYAML==6.0.2
requests==2.32.3
tree-sitter==0.23.2
tree-sitter-language-pack==0.7.2
cvss==3.3
Jinja2==3.1.4
xhtml2pdf==0.2.16
fastapi==0.115.5
uvicorn[standard]==0.32.1
pip-audit==2.7.3
click==8.1.7
rich==13.9.4
```

---

<a id="runassessmentpy"></a>
## `run_assessment.py`

```python
#!/usr/bin/env python
"""White-Box Security Assessment Framework — CLI entry point.

    python run_assessment.py --target-config config/worldmonitor.yaml
    python run_assessment.py --target-config config/worldmonitor.yaml --target-config config/fixture.yaml
    python run_assessment.py --target-config config/fixture.yaml --sast-only
    python run_assessment.py --target-config config/worldmonitor.yaml --dast-only

Runs: load config(s) -> SAST -> DAST -> correlate -> CVSS score -> generate
PoCs -> write JSON/HTML/PDF report. Every target's base_url is validated as
local/docker-scoped by engine.common.config before any DAST probe can fire —
see that module's UnsafeTargetError for the guardrail this enforces.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from engine.common.config import UnsafeTargetError, load_scan_config
from engine.orchestrator import run_multi
from report.report_generator import generate_report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="White-Box Security Assessment Framework for the World Monitor application (SIH 2026, PS 26163).",
    )
    parser.add_argument(
        "--target-config", action="append", dest="target_configs", required=True,
        help="Path to a target YAML config (config/worldmonitor.yaml, config/fixture.yaml). Repeatable.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--sast-only", action="store_true", help="Run only the SAST modules.")
    mode.add_argument("--dast-only", action="store_true", help="Run only the DAST modules.")
    parser.add_argument("--out-dir", default="output", help="Directory to write the report into (default: output/).")
    parser.add_argument("--report-title", default="World Monitor Security Assessment",
                         help="Title shown at the top of the generated report.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    configs = []
    for path in args.target_configs:
        try:
            configs.append(load_scan_config(path))
        except UnsafeTargetError as exc:
            print(f"REFUSING to load {path}: {exc}", file=sys.stderr)
            return 2
        except (OSError, KeyError) as exc:
            print(f"Failed to load {path}: {exc}", file=sys.stderr)
            return 2

    for c in configs:
        print(f"Target loaded: {c.target.name}  (auth_profile={c.target.auth_profile}, "
              f"base_url={c.target.base_url or '(SAST-only, no base_url)'})", file=sys.stderr)

    findings = run_multi(configs, sast_only=args.sast_only, dast_only=args.dast_only)

    paths = generate_report(findings, Path(args.out_dir), report_title=args.report_title)

    print("\n=== Report written ===", file=sys.stderr)
    for kind, path in paths.items():
        print(f"  {kind}: {path if path else '(skipped)'}", file=sys.stderr)

    confirmed = sum(1 for f in findings if f.status == "confirmed")
    print(f"\n{len(findings)} findings total ({confirmed} confirmed) across {len(configs)} target(s).",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

---
