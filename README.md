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
