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
