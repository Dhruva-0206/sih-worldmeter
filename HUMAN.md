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
