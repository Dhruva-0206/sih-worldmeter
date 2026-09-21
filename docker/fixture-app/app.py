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
