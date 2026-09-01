# NIST SSDF — Access Control & Auth Hygiene (OWASP A01 / A07)

These rules extend the NIST SSDF practice groups with checks for authorization
(OWASP A01: Broken Access Control) and authentication hygiene (OWASP A07:
Identification & Authentication Failures) beyond the baseline JWT/auth-middleware
checks in `api-security.md`.

## Auto-detection gate

The access-control checks below (missing auth middleware, IDOR heuristic,
admin-route-without-role-check) only fire on projects that appear to use
authentication — detected automatically from `package.json`/`requirements.txt`/
`Pipfile`/`pyproject.toml`/`setup.cfg` against a list of known auth libraries
(passport, flask-login, next-auth, pyjwt, etc.). This keeps them silent on
public APIs and internal tools that intentionally have no auth model. Set
`auth_scanning.enabled` to `true`/`false` in `config.json` or
`.claude/vibe-coding-guard.json` to force the gate open or shut manually. The
password-hashing, JWT-expiration, and session-cookie checks further below are
self-scoped — they only trigger on unambiguous password/JWT/session syntax —
and always run regardless of this gate.

## PW.9 — Authorization & Access Control
- **Never rely on an unguessable ID as access control.** A route that accepts
  an ID from the client and looks it up must also verify the authenticated
  user is allowed to access that specific resource (IDOR / OWASP A01)
- Filter database lookups by the current user's ID/ownership, or explicitly
  check `resource.owner_id == current_user.id` before returning data
- Protect admin/internal routes (`/admin/...`, `/internal/...`) with an
  explicit role or permission check — do not rely on the route being
  "unlisted" or assume only admins know the path
- Protect every mutation endpoint (POST/PUT/PATCH/DELETE) with an
  authentication dependency/middleware (see `api-security.md` PW.9)

## PW.7 — Password & Token Hygiene
- **Never hash passwords with a general-purpose digest** (SHA-256, SHA-512,
  SHA-1, MD5) — these are fast to compute, making offline brute-force and
  rainbow-table attacks practical against a leaked hash
- Use a password-safe KDF: bcrypt, scrypt, or argon2 (Python: `bcrypt.hashpw`
  / passlib; Node: the `bcrypt`/`argon2` packages)
- Always set a JWT expiration (`exp` claim / `expiresIn` option) — a token
  that never expires stays valid indefinitely if leaked
- Rotate JWT signing keys periodically

## PW.9 — Session & Cookie Security
- Set `HttpOnly` on session/auth cookies — without it, cookie values are
  readable by any JavaScript running on the page (XSS-based token theft)
- Set `Secure` on session/auth cookies — without it, the cookie can be sent
  over plain HTTP and intercepted
- Set `SameSite` (`Lax` or `Strict`) to limit cross-site cookie exposure
