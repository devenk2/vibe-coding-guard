#!/usr/bin/env bash
# Vibe Coding Guard — Auth & Access-Control Scanner
# Adds coverage for OWASP A01 (Broken Access Control) and A07 (Identification
# & Authentication Failures) beyond the baseline missing-auth-middleware/JWT
# checks already in scan-api-security.sh.
#
# Two tiers of checks:
#   - Gated (only meaningful if the project has an auth/authz model at all):
#     IDOR heuristic, admin-route-without-role-check. These take a precomputed
#     `auth_detected` flag ("true"/"false", from project_uses_auth() in
#     common.sh, computed once per hook invocation) so they stay silent on
#     projects that don't use/need auth (public APIs, internal tools).
#   - Self-scoped (always run): weak-password-hashing, jwt-missing-expiration,
#     session-cookie-missing-flags. These only trigger on unambiguous
#     password-hashing/JWT-signing/session-config syntax, so they're
#     inherently no-noise on non-auth projects — no gating needed.
#
# NOTE on implementation style — bash 3.2 local-in-loop bug: this function
# runs ~10 pattern-matching loops, most reading a multi-line "window" of
# source via `sed -n` for context. On this project's target shell (macOS's
# stock bash 3.2), re-declaring `local x; x=$(multi-line command substitution)`
# on EVERY iteration of a `while` loop that matches 2+ times was observed to
# leak a stray literal "x=$'...'" line onto stdout starting from the 2nd
# match — corrupting the JSON-lines output downstream hooks/tests parse. This
# reproduces even with a uniquely-named variable used only in one loop, so
# it's not a cross-loop name collision — it's specifically repeated `local`
# re-declaration within one loop body. Confirmed via stress-testing (15x
# repeated runs against a file matching every check at once) both before and
# after the fix. The same latent bug was found in two pre-existing checks
# elsewhere in this codebase while investigating (scan-api-security.sh's
# FastAPI missing-api-auth check, scan-llm.sh's LLM10 check) — both fixed
# alongside this file, since neither had previously been exercised by a
# fixture with 2+ matches. The fix, applied to every loop below: declare the
# local variable ONCE immediately before the `while`, then only assign inside
# the loop body (no `local` keyword there). Grep-result iteration also reads
# from a real temp file rather than `< <(...)` process substitution, out of
# the same abundance of caution for this shell's quirks under heavy
# sequential use within one function call.
#
# Handles Python and JavaScript/TypeScript in one function, mirroring
# scan-api-security.sh and scan-llm.sh. Outputs JSON findings (one per line).

# Usage: scan_auth_file <file> <auth_detected: "true"|"false">
scan_auth_file() {
  local file="$1"
  local auth_detected="${2:-false}"
  local _vcg_auth_tmp
  _vcg_auth_tmp=$(mktemp)

  # =====================================================================
  # === GATED CHECKS (require auth_detected == true) ===
  # =====================================================================

  # --- IDOR heuristic (OWASP A01) ---
  # A route with an ID-shaped path parameter whose handler reaches a DB
  # lookup with no visible ownership/authorization check nearby.
  if [[ "$auth_detected" == "true" && "${AUTH_CHECK_IDOR:-true}" == "true" ]]; then
    # NOTE: quote-character classes below use literal ["'] (via double-quoted
    # bash strings) rather than \x27 hex escapes for the apostrophe — this
    # project's target shell (stock macOS bash 3.2 + BSD grep) does not
    # support \x27 as a hex escape inside grep -E, even though several
    # pre-existing checks elsewhere in this codebase rely on it (a latent bug
    # worth a separate fix — see final summary).
    local ID_ROUTE_PY="@(app|router)\.(get|post|put|patch|delete)\s*\(\s*[\"'][^\"']*(\{[a-zA-Z_]*[Ii]d[a-zA-Z_]*\}|<[a-zA-Z_:]*[Ii]d[a-zA-Z_]*>)"
    local ID_ROUTE_JS="\.(get|post|put|patch|delete)\s*\(\s*[\"'\`][^\"'\`]*/:[a-zA-Z_]*[Ii]d\b"
    local DB_LOOKUP='(\.query\s*\(|\.get\s*\(|\.filter(_by)?\s*\(|objects\.get\s*\(|session\.query\s*\(|db\.session\.query\s*\(|\.find_by_id\s*\(|findById\s*\(|\.findOne\s*\(|\.find\s*\(|SELECT\b.*\bFROM\b)'
    local OWNERSHIP='(current_user|req\.user|request\.user|session\[.?user|g\.user|\.user_id\s*==|owner\s*==|\.owner\b|owner_id|userId\s*===|req\.session\.user)'
    local idor_window

    grep -nE "$ID_ROUTE_PY" "$file" 2>/dev/null | grep -v '^\s*#' > "$_vcg_auth_tmp" || true
    while IFS=: read -r line_num _; do
      idor_window=$(sed -n "${line_num},$((line_num + 15))p" "$file" 2>/dev/null)
      echo "$idor_window" | grep -qE "$DB_LOOKUP" || continue
      echo "$idor_window" | grep -qiE "$OWNERSHIP" && continue
      emit_finding "MEDIUM" "PW.9" "PW" "idor-heuristic" \
        "$file" "$line_num" "id-param route → DB lookup, no ownership check" \
        "Route takes an ID path parameter and reaches a database lookup with no visible ownership/authorization check — a caller could access another user's resource by changing the ID (IDOR, OWASP A01)." \
        "Verify the authenticated user owns/may access the resource before returning it: filter the query by the current user's ID, or explicitly check resource.owner_id == current_user.id"
    done < "$_vcg_auth_tmp"

    grep -nE "$ID_ROUTE_JS" "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' > "$_vcg_auth_tmp" || true
    while IFS=: read -r line_num _; do
      idor_window=$(sed -n "${line_num},$((line_num + 15))p" "$file" 2>/dev/null)
      echo "$idor_window" | grep -qE "$DB_LOOKUP" || continue
      echo "$idor_window" | grep -qiE "$OWNERSHIP" && continue
      emit_finding "MEDIUM" "PW.9" "PW" "idor-heuristic" \
        "$file" "$line_num" "id-param route → DB lookup, no ownership check" \
        "Route takes an ID path parameter and reaches a database lookup with no visible ownership/authorization check — a caller could access another user's resource by changing the ID (IDOR, OWASP A01)." \
        "Verify the authenticated user owns/may access the resource before returning it: filter the query by the current user's ID, or explicitly check resource.ownerId === req.user.id"
    done < "$_vcg_auth_tmp"
  fi

  # --- Admin/internal route without role check (OWASP A01) ---
  if [[ "$auth_detected" == "true" && "${AUTH_CHECK_ADMIN_ROLE:-true}" == "true" ]]; then
    local ADMIN_ROUTE_PY="@(app|router)\.(get|post|put|patch|delete)\s*\(\s*[\"'][^\"']*/(admin|internal|staff|superuser)(/|[\"'])"
    local ADMIN_ROUTE_JS="\.(get|post|put|patch|delete)\s*\(\s*[\"'\`][^\"'\`]*/(admin|internal|staff|superuser)(/|[\"'\`])"
    local ROLE_CHECK='(is_admin|require_role|has_permission|check_permission|role_required|permission_classes|IsAdminUser|admin_required|current_user\.is_admin|req\.user\.role|isAdmin|requireRole|checkRole|hasRole|RBAC|roles_required|permission_required)'
    local admin_window

    grep -nE "$ADMIN_ROUTE_PY" "$file" 2>/dev/null | grep -v '^\s*#' > "$_vcg_auth_tmp" || true
    while IFS=: read -r line_num _; do
      admin_window=$(sed -n "${line_num},$((line_num + 8))p" "$file" 2>/dev/null)
      echo "$admin_window" | grep -qiE "$ROLE_CHECK" && continue
      emit_finding "MEDIUM" "PW.9" "PW" "admin-route-without-role-check" \
        "$file" "$line_num" "/admin route without role/permission check" \
        "Route path suggests an administrative/internal endpoint but no role or permission check is visible in the handler — any authenticated (or unauthenticated) user could reach admin functionality (OWASP A01)." \
        "Add an explicit role/permission check (e.g. Depends(require_admin), @admin_required, req.user.role === 'admin') before performing the admin action"
    done < "$_vcg_auth_tmp"

    grep -nE "$ADMIN_ROUTE_JS" "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' > "$_vcg_auth_tmp" || true
    while IFS=: read -r line_num _; do
      admin_window=$(sed -n "${line_num},$((line_num + 8))p" "$file" 2>/dev/null)
      echo "$admin_window" | grep -qiE "$ROLE_CHECK" && continue
      emit_finding "MEDIUM" "PW.9" "PW" "admin-route-without-role-check" \
        "$file" "$line_num" "/admin route without role/permission check" \
        "Route path suggests an administrative/internal endpoint but no role or permission check is visible in the handler — any authenticated (or unauthenticated) user could reach admin functionality (OWASP A01)." \
        "Add an explicit role/permission check (e.g. requireRole('admin'), req.user.role === 'admin') before performing the admin action"
    done < "$_vcg_auth_tmp"
  fi

  # =====================================================================
  # === SELF-SCOPED CHECKS (always run — no auth_detected gate) ===
  # =====================================================================

  # --- Weak password hashing (OWASP A07) ---
  # A password-named variable hashed with a general-purpose digest instead of
  # a password-safe KDF. Backward-only window: the password variable is
  # declared/referenced before the hash call, not after.
  if [[ "${AUTH_CHECK_WEAK_PW_HASH:-true}" == "true" ]]; then
    local PW_TOKEN='(password|passwd|pwd)'
    local WEAK_HASH_PY="(hashlib\.(sha256|sha512|sha1|md5)\s*\(|hashlib\.new\s*\(\s*[\"'](sha256|sha512|sha1|md5))"
    local WEAK_HASH_JS="crypto\.createHash\s*\(\s*[\"'](sha256|sha512|sha1|md5)[\"']"
    local pwhash_win_start
    local pwhash_window

    grep -nE "$WEAK_HASH_PY" "$file" 2>/dev/null | grep -v '^\s*#' > "$_vcg_auth_tmp" || true
    while IFS=: read -r line_num _; do
      pwhash_win_start=$(( line_num > 6 ? line_num - 6 : 1 ))
      pwhash_window=$(sed -n "${pwhash_win_start},${line_num}p" "$file" 2>/dev/null)
      echo "$pwhash_window" | grep -qiE "$PW_TOKEN" || continue
      emit_finding "MEDIUM" "PW.7" "PW" "weak-password-hashing" \
        "$file" "$line_num" "password hashed with sha256/sha1/md5" \
        "A password appears to be hashed with a general-purpose digest instead of a password-safe algorithm. General digests are fast to compute, making offline brute-force/rainbow-table attacks practical against a leaked hash (OWASP A07)." \
        "Use a password-safe KDF: bcrypt, scrypt, or argon2 (Python: bcrypt.hashpw / passlib). Never hash passwords with a general-purpose digest alone, even with a salt"
    done < "$_vcg_auth_tmp"

    grep -nE "$WEAK_HASH_JS" "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' > "$_vcg_auth_tmp" || true
    while IFS=: read -r line_num _; do
      pwhash_win_start=$(( line_num > 6 ? line_num - 6 : 1 ))
      pwhash_window=$(sed -n "${pwhash_win_start},${line_num}p" "$file" 2>/dev/null)
      echo "$pwhash_window" | grep -qiE "$PW_TOKEN" || continue
      emit_finding "MEDIUM" "PW.7" "PW" "weak-password-hashing" \
        "$file" "$line_num" "password hashed with sha256/sha1/md5" \
        "A password appears to be hashed with a general-purpose digest instead of a password-safe algorithm. General digests are fast to compute, making offline brute-force/rainbow-table attacks practical against a leaked hash (OWASP A07)." \
        "Use a password-safe KDF: bcrypt or argon2 (Node: the bcrypt or argon2 packages). Never hash passwords with crypto.createHash alone, even with a salt"
    done < "$_vcg_auth_tmp"
  fi

  # --- JWT missing expiration (OWASP A07) ---
  # Bidirectional window: the payload is very commonly built on lines BEFORE
  # the encode/sign call (payload = {"exp": ...}; jwt.encode(payload, ...)),
  # so a forward-only window would false-positive on that safe, common case.
  if [[ "${AUTH_CHECK_JWT_EXPIRATION:-true}" == "true" ]]; then
    local jwt_win_start
    local jwt_window

    grep -nE 'jwt\.(encode|sign)\s*\(' "$file" 2>/dev/null | grep -vE '^\s*(#|//|\*)' > "$_vcg_auth_tmp" || true
    while IFS=: read -r line_num _; do
      jwt_win_start=$(( line_num > 10 ? line_num - 10 : 1 ))
      jwt_window=$(sed -n "${jwt_win_start},$((line_num + 3))p" "$file" 2>/dev/null)
      if ! echo "$jwt_window" | grep -qE "(['\"]exp['\"]\s*[:=]|expiresIn\s*[:=]|\.exp\s*=)"; then
        emit_finding "LOW" "PW.7" "PW" "jwt-missing-expiration" \
          "$file" "$line_num" "jwt.encode/jwt.sign without exp claim" \
          "A JWT is issued with no visible expiration claim — tokens that never expire remain valid indefinitely if leaked, widening the blast radius of any compromise (OWASP A07)." \
          "Always set an expiration: include an 'exp' claim in the payload (Python) or pass { expiresIn: '1h' } (Node jsonwebtoken)"
      fi
    done < "$_vcg_auth_tmp"
  fi

  # --- Session/cookie missing security flags (OWASP A07) ---
  if [[ "${AUTH_CHECK_SESSION_COOKIE:-true}" == "true" ]]; then
    local cookie_window
    local cookie_missing

    # Python: response.set_cookie(...) missing httponly/secure
    grep -nE '\.set_cookie\s*\(' "$file" 2>/dev/null | grep -v '^\s*#' > "$_vcg_auth_tmp" || true
    while IFS=: read -r line_num _; do
      cookie_window=$(sed -n "${line_num},$((line_num + 3))p" "$file" 2>/dev/null)
      cookie_missing=""
      echo "$cookie_window" | grep -qiE 'httponly\s*=\s*True' || cookie_missing="httponly"
      echo "$cookie_window" | grep -qiE '\bsecure\s*=\s*True' || cookie_missing="${cookie_missing:+$cookie_missing, }secure"
      [[ -n "$cookie_missing" ]] && emit_finding "LOW" "PW.9" "PW" "session-cookie-missing-flags" \
        "$file" "$line_num" "set_cookie() missing $cookie_missing" \
        "A cookie is set without the $cookie_missing flag(s) — without HttpOnly it's readable by JavaScript (XSS token theft); without Secure it can be sent over plain HTTP (OWASP A07)." \
        "Set both flags: response.set_cookie(..., httponly=True, secure=True, samesite='Lax')"
    done < "$_vcg_auth_tmp"

    # JS: res.cookie(...) missing httpOnly/secure
    grep -nE '\bres\.cookie\s*\(' "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' > "$_vcg_auth_tmp" || true
    while IFS=: read -r line_num _; do
      cookie_window=$(sed -n "${line_num},$((line_num + 3))p" "$file" 2>/dev/null)
      cookie_missing=""
      echo "$cookie_window" | grep -qE 'httpOnly\s*:\s*true' || cookie_missing="httpOnly"
      echo "$cookie_window" | grep -qE '\bsecure\s*:\s*true' || cookie_missing="${cookie_missing:+$cookie_missing, }secure"
      [[ -n "$cookie_missing" ]] && emit_finding "LOW" "PW.9" "PW" "session-cookie-missing-flags" \
        "$file" "$line_num" "res.cookie() missing $cookie_missing" \
        "A cookie is set without the $cookie_missing flag(s) — without httpOnly it's readable by JavaScript (XSS token theft); without secure it can be sent over plain HTTP (OWASP A07)." \
        "Set both flags: res.cookie('name', value, { httpOnly: true, secure: true, sameSite: 'lax' })"
    done < "$_vcg_auth_tmp"

    # JS: express-session config block missing httpOnly on its cookie option
    # (single finding per file — this is app-level config, like the existing
    # missing-rate-limit/missing-security-headers checks in scan-api-security.sh)
    local session_line
    session_line=$(grep -nE '\bsession\s*\(\s*\{' "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' | head -1 | cut -d: -f1 || true)
    if [[ -n "$session_line" ]]; then
      local session_window
      session_window=$(sed -n "${session_line},$((session_line + 12))p" "$file" 2>/dev/null)
      if ! echo "$session_window" | grep -qE 'httpOnly\s*:\s*true'; then
        emit_finding "LOW" "PW.9" "PW" "session-cookie-missing-flags" \
          "$file" "$session_line" "session() config without httpOnly cookie flag" \
          "Session middleware is configured without httpOnly set on its cookie — the session cookie is readable by JavaScript, widening XSS-based session theft (OWASP A07)." \
          "Set cookie: { httpOnly: true, secure: true, sameSite: 'lax' } in the session() configuration"
      fi
    fi
  fi

  rm -f "$_vcg_auth_tmp"
  return 0
}
