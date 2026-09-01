#!/usr/bin/env bash
# Vibe Coding Guard — Auth & Access-Control scanner tests
# Covers project_uses_auth() detection, scan_auth_file detections (OWASP
# A01/A07), the auth_detected gate (both direct and via the missing-api-auth
# check in scan-api-security.sh), self-scoped checks being gate-independent,
# and end-to-end auto-detection/manual-override through the real hook.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Build a VCG_HOME that mirrors an install (used for the end-to-end hook tests).
TEST_VCG_HOME=$(mktemp -d)
cp -r "$PROJECT_DIR/lib" "$TEST_VCG_HOME/"
cp -r "$PROJECT_DIR/hooks" "$TEST_VCG_HOME/"
cp "$PROJECT_DIR/config.json" "$TEST_VCG_HOME/config.json"
for f in "$TEST_VCG_HOME/hooks/"*.sh "$TEST_VCG_HOME/lib/"*.sh; do
  sed -i '' "s|__VCG_HOME_PLACEHOLDER__|$TEST_VCG_HOME|g" "$f" 2>/dev/null || \
  sed -i "s|__VCG_HOME_PLACEHOLDER__|$TEST_VCG_HOME|g" "$f" 2>/dev/null || true
done
export VCG_HOME="$TEST_VCG_HOME"

WORK=$(mktemp -d)
trap "rm -rf '$TEST_VCG_HOME' '$WORK'" EXIT

HOOK="$TEST_VCG_HOME/hooks/post-tool-use.sh"
PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# ── Part 1: project_uses_auth() + scan_auth_file() direct unit tests ────────
source "$TEST_VCG_HOME/lib/common.sh"
source "$TEST_VCG_HOME/lib/scan-auth.sh"
source "$TEST_VCG_HOME/lib/scan-api-security.sh"
load_config ""
# common.sh enables `set -euo pipefail`; relax it here (helpers are called as
# bare statements and some greps intentionally return non-zero).
set +e +u
set +o pipefail

count_cat() { scan_auth_file "$1" "$2" | grep -c "\"category\":\"$3\""; }

echo ""
echo "=== Auth & Access-Control Scanner Tests ==="
echo ""
echo "--- Part 1a: project_uses_auth() detection ---"

mkdir -p "$WORK/noauth" "$WORK/npmauth" "$WORK/npmnoauth" "$WORK/pyauth" "$WORK/pynoauth"

# no manifest at all
project_uses_auth "$WORK/noauth"
[[ $? -eq 1 ]] && ok "no manifest → not detected (auto mode)" || bad "no manifest should not be detected"

# package.json declaring a known auth library
cat > "$WORK/npmauth/package.json" <<'JSON'
{"name":"x","dependencies":{"express":"^4.0.0","passport":"^0.6.0"}}
JSON
project_uses_auth "$WORK/npmauth"
[[ $? -eq 0 ]] && ok "package.json with passport → detected" || bad "package.json with passport should be detected"

# package.json without any auth library
cat > "$WORK/npmnoauth/package.json" <<'JSON'
{"name":"x","dependencies":{"express":"^4.0.0","lodash":"^4.0.0"}}
JSON
project_uses_auth "$WORK/npmnoauth"
[[ $? -eq 1 ]] && ok "package.json without auth lib → not detected" || bad "package.json without auth lib should not be detected"

# requirements.txt declaring a known auth library
cat > "$WORK/pyauth/requirements.txt" <<'TXT'
flask==2.3.0
flask-login==0.6.2
TXT
project_uses_auth "$WORK/pyauth"
[[ $? -eq 0 ]] && ok "requirements.txt with flask-login → detected" || bad "requirements.txt with flask-login should be detected"

# requirements.txt without any auth library
cat > "$WORK/pynoauth/requirements.txt" <<'TXT'
flask==2.3.0
requests==2.31.0
TXT
project_uses_auth "$WORK/pynoauth"
[[ $? -eq 1 ]] && ok "requirements.txt without auth lib → not detected" || bad "requirements.txt without auth lib should not be detected"

# manual override: mode=true wins even with no manifest
AUTH_SCANNING_MODE="true"
project_uses_auth "$WORK/noauth"
[[ $? -eq 0 ]] && ok "manual override enabled=true wins with no manifest" || bad "manual override enabled=true should win"
AUTH_SCANNING_MODE="auto"

# manual override: mode=false wins even with a declared auth library
AUTH_SCANNING_MODE="false"
project_uses_auth "$WORK/npmauth"
[[ $? -eq 1 ]] && ok "manual override enabled=false wins despite passport present" || bad "manual override enabled=false should win"
AUTH_SCANNING_MODE="auto"

echo ""
echo "--- Part 1b: scan_auth_file() gated checks (IDOR, admin-route) ---"

cat > "$WORK/idor_vuln.py" <<'PY'
from fastapi import APIRouter
router = APIRouter()

@router.get("/users/{user_id}/profile")
async def get_profile(user_id: int):
    user = db.session.query(User).get(user_id)
    return user
PY
[[ "$(count_cat "$WORK/idor_vuln.py" true idor-heuristic)" -ge 1 ]] \
  && ok "IDOR heuristic flagged (auth_detected=true)" || bad "IDOR heuristic missed"

cat > "$WORK/idor_safe.py" <<'PY'
from fastapi import APIRouter
router = APIRouter()

@router.get("/users/{user_id}/profile")
async def get_profile(user_id: int, current_user=Depends(get_current_user)):
    user = db.session.query(User).get(user_id)
    if user.owner_id != current_user.id:
        raise HTTPException(403)
    return user
PY
n=$(scan_auth_file "$WORK/idor_safe.py" "true" | grep -c "\"category\":\"idor-heuristic\"")
[[ "$n" -eq 0 ]] && ok "IDOR heuristic silent when ownership check present" || bad "IDOR heuristic false-positived on guarded route"

n=$(scan_auth_file "$WORK/idor_vuln.py" "false" | grep -c "\"category\":\"idor-heuristic\"")
[[ "$n" -eq 0 ]] && ok "IDOR heuristic gated off when auth_detected=false" || bad "IDOR heuristic fired despite auth_detected=false"

cat > "$WORK/admin_vuln.js" <<'JS'
router.delete('/admin/users/:id', (req, res) => {
  db.users.remove(req.params.id);
});
JS
[[ "$(count_cat "$WORK/admin_vuln.js" true admin-route-without-role-check)" -ge 1 ]] \
  && ok "admin-route-without-role-check flagged (auth_detected=true)" || bad "admin-route-without-role-check missed"

cat > "$WORK/admin_safe.js" <<'JS'
router.delete('/admin/users/:id', requireRole('admin'), (req, res) => {
  db.users.remove(req.params.id);
});
JS
n=$(scan_auth_file "$WORK/admin_safe.js" "true" | grep -c "\"category\":\"admin-route-without-role-check\"")
[[ "$n" -eq 0 ]] && ok "admin-route check silent when role check present" || bad "admin-route check false-positived on guarded route"

n=$(scan_auth_file "$WORK/admin_vuln.js" "false" | grep -c "\"category\":\"admin-route-without-role-check\"")
[[ "$n" -eq 0 ]] && ok "admin-route check gated off when auth_detected=false" || bad "admin-route check fired despite auth_detected=false"

echo ""
echo "--- Part 1c: scan_auth_file() self-scoped checks (always run) ---"

cat > "$WORK/pwhash_vuln.py" <<'PY'
import hashlib
def hash_password(raw_password):
    return hashlib.sha256(raw_password.encode()).hexdigest()
PY
[[ "$(count_cat "$WORK/pwhash_vuln.py" false weak-password-hashing)" -ge 1 ]] \
  && ok "weak-password-hashing flagged even with auth_detected=false (self-scoped)" || bad "weak-password-hashing missed"

cat > "$WORK/pwhash_safe.py" <<'PY'
import bcrypt
def hash_password(raw_password):
    return bcrypt.hashpw(raw_password.encode(), bcrypt.gensalt())
PY
n=$(scan_auth_file "$WORK/pwhash_safe.py" "false" | grep -c "\"category\":\"weak-password-hashing\"")
[[ "$n" -eq 0 ]] && ok "weak-password-hashing silent for bcrypt" || bad "weak-password-hashing false-positived on bcrypt"

cat > "$WORK/jwt_vuln.py" <<'PY'
import jwt
def make_token(user_id):
    payload = {"user_id": user_id}
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token
PY
[[ "$(count_cat "$WORK/jwt_vuln.py" false jwt-missing-expiration)" -ge 1 ]] \
  && ok "jwt-missing-expiration flagged (self-scoped)" || bad "jwt-missing-expiration missed"

# Regression case for the bidirectional-window fix: payload built with `exp`
# BEFORE the encode() call is the common safe pattern — a forward-only window
# would false-positive here.
cat > "$WORK/jwt_safe.py" <<'PY'
import jwt
from datetime import datetime, timedelta
def make_token(user_id):
    payload = {"user_id": user_id, "exp": datetime.utcnow() + timedelta(hours=1)}
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token
PY
n=$(scan_auth_file "$WORK/jwt_safe.py" "false" | grep -c "\"category\":\"jwt-missing-expiration\"")
[[ "$n" -eq 0 ]] && ok "jwt-missing-expiration silent when exp set before encode() (bidirectional window)" || bad "jwt-missing-expiration false-positived on safe payload-before-encode pattern"

cat > "$WORK/cookie_vuln.py" <<'PY'
def login(response):
    response.set_cookie("session_id", "abc123")
PY
[[ "$(count_cat "$WORK/cookie_vuln.py" false session-cookie-missing-flags)" -ge 1 ]] \
  && ok "session-cookie-missing-flags flagged (self-scoped)" || bad "session-cookie-missing-flags missed"

cat > "$WORK/cookie_safe.py" <<'PY'
def login(response):
    response.set_cookie("session_id", "abc123", httponly=True, secure=True, samesite="Lax")
PY
n=$(scan_auth_file "$WORK/cookie_safe.py" "false" | grep -c "\"category\":\"session-cookie-missing-flags\"")
[[ "$n" -eq 0 ]] && ok "session-cookie-missing-flags silent when flags set" || bad "session-cookie-missing-flags false-positived on safe cookie"

echo ""
echo "--- Part 1d: scan-api-security.sh missing-api-auth gate ---"

count_api_cat() { scan_api_security_file "$1" "$2" | grep -c "\"category\":\"$3\""; }

cat > "$WORK/route_vuln.js" <<'JS'
const express = require('express');
const app = express();
app.post('/items', (req, res) => {
  res.json({ status: 'created' });
});
JS
[[ "$(count_api_cat "$WORK/route_vuln.js" true missing-api-auth)" -ge 1 ]] \
  && ok "missing-api-auth flagged when auth_detected=true" || bad "missing-api-auth missed when auth_detected=true"

n=$(scan_api_security_file "$WORK/route_vuln.js" "false" | grep -c "\"category\":\"missing-api-auth\"")
[[ "$n" -eq 0 ]] && ok "missing-api-auth gated off when auth_detected=false" || bad "missing-api-auth fired despite auth_detected=false"

n=$(scan_api_security_file "$WORK/route_vuln.js" | grep -c "\"category\":\"missing-api-auth\"")
[[ "$n" -eq 0 ]] && ok "missing-api-auth defaults to gated off when 2nd arg omitted" || bad "missing-api-auth should default to gated off"

# ── Part 2: end-to-end auto-detection + manual override (real hook) ─────────
echo ""
echo "--- Part 2: auto-detection + manual override (end-to-end) ---"
mkdir -p "$WORK/e2e/.claude"

run_hook() { # file_path cwd → prints EXIT code
  jq -n --arg fp "$1" --arg cwd "$2" \
    '{tool_name:"Write", tool_input:{file_path:$fp}, tool_response:{success:true}, session_id:"a", cwd:$cwd}' \
    | bash "$HOOK" >/dev/null 2>/dev/null; echo $?
}

cat > "$WORK/e2e/vuln_admin.js" <<'JS'
router.delete('/admin/users/:id', (req, res) => {
  db.users.remove(req.params.id);
});
JS
printf '{"analysis_mode":"fast"}\n' > "$WORK/e2e/.claude/vibe-coding-guard.json"

rc=$(run_hook "$WORK/e2e/vuln_admin.js" "$WORK/e2e")
[[ "$rc" -eq 0 ]] && ok "auto mode, no manifest: admin-route not flagged (exit 0)" || bad "auto mode, no manifest: expected exit 0, got $rc"

cat > "$WORK/e2e/package.json" <<'JSON'
{"name":"x","dependencies":{"passport":"^0.6.0"}}
JSON
rc=$(run_hook "$WORK/e2e/vuln_admin.js" "$WORK/e2e")
[[ "$rc" -eq 2 ]] && ok "auto mode, passport declared: admin-route flagged (exit 2)" || bad "auto mode, passport declared: expected exit 2, got $rc"

# Manual override (JSON boolean false) wins over auto-detection despite passport
printf '{"analysis_mode":"fast","auth_scanning":{"enabled":false}}\n' > "$WORK/e2e/.claude/vibe-coding-guard.json"
rc=$(run_hook "$WORK/e2e/vuln_admin.js" "$WORK/e2e")
[[ "$rc" -eq 0 ]] && ok "manual override enabled=false wins over auto-detection (exit 0)" || bad "manual override enabled=false: expected exit 0, got $rc"

# Self-scoped check still fires even with no auth signal anywhere
printf '{"analysis_mode":"fast"}\n' > "$WORK/e2e/.claude/vibe-coding-guard.json"
rm -f "$WORK/e2e/package.json"
cat > "$WORK/e2e/pwhash.py" <<'PY'
import hashlib
def hash_password(raw_password):
    return hashlib.sha256(raw_password.encode()).hexdigest()
PY
rc=$(run_hook "$WORK/e2e/pwhash.py" "$WORK/e2e")
[[ "$rc" -eq 2 ]] && ok "self-scoped weak-password-hashing fires with no auth signal at all (exit 2)" || bad "self-scoped check: expected exit 2, got $rc"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
echo ""
[[ $FAIL -gt 0 ]] && exit 1
exit 0
