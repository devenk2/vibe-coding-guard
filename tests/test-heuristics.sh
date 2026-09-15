#!/usr/bin/env bash
# Vibe Coding Guard — Trigger/precision heuristics tests
# Covers: test-file skip, security-relevant coverage trigger, secret precision
# (empty RHS, template/example files).
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Build a VCG_HOME that mirrors an install, keeping analysis_mode=hybrid so the
# security-relevant coverage trigger (hybrid-only) is exercised end-to-end.
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

ok()   { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# ── Part 1: pure helper unit tests ──────────────────────────────────────────
# Load config the same way the hook does, so the pattern vars come from config.json.
source "$TEST_VCG_HOME/lib/common.sh"
source "$TEST_VCG_HOME/lib/scan-general.sh"
load_config ""
# common.sh enables `set -euo pipefail`, which suits the hook (it calls these
# helpers inside `if`/`&&` conditions) but not this test, which calls them as
# bare statements and expects non-zero returns. Relax the strict flags here.
set +e +u
set +o pipefail

assert_rc() { # description expected_rc actual_rc
  if [[ "$2" -eq "$3" ]]; then ok "$1"; else bad "$1 (expected rc=$2, got $3)"; fi
}

echo ""
echo "=== Heuristics Tests ==="
echo ""
echo "--- is_test_file ---"
is_test_file "/proj/test_config.py";        assert_rc "test_config.py is a test file" 0 $?
is_test_file "/proj/config_test.py";        assert_rc "config_test.py is a test file" 0 $?
is_test_file "/proj/api.spec.ts";           assert_rc "api.spec.ts is a test file" 0 $?
is_test_file "/proj/tests/helpers.py";      assert_rc "file under /tests/ is a test file" 0 $?
is_test_file "/proj/__tests__/a.js";        assert_rc "file under /__tests__/ is a test file" 0 $?
is_test_file "/proj/config.py";             assert_rc "config.py is NOT a test file" 1 $?

echo ""
echo "--- is_security_relevant_file ---"
is_security_relevant_file "/proj/config.py";        assert_rc "config.py is security-relevant" 0 $?
is_security_relevant_file "/proj/logging_setup.py"; assert_rc "logging_setup.py is security-relevant" 0 $?
is_security_relevant_file "/proj/app/auth/jwt.py";  assert_rc "auth path is security-relevant" 0 $?
is_security_relevant_file "/proj/rankings.py";      assert_rc "rankings.py is NOT security-relevant" 1 $?

echo ""
echo "--- is_vcg_config_file / is_security_relevant_file override-proofing ---"
is_vcg_config_file "/proj/.claude/vibe-coding-guard.json"; assert_rc "project-local vcg config is recognized" 0 $?
is_vcg_config_file "$VCG_HOME/config.json";                assert_rc "global install config is OUT of scope (not agent-writable mid-session)" 1 $?
is_vcg_config_file "/proj/other.json";                     assert_rc "unrelated json is NOT recognized" 1 $?
# Even with SECURITY_RELEVANT_PATTERNS overridden to something that would
# never match the vcg config path, it must still be treated as relevant —
# this is the exact bypass a hostile project config could otherwise use.
SECURITY_RELEVANT_PATTERNS=$'zzz-nonmatching-pattern'
is_security_relevant_file "/proj/.claude/vibe-coding-guard.json"
assert_rc "vcg config stays security-relevant even if patterns list is hostile" 0 $?
load_config ""

echo ""
echo "--- scan_vcg_config_file: weakening detection ---"
printf '{"analysis_mode": "fast"}\n' > "$WORK/weak1.json"
n=$(scan_vcg_config_file "$WORK/weak1.json" | wc -l | tr -d ' ')
[[ "$n" -ge 1 ]] && ok "analysis_mode=fast is flagged" || bad "analysis_mode=fast NOT flagged"

printf '{"auth_scanning": {"enabled": false}}\n' > "$WORK/weak2.json"
n=$(scan_vcg_config_file "$WORK/weak2.json" | wc -l | tr -d ' ')
[[ "$n" -ge 1 ]] && ok "auth_scanning.enabled=false is flagged" || bad "auth_scanning.enabled=false NOT flagged"

printf '{"blocking_severity": "LOW"}\n' > "$WORK/weak3.json"
n=$(scan_vcg_config_file "$WORK/weak3.json" | wc -l | tr -d ' ')
[[ "$n" -ge 1 ]] && ok "blocking_severity=LOW is flagged" || bad "blocking_severity=LOW NOT flagged"

printf '{"version": "1.0.0", "blocking_severity": "MEDIUM"}\n' > "$WORK/clean.json"
n=$(scan_vcg_config_file "$WORK/clean.json" | wc -l | tr -d ' ')
[[ "$n" -eq 0 ]] && ok "unmodified-looking config produces no findings" || bad "clean config flagged ($n findings)"

mkdir -p "$WORK/.claude"
printf '{"ignore_paths": [".claude", "src"]}\n' > "$WORK/.claude/vibe-coding-guard.json"
n=$(scan_vcg_config_file "$WORK/.claude/vibe-coding-guard.json" | wc -l | tr -d ' ')
[[ "$n" -ge 1 ]] && ok "project-local ignore_paths addition is flagged" || bad "ignore_paths addition NOT flagged"

# Inverted-logic regression: false on these two keys means MORE scanning,
# not less — must never be flagged as "weakened".
printf '{"doc_scanning": {"secrets_only": false}}\n' > "$WORK/hardened1.json"
n=$(scan_vcg_config_file "$WORK/hardened1.json" | wc -l | tr -d ' ')
[[ "$n" -eq 0 ]] && ok "doc_scanning.secrets_only=false (more scanning) is NOT flagged" || bad "doc_scanning.secrets_only=false wrongly flagged ($n findings)"

printf '{"test_scanning": {"skip_tests": false}}\n' > "$WORK/hardened2.json"
n=$(scan_vcg_config_file "$WORK/hardened2.json" | wc -l | tr -d ' ')
[[ "$n" -eq 0 ]] && ok "test_scanning.skip_tests=false (more scanning) is NOT flagged" || bad "test_scanning.skip_tests=false wrongly flagged ($n findings)"

echo ""
echo "--- scan_vcg_config_file: _vcg_acknowledged suppression ---"
printf '{"analysis_mode": "fast", "_vcg_acknowledged": ["analysis_mode"]}\n' > "$WORK/acked1.json"
n=$(scan_vcg_config_file "$WORK/acked1.json" | wc -l | tr -d ' ')
[[ "$n" -eq 0 ]] && ok "acknowledged analysis_mode=fast produces no finding" || bad "acknowledged analysis_mode=fast still flagged ($n findings)"

printf '{"analysis_mode": "fast", "auth_scanning": {"enabled": false}, "_vcg_acknowledged": ["analysis_mode"]}\n' > "$WORK/acked2.json"
n=$(scan_vcg_config_file "$WORK/acked2.json" | wc -l | tr -d ' ')
[[ "$n" -eq 1 ]] && ok "acknowledging one key leaves an unacknowledged key still flagged" || bad "expected exactly 1 finding, got $n"

printf '{"analysis_mode": "fast", "auth_scanning": {"enabled": false}, "_vcg_acknowledged": ["analysis_mode", "auth_scanning.enabled"]}\n' > "$WORK/acked3.json"
n=$(scan_vcg_config_file "$WORK/acked3.json" | wc -l | tr -d ' ')
[[ "$n" -eq 0 ]] && ok "acknowledging both keys independently silences both" || bad "expected 0 findings, got $n"

echo ""
echo "--- end-to-end: vcg config bypass attempts are still scanned ---"
mkdir -p "$WORK/proj2/.claude"
run_hook_cwd() { # file_path cwd  → prints EXIT code
  jq -n --arg fp "$1" --arg cwd "$2" \
    '{tool_name:"Write", tool_input:{file_path:$fp}, tool_response:{success:true}, session_id:"h", cwd:$cwd}' \
    | bash "$HOOK" >/dev/null 2>/dev/null; echo $?
}
# Even in `fast` mode (no LLM calls at all), a weakening edit to the vcg
# config itself must still produce a regex-level finding (exit 2).
printf '{"analysis_mode": "fast", "auth_scanning": {"enabled": false}}\n' > "$WORK/proj2/.claude/vibe-coding-guard.json"
rc=$(run_hook_cwd "$WORK/proj2/.claude/vibe-coding-guard.json" "$WORK/proj2")
assert_rc "weakened vcg config is flagged even under its own fast mode" 2 "$rc"

# analysis_mode=fast alone (a legitimate, documented tradeoff) must still
# surface once, unacknowledged — then go quiet once acknowledged, with no
# LLM fallback to catch it since fast mode has no LLM step at all.
printf '{"analysis_mode": "fast"}\n' > "$WORK/proj2/.claude/vibe-coding-guard.json"
rc=$(run_hook_cwd "$WORK/proj2/.claude/vibe-coding-guard.json" "$WORK/proj2")
assert_rc "unacknowledged analysis_mode=fast alone still surfaces (exit 2)" 2 "$rc"

printf '{"analysis_mode": "fast", "_vcg_acknowledged": ["analysis_mode"]}\n' > "$WORK/proj2/.claude/vibe-coding-guard.json"
rc=$(run_hook_cwd "$WORK/proj2/.claude/vibe-coding-guard.json" "$WORK/proj2")
assert_rc "acknowledged analysis_mode=fast alone is silent (exit 0)" 0 "$rc"

# The global install config must NOT get vcg-config treatment at all.
printf '{"analysis_mode": "fast", "auth_scanning": {"enabled": false}}\n' > "$WORK/global_config_copy.json"
cp "$WORK/global_config_copy.json" "$VCG_HOME/config.json"
rc=$(run_hook_cwd "$VCG_HOME/config.json" "$WORK/proj2")
assert_rc "global install config write is NOT scanned as vcg config (exit 0)" 0 "$rc"
cp "$PROJECT_DIR/config.json" "$VCG_HOME/config.json"

echo ""
echo "--- secret precision (scan_secrets_file) ---"
# Empty RHS in a real .env must NOT flag
printf 'OPENAI_API_KEY=\nDB_PASSWORD=""\n' > "$WORK/.env"
n=$(scan_secrets_file "$WORK/.env" | wc -l | tr -d ' ')
[[ "$n" -eq 0 ]] && ok "empty-RHS .env keys produce no findings" || bad "empty-RHS .env flagged ($n findings)"

# A real value in a real .env MUST flag
printf 'DATABASE_URL=postgres://admin:S3cr3tPass@db.internal/prod\n' > "$WORK/.env"
n=$(scan_secrets_file "$WORK/.env" | wc -l | tr -d ' ')
[[ "$n" -ge 1 ]] && ok "real .env credential still flagged" || bad "real .env credential missed"

# Template/example file: naive KEY= heuristic suppressed
printf 'OPENAI_API_KEY=sk_placeholder_here\nDATABASE_URL=postgres://user:pass@localhost/db\n' > "$WORK/.env.example"
n=$(scan_secrets_file "$WORK/.env.example" | wc -l | tr -d ' ')
[[ "$n" -eq 0 ]] && ok ".env.example template produces no env-heuristic noise" || bad ".env.example flagged ($n findings)"

# ── Part 2: end-to-end hook behavior (hybrid mode) ──────────────────────────
run_hook() { # file_path  → prints EXIT code
  jq -n --arg fp "$1" --arg cwd "$WORK" \
    '{tool_name:"Write", tool_input:{file_path:$fp}, tool_response:{success:true}, session_id:"h", cwd:$cwd}' \
    | bash "$HOOK" >/dev/null 2>/dev/null; echo $?
}

echo ""
echo "--- end-to-end: test-file skip (hybrid) ---"
# A test file containing a REAL-format key must be skipped entirely (exit 0)
printf 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n' > "$WORK/test_leak.py"
rc=$(run_hook "$WORK/test_leak.py")
assert_rc "test_leak.py with a key is skipped (exit 0)" 0 "$rc"

echo ""
echo "--- end-to-end: security-relevant coverage trigger (hybrid) ---"
# config.py with NO regex issues and NO request/sink tokens: name alone forces analysis
printf 'SETTINGS = {"debug": False}\n' > "$WORK/config.py"
rc=$(run_hook "$WORK/config.py")
assert_rc "clean config.py forces contextual analysis (exit 2)" 2 "$rc"

# Control: a non-security, non-test file with no issues stays silent
printf 'def add(a, b):\n    return a + b\n' > "$WORK/mathutil.py"
rc=$(run_hook "$WORK/mathutil.py")
assert_rc "clean non-security file stays silent (exit 0)" 0 "$rc"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
echo ""
[[ $FAIL -gt 0 ]] && exit 1
exit 0
