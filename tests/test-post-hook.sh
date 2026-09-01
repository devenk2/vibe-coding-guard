#!/usr/bin/env bash
# Vibe Coding Guard — PostToolUse Hook Tests
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Create a test-specific VCG_HOME with fast analysis mode
TEST_VCG_HOME=$(mktemp -d)
cp -r "$PROJECT_DIR/lib" "$TEST_VCG_HOME/"
cp -r "$PROJECT_DIR/hooks" "$TEST_VCG_HOME/"

# Create config with fast mode for deterministic testing.
# Also disable test-file skipping: these fixtures deliberately live under
# tests/fixtures/, and this suite exists to exercise the scanners on them.
# (test-file skip behavior itself is covered by test-heuristics.sh.)
# auth_scanning.enabled is forced true so the missing-api-auth check (now
# gated on project_uses_auth) keeps firing unconditionally here, since these
# fixtures are meant to test "does the scanner detect X" in isolation, not
# the auth-detection gate itself — that's covered by test-auth-scanning.sh.
cat "$PROJECT_DIR/config.json" | jq '.analysis_mode = "fast" | .test_scanning.skip_tests = false | .auth_scanning.enabled = true' > "$TEST_VCG_HOME/config.json"

# Update VCG_HOME placeholder in test copies
for f in "$TEST_VCG_HOME/hooks/"*.sh "$TEST_VCG_HOME/lib/"*.sh; do
  sed -i '' "s|__VCG_HOME_PLACEHOLDER__|$TEST_VCG_HOME|g" "$f" 2>/dev/null || \
  sed -i "s|__VCG_HOME_PLACEHOLDER__|$TEST_VCG_HOME|g" "$f" 2>/dev/null || true
done

export VCG_HOME="$TEST_VCG_HOME"
trap "rm -rf '$TEST_VCG_HOME'" EXIT

HOOK="$TEST_VCG_HOME/hooks/post-tool-use.sh"
FIXTURES="$SCRIPT_DIR/fixtures"
PASS=0
FAIL=0

# Helper: run hook with a mock file write and check exit code
test_file_scan() {
  local description="$1"
  local file_path="$2"
  local expected_exit="$3"

  local input
  input=$(jq -n --arg fp "$file_path" '{
    tool_name: "Write",
    tool_input: { file_path: $fp },
    tool_response: { success: true },
    session_id: "test-session",
    cwd: "/tmp"
  }')

  local actual_exit=0
  echo "$input" | bash "$HOOK" > /dev/null 2>/dev/null || actual_exit=$?

  if [[ $actual_exit -eq $expected_exit ]]; then
    echo "  PASS: $description (exit=$actual_exit)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $description (expected exit=$expected_exit, got exit=$actual_exit)"
    FAIL=$((FAIL + 1))
  fi
}

# Helper: run hook and capture stderr for finding count
test_file_scan_with_count() {
  local description="$1"
  local file_path="$2"
  local min_findings="$3"

  local input
  input=$(jq -n --arg fp "$file_path" '{
    tool_name: "Write",
    tool_input: { file_path: $fp },
    tool_response: { success: true },
    session_id: "test-session",
    cwd: "/tmp"
  }')

  local stderr_output
  stderr_output=$(echo "$input" | bash "$HOOK" 2>&1 1>/dev/null || true)

  # Count findings by looking for severity markers
  local count
  count=$(echo "$stderr_output" | grep -c '\[HIGH\]\|\[MEDIUM\]\|\[LOW\]' || true)

  if [[ $count -ge $min_findings ]]; then
    echo "  PASS: $description (found $count findings, expected >= $min_findings)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $description (found $count findings, expected >= $min_findings)"
    FAIL=$((FAIL + 1))
  fi
}

# Helper: test that non-Write/Edit tools are ignored
test_non_write_tool() {
  local input
  input=$(jq -n '{
    tool_name: "Bash",
    tool_input: { command: "echo hello" },
    session_id: "test-session",
    cwd: "/tmp"
  }')

  local actual_exit=0
  echo "$input" | bash "$HOOK" > /dev/null 2>/dev/null || actual_exit=$?

  if [[ $actual_exit -eq 0 ]]; then
    echo "  PASS: Non-Write tool is ignored (exit=0)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: Non-Write tool should be ignored (expected exit=0, got exit=$actual_exit)"
    FAIL=$((FAIL + 1))
  fi
}

echo ""
echo "=== PostToolUse Hook Tests ==="
echo ""

echo "--- Dangerous Python file (should find issues, exit=2) ---"
test_file_scan "Dangerous Python file triggers findings" "$FIXTURES/dangerous-python.py" 2
test_file_scan_with_count "Dangerous Python file has multiple findings" "$FIXTURES/dangerous-python.py" 5

echo ""
echo "--- Dangerous JS file (should find issues, exit=2) ---"
test_file_scan "Dangerous JS file triggers findings" "$FIXTURES/dangerous-js.js" 2
test_file_scan_with_count "Dangerous JS file has multiple findings" "$FIXTURES/dangerous-js.js" 5

echo ""
echo "--- Missing input validation (should find issues, exit=2) ---"
test_file_scan "Route without validation triggers findings" "$FIXTURES/no-validation-route.py" 2
test_file_scan_with_count "Route without validation has findings" "$FIXTURES/no-validation-route.py" 1

echo ""
echo "--- Dangerous Python API file (should find API security issues, exit=2) ---"
test_file_scan "Python API security file triggers findings" "$FIXTURES/dangerous-api-python.py" 2
test_file_scan_with_count "Python API security file has multiple findings" "$FIXTURES/dangerous-api-python.py" 10

echo ""
echo "--- Dangerous JS API file (should find API security issues, exit=2) ---"
test_file_scan "JS API security file triggers findings" "$FIXTURES/dangerous-api-js.js" 2
test_file_scan_with_count "JS API security file has multiple findings" "$FIXTURES/dangerous-api-js.js" 5

echo ""
echo "--- Dangerous Swift file (should find issues, exit=2) ---"
test_file_scan "Dangerous Swift file triggers findings" "$FIXTURES/dangerous-swift.swift" 2
test_file_scan_with_count "Dangerous Swift file has multiple findings" "$FIXTURES/dangerous-swift.swift" 15

echo ""
echo "--- Missing logging in Python (should find issues, exit=2) ---"
test_file_scan "Python missing-logging triggers findings" "$FIXTURES/missing-logging-python.py" 2
test_file_scan_with_count "Python missing-logging has findings" "$FIXTURES/missing-logging-python.py" 3

echo ""
echo "--- Missing logging in JS (should find issues, exit=2) ---"
test_file_scan "JS missing-logging triggers findings" "$FIXTURES/missing-logging-js.js" 2
test_file_scan_with_count "JS missing-logging has findings" "$FIXTURES/missing-logging-js.js" 3

echo ""
echo "--- Safe Python file (should pass, exit=0) ---"
test_file_scan "Safe Python file passes cleanly" "$FIXTURES/safe-example.py" 0

echo ""
echo "--- Markdown docs: secrets-only scanning ---"
test_file_scan "Markdown with a real secret still triggers (exit=2)" "$FIXTURES/doc-with-secret.md" 2
test_file_scan_with_count "Markdown secret produces a finding" "$FIXTURES/doc-with-secret.md" 1
test_file_scan "Markdown with only code-flow noise passes (exit=0)" "$FIXTURES/doc-with-noise.md" 0

echo ""
echo "--- Edge cases ---"
test_non_write_tool
test_file_scan "Non-existent file passes" "/tmp/nonexistent-vcg-test-file.py" 0

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
echo ""

if [[ $FAIL -gt 0 ]]; then
  exit 1
fi
exit 0
