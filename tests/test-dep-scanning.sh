#!/usr/bin/env bash
# Vibe Coding Guard — Dependency Scanning Tests
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Use the project source directly for testing
export VCG_HOME="$PROJECT_DIR"

source "$VCG_HOME/lib/common.sh"
source "$VCG_HOME/lib/scan-dependencies.sh"

PASS=0
FAIL=0

# Helper: test typosquatting detection
test_typosquat() {
  local description="$1"
  local package="$2"
  local ecosystem="$3"
  local expect_detected="$4"  # "yes" or "no"

  local result=""
  local detected="no"
  result=$(check_typosquat "$package" "$ecosystem" 2>/dev/null) && detected="yes"

  if [[ "$detected" == "$expect_detected" ]]; then
    if [[ "$detected" == "yes" ]]; then
      echo "  PASS: $description (detected, similar to: $result)"
    else
      echo "  PASS: $description (not flagged)"
    fi
    PASS=$((PASS + 1))
  else
    if [[ "$detected" == "yes" ]]; then
      echo "  FAIL: $description (unexpected detection, similar to: $result)"
    else
      echo "  FAIL: $description (expected detection but was not flagged)"
    fi
    FAIL=$((FAIL + 1))
  fi
}

# Helper: test package extraction from commands
test_extract_packages() {
  local description="$1"
  local command="$2"
  local expected_contains="$3"

  local result
  result=$(extract_packages_from_command "$command" 2>/dev/null)

  if echo "$result" | grep -q "$expected_contains"; then
    echo "  PASS: $description (found: $expected_contains)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $description (expected '$expected_contains' in output: $result)"
    FAIL=$((FAIL + 1))
  fi
}

# Helper: test full dependency security check via pre-hook
test_dep_command() {
  local description="$1"
  local command="$2"
  local expected_exit="$3"

  local HOOK="$PROJECT_DIR/hooks/pre-tool-use.sh"
  local input
  input=$(jq -n --arg cmd "$command" '{
    tool_name: "Bash",
    tool_input: { command: $cmd },
    session_id: "test-dep-session",
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

echo ""
echo "=== Dependency Scanning Tests ==="
echo ""

echo "--- Typosquatting Detection (PyPI) ---"
test_typosquat "Exact match: requests" "requests" "pypi" "no"
test_typosquat "Exact match: flask" "flask" "pypi" "no"
test_typosquat "Exact match: numpy" "numpy" "pypi" "no"
test_typosquat "Exact match: django" "django" "pypi" "no"
test_typosquat "Typo: reqeusts (swap e/u)" "reqeusts" "pypi" "yes"
test_typosquat "Typo: requets (missing s)" "requets" "pypi" "yes"
test_typosquat "Typo: flaask (double a)" "flaask" "pypi" "yes"
test_typosquat "Typo: numppy (double p)" "numppy" "pypi" "yes"
test_typosquat "Prefix trick: python-requests" "python-requests" "pypi" "yes"
test_typosquat "Suffix trick: flask-python" "flask-python" "pypi" "yes"
test_typosquat "Suffix trick: requests-dev" "requests-dev" "pypi" "yes"
test_typosquat "Completely different name" "my-custom-tool" "pypi" "no"
test_typosquat "Underscore normalization: requests" "requests" "pypi" "no"

echo ""
echo "--- Typosquatting Detection (npm) ---"
test_typosquat "Exact match: express" "express" "npm" "no"
test_typosquat "Exact match: lodash" "lodash" "npm" "no"
test_typosquat "Exact match: react" "react" "npm" "no"
test_typosquat "Typo: expresss (extra s)" "expresss" "npm" "yes"
test_typosquat "Typo: loadsh (swap a/d)" "loadsh" "npm" "yes"
test_typosquat "Prefix trick: node-express" "node-express" "npm" "yes"
test_typosquat "Suffix trick: lodash-js" "lodash-js" "npm" "yes"
test_typosquat "Completely different name" "my-widget" "npm" "no"

echo ""
echo "--- Package Extraction ---"
test_extract_packages "pip install single" "pip install requests" "requests"
test_extract_packages "pip install pinned" "pip install flask==2.3.0" "flask"
test_extract_packages "pip install multiple" "pip install requests flask" "requests"
test_extract_packages "pip3 install" "pip3 install django" "django"
test_extract_packages "npm install single" "npm install express" "express"
test_extract_packages "npm install scoped" "npm install @types/node" "@types/node"
test_extract_packages "yarn add" "yarn add lodash" "lodash"

echo ""
echo "--- Pre-Hook Integration (typosquatting → block) ---"
# Disable OSV API calls during testing to avoid network dependencies and timeouts
export VCG_SKIP_OSV="true"
test_dep_command "Typosquatted pip package" "pip install reqeusts" 2
test_dep_command "Typosquatted npm package" "npm install expresss" 2
test_dep_command "Legitimate pip install (pinned)" "pip install flask==2.3.0" 0
test_dep_command "Legitimate npm install" "npm install express@4.18.2" 0
test_dep_command "Safe pip install" "pip install requests==2.31.0" 0
unset VCG_SKIP_OSV

echo ""
echo "--- Levenshtein Distance Unit Tests ---"
# Test the internal distance function
test_levenshtein() {
  local s1="$1"
  local s2="$2"
  local expected="$3"
  local actual
  actual=$(_levenshtein "$s1" "$s2")
  if [[ "$actual" -eq "$expected" ]]; then
    echo "  PASS: distance('$s1', '$s2') = $actual"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: distance('$s1', '$s2') = $actual (expected $expected)"
    FAIL=$((FAIL + 1))
  fi
}

test_levenshtein "kitten" "sitting" 3
test_levenshtein "requests" "reqeusts" 2
test_levenshtein "flask" "flaask" 1
test_levenshtein "same" "same" 0
test_levenshtein "" "abc" 3
test_levenshtein "express" "expresss" 1

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
echo ""

if [[ $FAIL -gt 0 ]]; then
  exit 1
fi
exit 0
