#!/usr/bin/env bash
# Vibe Coding Guard — Test Runner
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  Vibe Coding Guard — Test Suite${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Check prerequisites
if ! command -v jq &> /dev/null; then
  echo -e "${RED}ERROR: jq is required to run tests${NC}"
  exit 1
fi

TOTAL_PASS=0
TOTAL_FAIL=0

# Run PreToolUse tests
echo -e "${BLUE}Running PreToolUse hook tests...${NC}"
if bash "$SCRIPT_DIR/test-pre-hook.sh"; then
  echo -e "${GREEN}PreToolUse tests passed${NC}"
else
  echo -e "${RED}PreToolUse tests had failures${NC}"
  TOTAL_FAIL=$((TOTAL_FAIL + 1))
fi
echo ""

# Run PostToolUse tests
echo -e "${BLUE}Running PostToolUse hook tests...${NC}"
if bash "$SCRIPT_DIR/test-post-hook.sh"; then
  echo -e "${GREEN}PostToolUse tests passed${NC}"
else
  echo -e "${RED}PostToolUse tests had failures${NC}"
  TOTAL_FAIL=$((TOTAL_FAIL + 1))
fi
echo ""

# Run Heuristics tests
echo -e "${BLUE}Running Heuristics tests...${NC}"
if bash "$SCRIPT_DIR/test-heuristics.sh"; then
  echo -e "${GREEN}Heuristics tests passed${NC}"
else
  echo -e "${RED}Heuristics tests had failures${NC}"
  TOTAL_FAIL=$((TOTAL_FAIL + 1))
fi
echo ""

# Run Dependency Scanning tests
echo -e "${BLUE}Running Dependency Scanning tests...${NC}"
if bash "$SCRIPT_DIR/test-dep-scanning.sh"; then
  echo -e "${GREEN}Dependency Scanning tests passed${NC}"
else
  echo -e "${RED}Dependency Scanning tests had failures${NC}"
  TOTAL_FAIL=$((TOTAL_FAIL + 1))
fi
echo ""

# Run LLM-application scanner tests
echo -e "${BLUE}Running LLM Scanner tests...${NC}"
if bash "$SCRIPT_DIR/test-llm-scan.sh"; then
  echo -e "${GREEN}LLM Scanner tests passed${NC}"
else
  echo -e "${RED}LLM Scanner tests had failures${NC}"
  TOTAL_FAIL=$((TOTAL_FAIL + 1))
fi

echo ""
echo -e "${BLUE}============================================${NC}"
if [[ $TOTAL_FAIL -eq 0 ]]; then
  echo -e "${GREEN}  All test suites passed!${NC}"
else
  echo -e "${RED}  $TOTAL_FAIL test suite(s) had failures${NC}"
fi
echo -e "${BLUE}============================================${NC}"
echo ""

exit $TOTAL_FAIL
