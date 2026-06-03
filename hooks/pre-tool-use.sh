#!/usr/bin/env bash
# Vibe Coding Guard — PreToolUse Hook
# Intercepts Bash tool calls and blocks dangerous commands
# Supports hybrid mode: regex blocking + LLM contextual analysis
set -euo pipefail

VCG_HOME="${VCG_HOME:-__VCG_HOME_PLACEHOLDER__}"
source "$VCG_HOME/lib/common.sh"
source "$VCG_HOME/lib/command-blocklist.sh"
source "$VCG_HOME/lib/scan-dependencies.sh"
source "$VCG_HOME/lib/llm-analyzer.sh"

# Read JSON input from stdin
INPUT="$(cat)"

TOOL_NAME="$(echo "$INPUT" | jq -r '.tool_name // empty')"

# Only process Bash tool calls
if [[ "$TOOL_NAME" != "Bash" ]]; then
  exit 0
fi

COMMAND="$(echo "$INPUT" | jq -r '.tool_input.command // empty')"
if [[ -z "$COMMAND" ]]; then
  exit 0
fi

log_debug "Checking command: $COMMAND"

# Extract project directory from input (cwd) for per-project config
PROJECT_DIR="$(echo "$INPUT" | jq -r '.cwd // empty')"

# Load configuration (with project-local overrides if available)
load_config "$PROJECT_DIR"

# Run command through blocklist checks
FINDINGS_FILE=$(mktemp)
trap "rm -f '$FINDINGS_FILE'" EXIT

check_command "$COMMAND" > "$FINDINGS_FILE" || true

# Run dependency security checks (typosquatting + OSV vulnerability lookup)
if echo "$COMMAND" | grep -qEi '\b(pip3?\s+install|npm\s+install|yarn\s+add|pnpm\s+(add|install))\b'; then
  log_debug "Dependency install detected — running security checks"
  check_dependency_security "$COMMAND" >> "$FINDINGS_FILE" || true
fi

REGEX_FOUND_ISSUES="false"
if [[ -s "$FINDINGS_FILE" ]]; then
  REGEX_FOUND_ISSUES="true"
fi

# === Determine Analysis Mode Behavior ===
RUN_LLM_ANALYSIS="false"

case "$ANALYSIS_MODE" in
  fast)
    # Fast mode: regex only
    RUN_LLM_ANALYSIS="false"
    ;;
  deep)
    # Deep mode: always analyze commands
    RUN_LLM_ANALYSIS="true"
    ;;
  hybrid)
    # Hybrid: LLM for ambiguous cases or when regex found low/medium issues
    if [[ "$REGEX_FOUND_ISSUES" == "true" ]]; then
      # Get max severity - only do LLM analysis for non-HIGH (ambiguous) cases
      MAX_SEV=$(get_max_severity "$FINDINGS_FILE")
      if [[ "$MAX_SEV" != "HIGH" ]]; then
        RUN_LLM_ANALYSIS="true"
      fi
    fi
    # Also analyze complex/piped commands that might have subtle issues
    if echo "$COMMAND" | grep -qE '(\||&&|;|`|\$\()' 2>/dev/null; then
      if [[ "$LLM_ANALYZE_COMPLEX" == "true" ]]; then
        RUN_LLM_ANALYSIS="true"
      fi
    fi
    ;;
esac

# === Handle HIGH Severity (Always Block) ===
if [[ -s "$FINDINGS_FILE" ]]; then
  MAX_SEV=$(get_max_severity "$FINDINGS_FILE")
  
  if severity_meets_threshold "$MAX_SEV" "$BLOCKING_SEVERITY"; then
    # Block the command immediately - no LLM needed for clear violations
    REASON=$(jq -s '.' "$FINDINGS_FILE")
    echo "{\"hookSpecificOutput\":{\"decision\":\"block\",\"reason\":$REASON}}"
    format_findings_stderr "$FINDINGS_FILE" >&2
    audit_log "$FINDINGS_FILE" "pre-hook" "$COMMAND"
    exit 2
  fi
fi

# === LLM Analysis for Ambiguous Cases ===
if [[ "$RUN_LLM_ANALYSIS" == "true" ]]; then
  # Prepare findings JSON
  REGEX_FINDINGS_JSON="[]"
  if [[ -s "$FINDINGS_FILE" ]]; then
    REGEX_FINDINGS_JSON=$(jq -s '.' "$FINDINGS_FILE")
  fi
  
  {
    echo ""
    echo "============================================"
    echo "  Vibe Coding Guard — Command Analysis"
    echo "============================================"
    echo ""
    echo "Analysis mode: $ANALYSIS_MODE"
    echo ""
    echo "Command: $COMMAND"
    echo ""
    
    if [[ -s "$FINDINGS_FILE" ]]; then
      echo "## Pattern-Based Concerns (non-blocking):"
      while IFS= read -r finding; do
        local_sev=$(echo "$finding" | jq -r '.severity')
        local_desc=$(echo "$finding" | jq -r '.description')
        local_practice=$(echo "$finding" | jq -r '.ssdf_practice')
        echo "  [$local_sev] $local_desc (SSDF: $local_practice)"
      done < "$FINDINGS_FILE"
      echo ""
    fi
    
    echo "## Contextual Analysis Request"
    echo ""
    echo "**Claude: Please evaluate this command's safety.**"
    echo ""
    echo "Consider:"
    echo "1. What is the actual intent of this command?"
    echo "2. In the context of this project, is it safe?"
    echo "3. Could it cause unintended data loss or security issues?"
    echo "4. Is there a safer alternative?"
    echo ""
    echo "Proceed only if you determine the command is safe in context."
    echo ""
    echo "============================================"
  } >&2
  
  exit 0  # Allow but request reasoning
fi

# === No Issues Found ===
if [[ ! -s "$FINDINGS_FILE" ]]; then
  log_debug "Command passed security check"
  exit 0
fi

# === Non-blocking warnings (MEDIUM/LOW with no LLM) ===
echo "[Vibe Coding Guard] WARNING: Security concerns detected (non-blocking):" >&2
while IFS= read -r finding; do
  local_sev=$(echo "$finding" | jq -r '.severity')
  local_desc=$(echo "$finding" | jq -r '.description')
  local_practice=$(echo "$finding" | jq -r '.ssdf_practice')
  echo "  [$local_sev] $local_desc (SSDF: $local_practice)" >&2
done < "$FINDINGS_FILE"
exit 0
