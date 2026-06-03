#!/usr/bin/env bash
# Vibe Coding Guard — Shared utilities
# Used by all hook scripts and scanners

set -euo pipefail

VCG_HOME="${VCG_HOME:-__VCG_HOME_PLACEHOLDER__}"

# Severity ranking for comparisons (bash 3.2 compatible — no associative arrays)
_severity_rank() {
  case "$1" in
    LOW)    echo 1 ;;
    MEDIUM) echo 2 ;;
    HIGH)   echo 3 ;;
    *)      echo 0 ;;
  esac
}

# Load configuration from config.json
# Supports per-project config: checks .claude/vibe-coding-guard.json first, then global
# Usage: load_config [project_dir]
load_config() {
  local project_dir="${1:-}"
  local global_config="$VCG_HOME/config.json"
  local project_config=""
  
  # Find project config if project_dir provided
  if [[ -n "$project_dir" ]]; then
    project_config="$project_dir/.claude/vibe-coding-guard.json"
    if [[ ! -f "$project_config" ]]; then
      project_config=""
    fi
  fi
  
  # Set defaults
  BLOCKING_SEVERITY="MEDIUM"
  MAX_FILE_SIZE_KB=500
  ANALYSIS_MODE="hybrid"
  LLM_ENABLED="true"
  LLM_ANALYZE_ON_REGEX_MATCH="true"
  LLM_ANALYZE_COMPLEX="true"
  LLM_MAX_CONTEXT_LINES=50
  LLM_TIMEOUT_SECONDS=30
  IGNORE_PATHS=""
  CUSTOM_SECRET_PATTERNS=""
  DEP_SCANNING_ENABLED="true"
  DEP_CHECK_TYPOSQUAT="true"
  DEP_CHECK_OSV="true"
  DEP_OSV_TIMEOUT=5
  DEP_POST_INSTALL_AUDIT="true"
  
  # Load global config first
  if [[ -f "$global_config" ]]; then
    BLOCKING_SEVERITY=$(jq -r '.blocking_severity // "HIGH"' "$global_config")
    MAX_FILE_SIZE_KB=$(jq -r '.max_file_size_kb // 500' "$global_config")
    IGNORE_PATHS=$(jq -r '.ignore_paths[]' "$global_config" 2>/dev/null || echo "")
    CUSTOM_SECRET_PATTERNS=$(jq -r '.custom_secret_patterns[]' "$global_config" 2>/dev/null || echo "")
    ANALYSIS_MODE=$(jq -r '.analysis_mode // "hybrid"' "$global_config")
    LLM_ENABLED=$(jq -r '.llm_analysis.enabled // true' "$global_config")
    LLM_ANALYZE_ON_REGEX_MATCH=$(jq -r '.llm_analysis.analyze_on_regex_match // true' "$global_config")
    LLM_ANALYZE_COMPLEX=$(jq -r '.llm_analysis.analyze_complex_patterns // true' "$global_config")
    LLM_MAX_CONTEXT_LINES=$(jq -r '.llm_analysis.max_context_lines // 50' "$global_config")
    LLM_TIMEOUT_SECONDS=$(jq -r '.llm_analysis.timeout_seconds // 30' "$global_config")
    DEP_SCANNING_ENABLED=$(jq -r '.dependency_scanning.enabled // true' "$global_config")
    DEP_CHECK_TYPOSQUAT=$(jq -r '.dependency_scanning.typosquatting_detection // true' "$global_config")
    DEP_CHECK_OSV=$(jq -r '.dependency_scanning.osv_vulnerability_check // true' "$global_config")
    DEP_OSV_TIMEOUT=$(jq -r '.dependency_scanning.osv_api_timeout_seconds // 5' "$global_config")
    DEP_POST_INSTALL_AUDIT=$(jq -r '.dependency_scanning.post_install_audit // true' "$global_config")
    log_debug "Loaded global config from $global_config"
  else
    log_debug "Global config not found at $global_config, using defaults"
  fi
  
  # Override with project-local config if present
  if [[ -n "$project_config" ]]; then
    log_debug "Loading project config from $project_config"
    
    # Only override values that are explicitly set in project config
    local val
    
    val=$(jq -r '.blocking_severity // empty' "$project_config")
    [[ -n "$val" ]] && BLOCKING_SEVERITY="$val"
    
    val=$(jq -r '.max_file_size_kb // empty' "$project_config")
    [[ -n "$val" ]] && MAX_FILE_SIZE_KB="$val"
    
    val=$(jq -r '.analysis_mode // empty' "$project_config")
    [[ -n "$val" ]] && ANALYSIS_MODE="$val"
    
    val=$(jq -r '.llm_analysis.enabled // empty' "$project_config")
    [[ -n "$val" ]] && LLM_ENABLED="$val"
    
    val=$(jq -r '.llm_analysis.analyze_on_regex_match // empty' "$project_config")
    [[ -n "$val" ]] && LLM_ANALYZE_ON_REGEX_MATCH="$val"
    
    val=$(jq -r '.llm_analysis.analyze_complex_patterns // empty' "$project_config")
    [[ -n "$val" ]] && LLM_ANALYZE_COMPLEX="$val"
    
    val=$(jq -r '.llm_analysis.max_context_lines // empty' "$project_config")
    [[ -n "$val" ]] && LLM_MAX_CONTEXT_LINES="$val"
    
    val=$(jq -r '.llm_analysis.timeout_seconds // empty' "$project_config")
    [[ -n "$val" ]] && LLM_TIMEOUT_SECONDS="$val"
    
    # Override dependency scanning settings
    val=$(jq -r '.dependency_scanning.enabled // empty' "$project_config")
    [[ -n "$val" ]] && DEP_SCANNING_ENABLED="$val"
    
    val=$(jq -r '.dependency_scanning.typosquatting_detection // empty' "$project_config")
    [[ -n "$val" ]] && DEP_CHECK_TYPOSQUAT="$val"
    
    val=$(jq -r '.dependency_scanning.osv_vulnerability_check // empty' "$project_config")
    [[ -n "$val" ]] && DEP_CHECK_OSV="$val"
    
    val=$(jq -r '.dependency_scanning.osv_api_timeout_seconds // empty' "$project_config")
    [[ -n "$val" ]] && DEP_OSV_TIMEOUT="$val"
    
    val=$(jq -r '.dependency_scanning.post_install_audit // empty' "$project_config")
    [[ -n "$val" ]] && DEP_POST_INSTALL_AUDIT="$val"
    
    # Merge ignore_paths (project adds to global)
    local project_ignores
    project_ignores=$(jq -r '.ignore_paths[]' "$project_config" 2>/dev/null || echo "")
    if [[ -n "$project_ignores" ]]; then
      IGNORE_PATHS="$IGNORE_PATHS"$'\n'"$project_ignores"
    fi
    
    # Merge custom_secret_patterns (project adds to global)
    local project_secrets
    project_secrets=$(jq -r '.custom_secret_patterns[]' "$project_config" 2>/dev/null || echo "")
    if [[ -n "$project_secrets" ]]; then
      CUSTOM_SECRET_PATTERNS="$CUSTOM_SECRET_PATTERNS"$'\n'"$project_secrets"
    fi
    
    log_debug "Applied project-local config overrides (analysis_mode=$ANALYSIS_MODE)"
  fi
}

# Emit a structured JSON finding to stdout (one per line)
# Usage: emit_finding SEVERITY SSDF_PRACTICE SSDF_GROUP CATEGORY FILE LINE PATTERN DESCRIPTION REMEDIATION
emit_finding() {
  local severity="$1"
  local ssdf_practice="$2"
  local ssdf_group="$3"
  local category="$4"
  local file="$5"
  local line="$6"
  local pattern_matched="$7"
  local description="$8"
  local remediation="$9"

  jq -n -c \
    --arg sev "$severity" \
    --arg practice "$ssdf_practice" \
    --arg group "$ssdf_group" \
    --arg cat "$category" \
    --arg file "$file" \
    --arg line "$line" \
    --arg pattern "$pattern_matched" \
    --arg desc "$description" \
    --arg rem "$remediation" \
    '{
      severity: $sev,
      ssdf_practice: $practice,
      ssdf_group: $group,
      category: $cat,
      file: $file,
      line: ($line | tonumber),
      pattern_matched: $pattern,
      description: $desc,
      remediation: $rem
    }'
}

# Check if a file path should be ignored
should_ignore_path() {
  local filepath="$1"
  if [[ -z "${IGNORE_PATHS:-}" ]]; then
    return 1
  fi

  while IFS= read -r ignore_pattern; do
    [[ -z "$ignore_pattern" ]] && continue
    # Match as a path component (bounded by / or start/end of string)
    if [[ "$filepath" == *"/$ignore_pattern/"* || "$filepath" == *"/$ignore_pattern" || "$filepath" == "$ignore_pattern/"* || "$filepath" == "$ignore_pattern" ]]; then
      return 0
    fi
  done <<< "$IGNORE_PATHS"

  return 1
}

# Get normalized file extension
get_file_extension() {
  local filepath="$1"
  local filename
  filename=$(basename "$filepath")
  local ext="${filename##*.}"
  if [[ "$ext" == "$filename" ]]; then
    echo ""
  else
    echo ".$ext"
  fi
}

# Check if a severity meets the blocking threshold
severity_meets_threshold() {
  local severity="$1"
  local threshold="$2"
  local sev_rank
  sev_rank=$(_severity_rank "$severity")
  local thresh_rank
  thresh_rank=$(_severity_rank "$threshold")
  [[ $sev_rank -ge $thresh_rank ]]
}

# Get the highest severity from a findings file (one JSON per line)
get_max_severity() {
  local findings_file="$1"
  local max_rank=0
  local max_sev="LOW"

  while IFS= read -r finding; do
    local sev
    sev=$(echo "$finding" | jq -r '.severity')
    local rank
    rank=$(_severity_rank "$sev")
    if [[ $rank -gt $max_rank ]]; then
      max_rank=$rank
      max_sev="$sev"
    fi
  done < "$findings_file"

  echo "$max_sev"
}

# Format findings for stderr output (human-readable)
format_findings_stderr() {
  local findings_file="$1"
  local count
  count=$(wc -l < "$findings_file" | tr -d ' ')

  echo ""
  echo "============================================"
  echo "  Vibe Coding Guard — Security Scan Results"
  echo "============================================"
  echo ""
  echo "Found $count security issue(s):"
  echo ""

  while IFS= read -r finding; do
    local sev desc line practice rem
    sev=$(echo "$finding" | jq -r '.severity')
    desc=$(echo "$finding" | jq -r '.description')
    line=$(echo "$finding" | jq -r '.line')
    practice=$(echo "$finding" | jq -r '.ssdf_practice')
    rem=$(echo "$finding" | jq -r '.remediation')

    echo "  [$sev] Line $line: $desc (SSDF: $practice)"
    echo "    Remediation: $rem"
    echo ""
  done < "$findings_file"

  echo "Please fix these issues before continuing."
  echo "============================================"
}

# Debug logging (enabled with VCG_DEBUG=1)
log_debug() {
  if [[ "${VCG_DEBUG:-0}" == "1" ]]; then
    echo "[VCG DEBUG] $*" >&2
  fi
}

# Persistent audit logging — appends findings to a log file for post-hoc review
# Usage: audit_log <findings_file> <source> [target]
#   source: "pre-hook" or "post-hook"
#   target: file path or command string being evaluated
audit_log() {
  local findings_file="$1"
  local source="$2"
  local target="${3:-unknown}"
  local audit_file="${VCG_HOME}/audit.log"
  local timestamp
  timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date '+%Y-%m-%dT%H:%M:%SZ')

  # Ensure audit log directory exists
  mkdir -p "$(dirname "$audit_file")" 2>/dev/null || true

  while IFS= read -r finding; do
    local sev category desc
    sev=$(echo "$finding" | jq -r '.severity' 2>/dev/null || echo "UNKNOWN")
    category=$(echo "$finding" | jq -r '.category' 2>/dev/null || echo "unknown")
    desc=$(echo "$finding" | jq -r '.description' 2>/dev/null || echo "")
    echo "[$timestamp] [$sev] [$source] target=$target category=$category desc=\"$desc\"" >> "$audit_file" 2>/dev/null || true
  done < "$findings_file"
}
