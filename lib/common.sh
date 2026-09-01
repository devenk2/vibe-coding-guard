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
  # Documentation/text files: scan for secrets only by default (code-flow
  # vulnerability patterns in non-executable docs are almost always noise).
  DOC_SECRETS_ONLY="true"
  DOC_EXTENSIONS=$'.md\n.markdown\n.mdx\n.rst\n.txt'
  # Test files: skipped by default. Test fixtures are full of fake sentinels,
  # negative-test http:// URLs, and dummy credentials that produce pure noise.
  SKIP_TEST_FILES="true"
  TEST_FILE_PATTERNS=$'test_*\n*_test.*\n*.test.*\n*.spec.*\n*_spec.*\n/tests/\n/test/\n/__tests__/\n/spec/'
  # Security-relevant files: always get contextual analysis in hybrid mode,
  # regardless of the request→sink token heuristic. These modules (config,
  # secrets, auth, crypto, logging) are exactly what the lexical trigger misses.
  SECURITY_ALWAYS_ANALYZE="true"
  SECURITY_RELEVANT_PATTERNS=$'config\nsettings\nsecret\ncredential\nauth\ncrypto\nlogging\nsecurity\nmiddleware\npassword'
  # LLM-application scanning: opt-in (default false). When true, the OWASP-LLM
  # Top-10 checks in scan-llm.sh run on Python/JS files. Off by default because
  # they only make sense for code that actually calls an LLM.
  LLM_APP_SCANNING="false"
  # Auth/access-control scanning: "auto" (default) detects whether the project
  # uses authentication via its dependency manifest and gates the
  # access-control checks accordingly; "true"/"false" force the gate open/shut.
  AUTH_SCANNING_MODE="auto"
  AUTH_CHECK_MISSING_MIDDLEWARE="true"
  AUTH_CHECK_IDOR="true"
  AUTH_CHECK_ADMIN_ROLE="true"
  AUTH_CHECK_WEAK_PW_HASH="true"
  AUTH_CHECK_JWT_EXPIRATION="true"
  AUTH_CHECK_SESSION_COOKIE="true"
  AUTH_NPM_LIBRARIES=$'passport\nnext-auth\nauth0\n@okta/okta-sdk-nodejs\nfirebase-admin\njsonwebtoken\nexpress-session\ncookie-session\n@clerk/nextjs\n@clerk/clerk-sdk-node\nsupertokens-node\nkeycloak-connect\nopenid-client\noidc-client-ts'
  AUTH_PYPI_LIBRARIES=$'django-allauth\ndjango-oauth-toolkit\nsocial-auth-app-django\nflask-login\nflask-jwt-extended\nflask-security\nflask-security-too\nauthlib\npython-jose\npyjwt\ndjangorestframework-simplejwt\nfastapi-users\nfastapi-login\nsupertokens-python\nauth0-python\npython-keycloak\nfirebase-admin'
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
    # NOTE: use an explicit null-check, not `// true`. jq's `//` treats a
    # `false` value the same as null, so `false // true` yields true — which
    # would make it impossible to turn a boolean OFF via config.
    DOC_SECRETS_ONLY=$(jq -r 'if .doc_scanning.secrets_only == null then true else .doc_scanning.secrets_only end' "$global_config")
    local global_doc_exts
    global_doc_exts=$(jq -r '.doc_scanning.doc_extensions[]' "$global_config" 2>/dev/null || echo "")
    [[ -n "$global_doc_exts" ]] && DOC_EXTENSIONS="$global_doc_exts"
    SKIP_TEST_FILES=$(jq -r 'if .test_scanning.skip_tests == null then true else .test_scanning.skip_tests end' "$global_config")
    local global_test_pats
    global_test_pats=$(jq -r '.test_scanning.test_patterns[]' "$global_config" 2>/dev/null || echo "")
    [[ -n "$global_test_pats" ]] && TEST_FILE_PATTERNS="$global_test_pats"
    SECURITY_ALWAYS_ANALYZE=$(jq -r 'if .security_relevant.always_analyze == null then true else .security_relevant.always_analyze end' "$global_config")
    local global_sec_pats
    global_sec_pats=$(jq -r '.security_relevant.patterns[]' "$global_config" 2>/dev/null || echo "")
    [[ -n "$global_sec_pats" ]] && SECURITY_RELEVANT_PATTERNS="$global_sec_pats"
    # Explicit null-check (default false) so a `false` value isn't coerced to the
    # default by jq's `//` operator (false // true → true).
    LLM_APP_SCANNING=$(jq -r 'if .llm_app_scanning.enabled == null then false else .llm_app_scanning.enabled end' "$global_config")
    # auth_scanning.enabled accepts either the string enum ("auto"/"true"/
    # "false") or a native JSON boolean (true/false) for convenience/parity
    # with this file's other *.enabled keys. A JSON boolean false must be
    # explicitly normalized to the string "false" here — jq's `//` treats
    # `false` the same as null, so a plain `// "auto"` would silently coerce
    # a real `false` back to the default (the same footgun documented above
    # for LLM_APP_SCANNING etc.).
    AUTH_SCANNING_MODE=$(jq -r '.auth_scanning.enabled | if . == null then "auto" elif type == "boolean" then (if . then "true" else "false" end) else . end' "$global_config")
    AUTH_CHECK_MISSING_MIDDLEWARE=$(jq -r 'if .auth_scanning.checks.missing_auth_middleware == null then true else .auth_scanning.checks.missing_auth_middleware end' "$global_config")
    AUTH_CHECK_IDOR=$(jq -r 'if .auth_scanning.checks.idor_heuristic == null then true else .auth_scanning.checks.idor_heuristic end' "$global_config")
    AUTH_CHECK_ADMIN_ROLE=$(jq -r 'if .auth_scanning.checks.admin_role_check == null then true else .auth_scanning.checks.admin_role_check end' "$global_config")
    AUTH_CHECK_WEAK_PW_HASH=$(jq -r 'if .auth_scanning.checks.weak_password_hashing == null then true else .auth_scanning.checks.weak_password_hashing end' "$global_config")
    AUTH_CHECK_JWT_EXPIRATION=$(jq -r 'if .auth_scanning.checks.jwt_missing_expiration == null then true else .auth_scanning.checks.jwt_missing_expiration end' "$global_config")
    AUTH_CHECK_SESSION_COOKIE=$(jq -r 'if .auth_scanning.checks.session_cookie_flags == null then true else .auth_scanning.checks.session_cookie_flags end' "$global_config")
    local global_auth_npm global_auth_pypi
    global_auth_npm=$(jq -r '.auth_scanning.libraries.npm[]' "$global_config" 2>/dev/null || echo "")
    [[ -n "$global_auth_npm" ]] && AUTH_NPM_LIBRARIES="$global_auth_npm"
    global_auth_pypi=$(jq -r '.auth_scanning.libraries.pypi[]' "$global_config" 2>/dev/null || echo "")
    [[ -n "$global_auth_pypi" ]] && AUTH_PYPI_LIBRARIES="$global_auth_pypi"
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

    # Override doc-scanning settings (explicit null-check so `false` is honored)
    val=$(jq -r 'if .doc_scanning.secrets_only == null then empty else .doc_scanning.secrets_only end' "$project_config")
    [[ -n "$val" ]] && DOC_SECRETS_ONLY="$val"

    local project_doc_exts
    project_doc_exts=$(jq -r '.doc_scanning.doc_extensions[]' "$project_config" 2>/dev/null || echo "")
    [[ -n "$project_doc_exts" ]] && DOC_EXTENSIONS="$project_doc_exts"

    # Override test-scanning settings. Explicit null-check so a `false` override
    # is honored (jq's `// empty` would drop false the same as null).
    val=$(jq -r 'if .test_scanning.skip_tests == null then empty else .test_scanning.skip_tests end' "$project_config")
    [[ -n "$val" ]] && SKIP_TEST_FILES="$val"

    local project_test_pats
    project_test_pats=$(jq -r '.test_scanning.test_patterns[]' "$project_config" 2>/dev/null || echo "")
    [[ -n "$project_test_pats" ]] && TEST_FILE_PATTERNS="$project_test_pats"

    # Override security-relevant settings
    val=$(jq -r 'if .security_relevant.always_analyze == null then empty else .security_relevant.always_analyze end' "$project_config")
    [[ -n "$val" ]] && SECURITY_ALWAYS_ANALYZE="$val"

    local project_sec_pats
    project_sec_pats=$(jq -r '.security_relevant.patterns[]' "$project_config" 2>/dev/null || echo "")
    [[ -n "$project_sec_pats" ]] && SECURITY_RELEVANT_PATTERNS="$project_sec_pats"

    # Override LLM-app scanning flag (explicit null-check so a `false` is honored)
    val=$(jq -r 'if .llm_app_scanning.enabled == null then empty else .llm_app_scanning.enabled end' "$project_config")
    [[ -n "$val" ]] && LLM_APP_SCANNING="$val"

    # Override auth-scanning settings (see the global-load comment above for
    # why a native JSON boolean must be normalized rather than using `// empty`)
    val=$(jq -r '.auth_scanning.enabled | if . == null then empty elif type == "boolean" then (if . then "true" else "false" end) else . end' "$project_config")
    [[ -n "$val" ]] && AUTH_SCANNING_MODE="$val"

    val=$(jq -r 'if .auth_scanning.checks.missing_auth_middleware == null then empty else .auth_scanning.checks.missing_auth_middleware end' "$project_config")
    [[ -n "$val" ]] && AUTH_CHECK_MISSING_MIDDLEWARE="$val"

    val=$(jq -r 'if .auth_scanning.checks.idor_heuristic == null then empty else .auth_scanning.checks.idor_heuristic end' "$project_config")
    [[ -n "$val" ]] && AUTH_CHECK_IDOR="$val"

    val=$(jq -r 'if .auth_scanning.checks.admin_role_check == null then empty else .auth_scanning.checks.admin_role_check end' "$project_config")
    [[ -n "$val" ]] && AUTH_CHECK_ADMIN_ROLE="$val"

    val=$(jq -r 'if .auth_scanning.checks.weak_password_hashing == null then empty else .auth_scanning.checks.weak_password_hashing end' "$project_config")
    [[ -n "$val" ]] && AUTH_CHECK_WEAK_PW_HASH="$val"

    val=$(jq -r 'if .auth_scanning.checks.jwt_missing_expiration == null then empty else .auth_scanning.checks.jwt_missing_expiration end' "$project_config")
    [[ -n "$val" ]] && AUTH_CHECK_JWT_EXPIRATION="$val"

    val=$(jq -r 'if .auth_scanning.checks.session_cookie_flags == null then empty else .auth_scanning.checks.session_cookie_flags end' "$project_config")
    [[ -n "$val" ]] && AUTH_CHECK_SESSION_COOKIE="$val"

    # Auth library lists are replaced wholesale when a project declares its own
    # (matching doc_extensions/test_patterns replace-semantics), not merged —
    # a project either extends the well-known list explicitly or fully owns it.
    local project_auth_npm project_auth_pypi
    project_auth_npm=$(jq -r '.auth_scanning.libraries.npm[]' "$project_config" 2>/dev/null || echo "")
    [[ -n "$project_auth_npm" ]] && AUTH_NPM_LIBRARIES="$project_auth_npm"
    project_auth_pypi=$(jq -r '.auth_scanning.libraries.pypi[]' "$project_config" 2>/dev/null || echo "")
    [[ -n "$project_auth_pypi" ]] && AUTH_PYPI_LIBRARIES="$project_auth_pypi"

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

# Check whether a finding is suppressed via an inline "vcg-ignore" marker on
# the flagged line or the line immediately above it. Matching is a plain
# substring search, so it works regardless of comment syntax (#, //, --, ...).
# Bare "vcg-ignore" suppresses any finding on that line; "vcg-ignore: cat1,cat2"
# only suppresses the listed categories, leaving other checks on the same line
# active. Non-file targets (e.g. Bash command checks, which pass file="command")
# are never suppressible this way.
# Usage: _is_suppressed "$file" "$line" "$category"  → returns 0 if suppressed
_is_suppressed() {
  local file="$1"
  local line="$2"
  local category="$3"

  [[ -f "$file" ]] || return 1
  [[ "$line" =~ ^[0-9]+$ && "$line" -gt 0 ]] || return 1

  local prev=$(( line > 1 ? line - 1 : 1 ))
  local snippet
  snippet=$(sed -n "${prev},${line}p" "$file" 2>/dev/null)
  [[ -z "$snippet" ]] && return 1

  local marker
  marker=$(printf '%s' "$snippet" | grep -oEi 'vcg-ignore(:[[:space:]]*[a-zA-Z0-9_,-]+)?' | head -1)
  [[ -z "$marker" ]] && return 1

  # Bare marker (no ":category" list) suppresses any finding on the line.
  [[ "$marker" != *:* ]] && return 0

  # Category-scoped: only suppress if this finding's category is listed.
  local cats="${marker#*:}"
  cats="${cats// /}"
  local IFS=','
  local c
  for c in $cats; do
    [[ "$c" == "$category" ]] && return 0
  done
  return 1
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

  if _is_suppressed "$file" "$line" "$category"; then
    log_debug "Suppressed finding ($category) at $file:$line via vcg-ignore"
    return 0
  fi

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

# Check if a file extension is a documentation/text type.
# Docs are scanned for secrets only (see DOC_SECRETS_ONLY) because code-flow
# vulnerability patterns in non-executable files are almost always noise.
# Usage: is_doc_extension ".md"  → returns 0 if it's a doc extension
is_doc_extension() {
  local ext="$1"
  [[ -z "${DOC_EXTENSIONS:-}" ]] && return 1
  local doc_ext
  while IFS= read -r doc_ext; do
    [[ -z "$doc_ext" ]] && continue
    if [[ "$ext" == "$doc_ext" ]]; then
      return 0
    fi
  done <<< "$DOC_EXTENSIONS"
  return 1
}

# Check if a file is a test file (by name or path segment).
# Test fixtures are full of fake sentinels, dummy credentials, and negative-test
# URLs — scanning them produces almost entirely false positives.
# Patterns ending in / match a path segment; others match the basename glob.
# Usage: is_test_file "/a/b/test_config.py"  → returns 0 if it's a test file
is_test_file() {
  local filepath="$1"
  local base
  base=$(basename "$filepath")
  [[ -z "${TEST_FILE_PATTERNS:-}" ]] && return 1
  local pat
  while IFS= read -r pat; do
    [[ -z "$pat" ]] && continue
    if [[ "$pat" == */ || "$pat" == /* ]]; then
      # Path-segment pattern (e.g. /tests/): match anywhere in the full path
      local seg="${pat%/}"; seg="${seg#/}"
      if [[ "/$filepath/" == *"/$seg/"* ]]; then
        return 0
      fi
    else
      # Basename glob (e.g. test_*, *_test.*)
      # shellcheck disable=SC2053
      if [[ "$base" == $pat ]]; then
        return 0
      fi
    fi
  done <<< "$TEST_FILE_PATTERNS"
  return 1
}

# Check if a file is security-relevant by name/path (config, secrets, auth,
# crypto, logging, ...). These modules rarely resemble a request→sink handler,
# so the hybrid token heuristic misses them even though they are exactly where
# a secret-handling bug would live. Match is a case-insensitive substring.
# Usage: is_security_relevant_file "/a/b/config.py"  → returns 0 if relevant
is_security_relevant_file() {
  local filepath="$1"
  [[ -z "${SECURITY_RELEVANT_PATTERNS:-}" ]] && return 1
  local lower
  lower=$(printf '%s' "$filepath" | tr '[:upper:]' '[:lower:]')
  local pat
  while IFS= read -r pat; do
    [[ -z "$pat" ]] && continue
    if [[ "$lower" == *"$pat"* ]]; then
      return 0
    fi
  done <<< "$SECURITY_RELEVANT_PATTERNS"
  return 1
}

# Detect whether a project uses authentication, to gate access-control checks
# (missing-auth-middleware, IDOR heuristic, admin-role check) so they stay
# silent on projects that don't use/need auth (public APIs, internal tools).
# "auto" mode is a bounded, single-file-read check of the project's dependency
# manifest(s) against known auth-library names — NOT a project-wide tree walk
# (no such mechanism exists elsewhere in this codebase, and isn't needed here).
# Known limitation: only checks manifests at project_dir's root, so monorepos
# with the manifest elsewhere won't be detected.
# Usage: project_uses_auth "$project_dir"  → returns 0 if auth is in use/assumed
project_uses_auth() {
  local project_dir="${1:-.}"

  case "${AUTH_SCANNING_MODE:-auto}" in
    true)  return 0 ;;
    false) return 1 ;;
  esac

  # auto: check npm manifest
  local pkg_json="$project_dir/package.json"
  if [[ -f "$pkg_json" ]]; then
    local deps lib
    deps=$(jq -r '((.dependencies // {}) + (.devDependencies // {})) | keys[]?' "$pkg_json" 2>/dev/null || echo "")
    if [[ -n "$deps" ]]; then
      while IFS= read -r lib; do
        [[ -z "$lib" ]] && continue
        printf '%s\n' "$deps" | grep -qxF "$lib" && return 0
      done <<< "${AUTH_NPM_LIBRARIES:-}"
    fi
  fi

  # auto: check Python manifests (best-effort substring match, not a full parser)
  local mf
  for mf in requirements.txt requirements-dev.txt Pipfile pyproject.toml setup.cfg; do
    local manifest_path="$project_dir/$mf"
    [[ -f "$manifest_path" ]] || continue
    local lib
    while IFS= read -r lib; do
      [[ -z "$lib" ]] && continue
      if grep -qiE "(^|[\"'[:space:]])${lib}([\"'[:space:]=<>!~,]|\$)" "$manifest_path" 2>/dev/null; then
        return 0
      fi
    done <<< "${AUTH_PYPI_LIBRARIES:-}"
  done

  return 1
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
