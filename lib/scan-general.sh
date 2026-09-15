#!/usr/bin/env bash
# Vibe Coding Guard — General Security Scanner
# Language-agnostic security patterns (secrets, crypto, transport)

# Scan a file for hardcoded secrets / credentials only.
# This is the subset of checks that stays meaningful even in non-executable
# files (docs, markdown, text): a real key committed to a README is still a
# real, exploitable leak. Code-flow checks (path traversal, transport) are
# NOT included here — see scan_general_file for those.
# Outputs JSON findings (one per line) to stdout
scan_secrets_file() {
  local file="$1"

  # === HIGH SEVERITY ===

  # AWS Access Key ID
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "RV.1" "RV" "aws-key" \
      "$file" "$line_num" "AKIA..." \
      "AWS Access Key ID found in source code" \
      "Use environment variables or AWS IAM roles. Never commit AWS keys to source code"
  done < <(grep -nE 'AKIA[0-9A-Z]{16}' "$file" 2>/dev/null || true)

  # GitHub Personal Access Token
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "RV.1" "RV" "github-token" \
      "$file" "$line_num" "ghp_..." \
      "GitHub Personal Access Token found in source code" \
      "Use environment variables or GitHub Apps for authentication. Revoke exposed tokens"
  done < <(grep -nE 'ghp_[a-zA-Z0-9]{36}' "$file" 2>/dev/null || true)

  # Generic API key patterns (sk-, sk_live, sk_test)
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "RV.1" "RV" "api-key" \
      "$file" "$line_num" "sk-..." \
      "API key (sk-* pattern) found in source code" \
      "Use environment variables or a secrets manager. Rotate any exposed keys"
  done < <(grep -nE 'sk[-_](live|test|proj)?[-_]?[a-zA-Z0-9]{20,}' "$file" 2>/dev/null || true)

  # Slack tokens
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "RV.1" "RV" "slack-token" \
      "$file" "$line_num" "xox[bpsa]-..." \
      "Slack token found in source code" \
      "Use environment variables for Slack tokens. Revoke exposed tokens immediately"
  done < <(grep -nE 'xox[bpsa]-[0-9]{10,}' "$file" 2>/dev/null || true)

  # Private keys embedded in source
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "RV.1" "RV" "embedded-private-key" \
      "$file" "$line_num" "private key block" \
      "Private key embedded in source code" \
      "Store private keys in secure key management systems, never in source code"
  done < <(grep -nE 'BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY' "$file" 2>/dev/null || true)

  # Generic hardcoded credential patterns (broader catch)
  while IFS=: read -r line_num matched_line; do
    # Skip lines that look like config templates or examples
    if echo "$matched_line" | grep -qEi '(example|placeholder|changeme|xxx|your.*(key|token|password)|<.*>)'; then
      continue
    fi
    emit_finding "HIGH" "RV.1" "RV" "hardcoded-secret" \
      "$file" "$line_num" "credential pattern" \
      "Potential hardcoded credential found in source code" \
      "Use environment variables or a secrets manager instead of hardcoding credentials"
  done < <(grep -nEi '(database_url|db_password|mysql_pwd|postgres_password|redis_url)\s*[:=]\s*["\x27][^"\x27]{8,}' "$file" 2>/dev/null || true)

  # JWT tokens hardcoded in source
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "RV.1" "RV" "hardcoded-jwt" \
      "$file" "$line_num" "eyJ...JWT" \
      "Hardcoded JWT token found in source code" \
      "Never hardcode JWTs. Generate tokens at runtime and store them securely"
  done < <(grep -nE 'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}' "$file" 2>/dev/null || true)

  # Stripe API keys (sk_live, pk_live, rk_live, sk_test, pk_test, rk_test)
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "RV.1" "RV" "stripe-key" \
      "$file" "$line_num" "stripe key (sk/pk/rk_live/test)" \
      "Stripe API key found in source code" \
      "Use environment variables for Stripe keys. Rotate any exposed keys immediately"
  done < <(grep -nE '(sk|pk|rk)_(live|test)_[a-zA-Z0-9]{24,}' "$file" 2>/dev/null || true)

  # Twilio Account SID
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "RV.1" "RV" "twilio-sid" \
      "$file" "$line_num" "AC... (Twilio SID)" \
      "Twilio Account SID found in source code" \
      "Use environment variables for Twilio credentials. Rotate any exposed tokens"
  done < <(grep -nE 'AC[a-f0-9]{32}' "$file" 2>/dev/null || true)

  # SendGrid API key
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "RV.1" "RV" "sendgrid-key" \
      "$file" "$line_num" "SG... (SendGrid key)" \
      "SendGrid API key found in source code" \
      "Use environment variables for SendGrid keys. Rotate any exposed keys immediately"
  done < <(grep -nE 'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}' "$file" 2>/dev/null || true)

  # NOTE: path-traversal and insecure-transport checks intentionally live in
  # scan_general_file, not here — they are code-flow signals, not secrets.

  # Generic hardcoded password/secret across all languages
  while IFS=: read -r line_num matched_line; do
    # Skip lines that look like config templates, examples, or environment variable reads
    if echo "$matched_line" | grep -qEi '(example|placeholder|changeme|xxx|your.*(key|token|password)|<.*>|os\.environ|process\.env|getenv)'; then
      continue
    fi
    emit_finding "HIGH" "RV.1" "RV" "hardcoded-secret" \
      "$file" "$line_num" "password/secret assignment" \
      "Potential hardcoded password or secret found in source code" \
      "Use environment variables or a secrets manager instead of hardcoding credentials"
  done < <(grep -nEi '(password|passwd|secret|api_key|apikey|auth_token|private_key)\s*[:=]\s*["\x27][^"\x27]{8,}' "$file" 2>/dev/null || true)

  # Check custom secret patterns from config
  if [[ -n "${CUSTOM_SECRET_PATTERNS:-}" ]]; then
    while IFS= read -r pattern; do
      [[ -z "$pattern" ]] && continue
      # Validate regex pattern before use to prevent grep errors from malformed config
      if ! echo "" | grep -E "$pattern" > /dev/null 2>&1 && ! echo "" | grep -E "$pattern" 2>&1 | grep -q 'match'; then
        if ! echo "test" | grep -E "$pattern" > /dev/null 2>&1; then
          log_debug "Skipping invalid custom secret regex: $pattern"
          continue
        fi
      fi
      while IFS=: read -r line_num _; do
        emit_finding "HIGH" "RV.1" "RV" "custom-secret" \
          "$file" "$line_num" "$pattern" \
          "Custom secret pattern matched: $pattern" \
          "Remove the secret from source code and use environment variables or a secrets manager"
      done < <(grep -nE "$pattern" "$file" 2>/dev/null || true)
    done <<< "$CUSTOM_SECRET_PATTERNS"
  fi

  # === .env file detection ===
  # .env files often contain secrets as KEY=value assignments
  local filename
  filename=$(basename "$file")
  # Template/example files (.env.example, config.sample, *.template, *.dist) are
  # meant to hold placeholder values, so the naive KEY= heuristic is pure noise
  # on them. High-confidence provider-format patterns above still run, so a real
  # key mistakenly committed to a template is still caught.
  local is_template="false"
  if echo "$filename" | grep -qiE '\.(example|sample|template|dist)(\.|$)|\.example$|\.sample$|\.template$|\.dist$'; then
    is_template="true"
  fi
  if [[ "$is_template" == "false" && ( "$filename" == .env* || "$filename" == "*.env" ) ]]; then
    while IFS=: read -r line_num matched_line; do
      # Skip comments and empty lines
      if echo "$matched_line" | grep -qE '^\s*(#|$)'; then
        continue
      fi
      # Skip lines that look like placeholders
      if echo "$matched_line" | grep -qEi '(example|placeholder|changeme|xxx|your_|<.*>|TODO)'; then
        continue
      fi
      # Skip assignments with an empty / blank RHS (e.g. OPENAI_API_KEY= or KEY="")
      # — an unset key is a template stub, not a leaked secret.
      local rhs="${matched_line#*=}"
      rhs="${rhs//[[:space:]]/}"
      rhs="${rhs//\"/}"
      rhs="${rhs//\'/}"
      if [[ -z "$rhs" ]]; then
        continue
      fi
      emit_finding "HIGH" "RV.1" "RV" "env-file-secret" \
        "$file" "$line_num" ".env credential" \
        "Secret value found in .env file — .env files should never be committed to source control" \
        "Add .env to .gitignore. Use .env.example with placeholder values for documentation"
    done < <(grep -nEi '(password|passwd|secret|api_key|apikey|token|auth_token|private_key|database_url|db_password|redis_url)\s*=' "$file" 2>/dev/null || true)
  fi

  return 0
}

# Scan any file for general security issues.
# Superset of scan_secrets_file: also runs code-flow checks (path traversal,
# insecure transport) that only make sense for executable source, not docs.
# Outputs JSON findings (one per line) to stdout
scan_general_file() {
  local file="$1"

  # Secrets are relevant in every file type
  scan_secrets_file "$file"

  # === MEDIUM SEVERITY (code-flow) ===

  # Path traversal patterns (single or multiple levels)
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.5" "PW" "path-traversal" \
      "$file" "$line_num" "path traversal pattern" \
      "Path traversal pattern detected — could allow access to files outside intended directory" \
      "Use path canonicalization and validate that resolved paths stay within allowed directories"
  done < <(grep -nE '\.\./' "$file" 2>/dev/null | grep -vEi '(node_modules|vendor|go\.sum|package-lock|CHANGELOG|README)' || true)

  # === LOW SEVERITY (code-flow) ===

  # HTTP URLs (non-localhost)
  while IFS=: read -r line_num _; do
    emit_finding "LOW" "PW.9" "PW" "insecure-transport" \
      "$file" "$line_num" "insecure HTTP URL" \
      "Unencrypted HTTP URL found — data transmitted in plain text" \
      "Use HTTPS instead of HTTP for all external communication"
  done < <(grep -nE 'http://' "$file" 2>/dev/null | grep -vEi '(localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|schema|xml|\.dtd|w3\.org)' || true)  # vcg-ignore: insecure-transport (pattern definition necessarily contains its own literal match)

  return 0
}
