#!/usr/bin/env bash
# Vibe Coding Guard — JavaScript/TypeScript Security Scanner
# Scans JS/TS files for security anti-patterns

# Scan a JavaScript/TypeScript file for security issues
# Outputs JSON findings (one per line) to stdout
scan_js_file() {
  local file="$1"

  # === HIGH SEVERITY ===

  # eval() usage
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.6" "PW" "injection" \
      "$file" "$line_num" "eval(" \
      "Use of eval() allows arbitrary code execution" \
      "Avoid eval(). Use JSON.parse() for data, or restructure to avoid dynamic evaluation"
  done < <(grep -nE '\beval\s*\(' "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' || true)

  # innerHTML assignment with dynamic content
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.5" "PW" "xss" \
      "$file" "$line_num" ".innerHTML =" \
      "Setting innerHTML with dynamic content enables XSS attacks" \
      "Use textContent for text, or use a sanitization library like DOMPurify"
  done < <(grep -nE '\.innerHTML\s*=' "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' || true)

  # document.write
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.5" "PW" "xss" \
      "$file" "$line_num" "document.write(" \
      "document.write() with dynamic content enables XSS attacks" \
      "Use DOM APIs (createElement, textContent) instead of document.write()"
  done < <(grep -nE 'document\.write\s*\(' "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' || true)

  # new Function() constructor
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.6" "PW" "injection" \
      "$file" "$line_num" "new Function(" \
      "new Function() is similar to eval() and allows arbitrary code execution" \
      "Restructure code to avoid dynamic function creation"
  done < <(grep -nE '\bnew\s+Function\s*\(' "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' || true)

  # setTimeout/setInterval with string argument (equivalent to eval)
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.6" "PW" "injection" \
      "$file" "$line_num" "setTimeout/setInterval(string)" \
      "setTimeout/setInterval with a string argument executes it as code like eval()" \
      "Pass a function reference instead of a string: setTimeout(fn, delay) not setTimeout('code', delay)"
  done < <(grep -nE '(setTimeout|setInterval)\s*\(\s*["\x27`]' "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' || true)

  # child_process exec with string concatenation
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.6" "PW" "command-injection" \
      "$file" "$line_num" "child_process.exec(" \
      "Using exec() with string concatenation enables command injection" \
      "Use execFile() or spawn() with arguments as an array, not a concatenated string"
  done < <(grep -nE '(child_process|cp).*\bexec\s*\(' "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' || true)

  # Hardcoded secrets
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "RV.1" "RV" "hardcoded-secret" \
      "$file" "$line_num" "secret = 'value'" \
      "Potential hardcoded secret found in source code" \
      "Use environment variables (process.env) or a secrets manager instead"
  done < <(grep -nEi '(password|passwd|secret|api_key|apiKey|token|auth_token|privateKey)\s*[:=]\s*["\x27`][^"\x27`]{8,}' "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' || true)

  # === MEDIUM SEVERITY ===

  # dangerouslySetInnerHTML (React)
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.5" "PW" "xss" \
      "$file" "$line_num" "dangerouslySetInnerHTML" \
      "dangerouslySetInnerHTML bypasses React's XSS protections" \
      "Sanitize HTML with DOMPurify before using dangerouslySetInnerHTML"
  done < <(grep -nE 'dangerouslySetInnerHTML' "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' || true)

  # Prototype pollution via __proto__
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.6" "PW" "prototype-pollution" \
      "$file" "$line_num" "__proto__" \
      "Direct __proto__ access can enable prototype pollution attacks" \
      "Use Object.create(null) for lookup objects, or validate keys to exclude __proto__"
  done < <(grep -nE '__proto__' "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' || true)

  # SSL/TLS verification disabled
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.9" "PW" "ssl-bypass" \
      "$file" "$line_num" "rejectUnauthorized: false" \
      "Disabling TLS certificate validation makes connections vulnerable to MITM attacks" \
      "Remove rejectUnauthorized: false. Use proper CA certificates"
  done < <(grep -nE 'rejectUnauthorized\s*:\s*false' "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' || true)

  # Weak crypto
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.7" "PW" "weak-crypto" \
      "$file" "$line_num" "createHash('md5'/'sha1')" \
      "MD5 and SHA1 are cryptographically broken for security purposes" \
      "Use createHash('sha256') or createHash('sha3-256') for security-sensitive hashing"
  done < <(grep -nEi "createHash\s*\(\s*['\"]?(md5|sha1)['\"]?" "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' || true)

  # Math.random() used for security-sensitive purposes
  # Only flag when the result is assigned to / used with a security-sensitive name
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.7" "PW" "weak-random" \
      "$file" "$line_num" "Math.random()" \
      "Math.random() is not cryptographically secure — predictable output" \
      "Use crypto.randomBytes(), crypto.randomUUID(), or crypto.getRandomValues() for tokens, session IDs, and security-sensitive randomness"
  done < <(grep -nE 'Math\.random\s*\(' "$file" 2>/dev/null \
    | grep -iE '(token|secret|key|password|passwd|session|csrf|nonce|salt|otp|auth)' \
    | grep -vE '^\s*(//|\*)' || true)

  # require('child_process') import
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.6" "PW" "command-injection-risk" \
      "$file" "$line_num" "require('child_process')" \
      "Importing child_process module — ensure commands are not built from user input" \
      "Use execFile() or spawn() with argument arrays. Never pass user input to exec()"
  done < <(grep -nE "require\s*\(\s*['\"]child_process['\"]" "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' || true)

  # Direct DB write in route handler without input validation
  local has_route=false
  local has_db_write=false

  if grep -qE '\.(post|put|patch)\s*\(' "$file" 2>/dev/null && grep -qE '(router|app|express)' "$file" 2>/dev/null; then
    has_route=true
  fi

  if grep -qE '\.(create|save|insert|insertMany|updateOne|updateMany|findOneAndUpdate|bulkWrite)\s*\(|\b(repo|repository)\.\w*(save|create|insert|add|store|update|upsert|put)\w*\s*\(' "$file" 2>/dev/null; then
    has_db_write=true
  fi

  if [[ "$has_route" == true && "$has_db_write" == true ]]; then
    local has_validation=false
    if grep -qEi '(validat|sanitiz|escape|trim|xss|joi\.|yup\.|zod\.|\.isLength|\.isEmail|\.isAlphanumeric|express-validator|helmet|dompurify)' "$file" 2>/dev/null; then
      has_validation=true
    fi

    if [[ "$has_validation" == false ]]; then
      while IFS=: read -r line_num _; do
        emit_finding "MEDIUM" "PW.5" "PW" "missing-input-validation" \
          "$file" "$line_num" "route + db write" \
          "API route handler writes user input to database without apparent input validation or sanitization" \
          "Add input validation using express-validator, Joi, Zod, or manual sanitization (e.g., validator.escape(), DOMPurify)"
      done < <(grep -nE '\.(post|put|patch)\s*\(' "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' || true)
    fi
  fi

  # === LOGGING CHECKS ===

  # Check for sensitive operations without logging (only if logging is already configured)
  local has_logging_configured=false
  if grep -qE '\b(winston|pino|bunyan|log4js|morgan|signale|loglevel)\b|require\s*\(\s*["\x27](winston|pino|bunyan|log4js|morgan)["\x27]\)|from\s+["\x27](winston|pino|bunyan|log4js)["\x27]|createLogger|getLogger|Logger\s*\(' "$file" 2>/dev/null; then
    has_logging_configured=true
  fi

  if [[ "$has_logging_configured" == true ]]; then
    local sensitive_ops_pattern='(login|logout|authenticate|authorize|signIn|signOut|register|createUser|deleteUser|updatePassword|changePassword|resetPassword|grantRole|revokeRole|addRole|removeRole|setPermission|deleteAccount|suspendUser|banUser|charge|refund|payment|transferFunds|withdraw|adminAction|escalate|impersonate)\s*\('

    if grep -qE "$sensitive_ops_pattern" "$file" 2>/dev/null; then
      local has_logging_calls=false
      if grep -qE '\b(logger|log)\.(info|warn|error|fatal|debug|trace|audit)\s*\(|console\.(log|warn|error|info)\s*\(' "$file" 2>/dev/null; then
        has_logging_calls=true
      fi

      if [[ "$has_logging_calls" == false ]]; then
        while IFS=: read -r line_num _; do
          emit_finding "MEDIUM" "PW.8" "PW" "missing-logging" \
            "$file" "$line_num" "sensitive op without logging" \
            "Sensitive operation (auth/user-mgmt/payment) has no logging — security events must be logged for audit trails" \
            "Add logging for sensitive operations: logger.info('User logged in', { userId }). Log auth events, permission changes, and financial transactions"
        done < <(grep -nE "$sensitive_ops_pattern" "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' || true)
      fi
    fi
  fi

  # req.body spread directly into DB model
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.5" "PW" "unsanitized-db-write" \
      "$file" "$line_num" "Model.create(req.body)" \
      "Request body passed directly to database model without validation" \
      "Validate and sanitize req.body fields before passing to DB. Use a validation library (Joi, Zod, express-validator)"
  done < <(grep -nE '\.(create|insert|save)\s*\(\s*(req\.body|\{.*\.\.\.req\.body)' "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' || true)

  return 0
}
