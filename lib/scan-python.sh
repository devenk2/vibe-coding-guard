#!/usr/bin/env bash
# Vibe Coding Guard — Python Security Scanner
# Scans Python files for security anti-patterns

# Scan a Python file for security issues
# Outputs JSON findings (one per line) to stdout
scan_python_file() {
  local file="$1"

  # Skip comment-only matches by checking actual code lines
  # We use grep -n to get line numbers, then filter

  # === HIGH SEVERITY ===

  # eval() usage
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.6" "PW" "injection" \
      "$file" "$line_num" "eval(" \
      "Use of eval() allows arbitrary code execution" \
      "Use ast.literal_eval() for safe evaluation of literals, or restructure to avoid dynamic evaluation"
  done < <(grep -nE '\beval\s*\(' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # exec() usage
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.6" "PW" "injection" \
      "$file" "$line_num" "exec(" \
      "Use of exec() allows arbitrary code execution" \
      "Restructure code to avoid dynamic execution. Use importlib for dynamic imports"
  done < <(grep -nE '\bexec\s*\(' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # os.system() usage
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.6" "PW" "command-injection" \
      "$file" "$line_num" "os.system(" \
      "os.system() passes commands through the shell, enabling command injection" \
      "Use subprocess.run() with a list of arguments instead of a shell string"
  done < <(grep -nE '\bos\.system\s*\(' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # os.popen() usage
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.6" "PW" "command-injection" \
      "$file" "$line_num" "os.popen(" \
      "os.popen() passes commands through the shell, enabling command injection" \
      "Use subprocess.run() with a list of arguments instead of os.popen()"
  done < <(grep -nE '\bos\.popen\s*\(' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # pickle deserialization
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.6" "PW" "deserialization" \
      "$file" "$line_num" "pickle.load" \
      "Unpickling untrusted data can execute arbitrary code via __reduce__" \
      "Use JSON or other safe serialization formats. If pickle is required, only load trusted data"
  done < <(grep -nE '\bpickle\.(load|loads)\s*\(' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # subprocess with shell=True
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.6" "PW" "command-injection" \
      "$file" "$line_num" "shell=True" \
      "subprocess with shell=True enables shell injection attacks" \
      "Use subprocess.run() with shell=False (default) and pass arguments as a list"
  done < <(grep -nE 'subprocess\.\w+\(.*shell\s*=\s*True' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # SQL injection via string concatenation
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.5" "PW" "sql-injection" \
      "$file" "$line_num" "execute(... + ...)" \
      "SQL query built via string concatenation is vulnerable to SQL injection" \
      "Use parameterized queries with placeholders (e.g., cursor.execute('SELECT * FROM t WHERE id=?', (id,)))"
  done < <(grep -nE '\.execute\s*\(.*[+%]' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # SQL injection via f-strings
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.5" "PW" "sql-injection" \
      "$file" "$line_num" 'f"SELECT...{var}"' \
      "SQL query built with f-string interpolation is vulnerable to SQL injection" \
      "Use parameterized queries with placeholders instead of f-strings for SQL"
  done < <(grep -nE 'f["\x27].*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\{' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # Hardcoded secrets (password, secret, api_key, token assignments)
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "RV.1" "RV" "hardcoded-secret" \
      "$file" "$line_num" "secret = 'value'" \
      "Potential hardcoded secret found in source code" \
      "Use environment variables (os.environ) or a secrets manager instead of hardcoding credentials"
  done < <(grep -nEi '(password|passwd|secret|api_key|apikey|token|auth_token|private_key)\s*=\s*["\x27][^"\x27]{8,}' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # === MEDIUM SEVERITY ===

  # Weak cryptographic hash (MD5, SHA1) — direct call
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.7" "PW" "weak-crypto" \
      "$file" "$line_num" "hashlib.md5/sha1" \
      "MD5 and SHA1 are cryptographically broken for security purposes" \
      "Use hashlib.sha256() or hashlib.sha3_256() for security-sensitive hashing"
  done < <(grep -nE 'hashlib\.(md5|sha1)\s*\(' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # Weak cryptographic hash via hashlib.new('md5'/'sha1')
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.7" "PW" "weak-crypto" \
      "$file" "$line_num" "hashlib.new('md5'/'sha1')" \
      "MD5 and SHA1 via hashlib.new() are cryptographically broken for security purposes" \
      "Use hashlib.sha256() or hashlib.sha3_256() for security-sensitive hashing"
  done < <(grep -nEi 'hashlib\.new\s*\(\s*["\x27](md5|sha1)["\x27]' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # Insecure random number generator used for security-sensitive purposes
  # Only flag when the result is assigned to / used with a security-sensitive name
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.7" "PW" "weak-random" \
      "$file" "$line_num" "random.random/choice/randint" \
      "Python random module is not cryptographically secure — predictable output" \
      "Use the secrets module (secrets.token_hex(), secrets.choice()) for tokens, session IDs, and security-sensitive randomness"
  done < <(grep -nE '\brandom\.(random|choice|randint|randrange|sample|uniform)\s*\(' "$file" 2>/dev/null \
    | grep -iE '(token|secret|key|password|passwd|session|csrf|nonce|salt|otp|auth)' \
    | grep -v '^\s*#' || true)

  # assert used as security check
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.5" "PW" "assert-security" \
      "$file" "$line_num" "assert ... auth/permission" \
      "assert statements are removed when Python runs with -O flag — never use for security checks" \
      "Use if/raise instead of assert for authorization and authentication checks"
  done < <(grep -nEi 'assert\s+.*(auth|permission|role|admin|login|allowed|access|token|session|user)' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # Flask debug mode enabled
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.9" "PW" "flask-debug" \
      "$file" "$line_num" "app.run(debug=True)" \
      "Flask debug mode exposes an interactive debugger that allows remote code execution" \
      "Never enable debug=True in production. Use environment variables to control debug mode"
  done < <(grep -nE 'app\.run\s*\(.*debug\s*=\s*True' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # SSL verification disabled
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.9" "PW" "ssl-bypass" \
      "$file" "$line_num" "verify=False" \
      "Disabling SSL verification makes connections vulnerable to MITM attacks" \
      "Remove verify=False or set verify=True. Use proper CA certificates"
  done < <(grep -nE 'verify\s*=\s*False' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # Unsafe YAML loading
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.6" "PW" "unsafe-yaml" \
      "$file" "$line_num" "yaml.load(" \
      "yaml.load() without SafeLoader can execute arbitrary Python code" \
      "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)"
  done < <(grep -nE 'yaml\.load\s*\(' "$file" 2>/dev/null | grep -vE '(SafeLoader|safe_load)' | grep -v '^\s*#' || true)

  # Direct DB write in route handler without input validation
  # Detect files that have both route decorators AND db write operations
  local has_route_decorator=false
  local has_db_write=false

  if grep -qE '@(app|router)\.(post|put|patch)\b' "$file" 2>/dev/null; then
    has_route_decorator=true
  fi

  if grep -qE '\b(db|session)\.(add|execute|commit|insert|bulk_save_objects)\b|\.save\(\)|\b(repo|repository)\.\w*(save|create|insert|add|store|update|upsert|put)\w*\s*\(' "$file" 2>/dev/null; then
    has_db_write=true
  fi

  if [[ "$has_route_decorator" == true && "$has_db_write" == true ]]; then
    # Check if there's any sign of input validation/sanitization
    local has_validation=false
    if grep -Ei '(validat|sanitiz|clean|strip_tags|bleach|escape|html\.escape|markupsafe|re\.(sub|match|fullmatch)|len\s*\(.*\)\s*[<>]|max_length|min_length|Field\(.*max_length|validator|field_validator|model_validator|@validates)' "$file" 2>/dev/null | grep -qv '^\s*#'; then
      has_validation=true
    fi

    if [[ "$has_validation" == false ]]; then
      # Find the route handler lines to report
      while IFS=: read -r line_num _; do
        emit_finding "MEDIUM" "PW.5" "PW" "missing-input-validation" \
          "$file" "$line_num" "route + db write" \
          "API route handler writes user input to database without apparent input validation or sanitization" \
          "Add input validation: length limits, type checks, sanitization (e.g., bleach.clean(), html.escape()), or Pydantic validators (field_validator, Field(max_length=...))"
      done < <(grep -nE '@(app|router)\.(post|put|patch)\b' "$file" 2>/dev/null | grep -v '^\s*#' || true)
    fi
  fi

  # No-validation ORM pattern: .add() called with request body directly
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.5" "PW" "unsanitized-db-write" \
      "$file" "$line_num" "db.add(Model(**input))" \
      "User input appears to be passed directly to ORM model without sanitization" \
      "Validate and sanitize fields before creating DB objects. Use Pydantic field_validator or validate input explicitly"
  done < <(grep -nE '\.(add|insert)\s*\(\s*\w+\s*\(\s*\*\*' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # SQL query via .format() — often missed by the string concat check
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.5" "PW" "sql-injection" \
      "$file" "$line_num" ".format() in SQL" \
      "SQL query built with .format() is vulnerable to SQL injection" \
      "Use parameterized queries with placeholders instead of .format() for SQL"
  done < <(grep -nEi '(SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\.format\s*\(' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # === STREAMLIT SECURITY ===

  # unsafe_allow_html=True — XSS via raw HTML rendering (catches multiline st.markdown calls)
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.5" "PW" "streamlit-xss" \
      "$file" "$line_num" "unsafe_allow_html=True" \
      "unsafe_allow_html=True renders raw HTML, enabling XSS attacks (e.g., in st.markdown)" \
      "Remove unsafe_allow_html=True. If HTML is required, sanitize input with bleach.clean() or html.escape() before rendering"
  done < <(grep -nE 'unsafe_allow_html\s*=\s*True' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # st.components.v1.html() — embeds arbitrary HTML/JS in iframe
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.5" "PW" "streamlit-xss" \
      "$file" "$line_num" "st.components.v1.html()" \
      "st.components.v1.html() embeds arbitrary HTML and JavaScript — XSS risk if content is user-controlled" \
      "Never pass user input to components.html(). Sanitize content with bleach.clean() or use safer Streamlit display methods"
  done < <(grep -nE '(st\.components\.v1\.html|components\.html)\s*\(' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # st.write with allow_html — older API XSS variant
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.5" "PW" "streamlit-xss" \
      "$file" "$line_num" "st.write(allow_html=True)" \
      "st.write() with allow_html=True renders raw HTML, enabling XSS attacks" \
      "Remove allow_html=True. Use st.text() for plain text or sanitize HTML input before rendering"
  done < <(grep -nE 'st\.write\s*\(.*allow_html\s*=\s*True' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # Streamlit input → database/shell without validation
  # Detect files using both st.text_input/text_area AND db/shell operations
  local has_streamlit_input=false
  local has_sensitive_sink=false

  if grep -qE 'st\.(text_input|text_area|number_input|selectbox|multiselect|file_uploader)\s*\(' "$file" 2>/dev/null; then
    has_streamlit_input=true
  fi

  if grep -qE '(\.execute\s*\(|os\.system|subprocess\.|os\.popen|cursor\.|\.query\s*\()' "$file" 2>/dev/null; then
    has_sensitive_sink=true
  fi

  if [[ "$has_streamlit_input" == true && "$has_sensitive_sink" == true ]]; then
    local has_st_validation=false
    if grep -Ei '(validat|sanitiz|clean|escape|bleach|re\.(sub|match|fullmatch)|html\.escape|parameterized|placeholder|\?)' "$file" 2>/dev/null | grep -qv '^\s*#'; then
      has_st_validation=true
    fi

    if [[ "$has_st_validation" == false ]]; then
      while IFS=: read -r line_num _; do
        emit_finding "MEDIUM" "PW.5" "PW" "streamlit-input-injection" \
          "$file" "$line_num" "st.text_input → db/shell" \
          "Streamlit user input is used in a file with database or shell operations without apparent validation" \
          "Validate and sanitize all Streamlit inputs before passing to databases or shell commands. Use parameterized queries for SQL"
      done < <(grep -nE 'st\.(text_input|text_area|number_input)\s*\(' "$file" 2>/dev/null | grep -v '^\s*#' || true)
    fi
  fi

  # st.file_uploader without file type or size validation
  if grep -qE 'st\.file_uploader\s*\(' "$file" 2>/dev/null; then
    # Check if type= parameter is specified (file type restriction)
    while IFS=: read -r line_num matched_line; do
      if ! echo "$matched_line" | grep -qE 'type\s*='; then
        emit_finding "MEDIUM" "PW.5" "PW" "streamlit-unrestricted-upload" \
          "$file" "$line_num" "st.file_uploader (no type=)" \
          "st.file_uploader() without type= restriction allows uploading any file type including executables" \
          "Restrict file types: st.file_uploader('Upload', type=['csv', 'txt', 'pdf']). Validate file content, not just extension"
      fi
    done < <(grep -nE 'st\.file_uploader\s*\(' "$file" 2>/dev/null | grep -v '^\s*#' || true)
  fi

  # st.query_params / experimental_get_query_params used with sensitive sinks
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.5" "PW" "streamlit-query-param-injection" \
      "$file" "$line_num" "st.query_params" \
      "URL query parameters are user-controlled — validate before using in database queries, file paths, or shell commands" \
      "Sanitize and validate query parameter values. Use parameterized queries for SQL. Never pass directly to shell or file operations"
  done < <(grep -nE 'st\.(query_params|experimental_get_query_params)\s*' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # .streamlit/secrets.toml reference — remind about gitignore
  if grep -qE '(st\.secrets|\.streamlit/secrets)' "$file" 2>/dev/null; then
    while IFS=: read -r line_num _; do
      emit_finding "LOW" "RV.1" "RV" "streamlit-secrets" \
        "$file" "$line_num" "st.secrets" \
        "Ensure .streamlit/secrets.toml is in .gitignore — it contains sensitive configuration" \
        "Add '.streamlit/secrets.toml' to .gitignore. Use environment variables for production deployments instead of st.secrets"
    done < <(grep -nE '(st\.secrets|\.streamlit/secrets)' "$file" 2>/dev/null | grep -v '^\s*#' | head -1 || true)
  fi

  # === LOGGING CHECKS ===

  # Check for sensitive operations without logging (only if logging is already configured)
  local has_logging_configured=false
  if grep -qE '\bimport\s+logging\b|from\s+logging\s+import|getLogger\s*\(|structlog|loguru' "$file" 2>/dev/null; then
    has_logging_configured=true
  fi

  if [[ "$has_logging_configured" == true ]]; then
    # Sensitive operation patterns: auth, user management, payments, admin, delete
    local sensitive_ops_pattern='(login|logout|authenticate|authorize|sign_in|sign_out|register|create_user|delete_user|update_password|change_password|reset_password|grant_role|revoke_role|add_role|remove_role|set_permission|delete_account|suspend_user|ban_user|charge|refund|payment|transfer_funds|withdraw|admin_action|escalate|impersonate)\s*\('

    if grep -qE "$sensitive_ops_pattern" "$file" 2>/dev/null; then
      # Check if there are log calls in the file near sensitive operations
      local has_logging_calls=false
      if grep -qE '\b(logger|log|logging)\.(info|warning|error|critical|debug|audit|exception)\s*\(' "$file" 2>/dev/null; then
        has_logging_calls=true
      fi

      if [[ "$has_logging_calls" == false ]]; then
        while IFS=: read -r line_num _; do
          emit_finding "MEDIUM" "PW.8" "PW" "missing-logging" \
            "$file" "$line_num" "sensitive op without logging" \
            "Sensitive operation (auth/user-mgmt/payment) has no logging — security events must be logged for audit trails" \
            "Add logging for sensitive operations: logger.info('User %s logged in', user_id). Log auth events, permission changes, and financial transactions"
        done < <(grep -nE "$sensitive_ops_pattern" "$file" 2>/dev/null | grep -v '^\s*#' || true)
      fi
    fi
  fi

  # === LOW SEVERITY ===

  # Bare except clause
  while IFS=: read -r line_num _; do
    emit_finding "LOW" "PW.8" "PW" "error-swallowing" \
      "$file" "$line_num" "except:" \
      "Bare except clause catches all exceptions including SystemExit and KeyboardInterrupt" \
      "Catch specific exceptions (e.g., except ValueError:) or at minimum use except Exception:"
  done < <(grep -nE '^\s*except\s*:\s*$' "$file" 2>/dev/null || true)

  # Exception swallowing (except Exception: pass)
  while IFS=: read -r line_num _; do
    emit_finding "LOW" "PW.8" "PW" "error-swallowing" \
      "$file" "$line_num" "except Exception: pass" \
      "Catching and silently ignoring exceptions hides bugs and security issues" \
      "Log the exception or handle it explicitly. Avoid bare pass in exception handlers"
  done < <(grep -nE 'except\s+\w+.*:\s*$' "$file" 2>/dev/null | while IFS=: read -r ln _; do
    next_line=$((ln + 1))
    if sed -n "${next_line}p" "$file" | grep -qE '^\s*pass\s*$'; then
      echo "$ln:"
    fi
  done || true)

  return 0
}
