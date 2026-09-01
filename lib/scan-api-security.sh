#!/usr/bin/env bash
# Vibe Coding Guard — API Security Scanner
# Detects insecure API patterns across Python (requests, FastAPI, Flask, Django),
# JavaScript (fetch, axios, Express), and general HTTP/API anti-patterns.
# Language-agnostic where possible, with framework-specific checks.

# Scan a file for API security issues
# Outputs JSON findings (one per line) to stdout
scan_api_security_file() {
  local file="$1"
  # auth_detected: precomputed by the hook via project_uses_auth() — gates the
  # missing-api-auth checks below so they stay silent on projects that don't
  # use/need auth (public APIs, internal tools). See lib/scan-auth.sh.
  local auth_detected="${2:-false}"

  # =====================================================================
  # === HIGH SEVERITY ===
  # =====================================================================

  # --- SSRF: User input in URL for HTTP requests ---

  # Python: requests.get/post/put/delete/patch with f-string or .format() URL
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.5" "PW" "ssrf" \
      "$file" "$line_num" "requests.*f\"http..." \
      "HTTP request URL built from dynamic input — potential Server-Side Request Forgery (SSRF)" \
      "Validate and allowlist target URLs/hosts. Never let user input control the full URL. Use urllib.parse to validate the scheme and host"
  done < <(grep -nE 'requests\.(get|post|put|delete|patch|head|options)\s*\(\s*f["\x27]' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.5" "PW" "ssrf" \
      "$file" "$line_num" "requests.*format(" \
      "HTTP request URL built with .format() — potential SSRF" \
      "Validate and allowlist target URLs/hosts. Never pass user-controlled data as the full URL"
  done < <(grep -nE 'requests\.(get|post|put|delete|patch|head|options)\s*\(.*\.format\s*\(' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # Python: requests with string concatenation in URL
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.5" "PW" "ssrf" \
      "$file" "$line_num" "requests.*(url + ...)" \
      "HTTP request URL built via string concatenation — potential SSRF" \
      "Validate and allowlist target URLs/hosts. Use urllib.parse.urljoin() for safe URL construction"
  done < <(grep -nE 'requests\.(get|post|put|delete|patch|head|options)\s*\([^)]*\+' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # Python: httpx/aiohttp/urllib with dynamic URL
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.5" "PW" "ssrf" \
      "$file" "$line_num" "httpx/aiohttp dynamic URL" \
      "HTTP client request with dynamically constructed URL — potential SSRF" \
      "Validate target URLs against an allowlist of permitted hosts before making requests"
  done < <(grep -nE '(httpx\.(get|post|put|delete|patch|AsyncClient)|aiohttp\.ClientSession|urllib\.request\.(urlopen|urlretrieve))\s*\(.*(\+|\.format|f["\x27])' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # JavaScript: fetch/axios with template literal or concatenation
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.5" "PW" "ssrf" \
      "$file" "$line_num" "fetch/axios(\`...dynamic\`)" \
      "HTTP request URL built from dynamic input — potential SSRF" \
      "Validate and allowlist target URLs/hosts. Use the URL constructor to validate scheme and host"
  done < <(grep -nE '(fetch|axios\.(get|post|put|delete|patch)|axios)\s*\(\s*`' "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' || true)

  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.5" "PW" "ssrf" \
      "$file" "$line_num" "fetch/axios(url + ...)" \
      "HTTP request URL built via string concatenation — potential SSRF" \
      "Validate and allowlist target URLs/hosts. Never let user input control the full URL"
  done < <(grep -nE '(fetch|axios\.(get|post|put|delete|patch)|axios)\s*\([^)]*\+' "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' || true)

  # --- Missing Authentication / Authorization ---

  # FastAPI route without Depends() for auth — POST/PUT/PATCH/DELETE
  # Heuristic: route decorator present but no Depends() in the function signature
  # Gated: only meaningful if the project actually uses auth (see scan-auth.sh
  # header for the rationale — this avoids noise on public APIs/internal tools
  # that intentionally have no auth model).
  if [[ "$auth_detected" == "true" && "${AUTH_CHECK_MISSING_MIDDLEWARE:-true}" == "true" ]]; then
  if grep -qE '@(app|router)\.(post|put|patch|delete)\b' "$file" 2>/dev/null; then
    # NOTE: declared once, outside the loop — bash 3.2 (this project's target
    # shell) has a bug where re-declaring `local` with a multi-line
    # command-substitution value on every loop iteration can leak a stray
    # "func_sig=$'...'" line onto stdout starting from the 2nd match. See
    # lib/scan-auth.sh's header comment for the full writeup.
    local func_sig
    while IFS=: read -r line_num _; do
      # Read the next few lines to check for Depends in the function signature
      func_sig=$(sed -n "${line_num},$((line_num + 5))p" "$file" 2>/dev/null)
      if ! echo "$func_sig" | grep -qEi '(Depends|Security|HTTPBearer|HTTPBasic|OAuth2PasswordBearer|api_key|get_current_user|authenticate|require_auth|login_required|permission_required)'; then
        emit_finding "MEDIUM" "PW.9" "PW" "missing-api-auth" \
          "$file" "$line_num" "@router.post without Depends()" \
          "API mutation endpoint (POST/PUT/PATCH/DELETE) has no apparent authentication/authorization dependency" \
          "Add authentication via Depends() (e.g., Depends(get_current_user)) or Security() to protect mutation endpoints"
      fi
    done < <(grep -nE '@(app|router)\.(post|put|patch|delete)\b' "$file" 2>/dev/null | grep -v '^\s*#' || true)
  fi

  # Express.js route without auth middleware for mutations
  # Only applies to JS/TS files (check for express/require/import pattern to avoid matching Python files)
  if grep -qE '(require\s*\(|import\s.*from)' "$file" 2>/dev/null && grep -qE '(express|router|app)\s*[\.(=]' "$file" 2>/dev/null; then
    if grep -qE '\.(post|put|patch|delete)\s*\(' "$file" 2>/dev/null; then
      while IFS=: read -r line_num matched_line; do
        # Check if the route has an auth middleware argument between path and handler
        # Typical pattern: router.post('/path', authMiddleware, handler)
        if ! echo "$matched_line" | grep -qEi '(auth|protect|verify|guard|jwt|bearer|passport|isAuthenticated|requireLogin|ensureAuth|isAdmin|checkPermission)'; then
          emit_finding "MEDIUM" "PW.9" "PW" "missing-api-auth" \
            "$file" "$line_num" "router.post without auth middleware" \
            "API mutation endpoint has no apparent authentication middleware" \
            "Add authentication middleware (e.g., router.post('/path', authMiddleware, handler))"
        fi
      done < <(grep -nE '\.(post|put|patch|delete)\s*\(' "$file" 2>/dev/null | grep -vE '^\s*(//|\*)|@(app|router)\.' || true)
    fi
  fi
  fi

  # --- API Key / Token in URL Query Parameters ---
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "RV.1" "RV" "api-key-in-url" \
      "$file" "$line_num" "?api_key=... in URL" \
      "API key or token passed in URL query parameter — may be logged in server logs, browser history, and proxies" \
      "Send API keys and tokens in HTTP headers (Authorization header) instead of URL query parameters"
  done < <(grep -nEi '(url|endpoint|href|fetch|get|request)\s*[=(].*\?(.*&)?(api_key|apikey|token|access_token|auth_token|secret|key)=' "$file" 2>/dev/null | grep -vE '^\s*(#|//|\*)' || true)

  # Direct pattern: query string with sensitive parameters
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "RV.1" "RV" "api-key-in-url" \
      "$file" "$line_num" "?api_key=... / ?token=..." \
      "Sensitive credential passed as URL query parameter — visible in logs, referrers, and browser history" \
      "Send credentials via Authorization header or POST body, never as URL query parameters"
  done < <(grep -nEi '["\x27`]https?://[^"\x27`]*\?(.*&)?(api_key|apikey|token|access_token|secret_key|auth)=[^"\x27`&]+' "$file" 2>/dev/null | grep -vE '^\s*(#|//|\*)|example\.com|localhost' || true)

  # --- Unrestricted CORS ---

  # Python: allow_origins=["*"], CORS_ORIGIN_ALLOW_ALL=True
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.9" "PW" "cors-wildcard" \
      "$file" "$line_num" "Allow-Origin: *" \
      "Wildcard CORS origin allows any website to make authenticated requests to this API" \
      "Restrict CORS origins to specific trusted domains. Never use '*' with credentials"
  done < <(grep -nEi 'allow_origins\s*=\s*\[\s*"\*"\s*\]|origins\s*=\s*\[\s*"\*"\s*\]|CORS_ORIGIN_ALLOW_ALL\s*=\s*True' "$file" 2>/dev/null | grep -vE '^\s*(#|//|\*)' || true)

  # JavaScript/General: cors() with no config, origin: '*', Access-Control-Allow-Origin: *
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.9" "PW" "cors-wildcard" \
      "$file" "$line_num" "cors / origin: '*'" \
      "Wildcard CORS origin allows any website to make cross-origin requests to this API" \
      "Restrict CORS to specific domains: cors({ origin: ['https://trusted.example.com'] })"
  done < <(grep -nEi "app\.use\s*\(\s*cors\s*\(\s*\)\s*\)|origin\s*:\s*['\"]?\*['\"]?|Access-Control-Allow-Origin[^a-zA-Z]*['\"]?\*['\"]?" "$file" 2>/dev/null | grep -vE '^\s*(#|//|\*)' || true)

  # =====================================================================
  # === MEDIUM SEVERITY ===
  # =====================================================================

  # --- Missing Rate Limiting ---

  # FastAPI/Flask app without rate limiting import
  if grep -qE '(from fastapi|from flask|Flask\s*\(|FastAPI\s*\()' "$file" 2>/dev/null; then
    # Check if it's defining routes
    if grep -qE '@(app|router)\.(get|post|put|patch|delete)\b' "$file" 2>/dev/null; then
      # Check for rate limiting
      if ! grep -qEi '(slowapi|ratelimit|limiter|throttle|RateLim|rate_limit|Throttle)' "$file" 2>/dev/null; then
        local first_route_line
        first_route_line=$(grep -nE '@(app|router)\.(get|post|put|patch|delete)\b' "$file" 2>/dev/null | head -1 | cut -d: -f1)
        if [[ -n "$first_route_line" ]]; then
          emit_finding "MEDIUM" "PW.9" "PW" "missing-rate-limit" \
            "$file" "$first_route_line" "API routes without rate limiting" \
            "API routes defined without rate limiting — vulnerable to brute-force and denial-of-service attacks" \
            "Add rate limiting with slowapi (FastAPI) or flask-limiter (Flask). Example: from slowapi import Limiter"
        fi
      fi
    fi
  fi

  # Express app without rate limiting
  if grep -qE '(express\s*\(\)|require.*express)' "$file" 2>/dev/null; then
    if grep -qE '\.(get|post|put|patch|delete)\s*\(' "$file" 2>/dev/null; then
      if ! grep -qEi '(rateLimit|rate-limit|express-rate-limit|express-slow-down|throttle|limiter)' "$file" 2>/dev/null; then
        local first_route_line
        first_route_line=$(grep -nE '\.(get|post|put|patch|delete)\s*\(' "$file" 2>/dev/null | head -1 | cut -d: -f1)
        if [[ -n "$first_route_line" ]]; then
          emit_finding "MEDIUM" "PW.9" "PW" "missing-rate-limit" \
            "$file" "$first_route_line" "Express routes without rate limiting" \
            "Express API routes without rate limiting — vulnerable to brute-force and DoS attacks" \
            "Use express-rate-limit: const limiter = rateLimit({ windowMs: 15*60*1000, max: 100 }); app.use(limiter)"
        fi
      fi
    fi
  fi

  # --- Missing Security Headers ---

  # Python: FastAPI/Flask without security headers middleware
  if grep -qE '(FastAPI\s*\(|Flask\s*\()' "$file" 2>/dev/null; then
    if ! grep -qEi '(helmet|secure_headers|SecurityMiddleware|Talisman|flask-talisman|starlette\.middleware|TrustedHostMiddleware|X-Content-Type-Options|X-Frame-Options|Content-Security-Policy)' "$file" 2>/dev/null; then
      local app_def_line
      app_def_line=$(grep -nE '(FastAPI|Flask)\s*\(' "$file" 2>/dev/null | head -1 | cut -d: -f1)
      if [[ -n "$app_def_line" ]]; then
        emit_finding "MEDIUM" "PW.9" "PW" "missing-security-headers" \
          "$file" "$app_def_line" "No security headers middleware" \
          "API app created without security headers middleware — missing protections like X-Content-Type-Options, X-Frame-Options" \
          "Add security headers. FastAPI: use starlette-security-headers or add middleware. Flask: use flask-talisman"
      fi
    fi
  fi

  # JavaScript: Express without helmet
  if grep -qE '(express\s*\(\)|require.*express)' "$file" 2>/dev/null; then
    if ! grep -qEi '(helmet|security.*header|X-Content-Type-Options|X-Frame-Options|Content-Security-Policy)' "$file" 2>/dev/null; then
      local app_line
      app_line=$(grep -nE 'express\s*\(\)' "$file" 2>/dev/null | head -1 | cut -d: -f1)
      if [[ -n "$app_line" ]]; then
        emit_finding "MEDIUM" "PW.9" "PW" "missing-security-headers" \
          "$file" "$app_line" "Express without helmet" \
          "Express app without helmet middleware — missing important security headers" \
          "Install and use helmet: const helmet = require('helmet'); app.use(helmet());"
      fi
    fi
  fi

  # --- Sensitive Data in API Responses ---

  # Returning password/secret fields in API response
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.8" "PW" "sensitive-data-exposure" \
      "$file" "$line_num" "password/secret in response" \
      "API response may include sensitive fields (password, secret, token) — data exposure risk" \
      "Exclude sensitive fields from API responses. Use response models/serializers that explicitly allowlist returned fields"
  done < <(grep -nEi '(jsonify|JSONResponse|json\.dumps|res\.json|response\.json)\s*\(.*\b(password|passwd|secret|token|api_key|private_key|ssn|credit_card)\b' "$file" 2>/dev/null | grep -vE '^\s*(#|//|\*)' || true)

  # Django: model serialization without field exclusion
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.8" "PW" "sensitive-data-exposure" \
      "$file" "$line_num" "fields = '__all__'" \
      "Serializer/ModelForm with fields='__all__' may expose sensitive model fields in API responses" \
      "Explicitly list allowed fields instead of using '__all__'. Exclude sensitive fields like password, token"
  done < <(grep -nE "fields\s*=\s*['\"]__all__['\"]" "$file" 2>/dev/null | grep -vE '^\s*(#|//|\*)' || true)

  # --- Insecure Deserialization in API ---

  # Accepting arbitrary content types or deserializing untrusted data
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.6" "PW" "insecure-api-deserialization" \
      "$file" "$line_num" "yaml.load from request" \
      "Deserializing YAML from API request body without safe loader — can execute arbitrary code" \
      "Use yaml.safe_load() for YAML from API requests. Prefer JSON as the API data format"
  done < <(grep -nE 'yaml\.(load|unsafe_load)\s*\(.*\b(request|req|body|data|payload|content)\b' "$file" 2>/dev/null | grep -vE '^\s*(#|//|\*)' || true)

  # --- Verbose Error Responses ---

  # FastAPI/Flask debug or traceback in production
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.8" "PW" "verbose-error-response" \
      "$file" "$line_num" "traceback in API response" \
      "Returning stack traces or debug info in API error responses leaks internal server details" \
      "Return generic error messages to clients. Log detailed errors server-side only"
  done < <(grep -nEi '(traceback\.(format_exc|print_exc)|str\(e\)|repr\(e\)|exc_info).*\b(json|response|return|send)\b|\b(json|response|return|send)\b.*(traceback\.(format_exc|print_exc)|str\(e\)|repr\(e\))' "$file" 2>/dev/null | grep -vE '^\s*(#|//|\*)' || true)

  # Returning exception message directly
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.8" "PW" "verbose-error-response" \
      "$file" "$line_num" "str(e) in response" \
      "Exception details returned in API response — may leak sensitive internal information" \
      "Return generic error messages (e.g., 'Internal Server Error'). Log exception details server-side"
  done < <(grep -nEi '(JSONResponse|jsonify|res\.json|json\.dumps)\s*\(.*\bstr\s*\(\s*e\s*\)' "$file" 2>/dev/null | grep -vE '^\s*(#|//|\*)' || true)

  # --- Open Redirect ---

  # Redirect to user-supplied URL
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.5" "PW" "open-redirect" \
      "$file" "$line_num" "redirect(user_input)" \
      "Redirecting to a user-supplied URL may enable open redirect / phishing attacks" \
      "Validate redirect URLs against an allowlist of trusted domains. Use relative paths when possible"
  done < <(grep -nEi '(redirect|RedirectResponse|res\.redirect|location\s*=)\s*\(?\s*(request\.|req\.|params|query|body|user_input|url|next|return_to|redirect_url|callback|goto)' "$file" 2>/dev/null | grep -vE '^\s*(#|//|\*)' || true)

  # --- JWT Misconfiguration ---

  # JWT without algorithm verification (algorithm='none' or verify=False)
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.7" "PW" "jwt-no-verify" \
      "$file" "$line_num" "jwt.decode(verify=False)" \
      "JWT decoded without signature verification — tokens can be forged" \
      "Always verify JWT signatures: jwt.decode(token, key, algorithms=['HS256']). Never use verify=False"
  done < <(grep -nEi 'jwt\.(decode|verify)\s*\(.*verify\s*=\s*False' "$file" 2>/dev/null | grep -vE '^\s*(#|//|\*)' || true)

  # JWT with algorithm 'none'
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.7" "PW" "jwt-alg-none" \
      "$file" "$line_num" "algorithm='none'" \
      "JWT configured with algorithm 'none' — tokens have no signature and can be freely forged" \
      "Use a strong algorithm: algorithms=['HS256'] or algorithms=['RS256']. Never allow 'none'"
  done < <(grep -nEi "(algorithm|algorithms)\s*[:=]\s*['\"\[]?\s*['\"]?none['\"]?" "$file" 2>/dev/null | grep -vE '^\s*(#|//|\*)' || true)

  # =====================================================================
  # === LOW SEVERITY ===
  # =====================================================================

  # --- Missing Request Timeout ---

  # Python: requests without timeout
  while IFS=: read -r line_num matched_line; do
    if ! echo "$matched_line" | grep -qE 'timeout\s*='; then
      emit_finding "LOW" "PW.9" "PW" "missing-request-timeout" \
        "$file" "$line_num" "requests.get() without timeout" \
        "HTTP request without explicit timeout — can hang indefinitely and cause resource exhaustion" \
        "Always set a timeout: requests.get(url, timeout=30). Use a tuple for connect/read timeouts: timeout=(5, 30)"
    fi
  done < <(grep -nE 'requests\.(get|post|put|delete|patch|head|options)\s*\(' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # Python: httpx without timeout
  while IFS=: read -r line_num matched_line; do
    if ! echo "$matched_line" | grep -qE 'timeout\s*='; then
      emit_finding "LOW" "PW.9" "PW" "missing-request-timeout" \
        "$file" "$line_num" "httpx request without timeout" \
        "HTTP request without explicit timeout — can hang indefinitely" \
        "Set a timeout: httpx.get(url, timeout=30) or use httpx.Client(timeout=30)"
    fi
  done < <(grep -nE 'httpx\.(get|post|put|delete|patch|head|options)\s*\(' "$file" 2>/dev/null | grep -v '^\s*#' || true)

  # JavaScript: fetch without AbortController/timeout
  while IFS=: read -r line_num matched_line; do
    if ! echo "$matched_line" | grep -qEi '(signal|abort|timeout)'; then
      emit_finding "LOW" "PW.9" "PW" "missing-request-timeout" \
        "$file" "$line_num" "fetch() without timeout/signal" \
        "fetch() without AbortController signal — can hang indefinitely" \
        "Use AbortController with a timeout: const ctrl = new AbortController(); setTimeout(() => ctrl.abort(), 30000); fetch(url, { signal: ctrl.signal })"
    fi
  done < <(grep -nE '\bfetch\s*\(' "$file" 2>/dev/null | grep -vE '^\s*(//|\*)|import|require|mockFetch|jest' || true)

  # --- Missing Content-Type Validation ---

  # Express body parsing without content-type limits
  while IFS=: read -r line_num _; do
    emit_finding "LOW" "PW.5" "PW" "missing-content-type-limit" \
      "$file" "$line_num" "express.json() without limit" \
      "Body parser without size limit — vulnerable to large payload denial-of-service" \
      "Set a body size limit: express.json({ limit: '100kb' }) or app.use(express.json({ limit: '1mb' }))"
  done < <(grep -nE 'express\.(json|urlencoded)\s*\(\s*\)' "$file" 2>/dev/null | grep -vE '^\s*(//|\*)' || true)

  # --- HTTP Method Not Restricted ---

  # Flask route without methods restriction (defaults to GET only, but patterns can be misleading)
  # Catch routes that use @app.route with method-agnostic handlers doing writes
  # (This is a heuristic — may generate some noise)

  # --- API Versioning Missing ---
  # Informational: API routes without versioning pattern
  # Skipped as too noisy — better for LLM contextual analysis

  return 0
}
