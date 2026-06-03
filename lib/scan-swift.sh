#!/usr/bin/env bash
# Vibe Coding Guard — Swift Security Scanner
# Scans Swift files for security anti-patterns
# Covers OWASP Mobile Top 10 (2024) and iOS/macOS-specific issues

# Scan a Swift file for security issues
# Outputs JSON findings (one per line) to stdout
scan_swift_file() {
  local file="$1"

  # =====================================================================
  # === HIGH SEVERITY ===
  # =====================================================================

  # --- M1: Improper Credential Usage ---

  # Hardcoded secrets (API keys, passwords, tokens assigned to string literals)
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "RV.1" "RV" "hardcoded-secret" \
      "$file" "$line_num" "secret = \"value\"" \
      "Potential hardcoded secret found in source code (OWASP M1: Improper Credential Usage)" \
      "Store secrets in the Keychain (Security framework) or use environment variables. Never hardcode credentials in Swift source"
  done < <(grep -nEi '(password|passwd|secret|apiKey|api_key|apikey|token|authToken|auth_token|privateKey|private_key|clientSecret|client_secret)\s*[:=]\s*"[^"]{8,}"' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # Secrets stored in UserDefaults (insecure plaintext storage)
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "RV.1" "RV" "insecure-secret-storage" \
      "$file" "$line_num" "UserDefaults.set(secret)" \
      "Storing sensitive data in UserDefaults — data is saved as unencrypted plist (OWASP M9: Insecure Data Storage)" \
      "Use Keychain Services (SecItemAdd/SecItemUpdate) to store passwords, tokens, and keys securely"
  done < <(grep -nEi 'UserDefaults.*\.(set|setValue)\s*\(.*\b(password|passwd|secret|token|apiKey|api_key|authToken|pin|credential|ssn|creditCard)' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # Secrets stored in UserDefaults — reverse pattern (value, forKey: "secret")
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "RV.1" "RV" "insecure-secret-storage" \
      "$file" "$line_num" "UserDefaults.set(forKey: secret)" \
      "Storing sensitive data in UserDefaults — data is saved as unencrypted plist (OWASP M9: Insecure Data Storage)" \
      "Use Keychain Services (SecItemAdd/SecItemUpdate) to store passwords, tokens, and keys securely"
  done < <(grep -nEi 'UserDefaults.*forKey\s*:\s*"[^"]*\b(password|passwd|secret|token|apiKey|api_key|authToken|pin|credential|ssn|creditCard)' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # --- M4: Insufficient Input/Output Validation ---

  # SQL injection via string interpolation
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.5" "PW" "sql-injection" \
      "$file" "$line_num" "SQL with \\(variable)" \
      "SQL query built with string interpolation is vulnerable to SQL injection (OWASP M4)" \
      "Use parameterized queries with bound parameters. With SQLite: sqlite3_bind_text(). With GRDB: use ? placeholders"
  done < <(grep -nE '(SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\\(' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # Process/NSTask with shell command from user input
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.6" "PW" "command-injection" \
      "$file" "$line_num" "Process/NSTask shell execution" \
      "Using Process/NSTask to run shell commands — risk of command injection if arguments include user input" \
      "Validate and sanitize all arguments. Set arguments as array elements, never as a single shell string. Avoid /bin/sh -c"
  done < <(grep -nE '(Process|NSTask)\s*\(\)' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # Shell command via /bin/sh -c (command injection vector)
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.6" "PW" "command-injection" \
      "$file" "$line_num" "/bin/sh -c" \
      "Launching a shell with -c flag enables command injection if the command string includes dynamic input" \
      "Pass arguments as separate array elements to Process.arguments instead of using /bin/sh -c with a concatenated string"
  done < <(grep -nE '"/bin/(ba)?sh".*"-c"' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # --- M5: Insecure Communication ---

  # Disabled App Transport Security (ATS)
  # Note: This is typically in Info.plist (XML), but sometimes set programmatically or in string constants
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.9" "PW" "ats-disabled" \
      "$file" "$line_num" "NSAllowsArbitraryLoads" \
      "App Transport Security disabled — allows unencrypted HTTP connections (OWASP M5: Insecure Communication)" \
      "Remove NSAllowsArbitraryLoads or set it to false. Use NSExceptionDomains for specific domains that require HTTP"
  done < <(grep -nE 'NSAllowsArbitraryLoads.*true|NSAllowsArbitraryLoads.*YES' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # Disabled TLS certificate validation
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.9" "PW" "ssl-bypass" \
      "$file" "$line_num" "ServerTrust bypass" \
      "URLSession delegate bypasses TLS certificate validation — vulnerable to MITM attacks (OWASP M5)" \
      "Implement proper certificate validation. For certificate pinning, validate against known certificates instead of blindly trusting all"
  done < <(grep -nE '\.performDefaultHandling|\.useCredential.*ServerTrust|completionHandler\(.+\.serverTrust' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # Disabling TLS validation entirely
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.9" "PW" "ssl-bypass" \
      "$file" "$line_num" "TLS validation disabled" \
      "Disabling TLS/SSL validation makes connections vulnerable to man-in-the-middle attacks (OWASP M5)" \
      "Never disable certificate validation in production. Use proper certificate pinning if needed"
  done < <(grep -nE 'URLSessionDelegate.*didReceive.*challenge|\.cancelAuthenticationChallenge|allowsExpiredCertificates|allowsUntrustedCertificates|validatesDomainName\s*=\s*false' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # --- M6: Inadequate Privacy Controls ---

  # NSLog with sensitive data (logs are accessible on device)
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.8" "PW" "sensitive-logging" \
      "$file" "$line_num" "NSLog(sensitive data)" \
      "Logging sensitive data with NSLog — logs persist on device and may be accessible to other apps (OWASP M6)" \
      "Never log passwords, tokens, PII, or financial data. Use os_log with .private for sensitive values: os_log(.info, \"User: \\(userId, privacy: .private)\")"
  done < <(grep -nEi 'NSLog\s*\(.*\b(password|passwd|secret|token|apiKey|api_key|ssn|creditCard|cardNumber|cvv|pin|email|phone)' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # print() with sensitive data
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.8" "PW" "sensitive-logging" \
      "$file" "$line_num" "print(sensitive data)" \
      "Printing sensitive data to console — may be captured in device logs (OWASP M6)" \
      "Remove print() calls with sensitive data before release. Use OSLog with privacy modifiers for debug logging"
  done < <(grep -nEi '^\s*print\s*\(.*\b(password|passwd|secret|token|apiKey|api_key|ssn|creditCard|cardNumber|cvv|pin)\b' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # --- M10: Insufficient Cryptography ---

  # Weak hash algorithms (CC_MD5, CC_SHA1)
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.7" "PW" "weak-crypto" \
      "$file" "$line_num" "CC_MD5/CC_SHA1" \
      "MD5 and SHA1 are cryptographically broken for security purposes (OWASP M10: Insufficient Cryptography)" \
      "Use SHA256 or SHA512: import CryptoKit; SHA256.hash(data: data). For CommonCrypto use CC_SHA256"
  done < <(grep -nE '\b(CC_MD5|CC_SHA1)\s*\(' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # Insecure digest via CryptoKit
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.7" "PW" "weak-crypto" \
      "$file" "$line_num" "Insecure.MD5/SHA1" \
      "Using Insecure hash from CryptoKit — these are marked insecure for a reason (OWASP M10)" \
      "Use SHA256.hash(data:) or SHA512.hash(data:) from CryptoKit instead of Insecure.MD5 or Insecure.SHA1"
  done < <(grep -nE 'Insecure\.(MD5|SHA1)' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # ECB mode (insecure block cipher mode)
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.7" "PW" "weak-crypto-mode" \
      "$file" "$line_num" "ECB mode" \
      "ECB mode does not provide semantic security — identical plaintext blocks produce identical ciphertext (OWASP M10)" \
      "Use GCM (AES.GCM) or CBC with random IV. CryptoKit's AES.GCM.seal() is recommended"
  done < <(grep -nE '\.ECBMode|kCCOptionECBMode|\.ecb\b' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # Hardcoded encryption keys
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.7" "PW" "hardcoded-crypto-key" \
      "$file" "$line_num" "hardcoded encryption key" \
      "Hardcoded encryption/signing key in source code — keys can be extracted from app binary (OWASP M10)" \
      "Derive keys from user credentials using HKDF, or store in Keychain. Use SecRandomCopyBytes for key generation"
  done < <(grep -nEi '(encryptionKey|symmetricKey|signingKey|aesKey|cryptoKey)\s*[:=]\s*"[^"]{8,}"' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # =====================================================================
  # === MEDIUM SEVERITY ===
  # =====================================================================

  # --- M3: Insecure Authentication/Authorization ---

  # Biometric auth without fallback validation
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.5" "PW" "biometric-bypass" \
      "$file" "$line_num" "LAContext.evaluatePolicy" \
      "Biometric authentication via LocalAuthentication — ensure server-side validation is also performed (OWASP M3)" \
      "Never rely solely on local biometrics. Validate the authentication result on the server side. Use Keychain access control with .biometryCurrentSet"
  done < <(grep -nE 'evaluatePolicy\s*\(\s*\.deviceOwner' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # --- M4: Insufficient Input/Output Validation ---

  # WebView loading arbitrary URLs (XSS vector)
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.5" "PW" "webview-injection" \
      "$file" "$line_num" "WKWebView loadHTMLString" \
      "Loading dynamic HTML into WKWebView — risk of XSS if content includes user input (OWASP M4)" \
      "Sanitize HTML content before loading. Set WKWebViewConfiguration with strict content security policies"
  done < <(grep -nE '\.loadHTMLString\s*\(' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # JavaScript evaluation in WebView
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.6" "PW" "webview-js-eval" \
      "$file" "$line_num" "evaluateJavaScript" \
      "Executing JavaScript in WKWebView — risk of injection if script includes user-controlled data (OWASP M4)" \
      "Never interpolate user input into JavaScript strings. Use WKScriptMessageHandler for safe native-JS communication"
  done < <(grep -nE '\.evaluateJavaScript\s*\(' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # UIWebView usage (deprecated, no security controls)
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.9" "PW" "deprecated-webview" \
      "$file" "$line_num" "UIWebView" \
      "UIWebView is deprecated and lacks modern security features — Apple rejects apps using it (OWASP M8)" \
      "Migrate to WKWebView which provides better security: process isolation, content blocking, and security policies"
  done < <(grep -nE '\bUIWebView\b' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # Unvalidated deep link / URL scheme handling
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.5" "PW" "deep-link-injection" \
      "$file" "$line_num" "openURL handler" \
      "URL scheme handler without input validation — malicious apps can send crafted URLs (OWASP M4)" \
      "Validate all URL parameters from deep links. Use Universal Links instead of custom URL schemes for better security"
  done < <(grep -nE '(application\s*\(.*open\s+url|func\s+scene.*openURLContexts|openURL\s*\()' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # --- M5: Insecure Communication ---

  # HTTP URLs (non-localhost)
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.9" "PW" "insecure-transport" \
      "$file" "$line_num" "http://" \
      "Unencrypted HTTP URL — data transmitted in plain text (OWASP M5: Insecure Communication)" \
      "Use HTTPS for all network communication. Configure ATS to enforce secure connections"
  done < <(grep -nE '"http://' "$file" 2>/dev/null | grep -vEi '(localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com)' | grep -vE '^\s*//' || true)

  # --- M6: Inadequate Privacy Controls ---

  # Clipboard exposure for sensitive data
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.8" "PW" "clipboard-exposure" \
      "$file" "$line_num" "UIPasteboard with sensitive data" \
      "Copying sensitive data to clipboard — other apps can read clipboard contents (OWASP M6)" \
      "Set .localOnly and expiration on UIPasteboard items for sensitive data. Consider disabling copy for password fields"
  done < <(grep -nEi 'UIPasteboard.*\b(password|secret|token|apiKey|ssn|creditCard|cardNumber|cvv)\b|\b(password|secret|token|apiKey|ssn|creditCard|cardNumber|cvv)\b.*UIPasteboard' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # Screenshots not disabled for sensitive views
  # Check for sensitive UI without willResignActive screenshot prevention
  # This is a heuristic — flagging files that handle sensitive fields
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.8" "PW" "screenshot-exposure" \
      "$file" "$line_num" "isSecureTextEntry = false" \
      "Secure text entry disabled — text may be visible in screenshots and task switcher (OWASP M6)" \
      "Set isSecureTextEntry = true for password and sensitive input fields"
  done < <(grep -nE 'isSecureTextEntry\s*=\s*false' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # --- M8: Security Misconfiguration ---

  # File written with overly permissive attributes
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.9" "PW" "insecure-file-permissions" \
      "$file" "$line_num" ".posixPermissions: 0o777" \
      "Overly permissive file permissions — any user/process can read and modify the file (OWASP M8)" \
      "Use restrictive permissions (0o600 or 0o644). For sensitive files use FileProtectionType.complete"
  done < <(grep -nE '\.posixPermissions.*0o7(77|76|75|66)' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # Missing data protection on file writes
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.9" "PW" "missing-file-protection" \
      "$file" "$line_num" "write(to:) without protection" \
      "Writing sensitive data to file without FileProtection — data accessible when device is locked (OWASP M9)" \
      "Use FileProtectionType.complete: try data.write(to: url, options: [.completeFileProtection])"
  done < <(grep -nEi '\.write\s*\(\s*to\s*:.*\b(password|secret|token|key|credential|private)\b' "$file" 2>/dev/null \
    | grep -vE '(completeFileProtection|\.complete|FileProtection)' \
    | grep -vE '^\s*//' || true)

  # Keychain without access control
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.9" "PW" "keychain-no-access-control" \
      "$file" "$line_num" "kSecAttrAccessibleAlways" \
      "Keychain item accessible even when device is locked — data at risk if device is stolen (OWASP M9)" \
      "Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly or kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"
  done < <(grep -nE 'kSecAttrAccessibleAlways\b' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # --- M9: Insecure Data Storage ---

  # Realm/CoreData without encryption
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.9" "PW" "unencrypted-database" \
      "$file" "$line_num" "Realm/CoreData without encryption" \
      "Database created without encryption — data stored in plaintext on device (OWASP M9)" \
      "For Realm: set encryptionKey in Realm.Configuration. For CoreData: use NSPersistentStoreDescription with encryption options"
  done < <(grep -nE 'Realm\s*\(\s*\)|Realm\.Configuration\s*\(' "$file" 2>/dev/null \
    | grep -vE 'encryptionKey' \
    | grep -vE '^\s*//' || true)

  # --- M10: Insufficient Cryptography ---

  # Insecure random number generation (for security purposes)
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.7" "PW" "weak-random" \
      "$file" "$line_num" "arc4random/drand48 for security" \
      "Using non-cryptographic random for security-sensitive purpose — predictable output (OWASP M10)" \
      "Use SecRandomCopyBytes() or CryptoKit for cryptographically secure random data"
  done < <(grep -nE '(arc4random|drand48|srand|rand\(\))' "$file" 2>/dev/null \
    | grep -iE '(token|secret|key|password|session|nonce|salt|otp|auth|iv|encrypt)' \
    | grep -vE '^\s*//' || true)

  # --- Insecure Deserialization ---

  # NSKeyedUnarchiver without secure coding
  while IFS=: read -r line_num _; do
    emit_finding "MEDIUM" "PW.6" "PW" "insecure-deserialization" \
      "$file" "$line_num" "unarchiveObject (deprecated)" \
      "NSKeyedUnarchiver.unarchiveObject is deprecated and insecure — allows arbitrary class instantiation" \
      "Use unarchivedObject(ofClass:from:) with requiresSecureCoding = true to restrict deserialized types"
  done < <(grep -nE 'NSKeyedUnarchiver\.(unarchiveObject|unarchiveTopLevelObject)\s*\(' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # JSONDecoder with unvalidated external data
  # Only flag if combined with URL/network loading and no validation
  if grep -qE '(URLSession|Alamofire|Moya|AF\.)' "$file" 2>/dev/null; then
    local has_decoder=false
    local has_validation=false

    if grep -qE 'JSONDecoder\s*\(\)\.decode' "$file" 2>/dev/null; then
      has_decoder=true
    fi
    if grep -qEi '(validat|sanitiz|guard\s+let|if\s+let.*\.count|\.isEmpty)' "$file" 2>/dev/null; then
      has_validation=true
    fi

    if [[ "$has_decoder" == true && "$has_validation" == false ]]; then
      while IFS=: read -r line_num _; do
        emit_finding "MEDIUM" "PW.5" "PW" "missing-input-validation" \
          "$file" "$line_num" "JSONDecoder without validation" \
          "Decoding network response without apparent input validation (OWASP M4)" \
          "Validate decoded data before use: check string lengths, numeric ranges, and required fields"
      done < <(grep -nE 'JSONDecoder\s*\(\)\.decode' "$file" 2>/dev/null | grep -vE '^\s*//' || true)
    fi
  fi

  # =====================================================================
  # === LOGGING CHECKS ===
  # =====================================================================

  # Check for sensitive operations without logging (only if logging is already configured)
  local has_logging_configured=false
  if grep -qE '\bimport\s+os\b|import\s+OSLog\b|os_log\s*\(|Logger\s*\(' "$file" 2>/dev/null; then
    has_logging_configured=true
  fi

  if [[ "$has_logging_configured" == true ]]; then
    local sensitive_ops_pattern='(login|logout|authenticate|authorize|signIn|signOut|register|createUser|deleteUser|updatePassword|changePassword|resetPassword|grantRole|revokeRole|deleteAccount|suspendUser|charge|refund|payment|transferFunds|withdraw|escalate|impersonate)\s*\('

    if grep -qE "$sensitive_ops_pattern" "$file" 2>/dev/null; then
      local has_logging_calls=false
      if grep -qE '\b(logger|log|os_log)\.(info|warning|error|critical|debug|fault|notice|trace|log)\s*\(|os_log\s*\(' "$file" 2>/dev/null; then
        has_logging_calls=true
      fi

      if [[ "$has_logging_calls" == false ]]; then
        while IFS=: read -r line_num _; do
          emit_finding "MEDIUM" "PW.8" "PW" "missing-logging" \
            "$file" "$line_num" "sensitive op without logging" \
            "Sensitive operation (auth/user-mgmt/payment) has no logging — security events must be logged for audit trails" \
            "Add logging for sensitive operations: logger.info(\"User \\(userId, privacy: .private) logged in\"). Use OSLog with privacy modifiers"
        done < <(grep -nE "$sensitive_ops_pattern" "$file" 2>/dev/null | grep -vE '^\s*//' || true)
      fi
    fi
  fi

  # =====================================================================
  # === LOW SEVERITY ===
  # =====================================================================

  # Keyboard caching for sensitive fields (autocorrect/spellcheck)
  while IFS=: read -r line_num _; do
    emit_finding "LOW" "PW.8" "PW" "keyboard-cache" \
      "$file" "$line_num" "autocorrectionType not disabled" \
      "Text field with potential sensitive data has autocorrection enabled — cached by iOS keyboard" \
      "Set .autocorrectionType = .no and .spellCheckingType = .no for sensitive input fields"
  done < <(grep -nE '\.autocorrectionType\s*=\s*\.yes' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # Deprecated security APIs
  while IFS=: read -r line_num _; do
    emit_finding "LOW" "PW.9" "PW" "deprecated-api" \
      "$file" "$line_num" "deprecated security API" \
      "Using deprecated security API — may have known vulnerabilities or missing modern protections" \
      "Migrate to current APIs: use CryptoKit instead of CommonCrypto, WKWebView instead of UIWebView, URLSession instead of NSURLConnection"
  done < <(grep -nE '\b(NSURLConnection|SecTrustEvaluate)\b' "$file" 2>/dev/null | grep -vE '^\s*//' || true)

  # Debug/test code left in
  while IFS=: read -r line_num _; do
    emit_finding "LOW" "PW.9" "PW" "debug-code" \
      "$file" "$line_num" "#if DEBUG block" \
      "Debug-only code block found — verify sensitive debug features are properly guarded" \
      "Ensure all debug code is wrapped in #if DEBUG/#endif. Review for hardcoded test credentials or bypassed security"
  done < <(grep -nE '#if\s+DEBUG' "$file" 2>/dev/null | head -1 || true)

  return 0
}
