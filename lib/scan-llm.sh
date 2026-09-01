#!/usr/bin/env bash
# Vibe Coding Guard — LLM-Application Security Scanner
# Detects OWASP-LLM-Top-10 vulnerability classes that a developer could
# accidentally introduce in an application that CALLS an LLM on the backend
# (OpenAI / Anthropic / LangChain / Ollama / Bedrock / etc.).
#
# Scope: developer-accident classes, NOT model/framework building.
#   LLM01 prompt injection  — untrusted input flows into a prompt
#   LLM05 improper output handling — LLM output flows into eval/shell/SQL/HTML
#   LLM06 excessive agency  — agents wired with shell/code-exec tools
#   LLM02 secret-in-prompt  — secrets/PII interpolated into prompt content
#   LLM07 system-prompt exposure — hardcoded system prompt embedding a secret
#   LLM10 unbounded consumption — LLM call with no token/timeout limit
#
# Opt-in: only runs when llm_app_scanning.enabled=true (LLM_APP_SCANNING).
# Handles Python and JavaScript/TypeScript in one function, mirroring
# scan-api-security.sh. Outputs JSON findings (one per line) to stdout.

# Combined comment-line filter for the languages this scanner covers
# (Python `#`, JS `//` and block-comment `*` continuation lines).
_llm_strip_comments() {
  grep -vE '^[[:space:]]*(#|//|\*)' 2>/dev/null || true
}

scan_llm_file() {
  local file="$1"

  # ── Reusable signal fragments ─────────────────────────────────────────────
  # An LLM call/prompt-construction API (file-level "this code talks to an LLM").
  local LLM_CALL='(\.(chat\.completions|completions|messages|responses)\.create[[:space:]]*\(|openai\.(ChatCompletion|Completion)\.create|\.invoke[[:space:]]*\(|ollama\.(chat|generate)|invoke_model[[:space:]]*\(|PromptTemplate|ChatOpenAI|ChatAnthropic|ChatBedrock|anthropic\.|genai\.|generateText|streamText|createChatCompletion|new[[:space:]]+(OpenAI|Anthropic)[[:space:]]*\()'
  # An untrusted-input source (request data, user input, tool/web output).
  local TAINT='(request\.|req\.|\.body|\.args|args\.get|\.query|\.params|\bparams\b|user_input|user_message|user_query|user_content|input[[:space:]]*\()'
  # A dynamic string-construction marker (implies the string is not a constant).
  local DYNAMIC='(f["'\''"]|\.format[[:space:]]*\(|\+|`)'
  # Signs that output/input is being sanitized/validated/parsed safely.
  local MITIGATION='(bleach|DOMPurify|dompurify|html\.escape|escape[[:space:]]*\(|sanitiz|validat|moderations?\.create|guardrail|output_parser|ast\.literal_eval|json\.loads|shlex\.quote|allowlist|allow_list)'
  # Secret / PII tokens that must never be placed inside prompt content.
  local SECRET='(api[_-]?key|apikey|password|passwd|secret|auth[_-]?token|private[_-]?key|\bssn\b|os\.environ|getenv|process\.env)'
  # LLM-client configuration lines (legitimate place for a key — exclude from
  # secret-in-prompt to avoid flagging `OpenAI(api_key=os.environ[...])`).
  local CLIENT_CONFIG='(OpenAI[[:space:]]*\(|Anthropic[[:space:]]*\(|Client[[:space:]]*\(|api_key[[:space:]]*=|apiKey[[:space:]]*:|base_url|ChatOpenAI[[:space:]]*\(|ChatAnthropic[[:space:]]*\()'

  # Does the file call an LLM at all? Most checks are gated on this.
  local has_llm_call=false
  if grep -nE "$LLM_CALL" "$file" 2>/dev/null | _llm_strip_comments | grep -q .; then
    has_llm_call=true
  fi

  # File-level signals reused across checks: is there an untrusted-input source
  # anywhere in the file, and any sign of sanitization/validation/safe-parsing?
  local has_taint=false
  if grep -nE "$TAINT" "$file" 2>/dev/null | _llm_strip_comments | grep -q .; then
    has_taint=true
  fi
  local has_mitigation=false
  if grep -niE "$MITIGATION" "$file" 2>/dev/null | _llm_strip_comments | grep -q .; then
    has_mitigation=true
  fi

  # =====================================================================
  # === HIGH SEVERITY ===
  # =====================================================================

  # --- LLM01: Prompt injection — untrusted input built into a prompt ---
  # Two ways untrusted input reaches a prompt:
  #   (a) directly on the prompt-construction line (request.args in the f-string);
  #   (b) via an intermediate variable — the very common case where input is
  #       assigned to a var, then that var is interpolated into the prompt.
  # (a) is always high-confidence. (b) is inferred at file level: the file has an
  # untrusted source AND a dynamic prompt AND no visible sanitization.
  if [[ "$has_llm_call" == true ]]; then
    # Prompt-ish assignments / message content constructed dynamically.
    while IFS=: read -r line_num matched_line; do
      local line_tainted=false
      echo "$matched_line" | grep -qE "$TAINT" && line_tainted=true
      if [[ "$line_tainted" == true ]]; then
        : # direct: emit below
      elif [[ "$has_taint" == true && "$has_mitigation" == false ]]; then
        : # inferred via intermediate variable, no sanitization present: emit below
      else
        continue
      fi
      emit_finding "HIGH" "PW.5" "PW" "prompt-injection" \
        "$file" "$line_num" "prompt built from untrusted input" \
        "Untrusted input is built into an LLM prompt/message without delimiting — prompt injection (OWASP LLM01). A user can override instructions or exfiltrate the system prompt." \
        "Keep untrusted input out of the instruction channel: pass it as a clearly-delimited data block or a separate user message, add input validation, and never format it directly into system/instruction text"
    done < <(grep -nE "(prompt|messages?|system_prompt|system_message|user_prompt|instruction|content|template)[[:space:]]*(=|\+=|:).*$DYNAMIC" "$file" 2>/dev/null | _llm_strip_comments)

    # LLM call whose argument is itself a dynamic, tainted string (same line).
    while IFS=: read -r line_num matched_line; do
      echo "$matched_line" | grep -qE "$TAINT" || continue
      echo "$matched_line" | grep -qE "$DYNAMIC" || continue
      emit_finding "HIGH" "PW.5" "PW" "prompt-injection" \
        "$file" "$line_num" "LLM call with dynamic tainted prompt" \
        "An LLM call is passed a prompt built inline from untrusted input — prompt injection (OWASP LLM01)." \
        "Separate untrusted data from instructions: use a fixed system prompt plus a delimited user-data block, and validate the input before use"
    done < <(grep -nE "$LLM_CALL" "$file" 2>/dev/null | _llm_strip_comments)
  fi

  # --- LLM05: Improper output handling — LLM output reaches a dangerous sink -
  if [[ "$has_llm_call" == true ]]; then
    local dangerous_sink='(\beval[[:space:]]*\(|\bexec[[:space:]]*\(|\bos\.system[[:space:]]*\(|\bos\.popen[[:space:]]*\(|subprocess\.|\.execute[[:space:]]*\(|\.innerHTML[[:space:]]*=|dangerouslySetInnerHTML|new[[:space:]]+Function[[:space:]]*\(|child_process)'
    local has_mitigation=false
    if grep -iE "$MITIGATION" "$file" 2>/dev/null | _llm_strip_comments | grep -q .; then
      has_mitigation=true
    fi
    if [[ "$has_mitigation" == false ]]; then
      while IFS=: read -r line_num _; do
        emit_finding "HIGH" "PW.6" "PW" "unsafe-llm-output" \
          "$file" "$line_num" "LLM output → code/HTML/SQL sink" \
          "This file calls an LLM and passes model output to a dangerous sink (eval/exec/shell/SQL/innerHTML) with no visible sanitization — improper output handling (OWASP LLM05). Model output is untrusted and can carry an injected payload." \
          "Never execute or render raw LLM output. Parse to a strict schema (JSON/allowlist), escape before HTML (bleach/DOMPurify), use parameterized queries, and avoid eval/exec entirely"
      done < <(grep -nE "$dangerous_sink" "$file" 2>/dev/null | _llm_strip_comments)
    fi
  fi

  # --- LLM06: Excessive agency — agent wired with shell/code-exec tools ---
  # Sink-presence checks: granting an autonomous agent OS/code execution.
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.9" "PW" "excessive-agency" \
      "$file" "$line_num" "agent code/shell tool" \
      "An LLM agent is granted a code- or shell-execution tool (PythonREPL/Shell/Terminal). Combined with prompt injection this yields arbitrary code execution — excessive agency (OWASP LLM06)." \
      "Remove code/shell tools from agent toolsets, or sandbox them with a strict allowlist and human-in-the-loop approval. Grant the minimum capabilities the task needs"
  done < <(grep -nE '(PythonREPLTool|PythonAstREPLTool|ShellTool|Terminal[[:space:]]*\(|load_tools[[:space:]]*\([^)]*(terminal|shell|python_repl))' "$file" 2>/dev/null | _llm_strip_comments)

  # allow_dangerous_* flags explicitly opt into unsafe agent behavior.
  while IFS=: read -r line_num _; do
    emit_finding "HIGH" "PW.9" "PW" "excessive-agency" \
      "$file" "$line_num" "allow_dangerous_*=True" \
      "An 'allow_dangerous_*' flag is enabled, opting the agent/chain into unsafe execution or deserialization — excessive agency (OWASP LLM06)." \
      "Do not enable allow_dangerous_* in code exposed to untrusted input. Use a sandboxed, allowlisted alternative"
  done < <(grep -nEi 'allow_dangerous_[a-z_]+[[:space:]]*=[[:space:]]*True' "$file" 2>/dev/null | _llm_strip_comments)

  # =====================================================================
  # === MEDIUM SEVERITY ===
  # =====================================================================

  # --- LLM02: Secret / PII interpolated into prompt content ---
  if [[ "$has_llm_call" == true ]]; then
    while IFS=: read -r line_num matched_line; do
      # Skip legitimate client-config lines (api_key=os.environ[...] etc.).
      echo "$matched_line" | grep -qE "$CLIENT_CONFIG" && continue
      # System prompts are reported separately as LLM07.
      echo "$matched_line" | grep -qiE 'system' && continue
      emit_finding "MEDIUM" "RV.1" "RV" "secret-in-prompt" \
        "$file" "$line_num" "secret in prompt content" \
        "A secret or PII value appears to be interpolated into prompt/message content sent to the LLM (OWASP LLM02). It may be logged by the provider, echoed back to users, or leaked via injection." \
        "Never place credentials or PII in prompt text. Pass only the minimum data the model needs; keep secrets in the client config / environment, not the prompt"
    done < <(grep -nEi "(prompt|messages?|user_prompt|content|template)[[:space:]]*(=|\+=|:).*$SECRET" "$file" 2>/dev/null | _llm_strip_comments)
  fi

  # =====================================================================
  # === LOW SEVERITY ===
  # =====================================================================

  # --- LLM07: Hardcoded system prompt that embeds a secret / env value ---
  if [[ "$has_llm_call" == true ]]; then
    while IFS=: read -r line_num matched_line; do
      echo "$matched_line" | grep -qE "$CLIENT_CONFIG" && continue
      emit_finding "LOW" "PW.8" "PW" "system-prompt-exposure" \
        "$file" "$line_num" "secret in system prompt" \
        "A system prompt appears to embed a secret or environment value (OWASP LLM07). System prompts are recoverable via prompt injection, exposing the embedded secret." \
        "Keep secrets out of system prompts. If the model needs a capability, mediate it through a tool that holds the credential server-side"
    done < <(grep -nEi "(system_prompt|system_message|SystemMessage|\"system\"|'system'|role[[:space:]]*[:=][[:space:]]*[\"']system).*$SECRET" "$file" 2>/dev/null | _llm_strip_comments)
  fi

  # --- LLM10: Unbounded consumption — LLM call with no token/timeout limit ---
  # Windowed per-call check (the call may span several lines).
  if [[ "$has_llm_call" == true ]]; then
    # NOTE: declared once, outside the loop — bash 3.2 (this project's target
    # shell) has a bug where re-declaring `local` with a multi-line
    # command-substitution value on every loop iteration can leak a stray
    # "window=$'...'" line onto stdout starting from the 2nd LLM call in a
    # file. See lib/scan-auth.sh's header comment for the full writeup.
    local window
    while IFS=: read -r line_num _; do
      window=$(sed -n "${line_num},$((line_num + 6))p" "$file" 2>/dev/null)
      # Skip if a token/timeout limit is set anywhere in the call window.
      if echo "$window" | grep -qEi '(max_tokens|max_completion_tokens|max_output_tokens|maxTokens|maxOutputTokens|timeout|request_timeout)'; then
        continue
      fi
      emit_finding "LOW" "PW.9" "PW" "missing-llm-limits" \
        "$file" "$line_num" "LLM call without max_tokens/timeout" \
        "An LLM call sets no token cap or timeout — unbounded consumption / cost exposure (OWASP LLM10). A crafted or looping input can drive runaway spend or resource exhaustion." \
        "Set max_tokens (or max_completion_tokens) and a request timeout on every LLM call; add rate limiting to endpoints that trigger model calls"
    done < <(grep -nE "$LLM_CALL" "$file" 2>/dev/null | _llm_strip_comments)
  fi

  return 0
}
