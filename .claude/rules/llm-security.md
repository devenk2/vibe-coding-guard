# NIST SSDF — LLM / AI-Backend Application Security

These rules extend the NIST SSDF practice groups with checks for applications that
**call an LLM on the backend** (OpenAI, Anthropic, LangChain, Ollama, Bedrock, etc.).
They target the developer-accident subset of the **OWASP LLM Top 10** — mistakes a
developer can introduce while *using* an LLM — not the concerns of teams building
models or RAG infrastructure.

These checks are **opt-in**: they run only when `llm_app_scanning.enabled` is `true`
in `config.json` or `.claude/vibe-coding-guard.json`.

## PW.5 — Prompt Injection (OWASP LLM01)
- Never concatenate untrusted input (request data, uploaded files, retrieved
  documents, tool/web output) directly into a prompt or system message.
- Keep the instruction channel separate from the data channel: use a fixed system
  prompt plus a clearly-delimited user-data block, or a distinct user message.
- Validate and length-limit input before it reaches the model.
- Treat retrieved/tool content as untrusted too — indirect prompt injection is real.

## PW.6 — Improper Output Handling (OWASP LLM05)
- **Model output is untrusted.** Never pass it to `eval`, `exec`, `os.system`,
  `subprocess`, a raw SQL string, `innerHTML`, or `dangerouslySetInnerHTML`.
- Parse output to a strict schema (JSON with validation, an allowlist of actions).
- Escape before rendering (bleach / `html.escape` / DOMPurify); use parameterized
  queries for any DB access driven by model output.

## PW.9 — Excessive Agency & Unbounded Consumption (OWASP LLM06, LLM10)
- Do not grant autonomous agents code- or shell-execution tools (PythonREPL, Shell,
  Terminal) when they process untrusted input. Sandbox, allowlist, and add
  human-in-the-loop approval for high-impact actions.
- Never enable `allow_dangerous_*` flags in code exposed to untrusted input.
- Grant each agent the minimum capabilities its task requires (least privilege).
- Set `max_tokens` / `max_completion_tokens` and a request `timeout` on every LLM
  call. Add rate limiting to endpoints that trigger model calls to bound cost and
  prevent resource-exhaustion / wallet-drain attacks.

## RV.1 / PW.8 — Sensitive Data in Prompts (OWASP LLM02, LLM07)
- Never place credentials, API keys, or PII into prompt or system-prompt **content**.
  Prompt text may be logged by the provider, echoed to users, or recovered via
  injection (system-prompt leakage).
- Keep secrets in the client configuration / environment (e.g.
  `OpenAI(api_key=os.environ[...])`), not in the messages you send.
- If the model needs a capability that requires a secret, mediate it through a tool
  that holds the credential server-side.
