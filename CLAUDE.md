# Vibe Coding Guard — Active Security Monitoring

Vibe Coding Guard is actively monitoring this project for security vulnerabilities. All file writes and bash commands are automatically scanned against NIST SSDF (Secure Software Development Framework) security practices.

## Analysis Modes

This project supports three analysis modes (configured in `config.json` or `.claude/vibe-coding-guard.json`):

| Mode | How it works | When to use |
|------|-------------|-------------|
| **fast** | Regex-only scanning. Deterministic, zero LLM calls. Findings are reported directly from pattern matching. | Low-latency environments, CI, or when LLM cost is a concern |
| **hybrid** (default) | Regex scan first. If issues are found or the code has complex patterns (user input → sensitive sinks), a contextual analysis request is emitted asking you to reason about the findings. | Recommended balance of speed and coverage |
| **deep** | Always performs full LLM-driven contextual analysis on every file write and command, regardless of regex results. | Maximum security coverage; use for high-risk codebases |

### What each mode means for you (the LLM agent)

- **In `fast` mode**: You will only see regex-based findings. Act on them directly — no contextual analysis is requested.
- **In `hybrid` mode**: You may see a "Contextual Analysis Request" after regex findings. When you do, you MUST perform deeper analysis (see below).
- **In `deep` mode**: You will always receive a contextual analysis request for every file write/edit, even if no regex issues were found. Analyze thoroughly.

## LLM / AI-Backend App Scanning (opt-in)

If this project's application code **calls an LLM** (OpenAI, Anthropic, LangChain, Ollama, Bedrock, etc.), enable the OWASP-LLM-Top-10 checks by setting `llm_app_scanning.enabled` to `true` in `config.json` or `.claude/vibe-coding-guard.json`. It is **off by default** because these checks are noise for non-LLM projects.

When enabled, Python and JS/TS writes are additionally scanned for developer-accident LLM risks: prompt injection (untrusted input built into prompts), improper output handling (LLM output flowing into eval/shell/SQL/HTML), excessive agency (agents with shell/code tools), secrets/PII in prompt content, system-prompt exposure, and missing token/timeout limits. See `.claude/rules/llm-security.md` for the detailed practices.

## What This Means For You

- **File writes/edits** are scanned for security anti-patterns (injection, hardcoded secrets, weak crypto, XSS, etc.)
- **Bash commands** are checked for dangerous operations before execution (destructive commands, remote code execution, etc.)
- When a security issue is found, you will receive feedback with the specific issue, its NIST SSDF mapping, and remediation guidance

## When You Receive Security Feedback

If a hook returns a security finding (exit code 2), you MUST:
1. Read the finding carefully
2. Fix the identified issue in your next action
3. Do NOT ignore or work around the security check by rewriting correct code just to dodge a pattern match. The one exception: if a finding is a confirmed false positive or too noisy to be actionable in context, suppress it with an inline `vcg-ignore` (bare, or scoped as `vcg-ignore: category-name`) comment on the flagged line or the line above it — that is the intended escape hatch, not a workaround, and does not require rewriting the code.

### When Contextual Analysis is Requested

In hybrid/deep mode, the hook may request you to perform deeper analysis. When you see:

```
## Contextual Analysis Request
**Claude: Please perform deeper security analysis of this file.**
```

You MUST:
1. Read the file and understand data flow
2. For each regex finding, determine if it's a true positive in context:
   - Does user input actually reach this sink?
   - Is there sanitization/validation before it?
   - Is this test/example code or production?
3. Look for issues regex can't catch:
   - Business logic flaws
   - Authentication/authorization bypasses
   - Multi-step injection paths
4. Report your findings with reasoning
5. Fix any confirmed vulnerabilities before proceeding

## Secure Coding Practices to Follow

- **Never hardcode secrets** — use environment variables or secret managers
- **Use parameterized queries** — never build SQL with string concatenation or f-strings
- **Avoid eval/exec** — use safe alternatives (ast.literal_eval, importlib)
- **Avoid shell=True** — pass command arguments as lists to subprocess
- **Use strong crypto** — SHA-256+ not MD5/SHA1 for security purposes
- **Validate inputs** — especially at system boundaries
- **Use HTTPS** — for all external communication
- **Pin dependencies** — use exact versions in requirements files

See `.claude/rules/` for detailed NIST SSDF security rules.
