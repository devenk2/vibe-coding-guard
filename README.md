# Vibe Coding Guard

A security subagent for Claude Code that automatically scans code for vulnerabilities, mapped to the NIST Secure Software Development Framework (SSDF).

## What It Does

Vibe Coding Guard hooks into Claude Code's tool system to provide real-time security scanning:

- **PreToolUse hook** — Intercepts bash commands and **blocks** dangerous operations (remote code execution, destructive deletes, force pushes to main)
- **PostToolUse hook** — Scans files after every Write/Edit and **reports** security issues (injection, hardcoded secrets, weak crypto, XSS)
- **CLAUDE.md + Rules** — Makes the Claude Code agent security-aware with NIST SSDF guidelines

## Quick Start

### Prerequisites

- [Claude Code](https://claude.ai/code) CLI installed
- `jq` — Install with `brew install jq` (macOS) or `apt install jq` (Linux)

### Install

```bash
git clone https://github.com/your-username/Vibe-Coding-Guard.git
cd Vibe-Coding-Guard
./install.sh /path/to/your/project
```

This will:
1. Install Vibe Coding Guard globally to `~/.vibe-coding-guard/`
2. Add security hooks to your project's `.claude/settings.json`
3. Add security instructions to your project's `CLAUDE.md`
4. Install SSDF rules to your project's `.claude/rules/`

### Uninstall

```bash
./uninstall.sh /path/to/your/project          # Remove from project only
./uninstall.sh /path/to/your/project --global  # Also remove global install
```

## How It Works

```
Claude Code Session
  |
  |-- User asks for a feature
  |-- Claude writes code (Write/Edit tool)
  |     |
  |     +-- PostToolUse hook fires
  |           |-- Scans file for security patterns
  |           |-- Reports findings with SSDF mapping
  |           |-- Claude auto-remediates
  |
  |-- Claude runs a command (Bash tool)
        |
        +-- PreToolUse hook fires
              |-- Checks against dangerous command patterns
              |-- HIGH severity: BLOCKS the command
              |-- MEDIUM/LOW: warns and allows
```

## Security Checks

### Command Blocklist (PreToolUse)

| Pattern | Severity | SSDF | Action |
|---------|----------|------|--------|
| `curl \| bash` | HIGH | PS.3 | Block |
| `rm -rf /` | HIGH | PS.1 | Block |
| `chmod 777` | HIGH | PW.9 | Block |
| `git push --force main` | HIGH | PS.1 | Block |
| `eval "$(curl ...)"` | HIGH | PS.3 | Block |
| `pip install <unpinned>` | MEDIUM | PS.3 | Warn |
| `docker run --privileged` | MEDIUM | PW.9 | Warn |

### Python Scanner (PostToolUse)

| Pattern | Severity | SSDF | Category |
|---------|----------|------|----------|
| `eval()` / `exec()` | HIGH | PW.6 | Injection |
| `os.system()` | HIGH | PW.6 | Command injection |
| `pickle.load()` | HIGH | PW.6 | Deserialization |
| `subprocess(..., shell=True)` | HIGH | PW.6 | Command injection |
| SQL string concatenation | HIGH | PW.5 | SQL injection |
| Hardcoded secrets | HIGH | RV.1 | Credential exposure |
| `hashlib.md5()` / `.sha1()` | MEDIUM | PW.7 | Weak crypto |
| `verify=False` | MEDIUM | PW.9 | SSL bypass |
| `yaml.load()` (no SafeLoader) | MEDIUM | PW.6 | Unsafe YAML |
| Bare `except:` | LOW | PW.8 | Error swallowing |

### JavaScript/TypeScript Scanner (PostToolUse)

| Pattern | Severity | SSDF | Category |
|---------|----------|------|----------|
| `eval()` | HIGH | PW.6 | Injection |
| `.innerHTML =` | HIGH | PW.5 | XSS |
| `document.write()` | HIGH | PW.5 | XSS |
| `new Function()` | HIGH | PW.6 | Injection |
| `child_process.exec()` | HIGH | PW.6 | Command injection |
| `dangerouslySetInnerHTML` | MEDIUM | PW.5 | XSS |
| `__proto__` | MEDIUM | PW.6 | Prototype pollution |
| `rejectUnauthorized: false` | MEDIUM | PW.9 | SSL bypass |

### General Scanner (All Files)

| Pattern | Severity | SSDF | Category |
|---------|----------|------|----------|
| AWS keys (`AKIA...`) | HIGH | RV.1 | Credential exposure |
| GitHub tokens (`ghp_...`) | HIGH | RV.1 | Credential exposure |
| API keys (`sk-...`) | HIGH | RV.1 | Credential exposure |
| Private keys | HIGH | RV.1 | Credential exposure |
| Path traversal (`../../..`) | MEDIUM | PW.5 | Path traversal |
| `http://` URLs | LOW | PW.9 | Insecure transport |

## NIST SSDF Mapping

| Practice Group | Code | Description |
|---------------|------|-------------|
| **Produce Well-Secured Software** | PW | Input validation, secure coding, crypto, error handling |
| **Respond to Vulnerabilities** | RV | Hardcoded secrets, deprecated APIs, known-bad patterns |
| **Protect the Software** | PS | Supply chain, dependency pinning, destructive operations |

## Analysis Modes

Vibe Coding Guard supports three analysis modes, configurable via `analysis_mode` in config:

### Fast Mode (`"analysis_mode": "fast"`)
- **Regex-only scanning** — deterministic pattern matching
- Fastest execution (~milliseconds)
- Zero additional API cost
- Best for: High-confidence, unambiguous security patterns

### Deep Mode (`"analysis_mode": "deep"`)
- **LLM-powered analysis** — Claude reasons about security contextually
- Understands data flow and business logic
- Catches novel/complex vulnerabilities
- Best for: Thorough security review, complex codebases

### Hybrid Mode (`"analysis_mode": "hybrid"`) — **Recommended**
- **Layered approach** — regex first, then LLM for ambiguous cases
- Regex handles clear-cut issues (hardcoded keys, `curl | bash`)
- LLM triggered when:
  - Regex finds potential issues that need context validation
  - Code has user input flowing to security-sensitive sinks
  - Complex command pipelines need evaluation
- Best balance of speed, cost, and coverage

```
┌─────────────────────────────────────────────────────────────┐
│                    Hybrid Analysis Flow                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  File/Command ──► Regex Scan ──► HIGH severity? ──► BLOCK   │
│                        │                                    │
│                        ▼                                    │
│               Issues found OR                               │
│               Complex patterns?                             │
│                        │                                    │
│                   Yes  │  No                                │
│                        ▼   ▼                                │
│              Request LLM   Pass                             │
│              Analysis                                       │
│                        │                                    │
│                        ▼                                    │
│              Claude reasons about:                          │
│              • Data flow to sinks                           │
│              • Context (test vs prod)                       │
│              • False positive likelihood                    │
│              • Business logic flaws                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

Vibe Coding Guard supports two levels of configuration:

1. **Global config**: `~/.vibe-coding-guard/config.json` — applies to all projects
2. **Project config**: `.claude/vibe-coding-guard.json` — overrides global settings per-project

### Per-Project Configuration

Edit `.claude/vibe-coding-guard.json` in your project to customize settings for that repo:

```json
{
  "analysis_mode": "deep",
  "blocking_severity": "MEDIUM",
  "ignore_paths": ["generated/", "vendor/"]
}
```

Project settings **override** global settings. Arrays like `ignore_paths` and `custom_secret_patterns` are **merged** (project paths are added to global paths).

### Global Configuration

Edit `~/.vibe-coding-guard/config.json` to set defaults for all projects:

```json
{
  "blocking_severity": "MEDIUM",
  "enabled_rule_groups": ["PW", "RV", "PS"],
  "analysis_mode": "hybrid",
  "llm_analysis": {
    "enabled": true,
    "analyze_on_regex_match": true,
    "analyze_complex_patterns": true,
    "max_context_lines": 50,
    "timeout_seconds": 30
  },
  "ignore_paths": ["node_modules", ".venv", "__pycache__", ".git"],
  "max_file_size_kb": 500,
  "custom_secret_patterns": ["MY_CORP_TOKEN_[A-Z0-9]+"]
}
```

### Core Settings
- **blocking_severity** — Minimum severity to block commands in PreToolUse (HIGH, MEDIUM, LOW). Default: MEDIUM
- **analysis_mode** — `fast`, `deep`, or `hybrid` (recommended)
- **ignore_paths** — Directories to skip during scanning
- **max_file_size_kb** — Skip files larger than this
- **custom_secret_patterns** — Additional regex patterns to flag as secrets

### LLM Analysis Settings
- **llm_analysis.enabled** — Master switch for LLM features
- **llm_analysis.analyze_on_regex_match** — Run LLM when regex finds issues (validates/dismisses)
- **llm_analysis.analyze_complex_patterns** — Trigger LLM for complex code patterns
- **llm_analysis.max_context_lines** — Lines of code to include in analysis prompt
- **llm_analysis.timeout_seconds** — Max time for LLM analysis

## Suppressing False Positives

Regex scanning is not AST-aware, so some findings will be false positives in
context (e.g. a token/timeout limit set via a wrapper function the windowed
heuristic can't see). Rather than disabling a whole check project-wide, add an
inline `vcg-ignore` marker as a comment on the flagged line (or the line
directly above it). It works with any comment syntax (`#`, `//`, `--`, ...)
since it's matched as plain text:

```python
return client.chat.completions.create(  # vcg-ignore: missing-llm-limits
    model="gpt-4",
    messages=[{"role": "user", "content": prompt}],
)
```

A bare `vcg-ignore` (no category) suppresses every finding on that line.
`vcg-ignore: category-a,category-b` scopes it to specific finding categories —
the `category` field in a finding's JSON output (e.g. `missing-llm-limits`,
`hardcoded-secret`) — so other checks on the same line stay active. Suppressed
findings never reach the regex output, so they also don't trigger hybrid
mode's contextual-analysis request.

## Running Tests

```bash
./tests/run-tests.sh
```

## Debugging

Enable debug output:

```bash
VCG_DEBUG=1 ./tests/run-tests.sh
```

## Limitations

- **Regex scanning (fast mode)** — not AST-aware, may produce false positives on comments or strings
- **LLM analysis (deep/hybrid)** — depends on Claude's reasoning; non-deterministic results
- **Not a replacement for SAST** — best used alongside tools like Semgrep, Bandit, or ESLint security plugins
- **Latency** — fast mode adds ~1-2 seconds; hybrid/deep mode may add more for LLM reasoning

## License

MIT
