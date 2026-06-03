# Dependency Security Scanning

Vibe Coding Guard includes built-in dependency security scanning that runs automatically when Claude Code executes package install commands (`pip install`, `npm install`, `yarn add`, `pnpm add`).

## Built-In Protection (3 Layers)

### Layer 1: Typosquatting Detection (Pre-Install)

When a package install command is detected, VCG checks the package name against ~350 popular PyPI and npm packages using Levenshtein distance comparison. This catches:

- **Character transpositions**: `reqeusts` → did you mean `requests`?
- **Missing/extra characters**: `expresss` → did you mean `express`?
- **Prefix/suffix manipulation**: `python-requests`, `flask-dev`, `node-express`

**Severity**: HIGH (blocks the command)

### Layer 2: OSV Vulnerability Database (Pre-Install)

VCG queries the [OSV.dev](https://osv.dev) API (free, no API key needed) to check if the specific package + version has known CVEs before installation.

- Covers 20+ ecosystems (PyPI, npm, Go, Rust, etc.)
- 5-second timeout to avoid blocking
- Can be disabled: set `dependency_scanning.osv_vulnerability_check` to `false` in config

**Severity**: HIGH (blocks the command)

### Layer 3: Post-Install Audit

After a package install completes, VCG runs the appropriate audit tool:

| Ecosystem | Tool | Install |
|-----------|------|---------|
| Python | `pip-audit` | `pip install pip-audit` |
| Node.js | `npm audit` | Built into npm |

These check all installed dependencies (including transitive) for known vulnerabilities.

**Severity**: HIGH for critical/high CVEs, MEDIUM for moderate

## Configuration

In `config.json` or `.claude/vibe-coding-guard.json`:

```json
{
  "dependency_scanning": {
    "enabled": true,
    "typosquatting_detection": true,
    "osv_vulnerability_check": true,
    "osv_api_timeout_seconds": 5,
    "post_install_audit": true
  }
}
```

## Optional: Socket.dev MCP (Enhanced Protection)

For maximum supply chain security coverage, you can add the **Socket.dev MCP** to Claude Code. Socket goes beyond CVE databases and analyzes packages for:

- **Malware detection** — obfuscated code, install scripts, data exfiltration
- **Typosquatting** — comprehensive registry-level comparison
- **Maintainer changes** — new maintainer on a popular package (potential hijack)
- **License issues** — incompatible or unusual license changes
- **Quality signals** — package age, download counts, maintenance status

### Setup

1. **Get a Socket API key** at [https://socket.dev](https://socket.dev) (free tier available)

2. **Add the MCP to Claude Code**:

   ```bash
   claude mcp add socket-security -- npx -y @anthropic-ai/tutorial-mcp-server socket
   ```

   Or add to your `.claude/settings.json`:

   ```json
   {
     "mcpServers": {
       "socket-security": {
         "command": "npx",
         "args": ["-y", "@anthropic-ai/tutorial-mcp-server", "socket"],
         "env": {
           "SOCKET_API_KEY": "your-api-key-here"
         }
       }
     }
   }
   ```

   > **Note**: Store the API key in an environment variable rather than hardcoding it:
   > ```json
   > "env": { "SOCKET_API_KEY": "${SOCKET_API_KEY}" }
   > ```

3. **Alternative: Use Socket's official MCP** (check [socket.dev/docs](https://socket.dev) for the latest MCP setup instructions, as the MCP ecosystem is evolving rapidly)

### How it Complements VCG

| Check | VCG Built-In | Socket.dev MCP |
|-------|-------------|----------------|
| Typosquatting | ✅ Top ~350 packages | ✅ Full registry analysis |
| Known CVEs | ✅ OSV.dev database | ✅ Multiple sources |
| Malware detection | ❌ | ✅ Static analysis |
| Install scripts | ❌ | ✅ Detects & flags |
| Maintainer hijacking | ❌ | ✅ Monitors changes |
| License compliance | ❌ | ✅ License analysis |
| Transitive deps (pre-install) | ❌ | ✅ Full dependency tree |

## Other External Tools

These CLI tools can be installed and used alongside VCG:

| Tool | Ecosystem | Install | Usage |
|------|-----------|---------|-------|
| `pip-audit` | Python | `pip install pip-audit` | `pip-audit` |
| `npm audit` | Node.js | Built-in | `npm audit` |
| `osv-scanner` | Multi | [GitHub](https://github.com/google/osv-scanner) | `osv-scanner --lockfile=package-lock.json` |
| `safety` | Python | `pip install safety` | `safety check` |
| `snyk` | Multi | `npm install -g snyk` | `snyk test` |
| `trivy` | Multi | [Install](https://aquasecurity.github.io/trivy) | `trivy fs .` |

### Recommended Setup for Maximum Coverage

```bash
# Python projects
pip install pip-audit

# Node.js projects (npm audit is built-in)
# Optionally install osv-scanner for broader coverage
brew install osv-scanner  # macOS
```

VCG will automatically use `pip-audit` and `npm audit` when available for post-install verification.
