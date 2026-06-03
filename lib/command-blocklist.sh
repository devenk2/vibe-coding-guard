#!/usr/bin/env bash
# Vibe Coding Guard — Command Blocklist
# Checks bash commands for dangerous patterns

# Check a command string against known dangerous patterns
# Outputs JSON findings (one per line) to stdout
check_command() {
  local cmd="$1"

  # === HIGH SEVERITY ===

  # Remote code execution via pipe to shell
  if echo "$cmd" | grep -qEi '(curl|wget)\s+.*\|\s*(bash|sh|zsh|sudo)'; then
    emit_finding "HIGH" "PS.3" "PS" "remote-code-exec" \
      "command" "0" "curl|bash" \
      "Piping remote content directly to shell allows arbitrary code execution" \
      "Download the script first, review it, then execute it separately"
  fi

  # eval of remote content
  if echo "$cmd" | grep -qEi 'eval\s+.*\$\((curl|wget)'; then
    emit_finding "HIGH" "PS.3" "PS" "remote-code-exec" \
      "command" "0" 'eval "$(curl ...)"' \
      "Evaluating remote content allows arbitrary code execution" \
      "Download and review the script before executing"
  fi

  # Obfuscated remote code execution via base64 decode piped to shell
  if echo "$cmd" | grep -qEi 'base64\s+(-d|--decode).*\|\s*(bash|sh|zsh|sudo)'; then
    emit_finding "HIGH" "PS.3" "PS" "obfuscated-rce" \
      "command" "0" "base64 -d | bash" \
      "Decoding base64 content and piping to shell allows obfuscated code execution" \
      "Decode and review the content first, then execute it separately"
  fi

  # Destructive recursive force delete of root/home
  if echo "$cmd" | grep -qEi 'rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|(-[a-zA-Z]*f[a-zA-Z]*r))\s+(/\s|/\*|~/|"\$HOME|\$\{?HOME\}?)'; then
    emit_finding "HIGH" "PS.1" "PS" "destructive-command" \
      "command" "0" "rm -rf /" \
      "Recursive force deletion of root or home directory" \
      "Use targeted paths and double-check before deleting"
  fi

  # Broader rm -rf catch (still dangerous even on non-root paths if too broad)
  if echo "$cmd" | grep -qEi 'rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+/[a-z]'; then
    # Only flag if targeting system directories
    if echo "$cmd" | grep -qEi 'rm\s+.*\s+/(etc|usr|var|bin|sbin|lib|boot|sys|proc|dev)\b'; then
      emit_finding "HIGH" "PS.1" "PS" "destructive-command" \
        "command" "0" "rm -rf /system-dir" \
        "Recursive force deletion of system directory" \
        "Never delete system directories. Use targeted file paths instead"
    fi
  fi

  # chmod 777 — overly permissive
  if echo "$cmd" | grep -qEi 'chmod\s+777\b'; then
    emit_finding "HIGH" "PW.9" "PW" "overly-permissive" \
      "command" "0" "chmod 777" \
      "Setting permissions to 777 makes files world-readable/writable/executable" \
      "Use least-privilege permissions (e.g., chmod 644 for files, chmod 755 for directories)"
  fi

  # Writing to system config
  if echo "$cmd" | grep -qEi '>\s*/etc/'; then
    emit_finding "HIGH" "PS.1" "PS" "system-config-write" \
      "command" "0" "> /etc/" \
      "Writing to /etc/ can corrupt system configuration" \
      "Use proper system administration tools for config changes"
  fi

  # Destructive disk operations
  if echo "$cmd" | grep -qEi '(^|\s)(mkfs|dd\s+if=)'; then
    emit_finding "HIGH" "PS.1" "PS" "destructive-disk-op" \
      "command" "0" "mkfs/dd" \
      "Destructive disk operation that can cause data loss" \
      "Ensure you are targeting the correct device and have backups"
  fi

  # Force push to main/master
  if echo "$cmd" | grep -qEi 'git\s+push\s+.*--force.*\s+(main|master)\b'; then
    emit_finding "HIGH" "PS.1" "PS" "destructive-git" \
      "command" "0" "git push --force main" \
      "Force pushing to main/master can overwrite shared history" \
      "Use git push --force-with-lease or push to a feature branch instead"
  fi

  # Also catch: git push -f origin main
  if echo "$cmd" | grep -qEi 'git\s+push\s+-f\s+\w+\s+(main|master)\b'; then
    emit_finding "HIGH" "PS.1" "PS" "destructive-git" \
      "command" "0" "git push -f main" \
      "Force pushing to main/master can overwrite shared history" \
      "Use git push --force-with-lease or push to a feature branch instead"
  fi

  # git clean -fdx — destroys all untracked files including .env, local configs
  if echo "$cmd" | grep -qEi 'git\s+clean\s+.*-[a-zA-Z]*f'; then
    emit_finding "HIGH" "PS.1" "PS" "destructive-git" \
      "command" "0" "git clean -f" \
      "git clean -f permanently deletes untracked files including .env, local configs, and build artifacts" \
      "Use git clean -n (dry run) first to preview what will be deleted. Avoid -x flag which removes ignored files too"
  fi

  # git reset --hard on shared/protected branches
  if echo "$cmd" | grep -qEi 'git\s+reset\s+--hard'; then
    emit_finding "HIGH" "PS.1" "PS" "destructive-git" \
      "command" "0" "git reset --hard" \
      "git reset --hard discards all uncommitted changes and staged work irreversibly" \
      "Use git stash to save changes before resetting, or use git reset --soft/--mixed to preserve working tree"
  fi

  # .gitattributes filter manipulation — can execute arbitrary commands
  if echo "$cmd" | grep -qEi 'git\s+config\s+.*filter\.\w+\.(clean|smudge|process)'; then
    emit_finding "HIGH" "PS.2" "PS" "git-filter-abuse" \
      "command" "0" "git config filter.*.clean/smudge" \
      "Git filter attributes (clean/smudge) execute arbitrary commands on checkout and commit" \
      "Review filter configurations carefully. Only configure filters from trusted sources"
  fi

  # git commit of sensitive files (.env, keys, certs)
  if echo "$cmd" | grep -qEi 'git\s+(add|commit)\s+.*(\\.env|\\.pem|\\.key|\\.p12|\\.pfx|\\.jks|id_rsa|id_ed25519|credentials|\.secret)'; then
    emit_finding "HIGH" "RV.1" "RV" "git-secret-commit" \
      "command" "0" "git add/commit sensitive file" \
      "Committing secrets, keys, or credentials to git history — once pushed, they are permanently exposed" \
      "Add the file to .gitignore. If already committed, use git-filter-repo or BFG to purge from history and rotate the credential"
  fi

  # === MEDIUM SEVERITY ===

  # git clone over HTTP (not HTTPS)
  if echo "$cmd" | grep -qEi 'git\s+clone\s+http://'; then
    emit_finding "MEDIUM" "PW.9" "PW" "git-insecure-transport" \
      "command" "0" "git clone http://" \
      "Cloning over HTTP allows man-in-the-middle attacks — malicious code could be injected" \
      "Use HTTPS or SSH for git operations: git clone https://... or git clone git@..."
  fi

  # git remote add/set-url over HTTP
  if echo "$cmd" | grep -qEi 'git\s+remote\s+(add|set-url)\s+\w+\s+http://'; then
    emit_finding "MEDIUM" "PW.9" "PW" "git-insecure-transport" \
      "command" "0" "git remote add/set-url http://" \
      "Setting a git remote to HTTP allows man-in-the-middle attacks on future pushes and pulls" \
      "Use HTTPS or SSH URLs for remotes: https://... or git@..."
  fi

  # git submodule add from potentially untrusted source
  if echo "$cmd" | grep -qEi 'git\s+submodule\s+add\b'; then
    emit_finding "MEDIUM" "PS.3" "PS" "git-submodule-risk" \
      "command" "0" "git submodule add" \
      "Adding a git submodule pulls external code into your repository — supply chain risk" \
      "Verify the submodule source is trusted. Pin to a specific commit hash. Review the submodule code before use"
  fi

  # git checkout -- (discard uncommitted changes — irreversible data loss)
  if echo "$cmd" | grep -qEi 'git\s+checkout\s+--\s+'; then
    emit_finding "HIGH" "PS.1" "PS" "git-discard-changes" \
      "command" "0" "git checkout -- <path>" \
      "git checkout -- permanently discards uncommitted changes to the specified files. This is irreversible — Git does not keep a copy of unstaged work" \
      "Use git stash to save changes first, or use targeted Edit replacements to revert specific code instead of discarding entire files"
  fi

  # git restore (discard uncommitted changes — irreversible data loss)
  if echo "$cmd" | grep -qEi 'git\s+restore\s+(--worktree\s+)?(\.|[a-zA-Z])'; then
    emit_finding "HIGH" "PS.1" "PS" "git-discard-changes" \
      "command" "0" "git restore <path>" \
      "git restore permanently discards uncommitted changes to the specified files. This is irreversible — Git does not keep a copy of unstaged work" \
      "Use git stash to save changes first, or use targeted Edit replacements to revert specific code instead of discarding entire files"
  fi

  # git disable SSL verification
  if echo "$cmd" | grep -qEi 'git\s+.*(-c\s+http\.sslVerify\s*=\s*false|config\s+.*http\.sslVerify\s+false)'; then
    emit_finding "MEDIUM" "PW.9" "PW" "git-ssl-bypass" \
      "command" "0" "git http.sslVerify=false" \
      "Disabling SSL verification for git makes connections vulnerable to MITM attacks" \
      "Fix certificate issues properly instead of disabling SSL verification"
  fi

  # Unpinned pip install
  if echo "$cmd" | grep -qEi 'pip3?\s+install\s+(?!.*==)(?!.*-r\s)(?!.*requirements)(?!.*\.)' 2>/dev/null || \
     echo "$cmd" | grep -Ei 'pip3?\s+install\s+' | grep -qvEi '(==|-r\s|requirements|\.\s|\./)'; then
    if ! echo "$cmd" | grep -qEi '(==|-r\s|requirements\.txt|setup\.py|pyproject\.toml|\.\s*$|\.\/)'; then
      emit_finding "MEDIUM" "PS.3" "PS" "unpinned-dependency" \
        "command" "0" "pip install <pkg>" \
        "Installing dependencies without version pinning can introduce unexpected changes" \
        "Pin versions explicitly (e.g., pip install package==1.2.3) or use a requirements file"
    fi
  fi

  # Docker privileged mode
  if echo "$cmd" | grep -qEi 'docker\s+run\s+.*--privileged'; then
    emit_finding "MEDIUM" "PW.9" "PW" "privileged-container" \
      "command" "0" "docker run --privileged" \
      "Running containers in privileged mode disables security isolation" \
      "Use specific --cap-add flags instead of --privileged"
  fi

  # Generic curl/wget download (informational)
  if echo "$cmd" | grep -qEi '\b(curl|wget)\s+-' && ! echo "$cmd" | grep -qEi '\|\s*(bash|sh|zsh)'; then
    emit_finding "MEDIUM" "PS.3" "PS" "network-fetch" \
      "command" "0" "curl/wget" \
      "Downloading content from the network — verify the source is trusted" \
      "Ensure the URL points to a trusted, verified source"
  fi

  # Unpinned npm install
  if echo "$cmd" | grep -qEi '\bnpm\s+install\s+' 2>/dev/null; then
    if ! echo "$cmd" | grep -qEi '(@[0-9]|@\^|@~|@latest|--save-exact|package\.json|package-lock|\.tgz|\./)'; then
      emit_finding "MEDIUM" "PS.3" "PS" "unpinned-dependency" \
        "command" "0" "npm install <pkg>" \
        "Installing npm dependencies without version pinning can introduce unexpected changes" \
        "Pin versions explicitly (e.g., npm install package@1.2.3) or use --save-exact"
    fi
  fi

  # Git credential/URL manipulation (supply chain risk)
  if echo "$cmd" | grep -qEi 'git\s+config\s+.*(--(global|system))?\s*(credential|url\..*.insteadOf)'; then
    emit_finding "MEDIUM" "PS.2" "PS" "git-config-abuse" \
      "command" "0" "git config credential/url" \
      "Modifying git credential helpers or URL rewrites can redirect pushes or steal credentials" \
      "Review git config changes carefully. Avoid modifying credential helpers globally"
  fi

  # Shell history clearing (covering tracks)
  if echo "$cmd" | grep -qEi '(history\s+(-c|-d|--clear|--delete)|\bshred\s+.*history|>\s*~/\.\w+_history)'; then
    emit_finding "MEDIUM" "PS.2" "PS" "history-clearing" \
      "command" "0" "history -c / shred history" \
      "Clearing shell history can hide evidence of malicious commands" \
      "Avoid clearing shell history unless there is a specific, documented reason"
  fi

  return 0
}
