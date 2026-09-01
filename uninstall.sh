#!/usr/bin/env bash
# Vibe Coding Guard — Uninstaller
# Usage: ./uninstall.sh /path/to/target/project [--global]
set -euo pipefail

VCG_INSTALL_DIR="${VCG_HOME:-$HOME/.vibe-coding-guard}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
  echo ""
  echo -e "${BLUE}============================================${NC}"
  echo -e "${BLUE}  Vibe Coding Guard — Uninstaller${NC}"
  echo -e "${BLUE}============================================${NC}"
  echo ""
}

print_success() { echo -e "${GREEN}[OK]${NC} $1"; }
print_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
print_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }

print_header

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 /path/to/target/project [--global]"
  echo ""
  echo "Options:"
  echo "  --global    Also remove the global installation (~/.vibe-coding-guard)"
  exit 1
fi

TARGET_PROJECT="$(cd "$1" && pwd)"
REMOVE_GLOBAL=false

for arg in "$@"; do
  if [[ "$arg" == "--global" ]]; then
    REMOVE_GLOBAL=true
  fi
done

# --- Remove hooks from settings.json ---
SETTINGS_FILE="$TARGET_PROJECT/.claude/settings.json"

if [[ -f "$SETTINGS_FILE" ]]; then
  if command -v jq &> /dev/null; then
    # Remove VCG hook entries (those referencing vibe-coding-guard)
    CLEANED=$(jq '
      if .hooks then
        .hooks |= with_entries(
          .value |= [.[] | .hooks = [.hooks[] | select(.command | tostring | test("vibe-coding-guard") | not)] | select(.hooks | length > 0)]
        ) |
        .hooks |= with_entries(select(.value | length > 0)) |
        if (.hooks | length) == 0 then del(.hooks) else . end
      else . end
    ' "$SETTINGS_FILE")

    echo "$CLEANED" | jq '.' > "$SETTINGS_FILE"
    print_success "Removed hooks from settings.json"
  else
    print_warn "jq not found — cannot clean settings.json automatically"
    print_warn "Please manually remove vibe-coding-guard hook entries from $SETTINGS_FILE"
  fi
else
  print_warn "No settings.json found at $SETTINGS_FILE"
fi

# --- Remove VCG section from CLAUDE.md ---
CLAUDE_MD="$TARGET_PROJECT/CLAUDE.md"
VCG_MARKER="<!-- Vibe Coding Guard -->"
VCG_END_MARKER="<!-- /Vibe Coding Guard -->"

if [[ -f "$CLAUDE_MD" ]]; then
  if grep -q "$VCG_MARKER" "$CLAUDE_MD"; then
    # Remove everything between markers (inclusive)
    sed -i.bak '\|<!-- Vibe Coding Guard -->|,\|<!-- /Vibe Coding Guard -->|d' "$CLAUDE_MD"
    rm -f "${CLAUDE_MD}.bak"

    # If CLAUDE.md is now empty (or just whitespace), remove it
    if [[ ! -s "$CLAUDE_MD" ]] || [[ "$(cat "$CLAUDE_MD" | tr -d '[:space:]')" == "" ]]; then
      rm -f "$CLAUDE_MD"
      print_success "Removed CLAUDE.md (was only VCG content)"
    else
      print_success "Removed VCG section from CLAUDE.md"
    fi
  else
    print_warn "No VCG section found in CLAUDE.md"
  fi
fi

# --- Remove rules files ---
VCG_RULES=("pw-secure-coding.md" "rv-vulnerabilities.md" "ps-protect-software.md" "security-aware.md" "api-security.md" "llm-security.md" "access-control.md")
RULES_DIR="$TARGET_PROJECT/.claude/rules"

if [[ -d "$RULES_DIR" ]]; then
  for rule in "${VCG_RULES[@]}"; do
    if [[ -f "$RULES_DIR/$rule" ]]; then
      rm -f "$RULES_DIR/$rule"
    fi
  done
  print_success "Removed security rule files"

  # Remove rules dir if empty
  if [[ -z "$(ls -A "$RULES_DIR" 2>/dev/null)" ]]; then
    rmdir "$RULES_DIR"
  fi
fi

# --- Remove per-project config ---
PROJECT_CONFIG="$TARGET_PROJECT/.claude/vibe-coding-guard.json"
if [[ -f "$PROJECT_CONFIG" ]]; then
  rm -f "$PROJECT_CONFIG"
  print_success "Removed project config (vibe-coding-guard.json)"
fi

# --- Clean up .claude directory if empty ---
CLAUDE_DIR="$TARGET_PROJECT/.claude"
if [[ -d "$CLAUDE_DIR" ]] && [[ -z "$(ls -A "$CLAUDE_DIR" 2>/dev/null)" ]]; then
  rmdir "$CLAUDE_DIR"
  print_success "Removed empty .claude/ directory"
fi

# --- Remove global installation ---
if [[ "$REMOVE_GLOBAL" == true ]]; then
  if [[ -d "$VCG_INSTALL_DIR" ]]; then
    rm -rf "$VCG_INSTALL_DIR"
    print_success "Removed global installation: $VCG_INSTALL_DIR"
  else
    print_warn "Global installation not found at $VCG_INSTALL_DIR"
  fi
else
  print_info "Global installation kept at $VCG_INSTALL_DIR (use --global to remove)"
fi

echo ""
echo -e "${GREEN}Uninstall complete.${NC}"
echo ""
