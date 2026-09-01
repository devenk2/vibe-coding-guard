#!/usr/bin/env bash
# Vibe Coding Guard — Installer
# Usage: ./install.sh /path/to/target/project
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VCG_INSTALL_DIR="${VCG_HOME:-$HOME/.vibe-coding-guard}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
  echo ""
  echo -e "${BLUE}============================================${NC}"
  echo -e "${BLUE}  Vibe Coding Guard — Installer${NC}"
  echo -e "${BLUE}============================================${NC}"
  echo ""
}

print_success() { echo -e "${GREEN}[OK]${NC} $1"; }
print_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
print_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }

print_header

# --- Check arguments ---
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 /path/to/target/project"
  echo ""
  echo "Installs Vibe Coding Guard globally and wires it into your Claude Code project."
  exit 1
fi

TARGET_PROJECT="$(cd "$1" && pwd)"

if [[ ! -d "$TARGET_PROJECT" ]]; then
  print_error "Target project directory does not exist: $1"
  exit 1
fi

# --- Check prerequisites ---
if ! command -v jq &> /dev/null; then
  print_error "jq is required but not installed."
  echo ""
  echo "Install jq:"
  echo "  macOS:  brew install jq"
  echo "  Ubuntu: sudo apt install jq"
  echo "  Fedora: sudo dnf install jq"
  exit 1
fi
print_success "jq is installed"

# --- Step 1: Install globally ---
print_info "Installing to $VCG_INSTALL_DIR"

if [[ -d "$VCG_INSTALL_DIR" ]]; then
  print_warn "Existing installation found — updating"
  
  # Safety check: never rm -rf empty or root paths
  if [[ -z "$VCG_INSTALL_DIR" || "$VCG_INSTALL_DIR" == "/" || "$VCG_INSTALL_DIR" == "$HOME" ]]; then
    print_error "Refusing to remove dangerous path: '$VCG_INSTALL_DIR'"
    exit 1
  fi

  # Preserve user's config customizations if they exist
  if [[ -f "$VCG_INSTALL_DIR/config.json" ]]; then
    # Merge: keep user's values, add any new keys from source config
    EXISTING_CONFIG="$VCG_INSTALL_DIR/config.json"
    NEW_CONFIG="$SCRIPT_DIR/config.json"
    MERGED_CONFIG=$(jq -s '.[0] * .[1] | .version = .[1].version' "$EXISTING_CONFIG" "$NEW_CONFIG" 2>/dev/null || cat "$NEW_CONFIG")
    rm -rf "$VCG_INSTALL_DIR"
    mkdir -p "$VCG_INSTALL_DIR"
    echo "$MERGED_CONFIG" > "$VCG_INSTALL_DIR/config.json"
    print_success "Preserved user config customizations"
  else
    rm -rf "$VCG_INSTALL_DIR"
    mkdir -p "$VCG_INSTALL_DIR"
    cp "$SCRIPT_DIR/config.json" "$VCG_INSTALL_DIR/"
  fi
else
  mkdir -p "$VCG_INSTALL_DIR"
  cp "$SCRIPT_DIR/config.json" "$VCG_INSTALL_DIR/"
fi

cp -r "$SCRIPT_DIR/hooks" "$VCG_INSTALL_DIR/"
cp -r "$SCRIPT_DIR/lib" "$VCG_INSTALL_DIR/"
cp -r "$SCRIPT_DIR/rules" "$VCG_INSTALL_DIR/"
cp "$SCRIPT_DIR/CLAUDE.md" "$VCG_INSTALL_DIR/"

# Make hook scripts executable
chmod +x "$VCG_INSTALL_DIR/hooks/"*.sh
chmod +x "$VCG_INSTALL_DIR/lib/"*.sh

# Replace VCG_HOME placeholder in hook scripts
for hook_file in "$VCG_INSTALL_DIR/hooks/"*.sh; do
  sed -i.bak "s|__VCG_HOME_PLACEHOLDER__|$VCG_INSTALL_DIR|g" "$hook_file"
  rm -f "${hook_file}.bak"
done

# Also replace in lib files that reference VCG_HOME
for lib_file in "$VCG_INSTALL_DIR/lib/"*.sh; do
  sed -i.bak "s|__VCG_HOME_PLACEHOLDER__|$VCG_INSTALL_DIR|g" "$lib_file"
  rm -f "${lib_file}.bak"
done

print_success "Global installation complete"

# --- Step 2: Wire into target project ---
print_info "Configuring target project: $TARGET_PROJECT"

# Create .claude directory
mkdir -p "$TARGET_PROJECT/.claude/rules"

# --- Step 2a: Create per-project config ---
PROJECT_CONFIG="$TARGET_PROJECT/.claude/vibe-coding-guard.json"

if [[ -f "$PROJECT_CONFIG" ]]; then
  print_warn "Project config already exists — preserving"
else
  # Create default project config (users can customize)
  cat > "$PROJECT_CONFIG" <<'PROJCONFIG'
{
  "_comment": "Project-specific Vibe Coding Guard settings. Values here override global config (~/.vibe-coding-guard/config.json)",
  "blocking_severity": "MEDIUM",
  "blocking_severity_options": {
    "HIGH": "Only block clearly dangerous commands (rm -rf, force push, etc.)",
    "MEDIUM": "Block dangerous + risky commands (recommended — shows warnings before approval)",
    "LOW": "Block all flagged commands including informational findings"
  },
  "analysis_mode": "hybrid",
  "analysis_mode_options": {
    "fast": "Regex-only — fastest, deterministic, no LLM calls",
    "deep": "Always use LLM reasoning — best coverage, slower",
    "hybrid": "Regex first, LLM for ambiguous cases (recommended)"
  }
}
PROJCONFIG
  print_success "Created project config at .claude/vibe-coding-guard.json"
fi

# --- Step 2b: Merge hooks into .claude/settings.json ---
SETTINGS_FILE="$TARGET_PROJECT/.claude/settings.json"

# The hooks configuration to add
HOOKS_CONFIG=$(cat <<'HOOKSJSON'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "VCG_INSTALL_DIR_PLACEHOLDER/hooks/pre-tool-use.sh",
            "timeout": 10
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "VCG_INSTALL_DIR_PLACEHOLDER/hooks/post-tool-use.sh",
            "timeout": 15
          }
        ]
      }
    ]
  }
}
HOOKSJSON
)

# Replace placeholder with actual path
HOOKS_CONFIG=$(echo "$HOOKS_CONFIG" | sed "s|VCG_INSTALL_DIR_PLACEHOLDER|$VCG_INSTALL_DIR|g")

if [[ -f "$SETTINGS_FILE" ]]; then
  # Merge with existing settings.json
  EXISTING=$(cat "$SETTINGS_FILE")

  # Check if hooks already exist
  if echo "$EXISTING" | jq -e '.hooks' > /dev/null 2>&1; then
    # Check if VCG hooks are already present
    if echo "$EXISTING" | grep -q "vibe-coding-guard"; then
      print_warn "Vibe Coding Guard hooks already present in settings.json — skipping"
    else
      # Merge hooks arrays
      MERGED=$(echo "$EXISTING" | jq --argjson new_hooks "$(echo "$HOOKS_CONFIG" | jq '.hooks')" '
        .hooks.PreToolUse = (.hooks.PreToolUse // []) + $new_hooks.PreToolUse |
        .hooks.PostToolUse = (.hooks.PostToolUse // []) + $new_hooks.PostToolUse
      ')
      echo "$MERGED" | jq '.' > "$SETTINGS_FILE"
      print_success "Merged hooks into existing settings.json"
    fi
  else
    # Add hooks to existing settings
    MERGED=$(echo "$EXISTING" | jq --argjson hooks "$(echo "$HOOKS_CONFIG" | jq '.hooks')" '. + {hooks: $hooks}')
    echo "$MERGED" | jq '.' > "$SETTINGS_FILE"
    print_success "Added hooks to existing settings.json"
  fi
else
  # Create new settings.json
  echo "$HOOKS_CONFIG" | jq '.' > "$SETTINGS_FILE"
  print_success "Created settings.json with hooks"
fi

# --- Step 2c: Install CLAUDE.md ---
CLAUDE_MD="$TARGET_PROJECT/CLAUDE.md"
VCG_START_MARKER="<!-- Vibe Coding Guard -->"
VCG_END_MARKER="<!-- /Vibe Coding Guard -->"

if [[ -f "$CLAUDE_MD" ]]; then
  if grep -q "$VCG_START_MARKER" "$CLAUDE_MD"; then
    # Update existing VCG section (replace content between markers)
    # Use awk to remove old content and insert new
    TEMP_CLAUDE=$(mktemp)
    awk -v start="$VCG_START_MARKER" -v end="$VCG_END_MARKER" '
      $0 == start { skip=1; next }
      $0 == end { skip=0; next }
      !skip { print }
    ' "$CLAUDE_MD" > "$TEMP_CLAUDE"
    
    # Append fresh VCG content
    {
      cat "$TEMP_CLAUDE"
      echo ""
      echo "$VCG_START_MARKER"
      cat "$VCG_INSTALL_DIR/CLAUDE.md"
      echo "$VCG_END_MARKER"
    } > "$CLAUDE_MD"
    rm -f "$TEMP_CLAUDE"
    print_success "Updated Vibe Coding Guard section in CLAUDE.md"
  else
    # Append VCG section
    {
      echo ""
      echo "$VCG_START_MARKER"
      cat "$VCG_INSTALL_DIR/CLAUDE.md"
      echo "$VCG_END_MARKER"
    } >> "$CLAUDE_MD"
    print_success "Appended security instructions to existing CLAUDE.md"
  fi
else
  {
    echo "$VCG_START_MARKER"
    cat "$VCG_INSTALL_DIR/CLAUDE.md"
    echo "$VCG_END_MARKER"
  } > "$CLAUDE_MD"
  print_success "Created CLAUDE.md with security instructions"
fi

# --- Step 2d: Install rules ---
RULE_COUNT=0
for rule_file in "$VCG_INSTALL_DIR/rules/"*.md; do
  rule_name=$(basename "$rule_file")
  cp "$rule_file" "$TARGET_PROJECT/.claude/rules/$rule_name"
  RULE_COUNT=$((RULE_COUNT + 1))
done
print_success "Installed $RULE_COUNT SSDF security rule file(s) to .claude/rules/"

# --- Summary ---
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "  Global install:  $VCG_INSTALL_DIR"
echo "  Target project:  $TARGET_PROJECT"
echo ""
echo "  Files modified:"
echo "    - $SETTINGS_FILE"
echo "    - $PROJECT_CONFIG"
echo "    - $CLAUDE_MD"
echo "    - $TARGET_PROJECT/.claude/rules/ ($RULE_COUNT rule files)"
echo ""
echo "  Configuration:"
echo "    - Global config:  $VCG_INSTALL_DIR/config.json"
echo "    - Project config: $PROJECT_CONFIG"
echo "    - Set 'analysis_mode' to: fast | hybrid | deep"
echo ""
echo "  What happens now:"
echo "    - PreToolUse hook blocks dangerous bash commands"
echo "    - PostToolUse hook scans files after Write/Edit"
echo "    - CLAUDE.md makes the agent security-aware"
echo "    - Rules in .claude/rules/ provide SSDF guidance"
echo ""
echo "  To uninstall: ./uninstall.sh $TARGET_PROJECT"
echo ""
