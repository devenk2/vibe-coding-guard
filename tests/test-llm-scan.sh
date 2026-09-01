#!/usr/bin/env bash
# Vibe Coding Guard — LLM-application scanner tests
# Covers scan_llm_file detections (OWASP LLM01/05/06/02/07/10), false-positive
# suppression, and the opt-in flag gating end-to-end through the hook.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Build a VCG_HOME that mirrors an install (used for the end-to-end hook tests).
TEST_VCG_HOME=$(mktemp -d)
cp -r "$PROJECT_DIR/lib" "$TEST_VCG_HOME/"
cp -r "$PROJECT_DIR/hooks" "$TEST_VCG_HOME/"
cp "$PROJECT_DIR/config.json" "$TEST_VCG_HOME/config.json"
for f in "$TEST_VCG_HOME/hooks/"*.sh "$TEST_VCG_HOME/lib/"*.sh; do
  sed -i '' "s|__VCG_HOME_PLACEHOLDER__|$TEST_VCG_HOME|g" "$f" 2>/dev/null || \
  sed -i "s|__VCG_HOME_PLACEHOLDER__|$TEST_VCG_HOME|g" "$f" 2>/dev/null || true
done
export VCG_HOME="$TEST_VCG_HOME"

WORK=$(mktemp -d)
trap "rm -rf '$TEST_VCG_HOME' '$WORK'" EXIT

HOOK="$TEST_VCG_HOME/hooks/post-tool-use.sh"
PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# ── Part 1: direct scan_llm_file unit tests ─────────────────────────────────
source "$TEST_VCG_HOME/lib/common.sh"
source "$TEST_VCG_HOME/lib/scan-llm.sh"
# common.sh enables `set -euo pipefail`; relax it here (helpers are called as
# bare statements and some greps intentionally return non-zero).
set +e +u
set +o pipefail

# count_cat <file> <category>  → prints number of findings of that category
count_cat() { scan_llm_file "$1" | grep -c "\"category\":\"$2\""; }

echo ""
echo "=== LLM Scanner Tests ==="
echo ""
echo "--- Part 1: scan_llm_file detections ---"

# LLM01 — prompt injection: untrusted request data built into the prompt
cat > "$WORK/inject.py" <<'PY'
import openai
from flask import request

def handler():
    q = request.args.get("q")
    prompt = f"Answer the user: {q}"
    return openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=200,
    )
PY
[[ "$(count_cat "$WORK/inject.py" prompt-injection)" -ge 1 ]] \
  && ok "LLM01 prompt injection flagged" || bad "LLM01 prompt injection missed"

# LLM05 — improper output handling: model output passed to exec(), no mitigation
cat > "$WORK/output.py" <<'PY'
import openai

def run(task):
    resp = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "write code"}],
        max_tokens=200,
    )
    code = resp.choices[0].message.content
    exec(code)
PY
[[ "$(count_cat "$WORK/output.py" unsafe-llm-output)" -ge 1 ]] \
  && ok "LLM05 unsafe output handling flagged" || bad "LLM05 unsafe output handling missed"

# LLM06 — excessive agency: agent granted a terminal/shell tool
cat > "$WORK/agent.py" <<'PY'
from langchain.agents import load_tools, initialize_agent
from langchain.llms import OpenAI

llm = OpenAI()
tools = load_tools(["terminal"], llm=llm)
agent = initialize_agent(tools, llm)
PY
[[ "$(count_cat "$WORK/agent.py" excessive-agency)" -ge 1 ]] \
  && ok "LLM06 excessive agency flagged" || bad "LLM06 excessive agency missed"

# LLM02 — secret interpolated into prompt content
cat > "$WORK/secret.py" <<'PY'
import openai, os

def ask(user_q):
    api_key = os.environ["INTERNAL_KEY"]
    prompt = f"Our internal key is {api_key}. Answer: {user_q}"
    return openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=100,
    )
PY
[[ "$(count_cat "$WORK/secret.py" secret-in-prompt)" -ge 1 ]] \
  && ok "LLM02 secret-in-prompt flagged" || bad "LLM02 secret-in-prompt missed"

# LLM10 — missing token/timeout limits on the call
cat > "$WORK/nolimit.py" <<'PY'
import openai

def ask():
    return openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "hello"}],
    )
PY
[[ "$(count_cat "$WORK/nolimit.py" missing-llm-limits)" -ge 1 ]] \
  && ok "LLM10 missing-limits flagged" || bad "LLM10 missing-limits missed"

# LLM10 — vcg-ignore comment on the call line suppresses the finding (limits
# set via a wrapper/helper the windowed heuristic can't see).
cat > "$WORK/nolimit_suppressed.py" <<'PY'
import openai

def ask():
    return openai.chat.completions.create(  # vcg-ignore: missing-llm-limits
        model="gpt-4",
        messages=[{"role": "user", "content": "hello"}],
    )
PY
[[ "$(count_cat "$WORK/nolimit_suppressed.py" missing-llm-limits)" -eq 0 ]] \
  && ok "LLM10 missing-limits suppressed via vcg-ignore" || bad "LLM10 vcg-ignore suppression failed"

# vcg-ignore with a different category does NOT suppress this finding.
cat > "$WORK/nolimit_wrong_cat.py" <<'PY'
import openai

def ask():
    return openai.chat.completions.create(  # vcg-ignore: prompt-injection
        model="gpt-4",
        messages=[{"role": "user", "content": "hello"}],
    )
PY
[[ "$(count_cat "$WORK/nolimit_wrong_cat.py" missing-llm-limits)" -ge 1 ]] \
  && ok "vcg-ignore with unrelated category leaves finding active" || bad "vcg-ignore wrongly suppressed an unrelated category"

# SAFE — static prompt, sanitized output, client-config secret, token cap:
# must produce ZERO findings (false-positive guard).
cat > "$WORK/safe.py" <<'PY'
import openai, os
import bleach

client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])

def summarize(text):
    resp = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Summarize the provided text."}],
        max_tokens=300,
        timeout=30,
    )
    return bleach.clean(resp.choices[0].message.content)
PY
n=$(scan_llm_file "$WORK/safe.py" | grep -c .)
[[ "$n" -eq 0 ]] && ok "safe LLM code produces no findings" || bad "safe LLM code produced $n finding(s)"

# NON-LLM file — scanner must stay silent (no LLM call present anywhere).
cat > "$WORK/plain.py" <<'PY'
from flask import request

def handler():
    q = request.args.get("q")
    prompt = f"hello {q}"
    return prompt
PY
n=$(scan_llm_file "$WORK/plain.py" | grep -c .)
[[ "$n" -eq 0 ]] && ok "non-LLM file produces no LLM findings" || bad "non-LLM file produced $n finding(s)"

# ── Part 2: end-to-end opt-in flag gating (fast mode isolates regex) ─────────
echo ""
echo "--- Part 2: opt-in flag gating (end-to-end) ---"
mkdir -p "$WORK/.claude"

run_hook() { # file_path → prints EXIT code
  jq -n --arg fp "$1" --arg cwd "$WORK" \
    '{tool_name:"Write", tool_input:{file_path:$fp}, tool_response:{success:true}, session_id:"l", cwd:$cwd}' \
    | bash "$HOOK" >/dev/null 2>/dev/null; echo $?
}

# The inject.py fixture is flagged ONLY by the LLM scanner (no other scanner
# matches it), so it cleanly isolates the flag's effect.
printf '{"analysis_mode":"fast","llm_app_scanning":{"enabled":false}}\n' > "$WORK/.claude/vibe-coding-guard.json"
rc=$(run_hook "$WORK/inject.py")
[[ "$rc" -eq 0 ]] && ok "flag OFF: LLM vuln not flagged (exit 0)" || bad "flag OFF: expected exit 0, got $rc"

printf '{"analysis_mode":"fast","llm_app_scanning":{"enabled":true}}\n' > "$WORK/.claude/vibe-coding-guard.json"
rc=$(run_hook "$WORK/inject.py")
[[ "$rc" -eq 2 ]] && ok "flag ON: LLM vuln blocks the write (exit 2)" || bad "flag ON: expected exit 2, got $rc"

# With the flag ON, confirm the finding text names the injection category.
out=$(jq -n --arg fp "$WORK/inject.py" --arg cwd "$WORK" \
  '{tool_name:"Write", tool_input:{file_path:$fp}, tool_response:{success:true}, session_id:"l", cwd:$cwd}' \
  | bash "$HOOK" 2>&1 >/dev/null)
echo "$out" | grep -qi 'prompt injection' \
  && ok "flag ON: prompt-injection surfaced in output" || bad "flag ON: prompt-injection not in output"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
echo ""
[[ $FAIL -gt 0 ]] && exit 1
exit 0
