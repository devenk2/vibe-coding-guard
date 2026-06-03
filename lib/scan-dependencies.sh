#!/usr/bin/env bash
# Vibe Coding Guard — Dependency Security Scanner
# Pre-install checks: typosquatting detection, OSV vulnerability lookup
# Post-install checks: pip-audit / npm audit wrappers

# ─── Top 200 PyPI packages (most downloaded) ───
# Used for typosquatting detection via edit distance
POPULAR_PYPI_PACKAGES=(
  boto3 botocore urllib3 setuptools requests typing-extensions
  certifi charset-normalizer idna python-dateutil s3transfer pip
  packaging jmespath pyyaml six numpy cryptography pyasn1 colorama
  awscli cffi rsa docutils pycparser jinja2 markupsafe
  pydantic grpcio protobuf pandas scipy importlib-metadata
  pytz zipp attrs platformdirs click tomli pluggy filelock
  wheel fsspec pytest virtualenv aiohttp wrapt pillow
  jsonschema pyparsing pyopenssl pyjwt tqdm decorator
  google-api-core google-auth async-timeout multidict frozenlist
  aiosignal yarl sqlalchemy werkzeug flask pygments
  beautifulsoup4 lxml openpyxl paramiko psutil scikit-learn
  matplotlib docker celery redis pynacl httpx gunicorn
  tornado uvicorn fastapi starlette httpcore anyio sniffio
  httptools uvloop itsdangerous markupsafe mako alembic
  greenlet psycopg2 psycopg2-binary pymysql pymongo
  elasticsearch boto djangorestframework django
  scrapy twisted ansible fabric invoke black isort
  mypy pylint flake8 bandit coverage tox nox
  poetry pipenv pre-commit commitizen sphinx mkdocs
  rich typer textual httpie arrow pendulum
  pydantic-core annotated-types orjson ujson msgpack
  aiofiles python-multipart python-dotenv
  transformers torch torchvision tensorflow keras
  huggingface-hub tokenizers safetensors accelerate
  langchain openai anthropic tiktoken
  streamlit gradio dash plotly bokeh seaborn
  networkx sympy statsmodels xgboost lightgbm catboost
  dask polars vaex pyarrow
)

# ─── Top 150 npm packages ───
POPULAR_NPM_PACKAGES=(
  lodash chalk react express axios next vue
  typescript webpack babel-core eslint prettier jest
  mocha chai sinon cypress playwright
  commander inquirer yargs minimist glob
  fs-extra mkdirp rimraf cross-env dotenv
  uuid nanoid date-fns moment dayjs luxon
  underscore ramda rxjs bluebird async
  debug winston pino morgan bunyan
  body-parser cors helmet cookie-parser
  jsonwebtoken bcrypt passport express-validator
  sequelize mongoose typeorm prisma knex
  socket.io ws mqtt amqplib ioredis
  aws-sdk googleapis firebase
  react-dom react-router react-redux redux
  next-auth styled-components emotion tailwindcss
  material-ui antd chakra-ui
  angular zone.js core-js regenerator-runtime
  svelte solid-js preact lit
  vite rollup esbuild parcel turbo
  postcss autoprefixer sass less
  nodemon ts-node tsx concurrently
  lerna nx turbo changesets
  semver minimatch glob-parent picomatch
  ajv zod joi yup class-validator
  sharp jimp canvas pdf-lib
  puppeteer cheerio jsdom
  three d3 chart.js echarts
  electron tauri nw
  fastify koa hapi restify nest
  graphql apollo-server type-graphql
  docker-compose pm2 forever nodemailer
  marked markdown-it highlight.js prismjs
  ora listr2 boxen figlet gradient-string
)

# ─── Levenshtein Distance (bash implementation) ───
# Used for typosquatting detection
# Returns edit distance between two strings
_levenshtein() {
  local s1="$1"
  local s2="$2"
  local len1=${#s1}
  local len2=${#s2}
  
  # Quick checks
  if [[ $len1 -eq 0 ]]; then echo "$len2"; return; fi
  if [[ $len2 -eq 0 ]]; then echo "$len1"; return; fi
  if [[ "$s1" == "$s2" ]]; then echo 0; return; fi
  
  # For very long strings, skip (performance)
  if [[ $len1 -gt 30 || $len2 -gt 30 ]]; then echo 99; return; fi
  
  # Use a flat array to simulate 2D matrix (bash 3.2 compatible)
  local -a matrix
  local cols=$(( len2 + 1 ))
  
  # Initialize first row
  for (( j = 0; j <= len2; j++ )); do
    matrix[$j]=$j
  done
  
  for (( i = 1; i <= len1; i++ )); do
    matrix[$(( i * cols ))]=$i
    for (( j = 1; j <= len2; j++ )); do
      local cost=0
      if [[ "${s1:$((i-1)):1}" != "${s2:$((j-1)):1}" ]]; then
        cost=1
      fi
      
      local del=$(( matrix[$(( (i-1) * cols + j ))] + 1 ))
      local ins=$(( matrix[$(( i * cols + (j-1) ))] + 1 ))
      local sub=$(( matrix[$(( (i-1) * cols + (j-1) ))] + cost ))
      
      # min of three
      local min=$del
      [[ $ins -lt $min ]] && min=$ins
      [[ $sub -lt $min ]] && min=$sub
      
      matrix[$(( i * cols + j ))]=$min
    done
  done
  
  echo "${matrix[$(( len1 * cols + len2 ))]}"
}

# ─── Typosquatting Detection ───
# Checks if a package name is suspiciously close to a popular package
# Returns 0 if typosquatting suspected, 1 otherwise
# Outputs the suspected real package name on stdout
check_typosquat() {
  local pkg_name="$1"
  local ecosystem="${2:-pypi}"  # "pypi" or "npm"
  
  local -a packages
  if [[ "$ecosystem" == "pypi" ]]; then
    packages=("${POPULAR_PYPI_PACKAGES[@]}")
  else
    packages=("${POPULAR_NPM_PACKAGES[@]}")
  fi
  
  # Normalize: lowercase, replace underscores with hyphens
  local normalized
  normalized=$(echo "$pkg_name" | tr '[:upper:]' '[:lower:]' | tr '_' '-')
  
  # Exact match — not a typosquat
  for popular in "${packages[@]}"; do
    local pop_normalized
    pop_normalized=$(echo "$popular" | tr '[:upper:]' '[:lower:]' | tr '_' '-')
    if [[ "$normalized" == "$pop_normalized" ]]; then
      return 1
    fi
  done
  
  # Check edit distance against all popular packages
  for popular in "${packages[@]}"; do
    local pop_normalized
    pop_normalized=$(echo "$popular" | tr '[:upper:]' '[:lower:]' | tr '_' '-')
    
    # Skip if lengths are too different (optimization)
    local len_diff=$(( ${#normalized} - ${#pop_normalized} ))
    [[ $len_diff -lt 0 ]] && len_diff=$(( -len_diff ))
    if [[ $len_diff -gt 2 ]]; then
      continue
    fi
    
    local dist
    dist=$(_levenshtein "$normalized" "$pop_normalized")
    
    # Threshold: distance of 1 for very short names (<=5), 2 for longer names
    # This catches character transpositions (reqeusts→requests) while avoiding
    # false positives on short names (pip, six, etc.)
    local threshold=1
    if [[ ${#pop_normalized} -ge 6 ]]; then
      threshold=2
    fi
    
    if [[ $dist -le $threshold && $dist -gt 0 ]]; then
      echo "$popular"
      return 0
    fi
  done
  
  # Check common typosquatting patterns
  # 1. Prefix/suffix manipulation: python-requests vs requests-python
  for popular in "${packages[@]}"; do
    local pop_normalized
    pop_normalized=$(echo "$popular" | tr '[:upper:]' '[:lower:]' | tr '_' '-')
    
    # Package name is popular name with a suspicious prefix/suffix
    if [[ "$normalized" == "python-${pop_normalized}" || \
          "$normalized" == "py-${pop_normalized}" || \
          "$normalized" == "${pop_normalized}-python" || \
          "$normalized" == "${pop_normalized}-py" || \
          "$normalized" == "${pop_normalized}2" || \
          "$normalized" == "${pop_normalized}3" || \
          "$normalized" == "${pop_normalized}-dev" || \
          "$normalized" == "${pop_normalized}-lib" || \
          "$normalized" == "${pop_normalized}-sdk" || \
          "$normalized" == "${pop_normalized}-tool" || \
          "$normalized" == "${pop_normalized}-utils" || \
          "$normalized" == "node-${pop_normalized}" || \
          "$normalized" == "${pop_normalized}-js" || \
          "$normalized" == "${pop_normalized}-node" ]]; then
      echo "$popular"
      return 0
    fi
  done
  
  return 1
}

# ─── Extract Package Names from Install Command ───
# Parses pip/npm install commands and returns package names (one per line)
extract_packages_from_command() {
  local cmd="$1"
  local ecosystem="${2:-auto}"
  
  # Auto-detect ecosystem
  if [[ "$ecosystem" == "auto" ]]; then
    if echo "$cmd" | grep -qEi '\bpip3?\s+install\b'; then
      ecosystem="pypi"
    elif echo "$cmd" | grep -qEi '\bnpm\s+install\b|\byarn\s+add\b|\bpnpm\s+(add|install)\b'; then
      ecosystem="npm"
    else
      return 1
    fi
  fi
  
  local packages=""
  
  if [[ "$ecosystem" == "pypi" ]]; then
    # Extract packages from pip install command
    # Remove pip install prefix, flags, and version specifiers
    packages=$(echo "$cmd" | \
      sed -E 's/.*pip3?\s+install\s+//' | \
      tr ' ' '\n' | \
      grep -vE '^-' | \
      sed -E 's/(==|>=|<=|!=|~=|>|<).*//' | \
      grep -vE '^\.' | \
      grep -vE '^$' | \
      grep -vE '\.(txt|cfg|toml|py)$')
  elif [[ "$ecosystem" == "npm" ]]; then
    # Extract packages from npm install / yarn add
    packages=$(echo "$cmd" | \
      sed -E 's/.*(npm\s+install|yarn\s+add|pnpm\s+(add|install))\s+//' | \
      tr ' ' '\n' | \
      grep -vE '^-' | \
      sed -E 's/@[0-9^~].*//' | \
      grep -vE '^\.' | \
      grep -vE '^$')
  fi
  
  echo "$packages"
}

# ─── OSV.dev API Vulnerability Check ───
# Queries the OSV.dev API for known vulnerabilities in a package
# Free, no API key required
# Returns 0 if vulnerabilities found, 1 if clean
check_osv_vulnerabilities() {
  local pkg_name="$1"
  local ecosystem="$2"  # "PyPI" or "npm" (OSV uses capitalized names)
  local version="${3:-}"
  
  # Check if curl is available
  if ! command -v curl &>/dev/null; then
    log_debug "curl not available, skipping OSV check"
    return 1
  fi
  
  # Map ecosystem names to OSV format
  local osv_ecosystem
  case "$ecosystem" in
    pypi|PyPI)   osv_ecosystem="PyPI" ;;
    npm)         osv_ecosystem="npm" ;;
    *)           osv_ecosystem="$ecosystem" ;;
  esac
  
  # Build the query JSON
  local query
  if [[ -n "$version" ]]; then
    query=$(jq -n -c \
      --arg name "$pkg_name" \
      --arg eco "$osv_ecosystem" \
      --arg ver "$version" \
      '{"package": {"name": $name, "ecosystem": $eco}, "version": $ver}')
  else
    query=$(jq -n -c \
      --arg name "$pkg_name" \
      --arg eco "$osv_ecosystem" \
      '{"package": {"name": $name, "ecosystem": $eco}}')
  fi
  
  # Query the OSV API with timeout
  local response
  response=$(curl -s --max-time 5 \
    -X POST \
    -H "Content-Type: application/json" \
    -d "$query" \
    "https://api.osv.dev/v1/query" 2>/dev/null) || return 1
  
  # Check if vulnerabilities were found
  local vuln_count
  vuln_count=$(echo "$response" | jq '.vulns | length' 2>/dev/null) || return 1
  
  if [[ "$vuln_count" -gt 0 ]]; then
    # Extract vulnerability IDs and severities
    local vuln_ids
    vuln_ids=$(echo "$response" | jq -r '.vulns[].id' 2>/dev/null | head -5)
    
    local vuln_summary
    vuln_summary=$(echo "$response" | jq -r '.vulns[] | "\(.id): \(.summary // "No summary")"' 2>/dev/null | head -3)
    
    echo "$vuln_count|$vuln_ids|$vuln_summary"
    return 0
  fi
  
  return 1
}

# ─── Full Dependency Security Check ───
# Called from pre-hook when a pip/npm install command is detected
# Runs typosquatting detection + OSV vulnerability check
# Outputs findings to stdout (one JSON per line)
check_dependency_security() {
  local cmd="$1"
  
  # Determine ecosystem
  local ecosystem="auto"
  local osv_eco=""
  if echo "$cmd" | grep -qEi '\bpip3?\s+install\b'; then
    ecosystem="pypi"
    osv_eco="PyPI"
  elif echo "$cmd" | grep -qEi '\bnpm\s+install\b|\byarn\s+add\b|\bpnpm\s+(add|install)\b'; then
    ecosystem="npm"
    osv_eco="npm"
  else
    return 0
  fi
  
  # Extract package names
  local packages
  packages=$(extract_packages_from_command "$cmd" "$ecosystem")
  
  if [[ -z "$packages" ]]; then
    return 0
  fi
  
  # Check each package
  while IFS= read -r pkg; do
    [[ -z "$pkg" ]] && continue
    
    # Strip version specifier for checks
    local pkg_name
    pkg_name=$(echo "$pkg" | sed -E 's/(==|>=|<=|!=|~=|>|<|@).*//')
    [[ -z "$pkg_name" ]] && continue
    
    # Extract version if present
    local pkg_version=""
    if echo "$pkg" | grep -qE '(==|@[0-9])'; then
      pkg_version=$(echo "$pkg" | sed -E 's/.*?(==|@)([0-9][^ ]*)/\2/')
    fi
    
    # ── Check 1: Typosquatting ──
    local real_pkg=""
    real_pkg=$(check_typosquat "$pkg_name" "$ecosystem") && {
      emit_finding "HIGH" "PS.3" "PS" "typosquatting-suspect" \
        "command" "0" "$pkg_name" \
        "Possible typosquatting: '$pkg_name' is suspiciously similar to popular package '$real_pkg'" \
        "Verify the package name. Did you mean '$real_pkg'? Check https://pypi.org/project/$pkg_name/ or https://www.npmjs.com/package/$pkg_name"
    }
    
    # ── Check 2: OSV Vulnerability Database ──
    if [[ "${DEP_CHECK_OSV:-true}" == "true" && "${VCG_SKIP_OSV:-}" != "true" ]]; then
      local osv_result=""
      osv_result=$(check_osv_vulnerabilities "$pkg_name" "$osv_eco" "$pkg_version") && {
        local vuln_count vuln_ids vuln_summary
        vuln_count=$(echo "$osv_result" | cut -d'|' -f1)
        vuln_ids=$(echo "$osv_result" | cut -d'|' -f2 | tr '\n' ', ' | sed 's/,$//')
        vuln_summary=$(echo "$osv_result" | cut -d'|' -f3 | head -1)
        
        local severity="HIGH"
        local desc="Package '$pkg_name' has $vuln_count known vulnerability(ies): $vuln_summary"
        local remediation="Check https://osv.dev/list?ecosystem=${osv_eco}&q=${pkg_name} for details. Update to a patched version or find an alternative package"
        
        if [[ -n "$pkg_version" ]]; then
          desc="Package '$pkg_name@$pkg_version' has $vuln_count known vulnerability(ies): $vuln_summary"
        fi
        
        emit_finding "$severity" "RV.1" "RV" "vulnerable-dependency" \
          "command" "0" "$pkg_name" \
          "$desc" \
          "$remediation"
      }
    fi
    
  done <<< "$packages"
  
  return 0
}

# ─── Post-Install Audit ───
# Runs pip-audit or npm audit after an install command completes
# Called from post-tool-use hook when Bash tool with install detected
run_post_install_audit() {
  local cmd="$1"
  local cwd="${2:-.}"
  
  if echo "$cmd" | grep -qEi '\bpip3?\s+install\b'; then
    # Check if pip-audit is available
    if command -v pip-audit &>/dev/null; then
      log_debug "Running pip-audit post-install check"
      local audit_output
      audit_output=$(cd "$cwd" && pip-audit --format=json 2>/dev/null) || true
      
      if [[ -n "$audit_output" ]]; then
        local vuln_count
        vuln_count=$(echo "$audit_output" | jq '.dependencies | map(select(.vulns | length > 0)) | length' 2>/dev/null) || vuln_count=0
        
        if [[ "$vuln_count" -gt 0 ]]; then
          local vuln_details
          vuln_details=$(echo "$audit_output" | jq -r '.dependencies[] | select(.vulns | length > 0) | "\(.name) \(.version): \(.vulns[0].id)"' 2>/dev/null | head -5)
          
          emit_finding "HIGH" "RV.1" "RV" "vulnerable-dependency-installed" \
            "command" "0" "pip-audit" \
            "pip-audit found $vuln_count vulnerable package(s) installed: $vuln_details" \
            "Run 'pip-audit' for full details and update vulnerable packages to patched versions"
        fi
      fi
    else
      log_debug "pip-audit not installed — install with: pip install pip-audit"
    fi
    
  elif echo "$cmd" | grep -qEi '\bnpm\s+install\b|\byarn\s+add\b'; then
    # Check if npm audit is available
    if command -v npm &>/dev/null; then
      log_debug "Running npm audit post-install check"
      local audit_output
      audit_output=$(cd "$cwd" && npm audit --json 2>/dev/null) || true
      
      if [[ -n "$audit_output" ]]; then
        local vuln_count
        vuln_count=$(echo "$audit_output" | jq '.metadata.vulnerabilities.total // 0' 2>/dev/null) || vuln_count=0
        
        if [[ "$vuln_count" -gt 0 ]]; then
          local high_count moderate_count
          high_count=$(echo "$audit_output" | jq '.metadata.vulnerabilities.high // 0' 2>/dev/null) || high_count=0
          moderate_count=$(echo "$audit_output" | jq '.metadata.vulnerabilities.moderate // 0' 2>/dev/null) || moderate_count=0
          local critical_count
          critical_count=$(echo "$audit_output" | jq '.metadata.vulnerabilities.critical // 0' 2>/dev/null) || critical_count=0
          
          local severity="MEDIUM"
          if [[ "$critical_count" -gt 0 || "$high_count" -gt 0 ]]; then
            severity="HIGH"
          fi
          
          emit_finding "$severity" "RV.1" "RV" "vulnerable-dependency-installed" \
            "command" "0" "npm audit" \
            "npm audit found $vuln_count vulnerability(ies) ($critical_count critical, $high_count high, $moderate_count moderate)" \
            "Run 'npm audit fix' to auto-fix or 'npm audit' for details. Update packages to patched versions"
        fi
      fi
    fi
  fi
  
  return 0
}
