#!/usr/bin/env bash
# Vibe Coding Guard — .gitignore Auditor
# Checks that .gitignore includes critical entries based on project structure

# Audit a .gitignore file against the project's actual file structure
# Outputs JSON findings (one per line) to stdout
scan_gitignore_file() {
  local file="$1"
  local project_dir
  project_dir=$(dirname "$file")

  local gitignore_content
  gitignore_content=$(cat "$file" 2>/dev/null || echo "")

  # Helper: check if a pattern (or close variant) is covered in .gitignore
  _gitignore_has() {
    local pattern="$1"
    # Check for exact match, glob match, or directory match
    if echo "$gitignore_content" | grep -qEi "^/?${pattern}(/?\s*$|$)" 2>/dev/null; then
      return 0
    fi
    # Also check for broader globs that would cover it (e.g., *.pem covers id_rsa.pem)
    if echo "$gitignore_content" | grep -qF "$pattern" 2>/dev/null; then
      return 0
    fi
    return 1
  }

  # === UNIVERSAL ENTRIES (should always be in .gitignore) ===

  # .env files — almost always contain secrets
  if ! _gitignore_has ".env"; then
    emit_finding "HIGH" "RV.1" "RV" "gitignore-missing-env" \
      "$file" "0" ".env not in .gitignore" \
      ".env files typically contain secrets (API keys, database passwords) and must not be committed" \
      "Add '.env' and '.env.*' (except .env.example) to .gitignore"
  fi

  # Private keys
  if ! _gitignore_has "*.pem" && ! _gitignore_has "*.key"; then
    # Only flag if there are key/pem files in the project
    if find "$project_dir" -maxdepth 3 -name "*.pem" -o -name "*.key" 2>/dev/null | grep -q .; then
      emit_finding "HIGH" "RV.1" "RV" "gitignore-missing-keys" \
        "$file" "0" "*.pem / *.key not in .gitignore" \
        "Private key files (.pem, .key) found in project but not excluded from git" \
        "Add '*.pem' and '*.key' to .gitignore. Store keys in a secure vault, not in the repo"
    fi
  fi

  # SSH keys
  if ! _gitignore_has "id_rsa" && ! _gitignore_has "id_ed25519"; then
    if find "$project_dir" -maxdepth 3 -name "id_rsa*" -o -name "id_ed25519*" 2>/dev/null | grep -q .; then
      emit_finding "HIGH" "RV.1" "RV" "gitignore-missing-ssh-keys" \
        "$file" "0" "SSH keys not in .gitignore" \
        "SSH private key files found in project but not excluded from git" \
        "Add 'id_rsa', 'id_ed25519', and '*.pub' to .gitignore. Never commit SSH keys"
    fi
  fi

  # === FRAMEWORK-SPECIFIC ENTRIES (check based on project structure) ===

  # Node.js projects
  if [[ -f "$project_dir/package.json" ]]; then
    if ! _gitignore_has "node_modules"; then
      emit_finding "HIGH" "PS.3" "PS" "gitignore-missing-node-modules" \
        "$file" "0" "node_modules not in .gitignore" \
        "node_modules/ contains thousands of dependency files and must not be committed" \
        "Add 'node_modules/' to .gitignore. Dependencies are installed from package.json/lock"
    fi
    if ! _gitignore_has ".npm"; then
      if [[ -d "$project_dir/.npm" ]]; then
        emit_finding "MEDIUM" "PS.3" "PS" "gitignore-missing-npm-cache" \
          "$file" "0" ".npm not in .gitignore" \
          ".npm/ cache directory should not be committed" \
          "Add '.npm' to .gitignore"
      fi
    fi
  fi

  # Python projects
  if [[ -f "$project_dir/requirements.txt" || -f "$project_dir/pyproject.toml" || -f "$project_dir/setup.py" || -f "$project_dir/Pipfile" ]]; then
    # Virtual environments
    local has_venv_ignore=false
    if _gitignore_has "venv" || _gitignore_has ".venv" || _gitignore_has "env/"; then
      has_venv_ignore=true
    fi
    if [[ "$has_venv_ignore" == false ]]; then
      if [[ -d "$project_dir/venv" || -d "$project_dir/.venv" || -d "$project_dir/env" ]]; then
        emit_finding "HIGH" "PS.3" "PS" "gitignore-missing-venv" \
          "$file" "0" "venv not in .gitignore" \
          "Python virtual environment directory found but not excluded from git" \
          "Add 'venv/', '.venv/', and 'env/' to .gitignore"
      fi
    fi

    # __pycache__
    if ! _gitignore_has "__pycache__" && ! _gitignore_has "*.pyc"; then
      emit_finding "MEDIUM" "PS.3" "PS" "gitignore-missing-pycache" \
        "$file" "0" "__pycache__ not in .gitignore" \
        "Python bytecode cache should not be committed — it's platform-specific and regenerated" \
        "Add '__pycache__/' and '*.pyc' to .gitignore"
    fi
  fi

  # Build output directories
  if [[ -d "$project_dir/dist" ]] && ! _gitignore_has "dist"; then
    emit_finding "MEDIUM" "PS.3" "PS" "gitignore-missing-dist" \
      "$file" "0" "dist/ not in .gitignore" \
      "Build output directory 'dist/' should typically not be committed" \
      "Add 'dist/' to .gitignore unless you intentionally distribute built artifacts via git"
  fi

  if [[ -d "$project_dir/build" ]] && ! _gitignore_has "build"; then
    emit_finding "MEDIUM" "PS.3" "PS" "gitignore-missing-build" \
      "$file" "0" "build/ not in .gitignore" \
      "Build output directory 'build/' should typically not be committed" \
      "Add 'build/' to .gitignore unless you intentionally distribute built artifacts via git"
  fi

  # Coverage and test output
  if ! _gitignore_has "coverage" && ! _gitignore_has ".coverage"; then
    if [[ -d "$project_dir/coverage" || -f "$project_dir/.coverage" ]]; then
      emit_finding "LOW" "PS.3" "PS" "gitignore-missing-coverage" \
        "$file" "0" "coverage not in .gitignore" \
        "Test coverage output should not be committed — it's regenerated on each test run" \
        "Add 'coverage/', '.coverage', and '.nyc_output/' to .gitignore"
    fi
  fi

  # Streamlit secrets
  if [[ -d "$project_dir/.streamlit" ]] || grep -rql 'import streamlit\|from streamlit' "$project_dir"/*.py 2>/dev/null; then
    if ! _gitignore_has "secrets.toml" && ! _gitignore_has ".streamlit/secrets"; then
      emit_finding "HIGH" "RV.1" "RV" "gitignore-missing-streamlit-secrets" \
        "$file" "0" ".streamlit/secrets.toml not in .gitignore" \
        "Streamlit secrets.toml contains sensitive configuration (API keys, DB credentials) and must not be committed" \
        "Add '.streamlit/secrets.toml' to .gitignore. Use environment variables for production"
    fi
  fi

  # IDE/editor directories
  local has_ide_ignore=false
  if _gitignore_has ".idea" || _gitignore_has ".vscode" || _gitignore_has "*.swp" || _gitignore_has ".DS_Store"; then
    has_ide_ignore=true
  fi
  if [[ "$has_ide_ignore" == false ]]; then
    if [[ -d "$project_dir/.idea" || -d "$project_dir/.vscode" ]]; then
      emit_finding "LOW" "PS.2" "PS" "gitignore-missing-ide" \
        "$file" "0" "IDE config not in .gitignore" \
        "IDE configuration directories (.idea/, .vscode/) may contain personal settings or secrets" \
        "Add '.idea/', '.vscode/', '.DS_Store', and '*.swp' to .gitignore"
    fi
  fi

  # OS-specific files
  if ! _gitignore_has ".DS_Store" && ! _gitignore_has "Thumbs.db"; then
    emit_finding "LOW" "PS.2" "PS" "gitignore-missing-os-files" \
      "$file" "0" "OS files not in .gitignore" \
      ".DS_Store and Thumbs.db are OS-specific metadata files that clutter the repository" \
      "Add '.DS_Store' and 'Thumbs.db' to .gitignore"
  fi

  # Docker environment secrets
  if [[ -f "$project_dir/docker-compose.yml" || -f "$project_dir/docker-compose.yaml" || -f "$project_dir/Dockerfile" ]]; then
    if ! _gitignore_has ".docker" && ! _gitignore_has "docker-compose.override"; then
      emit_finding "LOW" "RV.1" "RV" "gitignore-missing-docker-override" \
        "$file" "0" "docker-compose.override not in .gitignore" \
        "docker-compose.override.yml often contains local secrets and environment-specific config" \
        "Add 'docker-compose.override.yml' to .gitignore"
    fi
  fi

  return 0
}
