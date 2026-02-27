#!/usr/bin/env bash
#
# PostureIQ — Pre-flight Check
#
# Validates the project before commit/push by running a comprehensive suite
# of checks: tests, lint, Bicep validation, YAML syntax, Docker build, and
# git status review.
#
# Usage:
#   ./scripts/preflight.sh               # Run all checks
#   ./scripts/preflight.sh --quick       # Skip Docker build (faster)
#   ./scripts/preflight.sh --docker-only # Run only the Docker build check
#
# Exit codes:
#   0  All checks passed
#   1  One or more checks failed
#
# Prerequisites:
#   - Python venv activated (.venv)
#   - pytest, ruff installed
#   - az cli with bicep extension
#   - docker daemon running (unless --quick)

set -uo pipefail

# ── Configuration ──────────────────────────────────────────
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

BICEP_MAIN="infra/main.bicep"
PARAM_FILES=("infra/parameters/dev.bicepparam" "infra/parameters/prod.bicepparam")
WORKFLOW_DIR=".github/workflows"
DOCKER_IMAGE_TAG="postureiq:preflight"

# ── Colours & Formatting ──────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Colour

pass_count=0
fail_count=0
skip_count=0
results=()

pass_check()  { ((pass_count++)); results+=("${GREEN}✔${NC} $1"); }
fail_check()  { ((fail_count++)); results+=("${RED}✘${NC} $1"); }
skip_check()  { ((skip_count++)); results+=("${YELLOW}⊘${NC} $1 ${YELLOW}(skipped)${NC}"); }
info()        { echo -e "${CYAN}▸${NC} $1"; }
section()     { echo -e "\n${BOLD}── $1 ──${NC}"; }

# ── Parse Arguments ────────────────────────────────────────
QUICK=false
DOCKER_ONLY=false

for arg in "$@"; do
  case "$arg" in
    --quick)       QUICK=true ;;
    --docker-only) DOCKER_ONLY=true ;;
    --help|-h)
      head -20 "$0" | grep '^#' | sed 's/^# \?//'
      exit 0
      ;;
    *)
      echo "Unknown option: $arg"
      exit 1
      ;;
  esac
done

# ── 1. Python Tests ──────────────────────────────────────
run_tests() {
  section "Python Tests (pytest)"
  if ! command -v pytest &>/dev/null; then
    fail_check "pytest — not installed"
    return
  fi

  local output
  output=$(python -m pytest tests/ --tb=short -q 2>&1) || true
  local last_line
  last_line=$(echo "$output" | tail -1)

  if echo "$last_line" | grep -qE '^[0-9]+ passed'; then
    local count
    count=$(echo "$last_line" | grep -oP '^\d+ passed')
    pass_check "Tests — ${count}"
    info "$last_line"
  else
    fail_check "Tests — failures detected"
    echo "$output" | tail -20
  fi
}

# ── 2. Linting ────────────────────────────────────────────
run_lint() {
  section "Linting (ruff)"
  if ! command -v ruff &>/dev/null; then
    skip_check "Lint — ruff not installed"
    return
  fi

  # 2a. Format check (matches CI: ruff format --check)
  local fmt_output fmt_exit=0
  fmt_output=$(ruff format --check src/ tests/ 2>&1) || fmt_exit=$?

  if [[ $fmt_exit -eq 0 ]]; then
    pass_check "Format — all files formatted"
  else
    local reformat_count
    reformat_count=$(echo "$fmt_output" | grep -c 'Would reformat' || echo "0")
    fail_check "Format — ${reformat_count} file(s) need formatting"
    echo "$fmt_output"
    info "Run 'ruff format src/ tests/' to auto-fix"
  fi

  # 2b. Lint rules (E = pycodestyle errors, F = pyflakes, W = warnings)
  local output exit_code=0
  output=$(ruff check --select E,F,W --statistics src/ tests/ 2>&1) || exit_code=$?

  if [[ $exit_code -eq 0 ]]; then
    pass_check "Lint — clean (E/F/W rules)"
  else
    local err_count
    err_count=$(echo "$output" | grep -oP 'Found \K\d+' || echo "?")
    # Distinguish fatal syntax/runtime errors from style/fixable warnings
    local blocking_count=0
    blocking_count=$(ruff check --select E4,E7,E9,F6,F8 src/ tests/ 2>&1 | grep -oP 'Found \K\d+' || echo "0")
    if [[ "$blocking_count" -gt 0 ]] 2>/dev/null; then
      fail_check "Lint — ${err_count} issues (${blocking_count} blocking)"
      echo "$output"
    else
      pass_check "Lint — ${err_count} issues (style only, no blocking errors)"
      info "Run 'ruff check --select E,F,W src/ tests/' to see details"
    fi
  fi
}

# ── 3. Bicep Validation ──────────────────────────────────
run_bicep() {
  section "Bicep Validation"
  if ! command -v az &>/dev/null || ! az bicep version &>/dev/null; then
    skip_check "Bicep — az cli or bicep extension not available"
    return
  fi

  # Build (compile)
  local build_output build_exit=0
  build_output=$(az bicep build --file "$BICEP_MAIN" 2>&1) || build_exit=$?
  # Clean up generated ARM template
  rm -f "${BICEP_MAIN%.bicep}.json"

  if [[ $build_exit -eq 0 ]]; then
    pass_check "Bicep compile — ${BICEP_MAIN}"
  else
    fail_check "Bicep compile — ${BICEP_MAIN}"
    echo "$build_output"
  fi

  # Lint
  local lint_output lint_exit=0
  lint_output=$(az bicep lint --file "$BICEP_MAIN" 2>&1) || lint_exit=$?

  if [[ $lint_exit -eq 0 ]]; then
    pass_check "Bicep lint — clean"
  else
    fail_check "Bicep lint — issues found"
    echo "$lint_output"
  fi

  # Parameter files
  for param_file in "${PARAM_FILES[@]}"; do
    if [[ -f "$param_file" ]]; then
      local param_output param_exit=0
      param_output=$(az bicep build-params --file "$param_file" 2>&1) || param_exit=$?
      if [[ $param_exit -eq 0 ]]; then
        pass_check "Bicep params — $(basename "$param_file")"
      else
        fail_check "Bicep params — $(basename "$param_file")"
        echo "$param_output"
      fi
    fi
  done
}

# ── 4. YAML Workflow Validation ───────────────────────────
run_yaml() {
  section "YAML Workflow Validation"
  if [[ ! -d "$WORKFLOW_DIR" ]]; then
    skip_check "YAML — no ${WORKFLOW_DIR} directory"
    return
  fi

  local yaml_files
  yaml_files=$(find "$WORKFLOW_DIR" -name '*.yml' -o -name '*.yaml' 2>/dev/null)

  if [[ -z "$yaml_files" ]]; then
    skip_check "YAML — no workflow files found"
    return
  fi

  local all_valid=true
  while IFS= read -r f; do
    local result
    result=$(python3 -c "
import yaml, sys
try:
    with open('$f') as fh:
        yaml.safe_load(fh)
    print('ok')
except Exception as e:
    print(f'error: {e}')
" 2>&1)
    if [[ "$result" == "ok" ]]; then
      pass_check "YAML — $(basename "$f")"
    else
      fail_check "YAML — $(basename "$f"): $result"
      all_valid=false
    fi
  done <<< "$yaml_files"
}

# ── 5. Docker Build ──────────────────────────────────────
run_docker() {
  section "Docker Build"
  if ! command -v docker &>/dev/null; then
    skip_check "Docker — not installed"
    return
  fi

  if ! docker info &>/dev/null 2>&1; then
    skip_check "Docker — daemon not running"
    return
  fi

  info "Building ${DOCKER_IMAGE_TAG} (this may take a few minutes)..."
  local build_output build_exit=0
  build_output=$(docker build --no-cache -t "$DOCKER_IMAGE_TAG" . 2>&1) || build_exit=$?

  if [[ $build_exit -eq 0 ]]; then
    pass_check "Docker build — image created"

    # Quick container smoke test
    info "Running container health check..."
    local container_id
    container_id=$(docker run --rm -d \
      -p 8199:8000 \
      -e AZURE_OPENAI_ENDPOINT=https://preflight-check \
      -e AZURE_OPENAI_DEPLOYMENT=gpt-4o \
      -e GITHUB_TOKEN=preflight \
      "$DOCKER_IMAGE_TAG" 2>&1)

    sleep 4
    local health
    health=$(curl -sf http://localhost:8199/health 2>/dev/null) || true

    if echo "$health" | grep -q '"healthy"'; then
      pass_check "Docker health — container responds healthy"
    else
      fail_check "Docker health — container did not respond healthy"
    fi

    docker stop "$container_id" &>/dev/null 2>&1 || true
  else
    fail_check "Docker build — failed (exit code ${build_exit})"
    echo "$build_output" | tail -30
  fi
}

# ── 6. Git Status ─────────────────────────────────────────
run_git_status() {
  section "Git Status"
  if ! command -v git &>/dev/null; then
    skip_check "Git — not installed"
    return
  fi

  local modified new_files
  modified=$(git diff --name-only 2>/dev/null | wc -l)
  new_files=$(git ls-files --others --exclude-standard 2>/dev/null | wc -l)
  local staged
  staged=$(git diff --cached --name-only 2>/dev/null | wc -l)

  info "Modified: ${modified} | Untracked: ${new_files} | Staged: ${staged}"

  if [[ $modified -gt 0 || $new_files -gt 0 ]]; then
    echo ""
    git status --short 2>/dev/null
  fi

  # Not a pass/fail — just informational
  pass_check "Git status — ${modified} modified, ${new_files} untracked, ${staged} staged"
}

# ── Run Checks ────────────────────────────────────────────
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║       PostureIQ — Pre-flight Check              ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"

if [[ "$DOCKER_ONLY" == true ]]; then
  run_docker
else
  run_tests
  run_lint
  run_bicep
  run_yaml
  if [[ "$QUICK" != true ]]; then
    run_docker
  else
    skip_check "Docker build — skipped (--quick mode)"
  fi
  run_git_status
fi

# ── Summary ───────────────────────────────────────────────
section "Summary"
for r in "${results[@]}"; do
  echo -e "  $r"
done

echo ""
if [[ $fail_count -gt 0 ]]; then
  echo -e "${RED}${BOLD}✘ FAILED${NC} — ${fail_count} check(s) failed, ${pass_count} passed, ${skip_count} skipped"
  exit 1
else
  echo -e "${GREEN}${BOLD}✔ ALL CHECKS PASSED${NC} — ${pass_count} passed, ${skip_count} skipped"
  echo -e "${CYAN}Ready to commit and push.${NC}"
  exit 0
fi
