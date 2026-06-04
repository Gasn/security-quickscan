#!/usr/bin/env bash
set -u

# repo-security-quickscan
# Reusable local security check for Node/pnpm, JS/TS, Python, and general repos.
# It is intentionally conservative: it runs common local checks and saves reports
# without requiring paid services or production credentials.

VERSION="1.0.0"
TARGET_DIR="."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPORT_ROOT="${REPORT_ROOT:-${REPORT_DIR:-$SCRIPT_DIR/security-reports}}"
case "$REPORT_ROOT" in
  /*) ;;
  *) REPORT_ROOT="$SCRIPT_DIR/$REPORT_ROOT" ;;
esac
STRICT="${STRICT:-false}"
RUN_ZAP="${RUN_ZAP:-false}"
ZAP_TARGET="${ZAP_TARGET:-}"
GENERATE_DASHBOARD="${GENERATE_DASHBOARD:-true}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --zap-target)
      if [ "$#" -lt 2 ]; then
        echo "ERROR: --zap-target requires a URL" >&2
        exit 2
      fi
      ZAP_TARGET="$2"
      RUN_ZAP="true"
      shift 2
      ;;
    --zap-target=*)
      ZAP_TARGET="${1#--zap-target=}"
      RUN_ZAP="true"
      shift
      ;;
    --)
      shift
      if [ "$#" -gt 0 ]; then
        TARGET_DIR="$1"
        shift
      fi
      ;;
    -*)
      echo "ERROR: unknown option: $1" >&2
      exit 2
      ;;
    *)
      TARGET_DIR="$1"
      shift
      ;;
  esac
done

if [ -n "$ZAP_TARGET" ]; then
  RUN_ZAP="true"
fi

if [ ! -d "$TARGET_DIR" ]; then
  echo "ERROR: target directory does not exist: $TARGET_DIR" >&2
  exit 2
fi

TARGET_ABS="$(cd "$TARGET_DIR" && pwd -P)" || exit 2
cd "$TARGET_ABS" || exit 2

if [ -d .git ] && command -v git >/dev/null 2>&1; then
  TARGET_REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd -P)"
else
  TARGET_REPO_ROOT="$(pwd -P)"
fi

TARGET_REPO_NAME="$(basename "$TARGET_REPO_ROOT")"
SAFE_TARGET_REPO_NAME="$(printf '%s' "$TARGET_REPO_NAME" | tr -c '[:alnum:]._-' '-')"
RUN_ID="$(date -u '+%Y%m%dT%H%M%SZ')"
REPORT_DIR="$REPORT_ROOT/$SAFE_TARGET_REPO_NAME-$RUN_ID"
mkdir -p "$REPORT_DIR"

SUMMARY="$REPORT_DIR/summary.md"
: > "$SUMMARY"

pass_count=0
warn_count=0
fail_count=0
skip_count=0

log_summary() {
  printf '%s\n' "$1" >> "$SUMMARY"
}

section() {
  echo ""
  echo "==> $1"
  log_summary ""
  log_summary "## $1"
}

mark_pass() {
  pass_count=$((pass_count + 1))
  echo "PASS: $1"
  log_summary "- PASS: $1"
}

mark_warn() {
  warn_count=$((warn_count + 1))
  echo "WARN: $1"
  log_summary "- WARN: $1"
}

mark_fail() {
  fail_count=$((fail_count + 1))
  echo "FAIL: $1"
  log_summary "- FAIL: $1"
}

mark_skip() {
  skip_count=$((skip_count + 1))
  echo "SKIP: $1"
  log_summary "- SKIP: $1"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

write_check_status() {
  local status_name="$1"
  local status="$2"
  local reason="$3"
  local log_file="$REPORT_DIR/$status_name.log"

  printf '%s\n' "$status" > "$REPORT_DIR/$status_name.status"
  printf '%s\n' "$reason" > "$REPORT_DIR/$status_name.reason"
  if [ ! -f "$log_file" ]; then
    printf '%s\n' "$reason" > "$log_file"
  fi
}

skip_check() {
  local status_name="$1"
  local reason="$2"

  write_check_status "$status_name" "not-run" "$reason"
  printf '%s\n' "$reason" > "$REPORT_DIR/$status_name.log"
  mark_skip "$reason"
}

run_cmd() {
  local name="$1"
  local outfile="$2"
  shift 2

  echo "Running: $name"
  echo "+ $*" > "$outfile"
  if "$@" >> "$outfile" 2>&1; then
    mark_pass "$name"
    return 0
  else
    mark_fail "$name — see $outfile"
    return 1
  fi
}

run_cmd_warn() {
  local name="$1"
  local outfile="$2"
  shift 2

  echo "Running: $name"
  echo "+ $*" > "$outfile"
  if "$@" >> "$outfile" 2>&1; then
    mark_pass "$name"
    return 0
  else
    mark_warn "$name found issues or failed — see $outfile"
    return 0
  fi
}

run_status_cmd() {
  local status_name="$1"
  local name="$2"
  local outfile="$3"
  shift 3

  echo "Running: $name"
  echo "+ $*" > "$outfile"
  if "$@" >> "$outfile" 2>&1; then
    write_check_status "$status_name" "pass" "Script completed successfully"
    mark_pass "$name"
    return 0
  else
    write_check_status "$status_name" "fail" "Script found but command exited non-zero"
    mark_fail "$name — see $outfile"
    return 1
  fi
}

run_status_cmd_warn() {
  local status_name="$1"
  local name="$2"
  local outfile="$3"
  shift 3

  echo "Running: $name"
  echo "+ $*" > "$outfile"
  if "$@" >> "$outfile" 2>&1; then
    write_check_status "$status_name" "pass" "Script completed successfully"
    mark_pass "$name"
    return 0
  else
    write_check_status "$status_name" "fail" "Script found but command exited non-zero"
    mark_warn "$name found issues or failed — see $outfile"
    return 0
  fi
}

run_audit_status() {
  local package_manager="$1"

  if [ "$package_manager" = "pnpm" ]; then
    echo "Running: pnpm audit high critical"
    echo "+ pnpm audit --audit-level high --json" > "$REPORT_DIR/audit.log"
    if pnpm audit --audit-level high --json > "$REPORT_DIR/pnpm-audit.json" 2>> "$REPORT_DIR/audit.log"; then
      write_check_status "audit" "pass" "Package manager audit completed successfully"
      mark_pass "pnpm audit high critical"
    else
      write_check_status "audit" "fail" "Package manager audit exited non-zero"
      mark_warn "pnpm audit found issues or failed — see $REPORT_DIR/audit.log"
    fi
  elif [ "$package_manager" = "npm" ]; then
    echo "Running: npm audit high"
    echo "+ npm audit --audit-level high --json" > "$REPORT_DIR/audit.log"
    if npm audit --audit-level high --json > "$REPORT_DIR/npm-audit.json" 2>> "$REPORT_DIR/audit.log"; then
      write_check_status "audit" "pass" "Package manager audit completed successfully"
      mark_pass "npm audit high"
    else
      write_check_status "audit" "fail" "Package manager audit exited non-zero"
      mark_warn "npm audit found issues or failed — see $REPORT_DIR/audit.log"
    fi
  fi
}

package_script_exists() {
  local script_name="$1"

  if ! have node; then
    return 1
  fi

  SCRIPT_NAME="$script_name" node <<'NODE'
const fs = require('fs');
const path = require('path');

const scriptName = process.env.SCRIPT_NAME;
const seen = new Set();

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function hasMagic(pattern) {
  return /[*?[\]{}]/.test(pattern);
}

function walkForPackageJson(dir, maxDepth = 6) {
  const out = [];
  function walk(current, depth) {
    if (depth > maxDepth) return;
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (['node_modules', '.git', 'security-reports'].includes(entry.name)) continue;
      const full = path.join(current, entry.name);
      const pkg = path.join(full, 'package.json');
      if (fs.existsSync(pkg)) out.push(pkg);
      walk(full, depth + 1);
    }
  }
  walk(dir, 0);
  return out;
}

function expandWorkspacePattern(pattern) {
  const normalized = pattern.replace(/\/package\.json$/, '').replace(/\/$/, '');
  const parts = normalized.split('/').filter(Boolean);
  const out = [];
  function expand(base, index) {
    if (index >= parts.length) {
      const pkg = path.join(base, 'package.json');
      if (fs.existsSync(pkg)) out.push(pkg);
      return;
    }
    const part = parts[index];
    if (part === '**') {
      for (const pkg of walkForPackageJson(base)) out.push(pkg);
      return;
    }
    if (hasMagic(part)) {
      let entries = [];
      try {
        entries = fs.readdirSync(base, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        if (entry.isDirectory() && part === '*') expand(path.join(base, entry.name), index + 1);
      }
      return;
    }
    expand(path.join(base, part), index + 1);
  }
  expand(process.cwd(), 0);
  return out;
}

const rootPackage = path.join(process.cwd(), 'package.json');
const root = readJson(rootPackage);
if (root) seen.add(rootPackage);

let workspacePatterns = [];
if (Array.isArray(root?.workspaces)) {
  workspacePatterns = root.workspaces;
} else if (Array.isArray(root?.workspaces?.packages)) {
  workspacePatterns = root.workspaces.packages;
}

const yamlText = fs.existsSync(path.join(process.cwd(), 'pnpm-workspace.yaml'))
  ? fs.readFileSync(path.join(process.cwd(), 'pnpm-workspace.yaml'), 'utf8')
  : '';
if (yamlText) {
  for (const line of yamlText.split(/\r?\n/)) {
    const match = line.match(/^\s*-\s*['"]?([^'"]+)['"]?\s*$/);
    if (match) workspacePatterns.push(match[1]);
  }
}

for (const pattern of workspacePatterns) {
  for (const pkg of expandWorkspacePattern(pattern)) seen.add(pkg);
}

for (const file of seen) {
  const pkg = readJson(file);
  if (pkg?.scripts && Object.prototype.hasOwnProperty.call(pkg.scripts, scriptName)) {
    process.exit(0);
  }
}
process.exit(1);
NODE
}

run_package_script_check() {
  local package_manager="$1"
  local status_name="$2"
  local script_name="$3"
  local warn_only="${4:-false}"

  if ! package_script_exists "$script_name"; then
    skip_check "$status_name" "No $script_name script found in package.json"
    return 0
  fi

  if [ "$package_manager" = "pnpm" ]; then
    if [ -f pnpm-workspace.yaml ]; then
      if [ "$warn_only" = "true" ]; then
        run_status_cmd_warn "$status_name" "pnpm recursive $script_name" "$REPORT_DIR/$status_name.log" pnpm -r --if-present --include-workspace-root run "$script_name"
      else
        run_status_cmd "$status_name" "pnpm recursive $script_name" "$REPORT_DIR/$status_name.log" pnpm -r --if-present --include-workspace-root run "$script_name"
      fi
    elif [ "$warn_only" = "true" ]; then
      run_status_cmd_warn "$status_name" "pnpm $script_name" "$REPORT_DIR/$status_name.log" pnpm run "$script_name"
    else
      run_status_cmd "$status_name" "pnpm $script_name" "$REPORT_DIR/$status_name.log" pnpm run "$script_name"
    fi
  elif [ "$package_manager" = "npm" ]; then
    if package_script_exists "$script_name" && node -e "const p=require('./package.json'); process.exit(p.workspaces ? 0 : 1)" 2>/dev/null; then
      if [ "$warn_only" = "true" ]; then
        run_status_cmd_warn "$status_name" "npm workspace $script_name" "$REPORT_DIR/$status_name.log" npm run "$script_name" --workspaces --if-present --include-workspace-root
      else
        run_status_cmd "$status_name" "npm workspace $script_name" "$REPORT_DIR/$status_name.log" npm run "$script_name" --workspaces --if-present --include-workspace-root
      fi
    elif [ "$warn_only" = "true" ]; then
      run_status_cmd_warn "$status_name" "npm $script_name" "$REPORT_DIR/$status_name.log" npm run "$script_name"
    else
      run_status_cmd "$status_name" "npm $script_name" "$REPORT_DIR/$status_name.log" npm run "$script_name"
    fi
  fi
}

for check_name in build typecheck test audit; do
  write_check_status "$check_name" "not-run" "Skipped because this is a scanner-only run"
done

log_summary "# Repo Security Quick Scan Summary"
log_summary ""
log_summary "- Version: $VERSION"
log_summary "- Target repo name: $TARGET_REPO_NAME"
log_summary "- Target path: $TARGET_ABS"
log_summary "- Target git root: $TARGET_REPO_ROOT"
log_summary "- Report root: $REPORT_ROOT"
log_summary "- Report directory: $REPORT_DIR"
log_summary "- Strict mode: $STRICT"
log_summary "- Generate dashboard: $GENERATE_DASHBOARD"
log_summary "- Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

section "1. Repository and environment"
if [ -d .git ]; then
  mark_pass "Git repository detected"
  git rev-parse --show-toplevel > "$REPORT_DIR/git-root.txt" 2>&1 || true
  git status --short > "$REPORT_DIR/git-status.txt" 2>&1 || true
else
  mark_warn "No .git directory detected; git history secret scan will be skipped"
fi

if [ -f package.json ]; then
  mark_pass "package.json detected"
else
  mark_skip "No package.json detected"
fi

if [ -f pnpm-lock.yaml ]; then
  mark_pass "pnpm lockfile detected"
elif [ -f package-lock.json ]; then
  mark_warn "npm lockfile detected; script currently prefers pnpm checks"
elif [ -f yarn.lock ]; then
  mark_warn "yarn lockfile detected; script currently prefers pnpm checks"
fi

section "2. Secrets scanning"
if have gitleaks; then
  if [ -d .git ]; then
    run_cmd_warn "Gitleaks git history scan" "$REPORT_DIR/gitleaks-git.txt" \
      gitleaks git . --redact --report-format json --report-path "$REPORT_DIR/gitleaks-git.json"
  fi
  run_cmd_warn "Gitleaks working tree scan" "$REPORT_DIR/gitleaks-dir.txt" \
    gitleaks dir . --redact --report-format json --report-path "$REPORT_DIR/gitleaks-dir.json"
else
  mark_skip "gitleaks not installed"
fi

section "3. Node build and dependency checks"
if [ -f package.json ]; then
  if have pnpm && [ -f pnpm-lock.yaml ]; then
    if run_cmd "pnpm install frozen lockfile" "$REPORT_DIR/pnpm-install.txt" pnpm install --frozen-lockfile; then
      run_package_script_check "pnpm" "typecheck" "typecheck"

      if package_script_exists "lint"; then
        if [ -f pnpm-workspace.yaml ]; then
          run_cmd_warn "pnpm recursive lint" "$REPORT_DIR/pnpm-lint.txt" pnpm -r --if-present run lint
        else
          run_cmd_warn "pnpm lint" "$REPORT_DIR/pnpm-lint.txt" pnpm run lint
        fi
      else
        mark_skip "No lint script found in package.json"
      fi

      run_package_script_check "pnpm" "test" "test" "true"
      run_package_script_check "pnpm" "build" "build"
      run_audit_status "pnpm"
    else
      skip_check "typecheck" "Skipped because install failed"
      skip_check "test" "Skipped because install failed"
      skip_check "build" "Skipped because install failed"
      skip_check "audit" "Skipped because install failed"
    fi
  elif have npm && [ -f package-lock.json ]; then
    if run_cmd "npm ci" "$REPORT_DIR/npm-ci.txt" npm ci; then
      run_audit_status "npm"
      run_package_script_check "npm" "typecheck" "typecheck"
      run_package_script_check "npm" "test" "test" "true"
      run_package_script_check "npm" "build" "build"
    else
      skip_check "typecheck" "Skipped because install failed"
      skip_check "test" "Skipped because install failed"
      skip_check "build" "Skipped because install failed"
      skip_check "audit" "Skipped because install failed"
    fi
  elif [ -f pnpm-lock.yaml ]; then
    skip_check "typecheck" "pnpm not installed"
    skip_check "test" "pnpm not installed"
    skip_check "build" "pnpm not installed"
    skip_check "audit" "pnpm not installed"
  elif [ -f package-lock.json ]; then
    skip_check "typecheck" "npm not installed"
    skip_check "test" "npm not installed"
    skip_check "build" "npm not installed"
    skip_check "audit" "npm not installed"
  else
    skip_check "typecheck" "No supported Node package manager lockfile found"
    skip_check "test" "No supported Node package manager lockfile found"
    skip_check "build" "No supported Node package manager lockfile found"
    skip_check "audit" "No supported Node package manager lockfile found"
  fi
else
  skip_check "typecheck" "No package.json found"
  skip_check "test" "No package.json found"
  skip_check "build" "No package.json found"
  skip_check "audit" "No package.json found"
fi


section "4. Static application security testing"
if have semgrep; then
  run_cmd_warn "Semgrep auto rules" "$REPORT_DIR/semgrep.txt" \
    semgrep scan --config auto --json -o "$REPORT_DIR/semgrep.json" .
  run_cmd_warn "Semgrep OWASP Top 10" "$REPORT_DIR/semgrep-owasp.txt" \
    semgrep scan --config p/owasp-top-ten --json -o "$REPORT_DIR/semgrep-owasp.json" .
else
  mark_skip "semgrep not installed"
fi

section "5. Dependency and supply-chain scanning"
if have trivy; then
  run_cmd_warn "Trivy filesystem high critical" "$REPORT_DIR/trivy.txt" \
    trivy fs --severity HIGH,CRITICAL --format json --output "$REPORT_DIR/trivy.json" .
else
  mark_skip "trivy not installed"
fi

if have osv-scanner; then
  run_cmd_warn "OSV-Scanner recursive" "$REPORT_DIR/osv-scanner.txt" \
    sh -c "osv-scanner scan -r . --format json > '$REPORT_DIR/osv.json'"
else
  mark_skip "osv-scanner not installed"
fi

section "6. Infrastructure and workflow scanning"
if have checkov; then
  run_cmd_warn "Checkov project scan" "$REPORT_DIR/checkov.txt" \
    sh -c "checkov -d . -o json > '$REPORT_DIR/checkov.json'"
else
  mark_skip "checkov not installed"
fi

section "7. Dynamic scan placeholder"
if [ "$RUN_ZAP" = "true" ]; then
  if [ -z "$ZAP_TARGET" ]; then
    printf '%s\n' "not-run" > "$REPORT_DIR/zap.status"
    printf '%s\n' "no target URL provided" > "$REPORT_DIR/zap.reason"
    mark_skip "ZAP not run: no target URL provided"
  elif have docker; then
    run_cmd_warn "OWASP ZAP baseline scan" "$REPORT_DIR/zap-baseline.txt" \
      docker run -v "$REPORT_DIR:/zap/wrk/:rw" -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
      -t "$ZAP_TARGET" -r zap-report.html -J zap-report.json
    if [ -f "$REPORT_DIR/zap-report.html" ]; then
      printf '%s\n' "pass" > "$REPORT_DIR/zap.status"
      printf '%s\n' "ZAP baseline scan completed" > "$REPORT_DIR/zap.reason"
      mark_pass "OWASP ZAP HTML report written to $REPORT_DIR/zap-report.html"
    else
      printf '%s\n' "fail" > "$REPORT_DIR/zap.status"
      printf '%s\n' "ZAP command completed without creating zap-report.html" > "$REPORT_DIR/zap.reason"
      mark_warn "OWASP ZAP HTML report was not created; see $REPORT_DIR/zap-baseline.txt"
    fi
  else
    printf '%s\n' "not-run" > "$REPORT_DIR/zap.status"
    printf '%s\n' "docker not installed; cannot run ZAP" > "$REPORT_DIR/zap.reason"
    mark_skip "docker not installed; cannot run ZAP"
  fi
else
  printf '%s\n' "not-run" > "$REPORT_DIR/zap.status"
  printf '%s\n' "no target URL provided" > "$REPORT_DIR/zap.reason"
  mark_skip "ZAP not run: no target URL provided"
fi

section "8. Manual review reminders"
cat > "$REPORT_DIR/manual-review-checklist.md" <<'CHECKLIST'
# Manual / AI-assisted security review checklist

Use this after the automated quick scan, especially for AI/Replit-generated code.

## Authentication and authorization
- Are all non-public API routes authenticated?
- Are role checks enforced on the backend, not only in the frontend?
- Can a user access another user, client, project, matter, invoice, file, or tenant record?

## Sensitive data
- Are API responses shaped to least privilege?
- Are legal, financial, staff, payroll, tax, bank, or client fields redacted unless needed?
- Are sensitive fields encrypted or otherwise protected where appropriate?
- Are sensitive values excluded from logs?

## Public and token routes
- Are public token links short-lived, single-use where appropriate, and rate-limited?
- Do public routes expose only the minimum required data?

## File handling
- Are upload size, file type, extension, and ownership checks enforced?
- Are downloads scoped to the correct user/client/project/matter?
- Is there a malware scanning or quarantine plan for production?

## Database and migrations
- Are schema changes in reviewed migrations?
- Does any startup code seed or mutate production data?
- Is there a backup/rollback or forward-fix plan?

## Integrations and secrets
- Are OAuth tokens encrypted or stored securely?
- Are webhooks verified?
- Are production secrets kept out of Replit and source control?

## Replit-to-production safety
- Can Replit deploy directly to production? It should not.
- Can Replit connect to production DB/storage? Usually it should not.
- Do all changes go through PR review and CI gates?
CHECKLIST
mark_pass "Manual review checklist written to $REPORT_DIR/manual-review-checklist.md"

section "9. Dashboard generation"
if [ "$GENERATE_DASHBOARD" = "true" ]; then
  if ! have node; then
    mark_skip "Dashboard not generated; node not installed"
  elif [ ! -f "$SCRIPT_DIR/generate-security-dashboard.js" ]; then
    mark_skip "Dashboard not generated; generate-security-dashboard.js not found"
  else
    echo "Running: security dashboard generator"
    if node "$SCRIPT_DIR/generate-security-dashboard.js" "$REPORT_DIR" > "$REPORT_DIR/dashboard-generator.log" 2>&1; then
      mark_pass "Security dashboard written to $REPORT_DIR/security-dashboard.html"
    else
      mark_warn "Security dashboard generation failed — see $REPORT_DIR/dashboard-generator.log"
    fi
  fi
else
  mark_skip "Dashboard generation disabled with GENERATE_DASHBOARD=false"
fi

cat <<EOF_SUMMARY >> "$SUMMARY"

## Final counts

- Pass: $pass_count
- Warn: $warn_count
- Fail: $fail_count
- Skip: $skip_count

## Interpretation

- FAIL means a required local reliability check failed, usually install/typecheck/build or invalid setup.
- WARN means a security scanner found issues, the tool failed, or a non-blocking check needs review.
- SKIP means the relevant tool or project file was not present.

Review all reports in: $REPORT_DIR
EOF_SUMMARY

echo ""
echo "Quick scan finished. Summary: $SUMMARY"
echo "Pass: $pass_count | Warn: $warn_count | Fail: $fail_count | Skip: $skip_count"

if [ "$STRICT" = "true" ] && [ "$fail_count" -gt 0 ]; then
  exit 1
fi

exit 0
