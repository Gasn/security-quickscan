# Repo Security Quick Scan

A reusable local security check for repositories before opening a PR or preparing a production deployment.

It is designed for AI/Replit-built or fast-moving repos where you want a repeatable local check before changes go to GitHub.

## What it runs

1. Git/repo sanity checks
2. Gitleaks secrets scan
3. Node/pnpm install, typecheck, lint, test, build, and audit where scripts exist
4. Semgrep SAST
5. Trivy dependency/supply-chain scan
6. OSV-Scanner dependency scan
7. Checkov infrastructure/config scan
8. Optional OWASP ZAP baseline scan against a running staging URL
9. Manual/AI security review checklist

## Install the tools

Recommended macOS setup:

```bash
brew install gitleaks semgrep trivy checkov
brew install osv-scanner
```

Alternative installs:

```bash
pipx install semgrep
pipx install checkov
```

For ZAP dynamic scanning, install Docker.

## Usage

From any repo:

```bash
/path/to/security-quickscan.sh .
```

Or copy the script into your repo and run:

```bash
./security-quickscan.sh
```

Reports are written to:

```text
<scanner-repo>/security-reports/<target-repo-name>-<timestamp>/
```

That means you can run the scanner against several repos from one checkout and keep the results separate, for example:

```text
security-reports/client-app-20260604T031504Z/
security-reports/api-service-20260604T032211Z/
```

## Generate the dashboard

After a scan finishes, `security-quickscan.sh` automatically generates a single static HTML dashboard at:

```text
security-reports/<target-repo-name>-<timestamp>/security-dashboard.html
```

To skip dashboard generation, set:

```bash
GENERATE_DASHBOARD=false ./security-quickscan.sh
```

You can also generate or regenerate a dashboard manually. By default, the newest folder under `security-reports/` is used:

```bash
node /path/to/generate-security-dashboard.js
```

The dashboard is written to:

```text
security-reports/<target-repo-name>-<timestamp>/security-dashboard.html
```

You can also point at a specific run folder:

```bash
node /path/to/generate-security-dashboard.js security-reports/client-app-20260604T031504Z
```

Open `security-dashboard.html` directly in a browser. No server is required. The generated file contains its own CSS and JavaScript-free markup; it does not load remote CSS, fonts, scripts, CDNs, or images.

The finding status cells and reviewer notes section are editable in the browser for local triage and print/PDF workflows.

## Strict mode

Strict mode exits with non-zero status if required local reliability checks fail.

```bash
STRICT=true ./security-quickscan.sh
```

## Custom report directory

```bash
REPORT_ROOT=.security-reports ./security-quickscan.sh
```

`REPORT_DIR` is still accepted as a legacy alias for the report root.

## Run OWASP ZAP baseline scan

Only run this against local/staging apps you own.

```bash
RUN_ZAP=true ZAP_TARGET=https://staging.example.com ./security-quickscan.sh
```

The ZAP HTML report is written inside the current run folder:

```text
security-reports/<target-repo-name>-<timestamp>/zap-report.html
```

Do not run active scans against production without explicit written approval.

## Recommended workflow

Use this locally before PR:

```bash
./security-quickscan.sh
```

Then attach or review:

```text
security-reports/<target-repo-name>-<timestamp>/summary.md
security-reports/<target-repo-name>-<timestamp>/manual-review-checklist.md
security-reports/<target-repo-name>-<timestamp>/security-dashboard.html
```

This does not replace formal security review. It is a repeatable first-pass scan.

## Expected report files

The dashboard parses whatever exists and marks missing tools as `Not run`.

```text
security-reports/<run>/gitleaks-git.json
security-reports/<run>/gitleaks-dir.json
security-reports/<run>/semgrep.json
security-reports/<run>/semgrep.sarif
security-reports/<run>/trivy.json
security-reports/<run>/osv.json
security-reports/<run>/checkov.json
security-reports/<run>/zap-report.json
security-reports/<run>/zap-report.html
security-reports/<run>/pnpm-audit.json
security-reports/<run>/npm-audit.json
security-reports/<run>/build.log
security-reports/<run>/typecheck.log
security-reports/<run>/test.log
security-reports/<run>/build.status
security-reports/<run>/typecheck.status
security-reports/<run>/test.status
security-reports/<run>/ai-review.md
```

The scanner also writes supporting `.txt` command logs and `summary.md`. For compatibility with older runs, the dashboard also understands existing files such as `semgrep-auto.json`, `semgrep-owasp.json`, `pnpm-build.txt`, `pnpm-typecheck.txt`, and `pnpm-test.txt`.

Status files contain one of:

```text
pass
fail
not-run
```

## Dashboard logic

Severity is normalized to:

```text
critical
high
medium
low
info
unknown
```

Tool mappings:

- Gitleaks JSON array findings count as secrets and are treated as critical unless explicitly marked false positive.
- Semgrep JSON or SARIF uses available severity metadata. `ERROR` maps to high, `WARNING` to medium, and `INFO` to low.
- Trivy uses `Results[].Vulnerabilities[].Severity` and includes package, installed version, fixed version, vulnerability ID, and title where available.
- OSV-Scanner parses known `results[].packages[].vulnerabilities[]` output and includes package, ecosystem, vulnerability IDs, and summaries where available.
- Checkov parses `failed_checks`; missing severity defaults to medium.
- ZAP parses JSON alerts when available. If only `zap-report.html` exists, ZAP is marked complete with `HTML only; detailed parsing unavailable`.
- Build, typecheck, and test prefer `.status` files. If status files are missing, logs are scanned for obvious failure markers.
- `ai-review.md` marks AI/manual review complete. `GO: yes` is pass, `GO: no` is fail, and `GO: conditional` is warning.

Go/no-go recommendation:

- `Fail / No-go` if any verified or untriaged secret is found, any critical finding exists, build fails, typecheck fails, or AI/manual review says `GO: no`.
- `Warning / Conditional go` if high findings exist, tests are missing or failed, scan outputs are incomplete, AI/manual review has not been completed, or AI/manual review says `GO: conditional`.
- `Pass / Go` if there are no critical/high findings, no secrets, build and typecheck pass, required scans completed, and AI/manual review is complete or explicitly not required.

## Add this to any repo

Copy or reference both scripts:

```bash
cp /path/to/repo-security-quickscan/security-quickscan.sh .
cp /path/to/repo-security-quickscan/generate-security-dashboard.js .
chmod +x security-quickscan.sh generate-security-dashboard.js
```

Run locally:

```bash
./security-quickscan.sh .
node ./generate-security-dashboard.js
```

For a custom report root:

```bash
REPORT_ROOT=.security-reports ./security-quickscan.sh .
node ./generate-security-dashboard.js .security-reports/<run-folder>
```

## Local-only safety

- Reports are read from disk and the dashboard is written to disk.
- Nothing is uploaded or sent to a remote service by the dashboard generator.
- No full secret values are printed by the dashboard; suspected secret-like values are redacted defensively, and Gitleaks is run with `--redact`.
- Large raw logs are not embedded by default. The dashboard shows status and summaries, while logs remain separate files in the report folder.

## Notes

- If Gitleaks finds a real secret, rotate it. Deleting the file is not enough.
- Replit should not hold production secrets or connect directly to production databases by default.
- Automated tools do not reliably catch business-logic authorization problems, so manual/AI review is still required.
