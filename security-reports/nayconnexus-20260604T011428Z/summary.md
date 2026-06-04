# Repo Security Quick Scan Summary

- Version: 1.0.0
- Target repo name: nayconnexus
- Target path: /Users/sangluu/Projects/AI Agency/clients/nayconnexus
- Target git root: /Users/sangluu/Projects/AI Agency/clients/nayconnexus
- Report root: /Users/sangluu/Projects/AI Agency/repo-security-quickscan/security-reports
- Report directory: /Users/sangluu/Projects/AI Agency/repo-security-quickscan/security-reports/nayconnexus-20260604T011428Z
- Strict mode: false
- Generate dashboard: true
- Generated: 2026-06-04T01:14:28Z

## 1. Repository and environment
- PASS: Git repository detected
- PASS: package.json detected
- PASS: pnpm lockfile detected

## 2. Secrets scanning
- PASS: Gitleaks git history scan
- PASS: Gitleaks working tree scan

## 3. Node build and dependency checks
- SKIP: pnpm not installed
- SKIP: pnpm not installed
- SKIP: pnpm not installed
- SKIP: pnpm not installed

## 4. Static application security testing
- PASS: Semgrep auto rules
- PASS: Semgrep OWASP Top 10

## 5. Dependency and supply-chain scanning
- PASS: Trivy filesystem high critical
- WARN: OSV-Scanner recursive found issues or failed — see /Users/sangluu/Projects/AI Agency/repo-security-quickscan/security-reports/nayconnexus-20260604T011428Z/osv-scanner.txt

## 6. Infrastructure and workflow scanning
- WARN: Checkov project scan found issues or failed — see /Users/sangluu/Projects/AI Agency/repo-security-quickscan/security-reports/nayconnexus-20260604T011428Z/checkov.txt

## 7. Dynamic scan placeholder
- SKIP: ZAP not run: no target URL provided

## 8. Manual review reminders
- PASS: Manual review checklist written to /Users/sangluu/Projects/AI Agency/repo-security-quickscan/security-reports/nayconnexus-20260604T011428Z/manual-review-checklist.md

## 9. Dashboard generation
- PASS: Security dashboard written to /Users/sangluu/Projects/AI Agency/repo-security-quickscan/security-reports/nayconnexus-20260604T011428Z/security-dashboard.html

## Final counts

- Pass: 10
- Warn: 2
- Fail: 0
- Skip: 5

## Interpretation

- FAIL means a required local reliability check failed, usually install/typecheck/build or invalid setup.
- WARN means a security scanner found issues, the tool failed, or a non-blocking check needs review.
- SKIP means the relevant tool or project file was not present.

Review all reports in: /Users/sangluu/Projects/AI Agency/repo-security-quickscan/security-reports/nayconnexus-20260604T011428Z
