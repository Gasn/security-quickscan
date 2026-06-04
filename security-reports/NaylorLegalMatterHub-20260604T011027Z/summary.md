# Repo Security Quick Scan Summary

- Version: 1.0.0
- Target repo name: NaylorLegalMatterHub
- Target path: /Users/sangluu/Projects/AI Agency/clients/NaylorLegalMatterHub
- Target git root: /Users/sangluu/Projects/AI Agency/clients/NaylorLegalMatterHub
- Report root: /Users/sangluu/Projects/AI Agency/repo-security-quickscan/security-reports
- Report directory: /Users/sangluu/Projects/AI Agency/repo-security-quickscan/security-reports/NaylorLegalMatterHub-20260604T011027Z
- Strict mode: false
- Generated: 2026-06-04T01:10:27Z

## 1. Repository and environment
- PASS: Git repository detected
- PASS: package.json detected
- PASS: pnpm lockfile detected

## 2. Secrets scanning
- WARN: Gitleaks git history scan found issues or failed — see /Users/sangluu/Projects/AI Agency/repo-security-quickscan/security-reports/NaylorLegalMatterHub-20260604T011027Z/gitleaks-git.txt
- WARN: Gitleaks working tree scan found issues or failed — see /Users/sangluu/Projects/AI Agency/repo-security-quickscan/security-reports/NaylorLegalMatterHub-20260604T011027Z/gitleaks-dir.txt

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
- WARN: OSV-Scanner recursive found issues or failed — see /Users/sangluu/Projects/AI Agency/repo-security-quickscan/security-reports/NaylorLegalMatterHub-20260604T011027Z/osv-scanner.txt

## 6. Infrastructure and workflow scanning
- WARN: Checkov project scan found issues or failed — see /Users/sangluu/Projects/AI Agency/repo-security-quickscan/security-reports/NaylorLegalMatterHub-20260604T011027Z/checkov.txt

## 7. Dynamic scan placeholder
- SKIP: ZAP not run: no target URL provided

## 8. Manual review reminders
- PASS: Manual review checklist written to /Users/sangluu/Projects/AI Agency/repo-security-quickscan/security-reports/NaylorLegalMatterHub-20260604T011027Z/manual-review-checklist.md

## Final counts

- Pass: 7
- Warn: 4
- Fail: 0
- Skip: 5

## Interpretation

- FAIL means a required local reliability check failed, usually install/typecheck/build or invalid setup.
- WARN means a security scanner found issues, the tool failed, or a non-blocking check needs review.
- SKIP means the relevant tool or project file was not present.

Review all reports in: /Users/sangluu/Projects/AI Agency/repo-security-quickscan/security-reports/NaylorLegalMatterHub-20260604T011027Z
