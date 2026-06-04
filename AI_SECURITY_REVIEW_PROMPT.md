# AI Security Review Prompt

Use this after running `security-quickscan.sh`.

```text
Review this repository or pull request as a security reviewer.

Context:
- The app may have been built with AI-assisted tools such as Replit.
- Treat legal, financial, staff, payroll, tax, bank, client, project, matter, invoice, bill, and file data as sensitive.
- Automated scan reports are available in security-reports/<target-repo-name>-<timestamp>/.

Review:
1. Authentication and session handling
2. Backend authorization and RBAC
3. Over-broad API responses
4. Cross-user, cross-client, cross-project, cross-matter, or cross-tenant data access
5. Public/token-based routes
6. File upload/download access control
7. SQL/query safety
8. Sensitive data in logs
9. Secrets and environment-variable handling
10. Database migrations and startup seeding
11. Third-party integrations and OAuth token handling
12. Replit-to-production safety

Output:
- Summary
- Files reviewed
- Critical findings
- High findings
- Medium findings
- Low findings
- Required fixes before merge
- Tests to add
- Production go/no-go recommendation
```
