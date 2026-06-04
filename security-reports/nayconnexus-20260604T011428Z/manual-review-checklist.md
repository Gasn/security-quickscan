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
