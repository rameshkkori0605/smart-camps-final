# Security Policy — Smart Campus

## Supported Versions

The Smart Campus platform at Sapthagiri NPS University adheres to strict enterprise security standards.

| Version | Supported          | Release Status |
| :---    | :---               | :---           |
| 1.0.x   | :white_check_mark: | Production / Active |

---

## Security Defense Architecture

Smart Campus enforces a multi-tiered security defense model:

### 1. Cross-Site Scripting (XSS) Prevention
- All user-submitted text across complaints, announcements, feedback, and admissions is sanitized using HTML entity encoding (`Security.sanitizeHTML`).
- Dynamic URL routing sanitizes schemes to block malicious `javascript:`, `vbscript:`, and data URLs (`Security.sanitizeUrl`).

### 2. Strict 10MB Per-File Storage Limit
- **Client-Side Validation**: File uploads are verified via `Security.validateFileUpload()` rejecting files $\ge$ 10MB before processing.
- **Pre-Commit Enforcement**: The repository includes `.git/hooks/pre-commit` and `check-size.ps1` ensuring no repository artifact ever exceeds 10MB.
- **MIME Type Whitelisting**: Strict verification ensuring only standard images (`image/jpeg`, `image/png`, `image/webp`) and verified document formats are accepted.

### 3. Role-Based Access Control (RBAC)
- All privileged actions (e.g., complaint status modification, user account provisioning, announcement authoring) require explicit authorization (`Security.authorize()`).
- Unauthorized requests throw HTTP 403 Forbidden exceptions.

### 4. Brute-Force & Rate Limiting Defense
- Rate limit buckets (`Security.checkRateLimit()`) prevent credential-stuffing and automated script hammering.

### 5. Content Security Policy (CSP) & HTTP Headers
- Modern security headers are configured via `vercel.json`:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: SAMEORIGIN`
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy: camera=(), microphone=(), geolocation=(self)`

---

## Reporting a Vulnerability

If you discover a security vulnerability in the Smart Campus platform:
1. Please **do not** open a public issue.
2. Email the Sapthagiri Technical Team at `security@sapthagiri.edu.in`.
3. Include details of the vulnerability, reproduction steps, and potential impact.
4. The team will acknowledge within 24 hours and issue a patch within 48 hours.
