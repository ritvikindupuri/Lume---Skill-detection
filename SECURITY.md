# Security Policy

## Overview

Lume is a security scanner for Claude skills that analyzes potentially malicious content. This document describes the security measures in place and residual risks to consider when deploying and using Lume.

## Security Hardening Measures

### 1. Secrets Management

**Changes:**
- Removed committed `.env` file from git tracking
- Added `.env` and `.env.local` to `.gitignore` 
- `.env.example` contains placeholders for all required environment variables

**Best Practices:**
- Never commit API keys, service role keys, or database credentials
- Use environment variables for all secrets
- Supabase anon/publishable keys are low-risk by design (enforced by RLS) but should still not be committed
- For production deployments, use Cloudflare Pages environment variables or your hosting platform's secrets management

**Required Environment Variables:**
```bash
SUPABASE_URL                    # Supabase project URL
SUPABASE_PUBLISHABLE_KEY        # Supabase anon/publishable key (RLS-protected)
VITE_SUPABASE_URL              # Same as SUPABASE_URL (client-side)
VITE_SUPABASE_PUBLISHABLE_KEY  # Same as SUPABASE_PUBLISHABLE_KEY (client-side)
OPENAI_API_KEY                 # OpenAI API key for AI scanning
ALLOWED_ORIGINS                # Optional: comma-separated CORS allowlist
```

### 2. API Authentication & Authorization

**Implementation:**
- All server functions use `requireSupabaseAuth` middleware
- JWT tokens validated on every request via `supabase.auth.getClaims()`
- Token format validated (must be 3-part JWT)
- Authorization header required with Bearer scheme
- `/api/ai-scan` endpoint has dedicated authorization check

**Row-Level Security (RLS):**
- All Supabase tables have RLS enabled
- Organization-based access control via helper functions:
  - `is_organization_member()` - checks membership
  - `has_organization_role()` - validates role-based permissions
- Roles: `admin`, `analyst`, `viewer`
- RLS policies enforce:
  - Members can only view their organization's data
  - Analysts can create scans and custom checks
  - Admins can manage organization settings and delete data

### 3. Input Validation & Sanitization

**File Upload Protection:**
- Maximum total size: 20 MB per upload
- Binary file detection and filtering
- ZIP archive extraction with **path traversal protection**:
  - Blocks `..` in paths
  - Blocks absolute paths (leading `/` or `C:\`)
  - Normalizes paths to prevent directory escape
- Content size limits: 500,000 characters per scan
- Zod schema validation on all API inputs

**Artifact Scanning Limits:**
- 200 deterministic findings max per scan
- 30 AI findings max per scan
- String length constraints on all user-controlled fields
- Evidence excerpts truncated to 220 characters

### 4. Cross-Site Scripting (XSS) Prevention

**Status:** ✅ No `dangerouslySetInnerHTML` or `innerHTML` usage detected in codebase

**Frontend Protection:**
- React 19 with automatic XSS escaping
- All user content rendered via React components
- Finding evidence and scan results safely escaped by default

**Recommendation:** When rendering any dynamic content from scan findings, continue to use React's built-in escaping rather than raw HTML injection.

### 5. CORS Configuration

**Implementation:**
- Optional CORS allowlist via `ALLOWED_ORIGINS` environment variable
- Format: comma-separated list of allowed origins
- If not set, CORS is permissive (suitable for development)
- For production, set to your frontend domain(s)

**Example:**
```bash
ALLOWED_ORIGINS=https://lume---skill-detection.codeworker.workers.dev,https://yourdomain.com
```

### 6. Security Headers

**API Routes (`/api/ai-scan`):**
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Cache-Control: no-cache, no-transform
```

**Frontend Hosting:**
For Cloudflare Pages, configure additional headers via `_headers` file in `public/`:
```
/*
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: geolocation=(), microphone=(), camera=()
```

**Content Security Policy (CSP):** Not currently enforced due to inline scripts from framework. Consider adding CSP in report-only mode first.

### 7. Supply Chain Security

**GitHub Actions:**
- Least-privilege permissions (`contents: read` only)
- `actions/checkout@v4` with `persist-credentials: false`
- Frozen lockfile for reproducible builds (`bun install --frozen-lockfile`)

**Dependabot:**
- Weekly dependency updates for npm packages
- Weekly GitHub Actions updates
- Grouped updates for related packages (Radix UI, TanStack)
- Open PR limit: 10 for npm, 5 for actions

**Manual Review:**
- Review dependency updates before merging
- Check release notes for breaking changes
- Monitor for security advisories

### 8. Database Security

**Migrations:**
All tables have:
- RLS enabled
- Role-based policies
- Input validation via CHECK constraints
- Foreign key integrity
- `SECURITY DEFINER` functions with `SET search_path` to prevent search path attacks

**Security Functions:**
- Located in `private` schema to reduce surface area
- `SECURITY INVOKER` wrapper functions in `public` schema
- Explicit grants (no PUBLIC/anon access)

### 9. SSRF Protection

**Current Status:** ⚠️ Limited external fetching

Lume does not currently fetch skills from external URLs. If this feature is added:
- Validate and sanitize URLs
- Block private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16)
- Block localhost and link-local addresses
- Enforce HTTPS for external resources
- Set connection timeouts
- Limit redirect following

## Residual Risks & Limitations

### 1. Prompt Injection via Scanned Content ⚠️

**Nature of Risk:**
Lume scans potentially malicious skill artifacts by feeding them to an LLM (GPT-6 Astra). A malicious skill could embed instructions designed to manipulate the scanning LLM itself.

**Mitigations in Place:**
- System prompt explicitly instructs the model to be "conservative and evidence-bound"
- Model is told to "never invent a finding"
- Human-in-the-loop approval workflow for all containment actions
- AI recommendations require explicit analyst approval
- Multi-stage validation (deterministic rules + AI review)
- Findings have confidence scores

**Residual Risk:**
A sophisticated attacker might craft a skill that causes:
- False negatives (convincing the AI reviewer to miss real threats)
- False positives (overwhelming analysts with noise)
- Resource exhaustion (extremely long or complex content)

**Recommendations:**
- Never fully trust automated verdicts for critical deployments
- Require human review for any skill before production deployment
- Treat "clean" verdicts as "no obvious threats" rather than "proven safe"
- Monitor AI review costs and response times for anomalies

### 2. Client-Side Scanning Logic

**Nature of Risk:**
Deterministic rule evaluation happens client-side in the browser. A malicious user could:
- Bypass or disable checks in their own browser
- Submit falsified scan results

**Mitigations in Place:**
- Server-side AI review provides independent validation
- All scan results stored server-side with authentication
- Organization membership required to view/act on scans
- RLS prevents cross-organization data access

**Residual Risk:**
A user could present manipulated scan results to themselves, but cannot affect other users' scans or bypass server-side authentication/authorization.

**Impact:** Low (primarily affects integrity of user's own view)

### 3. Denial of Service

**Potential Vectors:**
- Large file uploads (mitigated: 20 MB limit)
- ZIP bombs (mitigated: 20 MB uncompressed limit)
- Expensive AI scans (mitigated: 500k char limit, max 30 findings)
- Rate limiting: ⚠️ Not currently implemented

**Recommendations for Production:**
- Implement rate limiting on API endpoints (per-user, per-IP)
- Set OpenAI API spending limits
- Monitor scan queue depth
- Consider implementing scan credits or quotas per organization

### 4. Secret Exposure in Logs

**Risk:**
Server-side code has access to environment variables and could log them.

**Mitigations:**
- No debug logging of environment variables in codebase
- Supabase client uses opaque publishable keys (not bearer JWTs)
- Error messages don't expose credentials

**Recommendations:**
- Configure log redaction in production
- Use structured logging with secret filtering
- Regularly audit application logs for leaked secrets

### 5. Dependency Vulnerabilities

**Mitigations:**
- Dependabot enabled for weekly updates
- Lockfile ensures reproducible builds

**Ongoing Maintenance Required:**
- Review and merge security updates promptly
- Subscribe to security advisories for key dependencies:
  - `@supabase/supabase-js`
  - `@tanstack/react-start`
  - `ai` (Vercel AI SDK)
  - `jszip`
  - React

### 6. OpenAI API Key Exposure

**Risk:**
If `OPENAI_API_KEY` is compromised, attacker could:
- Generate expensive API calls
- Access chat history if `store: true` was used (currently `store: false`)

**Mitigations:**
- Key stored only as environment variable (not in code)
- OpenAI client configured with `store: false`
- Reasoning content marked with `include: ["reasoning.encrypted_content"]` for privacy

**Recommendations:**
- Rotate OpenAI API keys periodically
- Set usage limits in OpenAI dashboard
- Monitor OpenAI usage for anomalies
- Consider using separate API keys per environment (dev/staging/prod)

### 7. Frontend Security Headers & CSP

**Current Status:** ⚠️ Partially Implemented

**Applied:**
- Security headers on API routes
- X-Frame-Options, X-Content-Type-Options, Referrer-Policy

**Not Applied:**
- Content-Security-Policy (CSP) — difficult due to framework inline scripts
- Strict-Transport-Security (HSTS) — must be configured at CDN/hosting level

**For Production Deployments:**
- Configure HSTS via Cloudflare or hosting provider
- Test CSP in report-only mode before enforcing
- Consider using nonces for inline scripts if CSP is enforced

### 8. No Built-In Audit Log for Admin Actions

**Current State:**
- Scans have `scanned_by` and `scanned_at`
- Findings track `reviewed_by` and `reviewed_at`
- Risk settings track `updated_by` and `updated_at`

**Gap:**
No centralized audit log for:
- Organization membership changes
- Role promotions/demotions
- Deletion of scans or findings

**Impact:** Low to Medium (depending on compliance requirements)

**Recommendation:** If audit compliance is required, add a dedicated `audit_log` table.

## Reporting a Vulnerability

If you discover a security vulnerability in Lume, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email the maintainer at: [ritvikindupuri@gmail.com] (replace with actual email)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to respond to security reports within 48 hours and will work with you to understand and address the issue.

## Security Update Cadence

- **Dependencies:** Reviewed and updated weekly via Dependabot
- **Framework Updates:** Monitored and applied as released
- **This Document:** Updated after any security-relevant code changes

## Security Testing Recommendations

Before deploying to production:

1. **Dependency Audit:**
   ```bash
   bun audit
   npm audit
   ```

2. **Static Analysis:**
   - Review ESLint output for security issues
   - Consider adding `eslint-plugin-security`

3. **Environment Validation:**
   - Ensure all secrets are environment variables
   - Verify CORS allowlist is production domains only
   - Confirm Supabase RLS policies are active

4. **Penetration Testing Scenarios:**
   - ZIP path traversal attempts
   - JWT token tampering
   - Cross-organization data access attempts
   - Prompt injection in scanned skills
   - Large file uploads and ZIP bombs

## Additional Resources

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Supabase Row Level Security](https://supabase.com/docs/guides/auth/row-level-security)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)

---

**Last Updated:** September 28, 2026  
**Reviewed By:** Cursor Cloud Agent (Security Hardening Pass)
