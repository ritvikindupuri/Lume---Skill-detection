---
name: adversarial-security-audit
description: >-
  Conducts an adversarial security assessment (SAST, DAST, Threat Modeling, and Code Hardening)
  from an attacker's perspective across web applications, APIs, full-stack frameworks, and AI systems.
---

# Adversarial Security Audit & Code Hardening Skill

Use this skill to perform a comprehensive, production-grade security inspection of any full-stack web application, API, or AI-integrated software system from an offensive attacker's perspective.

---

## Audit Workflow — 5 Phases

```
┌─────────────────────────┐     ┌─────────────────────────┐     ┌─────────────────────────┐
│ Phase 1: Attack Surface │ ──> │ Phase 2: Threat Model   │ ──> │ Phase 3: Deep SAST Scan │
│ Discovery & Inventory   │     │ (Adversarial STRIDE)    │     │ & Sink Analysis         │
└─────────────────────────┘     └─────────────────────────┘     └─────────────────────────┘
                                                                             │
                                                                             ▼
┌─────────────────────────┐     ┌─────────────────────────┐     ┌─────────────────────────┐
│ Phase 5: Verification   │ <── │ Phase 4: DAST & Edge    │ <───┘ Remediation & Code      │
│ & Security Report       │     │ Header Hardening        │       Hardening               │
└─────────────────────────┘     └─────────────────────────┘
```

---

## Phase 1: Attack Surface Discovery & Inventory

1. **Map Entry Points:**
   - Catalog all public and protected HTTP routes (`/api/*`, SSR route handlers, server functions, RPC endpoints).
   - Identify static vs. dynamic routes and client vs. server boundaries.
2. **Credential & Secret Mapping:**
   - Verify environment variables. Ensure secret keys (`*_SECRET`, `SERVICE_ROLE`, `*_API_KEY`, DB passwords) are **never** prefixed with client-exposed prefixes (e.g., `VITE_`, `NEXT_PUBLIC_`, `PUBLIC_`).
   - Confirm server-only modules are isolated from client bundles.
3. **Dependency Integrity:**
   - Run `npm audit` or equivalent to flag vulnerable transitive dependencies.
   - Verify `package-lock.json` / `pnpm-lock.yaml` / `bun.lock` synchronization.

---

## Phase 2: Adversarial Threat Modeling (STRIDE)

Assess every feature against real-world attacker motivations:

### 1. Spoofing & Authentication Bypass
- **JWT Verification:** Ensure tokens are cryptographically validated for signature, expiration (`exp`), and subject (`sub`), not just decoded.
- **Session Lifecycle:** Verify unauthenticated requests redirect or return `401 Unauthorized` before processing payloads.
- **Provider Misconfigurations:** Confirm OAuth redirect URIs and scopes cannot be hijacked.

### 2. Tampering & Injection
- **SQL / NoSQL Injection:** Verify all database queries use parameterized interfaces (ORM / query builders / prepared statements). No raw string concatenation.
- **Command Injection:** Check for any calls to `eval()`, `exec()`, `spawn()`, or `child_process`.
- **ReDoS (Regex Denial of Service):** Ensure user-supplied regex patterns are length-capped and tested inside safe evaluation blocks.
- **Indirect Prompt Injection (AI Apps):** Ensure untrusted file contents, user inputs, or scraped data cannot override model system prompts or manipulate structured output formats (JSON/tool calls).

### 3. Repudiation & Auditability
- Ensure security-critical mutations (policy changes, deletions, approvals) record timestamps and actor identity (`user_id`).

### 4. Information Disclosure & IDOR
- **Row-Level Security (RLS) / Multi-Tenant Isolation:** Verify users cannot view, edit, or delete resources belonging to another organization/user by changing URL parameters (`id`, `orgId`, `scanId`).
- **Error Masking:** Ensure stack traces, database schema details, and unhandled exceptions are caught and sanitized before reaching client responses.

### 5. Denial of Service (DoS) & Resource Exhaustion
- **Payload Limits:** Check maximum body sizes on JSON endpoints, multipart forms, and text inputs.
- **Archive Ingestion (ZIP Bombs):** Ensure decompression limits both compressed file size AND uncompressed byte volume during extraction.
- **AI Streaming Leaks:** Ensure AI/LLM streaming connections propagate abort signals (`abortSignal: request.signal`) to terminate upstream model consumption on client disconnects.

### 6. Elevation of Privilege
- **RBAC Enforcement:** Ensure mutating server actions check user role (`admin`, `analyst`, `owner`) server-side, not just in UI toggle states.

---

## Phase 3: Deep SAST & Sink Inspection

Search the codebase for dangerous sinks:

| Vulnerability Category | Patterns / Sinks to Grep | Safe Alternative |
|---|---|---|
| **DOM XSS** | `dangerouslySetInnerHTML`, `innerHTML`, `document.write` | React JSX text interpolation / text nodes |
| **Code Execution** | `eval(`, `Function(`, `new Function`, `vm.runInContext` | Safe AST parsers / Zod validation |
| **Command Injection** | `child_process`, `execSync`, `spawnSync` | Avoid OS shell invocations |
| **Unsafe JSON Parse** | `JSON.parse(untrusted)` without `try/catch` | Safe wrapper with fallback |
| **Open Redirects** | `window.location.href = userInput` | Whitelist-validated relative paths |

---

## Phase 4: DAST & Edge Security Configuration

Ensure the deployment edge / server enforces defense-in-depth HTTP security headers:

```http
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), browsing-topics=()
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

---

## Phase 5: Verification & Reporting

1. Run automated build tests: `npm run build` or `bun run build`.
2. Run linters and typechecks: `npm run lint` and `tsc --noEmit`.
3. Output a structured **Security Audit Report** documenting:
   - Evaluated attack vectors
   - Found vulnerabilities & exact file locations
   - Remediations applied
   - Final posture verdict (PASS / ACTION REQUIRED)
