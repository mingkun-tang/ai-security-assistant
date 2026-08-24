# Security Report: demo_project

**Scan date:** 2026-08-24 02:48:22 UTC  
**Path:** `./tests/fixtures/demo_project`

# Scan Summary

**Score:** 40/100 · **Files:** 4 · **Findings:** 3 (H 3 / M 0 / L 0) · **Duration:** 0.003s

# Findings Overview

| Severity | Issue | File | Line |
| --- | --- | --- | ---: |
| High | Server-Side Request Forgery (SSRF) | `./app/api/fetch.py` | 6 |
| High | SQL Injection | `./app/routes/users.py` | 5 |
| High | Cross-Site Scripting (XSS) | `./lib/views.py` | 5 |

# Findings

## 1. Server-Side Request Forgery (SSRF)

`High` · `./app/api/fetch.py:6`

**Evidence**

```text
User-Controlled URL
request.args.get("url")
        ↓
Server Request
requests.get(url)
```

**Why:** Validation or restriction of outbound request destinations may be missing.

**Impact:** If this behavior is real and unauthenticated callers or normal users can trigger it, the likely impact is access to internal services, cloud metadata endpoints, or unintended…

**Remediation:** Allowlist approved destinations where practical; Validate URL schemes and hosts before making outbound requests; Block private and internal IP ranges where appropriate

## 2. SQL Injection

`High` · `./app/routes/users.py:5`

**Evidence**

```text
User Input (id)
request.args.get("id")
        ↓
Database Query
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
```

**Why:** The application may be constructing SQL queries using user-controlled input instead of parameterized queries.

**Impact:** If this behavior is real and unauthenticated callers or normal users can trigger it, the likely impact is read, modify, or delete database records, or bypass authentication.

**Remediation:** Use parameterized or prepared statements for all database access; Never concatenate user input into SQL strings; Prefer ORM parameter binding over raw dynamic SQL

## 3. Cross-Site Scripting (XSS)

`High` · `./lib/views.py:5`

**Evidence**

```text
User Input (name)
request.args.get("name")
        ↓
Rendered Output
render_template("hello.html", name=name)
```

**Why:** Output encoding or context-aware escaping may be missing.

**Impact:** If this behavior is real and unauthenticated callers or normal users can trigger it, the likely impact is arbitrary JavaScript execution, session theft, account compromise…

**Remediation:** Apply context-aware output encoding before rendering user input; Escape data for the correct HTML, JavaScript, or attribute context; Use a Content Security Policy to reduce script execution impact


---

_AI Security Assistant · demo_project · 2026-08-24 02:48:22 UTC · Deterministic engine is source of truth._
