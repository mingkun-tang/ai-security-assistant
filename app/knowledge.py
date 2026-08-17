RECOMMENDATIONS = {
    "idor": [
        "Enforce object-level authorization checks",
        "Validate that users can only access their own data",
        "Test by modifying user identifiers in requests",
    ],
    "modify_data": [
        "Verify ownership before allowing modifications",
        "Do not trust user-controlled input for sensitive updates",
        "Add server-side validation for all changes",
    ],
    "privilege_escalation": [
        "Restrict role assignment to authorized roles only",
        "Validate role changes on the server side",
        "Ensure users cannot assign themselves higher privileges",
    ],
    "delete_action": [
        "Restrict destructive actions to authorized roles only",
        "Add confirmation and logging for delete actions",
        "Prevent deletion of critical accounts (ex: last admin)",
    ],
    "sql_injection": [
        "Use parameterized or prepared statements for all database access",
        "Never concatenate user input into SQL strings",
        "Prefer ORM parameter binding over raw dynamic SQL",
        "Validate input where appropriate before it reaches the query layer",
        "Apply least-privilege database accounts",
        "Log SQL errors securely without exposing query details to users",
    ],
    "xss": [
        "Apply context-aware output encoding before rendering user input",
        "Escape data for the correct HTML, JavaScript, or attribute context",
        "Use a Content Security Policy to reduce script execution impact",
        "Validate and sanitize input, but do not rely on filtering alone",
    ],
    "ssrf": [
        "Allowlist approved destinations where practical",
        "Validate URL schemes and hosts before making outbound requests",
        "Block private and internal IP ranges where appropriate",
        "Prevent redirects from bypassing destination controls",
        "Restrict outbound network access from application servers",
        "Do not directly trust user-supplied URLs for server-side fetches",
    ],
    "file_upload": [
        "Allowlist approved file types rather than blocking a denylist",
        "Validate actual file content, not only the extension or MIME header",
        "Rename uploaded files with server-generated names",
        "Store uploads outside executable or web-root locations",
        "Disable execution permissions for upload directories",
        "Enforce file size limits",
        "Scan uploaded files where appropriate",
        "Do not trust user-controlled filenames or MIME types",
    ],
    "csrf": [
        "Use anti-CSRF tokens for state-changing requests where appropriate",
        "Use SameSite cookie protections as defense-in-depth",
        "Validate Origin or Referer headers where appropriate",
        "Avoid sensitive state changes via GET requests",
        "Require re-authentication or step-up verification for highly sensitive actions",
        "Ensure state-changing requests cannot be triggered cross-site without user intent",
    ],
    "unknown": [
        "Review the request and identify what action is being performed",
        "Check if the action involves another user's data or privileges",
        "Verify if proper authorization checks exist",
        "Try testing with different inputs to observe behavior",
    ],
}

FOLLOW_UP_QUESTIONS = {
    "idor": [
        "Can the action access another user's data?",
        "Does changing the user identifier expose different information?",
        "Is the request properly checking ownership?",
    ],
    "modify_data": [
        "Can another user's information be modified?",
        "Does the server verify ownership before updating data?",
        "Can sensitive fields be changed directly from the request?",
    ],
    "privilege_escalation": [
        "Can a normal user assign themselves higher privileges?",
        "Does the server validate role changes?",
        "Are role changes restricted to administrators?",
    ],
    "delete_action": [
        "Can a normal user delete another account?",
        "Does the system require authorization before deletion?",
        "Are destructive actions logged or protected?",
    ],
    "sql_injection": [
        "Is the value concatenated into a SQL string?",
        "Are parameterized queries or prepared statements used for this input?",
        "Does crafted input change the query structure or returned rows?",
        "Does the database account follow least privilege?",
    ],
    "xss": [
        "Is the input reflected or stored and then rendered in the page?",
        "Is the value encoded for the HTML or JavaScript context where it appears?",
        "Can a script payload execute in another user's browser?",
    ],
    "ssrf": [
        "Does the server fetch a destination supplied by the user?",
        "Can the destination be changed to an internal host or metadata endpoint?",
        "Are outbound destinations allowlisted and validated server-side?",
    ],
    "file_upload": [
        "Can a user upload an executable or script file type?",
        "Is the uploaded file stored where it can be requested or executed?",
        "Does the server validate content, not only extension or MIME type?",
    ],
    "csrf": [
        "Can a third-party site trigger this state-changing request while the user is logged in?",
        "Does the request require an anti-CSRF token or equivalent intent check?",
        "Would SameSite cookies or Origin/Referer validation block the forged request?",
    ],
    "unknown": [
        "What action is being performed?",
        "Does the behavior affect another user?",
        "Can the request change or expose sensitive information?",
    ],
}
