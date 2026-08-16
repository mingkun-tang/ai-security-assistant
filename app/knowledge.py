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
        "Use parameterized queries or a safe ORM for all database access",
        "Never concatenate untrusted input into SQL strings",
        "Validate and constrain input types before they reach the query layer",
        "Test search and filter parameters with intentional SQL metacharacters",
    ],
    "xss": [
        "Apply context-aware output encoding before rendering user input",
        "Escape data for the correct HTML, JavaScript, or attribute context",
        "Use a Content Security Policy to reduce script execution impact",
        "Validate and sanitize input, but do not rely on filtering alone",
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
        "Are parameterized queries or an ORM used for this parameter?",
        "Does crafted input change the query structure or returned rows?",
    ],
    "xss": [
        "Is the input reflected or stored and then rendered in the page?",
        "Is the value encoded for the HTML or JavaScript context where it appears?",
        "Can a script payload execute in another user's browser?",
    ],
    "unknown": [
        "What action is being performed?",
        "Does the behavior affect another user?",
        "Can the request change or expose sensitive information?",
    ],
}
