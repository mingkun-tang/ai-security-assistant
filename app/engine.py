import re

from knowledge import FOLLOW_UP_QUESTIONS, RECOMMENDATIONS

READ_WORDS = ["read", "view", "see", "access", "open", "look", "check"]
MODIFY_WORDS = [
    "change",
    "modify",
    "update",
    "edit",
    "mess",
    "alter",
    "make",
    "assign",
    "promote",
    "grant",
]
DELETE_WORDS = ["delete", "remove", "erase"]

OTHER_USER_WORDS = [
    "another user",
    "other user",
    "someone else",
    "someone else's",
    "another account",
    "other account",
    "their account",
    "their profile",
]
SELF_REFERENCE_WORDS = ["my own", "myself", "mine", "own", "my"]

AUTHORIZATION_SIGNAL_WORDS = {
    "admin_reference": ["admin", "boss"],
    "role_change": ["role change"],
    "permission_reference": ["permission", "permissions"],
    "privilege_reference": ["privilege", "privileges"],
}
DATA_SIGNAL_WORDS = {
    "email_reference": ["email"],
    "profile_reference": ["profile"],
    "account_reference": ["account"],
    "sensitive_data_reference": ["sensitive data"],
}
AUTHENTICATION_SIGNAL_WORDS = {
    "login_reference": ["login"],
    "password_reference": ["password"],
    "session_reference": ["session"],
}

USER_DATA_WORDS = [
    "data",
    "information",
    "profile",
    "account",
    "stuff",
    "info",
    "record",
    "details",
]
EMAIL_WORDS = ["email"]
ROLE_WORDS = [
    "role",
    "admin",
    "boss",
    "permission",
    "privilege",
    "permissions",
    "privileges",
]
CONTROL_POINT_WORDS = ["user", "account", "profile"]

USER_CONTROLLED_INPUT_WORDS = [
    "parameter",
    "input",
    "user input",
    "my input",
    "attacker input",
    "search parameter",
    "form field",
    "comment field",
    "comment",
    "request parameter",
    "query parameter",
    "url parameter",
    "search",
    "username",
    "password",
]
DATABASE_CONTEXT_WORDS = [
    "sql",
    "database",
    "db",
    "mysql",
    "postgres",
    "postgresql",
    "sqlite",
]
SQL_CONTEXT_WORDS = [
    "sql query",
    "sql statement",
    "select statement",
    "select query",
    "insert statement",
    "update statement",
    "where clause",
    "executes sql",
    "execute sql",
    "orm raw query",
    "raw sql",
    "login query",
    "select",
    "insert",
]
INJECTION_ATTEMPT_WORDS = [
    "inject",
    "injection",
    "sql injection",
    "sqli",
]
UNSAFE_QUERY_CONSTRUCTION_WORDS = [
    "string concatenation",
    "concatenated",
    "concatenates",
    "concatenate",
    "concatenated into",
    "dynamic sql",
    "unsanitized",
    "unvalidated",
    "without validation",
    "no validation",
    "raw query",
    "no parameterized query",
    "no prepared statement",
    "without parameterized",
    "without prepared",
    "directly inserted",
    "inserted directly",
    "inserted directly into",
    "inserted into the where",
    "inserted into",
    "query built from",
    "built with string concatenation",
    "builds sql",
    "build sql",
    "input concatenated",
    "concatenated into a sql",
    "concatenated into a select",
    "escaping missing",
    "without escaping",
]
MISSING_VALIDATION_WORDS = [
    "unsanitized",
    "unvalidated",
    "without validation",
    "no validation",
    "raw query",
    "string concatenation",
    "concatenated",
]
PARAMETERIZED_QUERY_PRESENT_WORDS = [
    "parameterized query",
    "parameterized queries",
    "prepared statement",
    "prepared statements",
    "uses parameterized",
    "parameter binding",
]
DATABASE_TARGET_WORDS = [
    "sql",
    "database",
    "query",
    "db",
    "mysql",
    "postgres",
    "postgresql",
    "sqlite",
    "select",
    "where clause",
]
RENDERED_OUTPUT_WORDS = ["rendered", "render", "displayed", "shown"]
HTML_CONTEXT_WORDS = ["html", "markup"]
JAVASCRIPT_CONTEXT_WORDS = ["javascript", "js", "script tag", "script"]
REFLECTED_OUTPUT_WORDS = ["reflected", "reflect", "echoed", "echo"]
BROWSER_RENDER_WORDS = [
    "into the page",
    "in the page",
    "browser",
    "in the browser",
]
APPEARS_IN_OUTPUT_WORDS = [
    "appears inside",
    "appears in",
    "appear in",
    "appears as",
]
MISSING_ESCAPING_WORDS = [
    "without escaping",
    "unescaped",
    "no escaping",
    "without encoding",
    "unsanitized",
]
RENDERED_CONTENT_TARGET_WORDS = [
    "html",
    "javascript",
    "js",
    "script",
    "rendered",
    "reflected",
    "page",
]
SERVER_REQUEST_WORDS = [
    "server fetches",
    "server fetch",
    "server retrieves",
    "server connects to",
    "server connects",
    "server sends request",
    "server sends a request",
    "server requests",
    "backend request",
    "backend requests",
    "backend fetches",
    "backend retrieves",
    "application retrieves",
    "application server connects",
    "make the backend request",
    "make the server fetch",
    "server-side request",
    "server side request",
]
USER_CONTROLLED_URL_WORDS = [
    "url supplied by the user",
    "user supplied url",
    "user-supplied url",
    "url parameter",
    "callback url",
    "webhook url",
    "remote url",
    "url i provide",
    "callback url i provide",
    "whatever callback url",
    "change the url",
    "change the url parameter",
]
DESTINATION_REFERENCE_WORDS = [
    "url",
    "host",
    "endpoint",
    "domain",
    "destination",
    "callback",
    "webhook",
]
REMOTE_URL_TARGET_WORDS = [
    "url",
    "host",
    "endpoint",
    "callback",
    "webhook",
    "remote url",
]
FILE_UPLOAD_ACTION_WORDS = [
    "upload file",
    "upload a file",
    "upload an",
    "upload a",
    "uploaded a",
    "uploaded an",
    "can upload",
    "lets me upload",
    "let me upload",
    "allows me to upload",
    "allows me upload",
    "submit file",
    "attach file",
    "send file",
    "upload php",
    "upload a php",
    "upload an executable",
    "upload a script",
    "upload script",
    "upload an executable file",
    "upload a script file",
]
DANGEROUS_FILE_WORDS = [
    "php",
    "php file",
    "jsp",
    "jsp file",
    "asp",
    "aspx",
    "asp file",
    "executable",
    "executable file",
    "exe",
    "shell",
    "shell script",
    "script file",
    "server-executable",
    "cgi",
    ".php",
    ".jsp",
    ".asp",
    ".aspx",
    ".exe",
    ".sh",
    ".py",
    ".cgi",
]
SAFE_FILE_WORDS = [
    "jpg",
    "jpeg",
    "png",
    "gif",
    "pdf",
    "profile picture",
    "image",
]
UPLOAD_EXECUTION_CONTEXT_WORDS = [
    "uploads folder",
    "upload folder",
    "web-accessible",
    "web accessible",
    "server serves",
    "serves it",
    "served directly",
    "served from",
    "can be executed",
    "executed",
    "access it from the website",
    "access it from the site",
    "filename is trusted",
    "content type is trusted",
    "mime type is trusted",
    "trusts the filename",
    "trusts the content type",
]
UPLOADED_FILE_TARGET_WORDS = [
    "upload",
    "uploaded",
    "file",
    "php",
    "executable",
    "script file",
]
STATE_CHANGE_WORDS = [
    "change password",
    "password change",
    "password-change",
    "update password",
    "update email",
    "email change",
    "change email",
    "update profile",
    "modify profile",
    "delete account",
    "delete the account",
    "delete the user's account",
    "delete their account",
    "can delete",
    "transfer money",
    "modify settings",
    "change settings",
    "update settings",
    "sensitive action",
]
SESSION_CONTEXT_WORDS = [
    "logged in",
    "authenticated",
    "authenticated session",
    "session cookie",
    "browser automatically sends",
    "automatically sends the session cookie",
    "authenticated user",
    "while i am logged in",
    "while the victim is authenticated",
    "existing session",
    "ambient credentials",
]
CROSS_SITE_TRIGGER_WORDS = [
    "malicious site",
    "malicious website",
    "another website",
    "another site",
    "forged request",
    "cross-site",
    "cross site",
    "from another site",
    "from another website",
    "can trigger",
    "trigger an",
    "trigger a",
]
MISSING_ANTI_CSRF_WORDS = [
    "no csrf token",
    "without csrf token",
    "missing csrf token",
    "has no csrf token",
    "request has no csrf token",
    "no anti-csrf",
    "missing anti-csrf",
    "without anti-csrf",
    "no request validation",
    "without request validation",
    "missing request validation",
    "accepts cross-site",
    "cross-site submission",
]
ANTI_CSRF_PRESENT_WORDS = [
    "valid csrf token",
    "includes a csrf token",
    "includes a valid csrf token",
    "has a csrf token",
    "with a csrf token",
    "anti-csrf token is present",
]
STATE_CHANGING_REQUEST_TARGET_WORDS = [
    "password",
    "email",
    "profile",
    "account",
    "settings",
    "transfer",
    "csrf",
]
INJECT_WORDS = ["inject", "injection"]

ISSUE_PRIORITY = [
    "privilege_escalation",
    "sql_injection",
    "xss",
    "ssrf",
    "file_upload",
    "csrf",
    "delete_action",
    "modify_data",
    "idor",
]


def term_in_text(text, term):
    pattern = r"\b" + re.escape(term) + r"\b"
    return re.search(pattern, text) is not None


def any_term_in_text(text, terms):
    return any(term_in_text(text, term) for term in terms)


def count_terms_in_text(text, terms):
    return sum(1 for term in terms if term_in_text(text, term))


def empty_signals():
    return {
        "ownership": {
            "other_user": False,
            "self_reference": False,
        },
        "authorization": {
            "admin_reference": False,
            "role_change": False,
            "permission_reference": False,
            "privilege_reference": False,
        },
        "data": {
            "email_reference": False,
            "profile_reference": False,
            "account_reference": False,
            "sensitive_data_reference": False,
        },
        "authentication": {
            "login_reference": False,
            "password_reference": False,
            "session_reference": False,
        },
        "input": {
            "user_controlled_input": False,
            "parameter_reference": False,
        },
        "injection": {
            "database_context": False,
            "sql_context": False,
            "query_context": False,
            "injection_attempt": False,
            "missing_validation": False,
            "unsafe_query_construction": False,
            "parameterized_query_present": False,
        },
        "database": {
            "database_context": False,
        },
        "sql_context": {
            "sql_language_context": False,
        },
        "query_construction": {
            "unsafe_construction": False,
        },
        "parameterization": {
            "parameterized_query_present": False,
        },
        "rendering": {
            "rendered_output": False,
            "html_context": False,
            "javascript_context": False,
            "reflected_output": False,
            "browser_render": False,
            "appears_in_output": False,
            "missing_escaping": False,
        },
        "network": {
            "server_request": False,
            "user_controlled_url": False,
            "destination_reference": False,
        },
        "upload": {
            "file_upload_action": False,
            "dangerous_file": False,
            "safe_file_type": False,
            "execution_context": False,
        },
        "request": {
            "state_change": False,
            "session_context": False,
            "cross_site_trigger": False,
            "missing_anti_csrf_validation": False,
            "anti_csrf_present": False,
        },
    }


def collect_signals(text):
    signals = empty_signals()
    signals["ownership"]["other_user"] = any_term_in_text(text, OTHER_USER_WORDS)
    signals["ownership"]["self_reference"] = any_term_in_text(
        text, SELF_REFERENCE_WORDS
    )

    for field, words in AUTHORIZATION_SIGNAL_WORDS.items():
        signals["authorization"][field] = any_term_in_text(text, words)

    if term_in_text(text, "role") and count_terms_in_text(text, MODIFY_WORDS) > 0:
        signals["authorization"]["role_change"] = True

    for field, words in DATA_SIGNAL_WORDS.items():
        signals["data"][field] = any_term_in_text(text, words)

    for field, words in AUTHENTICATION_SIGNAL_WORDS.items():
        signals["authentication"][field] = any_term_in_text(text, words)

    signals["input"]["user_controlled_input"] = any_term_in_text(
        text, USER_CONTROLLED_INPUT_WORDS
    )
    signals["input"]["parameter_reference"] = any_term_in_text(
        text,
        [
            "parameter",
            "search parameter",
            "request parameter",
            "query parameter",
            "url parameter",
            "form field",
        ],
    )
    signals["injection"]["database_context"] = any_term_in_text(
        text, DATABASE_CONTEXT_WORDS
    )
    signals["injection"]["sql_context"] = any_term_in_text(text, SQL_CONTEXT_WORDS)
    signals["injection"]["query_context"] = any_term_in_text(
        text, ["sql query", "login query", "select query", "query"]
    )
    signals["injection"]["injection_attempt"] = any_term_in_text(
        text, INJECTION_ATTEMPT_WORDS
    )
    signals["injection"]["missing_validation"] = any_term_in_text(
        text, MISSING_VALIDATION_WORDS
    )
    signals["injection"]["unsafe_query_construction"] = any_term_in_text(
        text, UNSAFE_QUERY_CONSTRUCTION_WORDS
    )
    signals["injection"]["parameterized_query_present"] = any_term_in_text(
        text, PARAMETERIZED_QUERY_PRESENT_WORDS
    )
    signals["database"]["database_context"] = signals["injection"]["database_context"]
    signals["sql_context"]["sql_language_context"] = signals["injection"]["sql_context"]
    signals["query_construction"]["unsafe_construction"] = signals["injection"][
        "unsafe_query_construction"
    ]
    signals["parameterization"]["parameterized_query_present"] = signals["injection"][
        "parameterized_query_present"
    ]

    signals["rendering"]["rendered_output"] = any_term_in_text(
        text, RENDERED_OUTPUT_WORDS
    )
    signals["rendering"]["html_context"] = any_term_in_text(text, HTML_CONTEXT_WORDS)
    signals["rendering"]["javascript_context"] = any_term_in_text(
        text, JAVASCRIPT_CONTEXT_WORDS
    )
    signals["rendering"]["reflected_output"] = any_term_in_text(
        text, REFLECTED_OUTPUT_WORDS
    )
    signals["rendering"]["browser_render"] = any_term_in_text(
        text, BROWSER_RENDER_WORDS
    )
    signals["rendering"]["appears_in_output"] = any_term_in_text(
        text, APPEARS_IN_OUTPUT_WORDS
    )
    signals["rendering"]["missing_escaping"] = any_term_in_text(
        text, MISSING_ESCAPING_WORDS
    )

    signals["network"]["server_request"] = any_term_in_text(text, SERVER_REQUEST_WORDS)
    signals["network"]["user_controlled_url"] = any_term_in_text(
        text, USER_CONTROLLED_URL_WORDS
    )
    signals["network"]["destination_reference"] = any_term_in_text(
        text, DESTINATION_REFERENCE_WORDS
    )

    signals["upload"]["file_upload_action"] = any_term_in_text(
        text, FILE_UPLOAD_ACTION_WORDS
    )
    signals["upload"]["dangerous_file"] = any_term_in_text(text, DANGEROUS_FILE_WORDS)
    signals["upload"]["safe_file_type"] = any_term_in_text(text, SAFE_FILE_WORDS)
    signals["upload"]["execution_context"] = any_term_in_text(
        text, UPLOAD_EXECUTION_CONTEXT_WORDS
    )

    signals["request"]["state_change"] = any_term_in_text(text, STATE_CHANGE_WORDS)
    signals["request"]["session_context"] = any_term_in_text(
        text, SESSION_CONTEXT_WORDS
    )
    signals["request"]["cross_site_trigger"] = any_term_in_text(
        text, CROSS_SITE_TRIGGER_WORDS
    )
    signals["request"]["missing_anti_csrf_validation"] = any_term_in_text(
        text, MISSING_ANTI_CSRF_WORDS
    )
    signals["request"]["anti_csrf_present"] = any_term_in_text(
        text, ANTI_CSRF_PRESENT_WORDS
    )

    return signals


def collect_targets(text):
    targets = []
    if any_term_in_text(text, EMAIL_WORDS):
        targets.append("user email")
    if any_term_in_text(text, USER_DATA_WORDS):
        targets.append("user data")
    if any_term_in_text(text, ROLE_WORDS):
        targets.append("user role")
    if any_term_in_text(text, DATABASE_TARGET_WORDS):
        targets.append("database")
    if any_term_in_text(text, RENDERED_CONTENT_TARGET_WORDS):
        targets.append("rendered content")
    if any_term_in_text(text, REMOTE_URL_TARGET_WORDS):
        targets.append("remote url")
    if any_term_in_text(text, UPLOADED_FILE_TARGET_WORDS):
        targets.append("uploaded file")
    if any_term_in_text(text, STATE_CHANGING_REQUEST_TARGET_WORDS):
        targets.append("state changing request")
    return targets


def score_actions(text):
    return {
        "read": count_terms_in_text(text, READ_WORDS),
        "modify": count_terms_in_text(text, MODIFY_WORDS),
        "delete": count_terms_in_text(text, DELETE_WORDS),
        "inject": count_terms_in_text(text, INJECT_WORDS),
    }


def choose_action(action_scores):
    if max(action_scores.values()) == 0:
        return None
    return max(action_scores, key=action_scores.get)


def detect_control_point(text):
    if any_term_in_text(text, CONTROL_POINT_WORDS):
        return "user account endpoint"
    return None


def normalize_input(user_input):
    text = user_input.lower()
    action_scores = score_actions(text)
    return {
        "action": choose_action(action_scores),
        "targets": collect_targets(text),
        "actor": "user",
        "control_point": detect_control_point(text),
        "signals": collect_signals(text),
        "action_scores": action_scores,
    }


def has_any_target(targets, candidate_targets):
    return any(target in targets for target in candidate_targets)


def build_issue(issue_type, missing_control, broken_trust, assumption, impact):
    return {
        "issue_type": issue_type,
        "missing_control": missing_control,
        "broken_trust": broken_trust,
        "assumption": assumption,
        "impact": impact,
        "vulnerability_indicated": True,
    }


def privilege_escalation_issue():
    return build_issue(
        "privilege_escalation",
        "role change authorization check",
        "user is allowed to control their own permissions",
        "users cannot assign themselves higher privileges",
        "privilege escalation and unauthorized access to restricted functionality",
    )


def delete_action_issue():
    return build_issue(
        "delete_action",
        "authorization check on destructive action",
        "user is allowed to perform a dangerous action without proper verification",
        "only authorized roles can delete user accounts",
        "unauthorized account deletion or system disruption",
    )


def modify_data_issue(targets):
    if "user email" in targets:
        impact = "possible account takeover"
    else:
        impact = "unauthorized modification of sensitive user information"
    return build_issue(
        "modify_data",
        "authorization check",
        "user-controlled input is trusted",
        "users can only modify their own data",
        impact,
    )


def idor_issue():
    return build_issue(
        "idor",
        "authorization check",
        "user can access data without verification",
        "users can only access their own data",
        "exposure of sensitive user information",
    )


def sql_injection_issue():
    return build_issue(
        "sql_injection",
        "SQL queries constructed from user-controlled input instead of parameterized queries",
        "attacker-controlled input is trusted as part of executable SQL",
        "user input cannot modify query structure",
        "read, modify, or delete database records, or bypass authentication",
    )


def has_sql_injection_user_input(signals):
    input_signals = signals.get("input", {})
    return (
        input_signals.get("user_controlled_input")
        or input_signals.get("parameter_reference")
    )


def has_sql_injection_database_context(signals):
    injection = signals.get("injection", {})
    return (
        injection.get("database_context")
        or injection.get("sql_context")
        or injection.get("query_context")
    )


def has_sql_injection_unsafe_construction(signals):
    injection = signals.get("injection", {})
    return (
        injection.get("unsafe_query_construction")
        or injection.get("injection_attempt")
        or injection.get("missing_validation")
    )


def has_sql_injection_evidence(signals):
    injection = signals.get("injection", {})
    if injection.get("parameterized_query_present"):
        return False
    return (
        has_sql_injection_user_input(signals)
        and has_sql_injection_database_context(signals)
        and has_sql_injection_unsafe_construction(signals)
    )


def xss_issue():
    return build_issue(
        "xss",
        "output encoding or context-aware escaping for rendered content",
        "application renders attacker-controlled input",
        "rendered user input is safe",
        "arbitrary JavaScript execution, session theft, account compromise, phishing, or DOM manipulation",
    )


def has_xss_evidence(signals):
    input_signals = signals.get("input", {})
    rendering = signals.get("rendering", {})
    injection = signals.get("injection", {})

    has_user_input = (
        input_signals.get("user_controlled_input")
        or input_signals.get("parameter_reference")
    )
    has_output_context = (
        rendering.get("rendered_output")
        or rendering.get("html_context")
        or rendering.get("javascript_context")
        or rendering.get("reflected_output")
        or rendering.get("browser_render")
    )
    has_abuse_or_missing_control = (
        injection.get("injection_attempt")
        or rendering.get("reflected_output")
        or rendering.get("rendered_output")
        or rendering.get("appears_in_output")
        or rendering.get("missing_escaping")
    )
    return has_user_input and has_output_context and has_abuse_or_missing_control


def ssrf_issue():
    return build_issue(
        "ssrf",
        "validation or restriction of server-side outbound request destinations",
        "server trusts a destination controlled by the user",
        "user-supplied destinations are safe for the server to contact",
        "access to internal services, cloud metadata endpoints, or unintended external resources",
    )


def has_ssrf_evidence(signals):
    network = signals.get("network", {})
    return (
        network.get("server_request")
        and network.get("user_controlled_url")
        and network.get("destination_reference")
    )


def file_upload_issue():
    return build_issue(
        "file_upload",
        "safe file-type validation, content validation, storage isolation, or execution prevention",
        "server trusts user-supplied files, filenames, extensions, or content types as safe",
        "uploaded files are harmless and cannot execute or affect the application",
        "upload of executable or malicious content leading to code execution, stored XSS, malware hosting, or application compromise",
    )


def has_file_upload_evidence(signals):
    upload = signals.get("upload", {})
    return upload.get("file_upload_action") and upload.get("dangerous_file")


def csrf_issue():
    return build_issue(
        "csrf",
        "anti-CSRF protections such as unpredictable request tokens or equivalent request-intent validation",
        "application trusts that a request carrying valid session credentials was intentionally initiated by the authenticated user",
        "possession of the user's session cookie proves user intent",
        "an authenticated user's browser may perform sensitive actions without the user's consent",
    )


def has_csrf_evidence(signals):
    request = signals.get("request", {})
    if request.get("anti_csrf_present"):
        return False
    has_state_change = request.get("state_change")
    has_session = request.get("session_context")
    has_forgery_or_missing_validation = (
        request.get("cross_site_trigger")
        or request.get("missing_anti_csrf_validation")
    )
    return has_state_change and has_session and has_forgery_or_missing_validation


def scenario_is_understood(action, targets):
    return action is not None and len(targets) > 0


def unknown_issue(action, targets):
    if scenario_is_understood(action, targets):
        return {
            "issue_type": "unknown",
            "missing_control": "no missing control identified from the current evidence",
            "broken_trust": "no unauthorized access pattern was identified",
            "assumption": "the described behavior may be intended for the user's own resource",
            "impact": "no clear security impact without evidence of unauthorized access",
            "vulnerability_indicated": False,
        }

    return {
        "issue_type": "unknown",
        "missing_control": "unknown",
        "broken_trust": "unknown",
        "assumption": "insufficient information to determine",
        "impact": "unable to determine potential impact",
        "vulnerability_indicated": False,
    }


def collect_matching_issues(data):
    action = data["action"]
    targets = data.get("targets", [])
    signals = data["signals"]
    other_user = signals["ownership"]["other_user"]
    matches = []

    if action == "modify" and has_any_target(targets, ["user role"]):
        matches.append(privilege_escalation_issue())

    if has_sql_injection_evidence(signals):
        matches.append(sql_injection_issue())

    if has_xss_evidence(signals):
        matches.append(xss_issue())

    if has_ssrf_evidence(signals):
        matches.append(ssrf_issue())

    if has_file_upload_evidence(signals):
        matches.append(file_upload_issue())

    if has_csrf_evidence(signals):
        matches.append(csrf_issue())

    if action == "delete" and has_any_target(targets, ["user data"]) and other_user:
        matches.append(delete_action_issue())

    if (
        action == "modify"
        and has_any_target(targets, ["user email", "user data"])
        and other_user
    ):
        matches.append(modify_data_issue(targets))

    if (
        action == "read"
        and has_any_target(targets, ["user email", "user data"])
        and other_user
    ):
        matches.append(idor_issue())

    return matches


def select_primary_issue(matches):
    by_type = {issue["issue_type"]: issue for issue in matches}
    for issue_type in ISSUE_PRIORITY:
        if issue_type in by_type:
            return by_type[issue_type]
    return None


def mixed_action_scores(action_scores):
    scored_actions = [value for value in action_scores.values() if value > 0]
    return len(scored_actions) > 1


def confidence_from_evidence(data, result):
    action = data["action"]
    targets = data.get("targets", [])
    ownership = data["signals"]["ownership"]
    other_user = ownership["other_user"]
    self_reference = ownership["self_reference"]
    mixed_ownership = other_user and self_reference
    missing_ownership = not other_user and not self_reference
    mixed_actions = mixed_action_scores(data.get("action_scores", {}))
    signals = data["signals"]

    if result["issue_type"] == "sql_injection":
        return "high"

    if result["issue_type"] == "xss":
        return "high"

    if result["issue_type"] == "ssrf":
        return "high"

    if result["issue_type"] == "file_upload":
        return "high"

    if result["issue_type"] == "csrf":
        return "high"

    partial_sqli_evidence = (
        has_sql_injection_user_input(signals)
        and has_sql_injection_database_context(signals)
        and not has_sql_injection_unsafe_construction(signals)
    )
    if not result.get("vulnerability_indicated") and partial_sqli_evidence:
        return "medium"

    database_only_sqli_mention = (
        has_sql_injection_database_context(signals)
        and not has_sql_injection_user_input(signals)
        and not has_sql_injection_unsafe_construction(signals)
    )
    if not result.get("vulnerability_indicated") and database_only_sqli_mention:
        if action is None:
            return "low"

    if action is None or not targets:
        return "low"

    ownership_is_unclear = mixed_ownership or missing_ownership

    if result["issue_type"] == "privilege_escalation":
        if mixed_ownership or mixed_actions:
            return "medium"
        return "high"

    if result["vulnerability_indicated"]:
        if mixed_ownership or mixed_actions:
            return "medium"
        return "high"

    if ownership_is_unclear or mixed_actions:
        return "medium"

    if self_reference and not other_user:
        return "high"

    return "medium"


def evidence_snapshot(data):
    ownership = data["signals"]["ownership"]
    injection = data["signals"].get("injection", {})
    input_signals = data["signals"].get("input", {})
    rendering = data["signals"].get("rendering", {})
    network = data["signals"].get("network", {})
    return {
        "action": data["action"],
        "targets": list(data.get("targets", [])),
        "other_user": ownership["other_user"],
        "self_reference": ownership["self_reference"],
        "action_scores": dict(data.get("action_scores", {})),
        "user_controlled_input": input_signals.get("user_controlled_input", False),
        "database_context": injection.get("database_context", False),
        "sql_context": injection.get("sql_context", False),
        "injection_attempt": injection.get("injection_attempt", False),
        "missing_validation": injection.get("missing_validation", False),
        "unsafe_query_construction": injection.get(
            "unsafe_query_construction", False
        ),
        "parameterized_query_present": injection.get(
            "parameterized_query_present", False
        ),
        "rendered_output": rendering.get("rendered_output", False),
        "html_context": rendering.get("html_context", False),
        "javascript_context": rendering.get("javascript_context", False),
        "reflected_output": rendering.get("reflected_output", False),
        "server_request": network.get("server_request", False),
        "user_controlled_url": network.get("user_controlled_url", False),
        "destination_reference": network.get("destination_reference", False),
        "file_upload_action": data["signals"].get("upload", {}).get(
            "file_upload_action", False
        ),
        "dangerous_file": data["signals"].get("upload", {}).get(
            "dangerous_file", False
        ),
        "execution_context": data["signals"].get("upload", {}).get(
            "execution_context", False
        ),
        "safe_file_type": data["signals"].get("upload", {}).get(
            "safe_file_type", False
        ),
        "state_change": data["signals"].get("request", {}).get("state_change", False),
        "session_context": data["signals"].get("request", {}).get(
            "session_context", False
        ),
        "cross_site_trigger": data["signals"].get("request", {}).get(
            "cross_site_trigger", False
        ),
        "missing_anti_csrf_validation": data["signals"].get("request", {}).get(
            "missing_anti_csrf_validation", False
        ),
    }


def analyze(data):
    matches = collect_matching_issues(data)
    result = select_primary_issue(matches)
    if result is None:
        result = unknown_issue(data["action"], data.get("targets", []))

    result["evidence"] = evidence_snapshot(data)
    result["confidence"] = confidence_from_evidence(data, result)
    return result


REPORT_RULE = "=" * 64
EVIDENCE_LABEL_WIDTH = 24
ISSUE_DISPLAY_NAMES = {
    "idor": "Insecure Direct Object Reference (IDOR)",
    "modify_data": "Unauthorized data modification",
    "privilege_escalation": "Privilege escalation",
    "delete_action": "Unauthorized destructive action",
    "sql_injection": "SQL Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "file_upload": "Insecure File Upload",
    "csrf": "Cross-Site Request Forgery (CSRF)",
    "unknown": "Insufficient evidence",
}
NO_FINDING_VERIFICATION = {
    "read": [
        "Confirm the user can only view their own data.",
        "Verify ownership is enforced server-side, not only in the UI.",
        "Ensure authentication is required before the data is returned.",
        "Test whether another user's record can be read by changing the identifier.",
    ],
    "modify": [
        "Confirm the user can only modify their own data.",
        "Verify ownership is enforced server-side before updates are saved.",
        "Ensure authentication is required for the change.",
        "Test whether another user's data can be changed by altering the request.",
    ],
    "delete": [
        "Confirm the user can only delete their own account.",
        "Verify ownership is enforced server-side, not only in the UI.",
        "Ensure authentication is required before the delete is processed.",
        "Test whether another user's account can be deleted by changing the identifier.",
    ],
}
DEFAULT_NO_FINDING_VERIFICATION = [
    "Confirm the user can only affect their own account.",
    "Verify ownership is enforced server-side.",
    "Ensure authentication is required.",
    "Test whether another user's account can be affected.",
]
INSUFFICIENT_INFORMATION_VERIFICATION = [
    "Identify the exact action being performed and the resource it affects.",
    "Determine whether the request can reach another user's data or privileges.",
    "Check whether authentication and authorization are required server-side.",
    "Re-run the analysis after those details are known.",
]


def explain_analysis(analysis):
    explanation = {
        "missing_control": "",
        "broken_trust": "",
        "assumption": "",
        "impact": "",
    }

    missing_control = analysis["missing_control"]
    if missing_control == "authorization check":
        explanation["missing_control"] = (
            "Object-level authorization may be missing. The server should "
            "confirm that the caller is allowed to act on this specific "
            "resource, not only that the caller is logged in."
        )
    elif missing_control == "role change authorization check":
        explanation["missing_control"] = (
            "Role-change authorization may be missing. Assigning or "
            "elevating privileges should be limited to administrators, "
            "and the server should reject self-service privilege changes."
        )
    elif missing_control == "authorization check on destructive action":
        explanation["missing_control"] = (
            "Authorization around a destructive action may be missing. "
            "Deletes should be limited to the resource owner or a privileged "
            "role, and the check must happen on the server."
        )
    elif missing_control == "parameterized queries or input validation for database queries":
        explanation["missing_control"] = (
            "Safe query handling may be missing. User-controlled values "
            "should be passed through parameterized queries or an ORM, "
            "not concatenated into SQL strings."
        )
    elif missing_control == "SQL queries constructed from user-controlled input instead of parameterized queries":
        explanation["missing_control"] = (
            "The application may be constructing SQL queries using "
            "user-controlled input instead of parameterized queries. "
            "Prepared statements or ORM parameter binding should keep "
            "untrusted values out of the query structure."
        )
    elif missing_control == "output encoding or context-aware escaping for rendered content":
        explanation["missing_control"] = (
            "Output encoding or context-aware escaping may be missing. "
            "User-controlled values should be encoded for the HTML, "
            "JavaScript, or attribute context where they are rendered, "
            "and input validation alone is not enough."
        )
    elif missing_control == "validation or restriction of server-side outbound request destinations":
        explanation["missing_control"] = (
            "Validation or restriction of outbound request destinations "
            "may be missing. The server should only contact approved hosts "
            "and schemes, and should not treat a user-supplied URL as a "
            "trusted destination."
        )
    elif missing_control == "safe file-type validation, content validation, storage isolation, or execution prevention":
        explanation["missing_control"] = (
            "Safe file handling controls may be missing. Uploads should be "
            "checked against an allowlist, validated by content rather than "
            "extension alone, stored outside executable web paths, and "
            "blocked from running as code."
        )
    elif missing_control == "anti-CSRF protections such as unpredictable request tokens or equivalent request-intent validation":
        explanation["missing_control"] = (
            "Anti-CSRF protections may be missing. State-changing requests "
            "should include unpredictable request tokens or equivalent "
            "request-intent validation so a cross-site caller cannot reuse "
            "the victim's session."
        )
    elif missing_control == "unknown":
        explanation["missing_control"] = (
            "There is not enough detail in the scenario to identify a "
            "missing control. Naming the action, the resource, and who "
            "owns that resource would make the analysis more reliable."
        )
    elif missing_control == "no missing control identified from the current evidence":
        explanation["missing_control"] = (
            "No missing control is indicated yet. A user acting on their "
            "own resource is a common intended behavior and is not, by "
            "itself, evidence of a vulnerability."
        )
    else:
        explanation["missing_control"] = "No specific missing control was identified."

    broken_trust = analysis["broken_trust"]
    if broken_trust == "user-controlled input is trusted":
        explanation["broken_trust"] = (
            "The application may be trusting a caller-controlled identifier "
            "or field. If that value selects another user's record, the "
            "server has crossed a trust boundary it should have enforced."
        )
    elif broken_trust == "user can access data without verification":
        explanation["broken_trust"] = (
            "The application may be returning another user's data without "
            "verifying ownership. Confidentiality depends on that check; "
            "authentication alone is not enough."
        )
    elif broken_trust == "user is allowed to control their own permissions":
        explanation["broken_trust"] = (
            "The application may be allowing a user to change their own "
            "role or permissions. Privilege assignment is an administrative "
            "trust boundary and should not be user-controlled."
        )
    elif broken_trust == "user is allowed to perform a dangerous action without proper verification":
        explanation["broken_trust"] = (
            "The application may be allowing a destructive action without "
            "confirming the caller is authorized to affect that account. "
            "Deletes are difficult to undo, so this boundary should be strict."
        )
    elif broken_trust == "user-controlled input is trusted inside a database query":
        explanation["broken_trust"] = (
            "The application may be treating attacker-controlled input as "
            "trusted SQL. That breaks the trust boundary between untrusted "
            "request data and the database engine."
        )
    elif broken_trust == "attacker-controlled input is trusted as part of executable SQL":
        explanation["broken_trust"] = (
            "The application may trust attacker-controlled input as part of "
            "executable SQL. That breaks the trust boundary between untrusted "
            "request data and the database query engine."
        )
    elif broken_trust == "application renders attacker-controlled input":
        explanation["broken_trust"] = (
            "The application may be rendering attacker-controlled input in "
            "the browser. That breaks the trust boundary between untrusted "
            "request data and executable page content."
        )
    elif broken_trust == "server trusts a destination controlled by the user":
        explanation["broken_trust"] = (
            "The server may be trusting a destination controlled by the "
            "user and making requests on the user's behalf. That breaks "
            "the trust boundary between untrusted input and the server's "
            "outbound network access."
        )
    elif broken_trust == "server trusts user-supplied files, filenames, extensions, or content types as safe":
        explanation["broken_trust"] = (
            "The server may be trusting user-supplied files, filenames, "
            "extensions, or content types as safe. That breaks the trust "
            "boundary between untrusted upload content and the application's "
            "storage or execution environment."
        )
    elif broken_trust == "application trusts that a request carrying valid session credentials was intentionally initiated by the authenticated user":
        explanation["broken_trust"] = (
            "The application may trust that a request carrying valid session "
            "credentials was intentionally started by the authenticated user. "
            "That breaks the trust boundary between ambient browser "
            "credentials and proven user intent."
        )
    elif broken_trust == "unknown":
        explanation["broken_trust"] = (
            "The trust boundary is unclear because the scenario does not "
            "say who owns the resource or whether the caller is authorized."
        )
    elif broken_trust == "no unauthorized access pattern was identified":
        explanation["broken_trust"] = (
            "No unauthorized-access pattern was found in the provided "
            "evidence. That is not proof the application is secure; it "
            "only means this scenario does not describe access to someone "
            "else's resource."
        )
    else:
        explanation["broken_trust"] = "No specific broken trust boundary was identified."

    explanation["assumption"] = (
        f"The system appears to assume that {analysis['assumption']}."
    )

    impact = analysis["impact"]
    if analysis.get("vulnerability_indicated"):
        explanation["impact"] = (
            f"If this behavior is real and unauthenticated callers or "
            f"normal users can trigger it, the likely impact is {impact}."
        )
    else:
        explanation["impact"] = (
            "No security impact is indicated from this scenario alone. "
            "Confirm in testing that the same action cannot be aimed at "
            "another user's resource."
        )

    return explanation


def format_yes_no(value):
    return "Yes" if value else "No"


def title_case_label(value):
    if not value:
        return "None"
    return str(value).replace("_", " ").title()


def format_targets(targets):
    if not targets:
        return "None"
    return ", ".join(title_case_label(target) for target in targets)


def ownership_label(evidence):
    other_user = evidence.get("other_user")
    self_reference = evidence.get("self_reference")
    if other_user and self_reference:
        return "Mixed (self and another user)"
    if other_user:
        return "Another user"
    if self_reference:
        return "Self"
    return "Not specified"


def print_section(title):
    print()
    print(title)
    print("-" * len(title))


def print_labeled(label, value):
    print(f"{label:<{EVIDENCE_LABEL_WIDTH}}{value}")


def print_bullets(items):
    for item in items:
        print(f"• {item}")


def describe_evidence(evidence):
    action = evidence.get("action")
    targets = evidence.get("targets") or []
    if not action and not targets:
        return (
            "The scenario did not identify a clear action or target "
            "resource, so the engine cannot infer a control failure."
        )

    action_text = action or "unspecified"
    target_text = format_targets(targets).lower()
    ownership = ownership_label(evidence).lower()
    article = "an" if action_text[0] in "aeiou" else "a"
    return (
        f"The engine observed {article} {action_text} action against {target_text}, "
        f"with ownership described as {ownership}."
    )


def assessment_title(analysis):
    issue_name = ISSUE_DISPLAY_NAMES.get(analysis.get("issue_type"), "Unknown")
    if analysis.get("vulnerability_indicated"):
        return f"Possible security issue: {issue_name}"

    evidence = analysis.get("evidence", {})
    if scenario_is_understood(evidence.get("action"), evidence.get("targets") or []):
        return "No evidence of unauthorized access detected."
    return "Insufficient evidence to indicate a vulnerability."


def assessment_scope_note(analysis):
    if analysis.get("vulnerability_indicated"):
        return (
            "This is a hypothesis from the described behavior, not a "
            "confirmed exploit. Validate it against the actual request "
            "and server-side authorization checks."
        )
    return (
        "This does not guarantee the application is secure. It only "
        "means the provided scenario does not contain enough evidence "
        "of a vulnerability."
    )


def verification_steps(analysis):
    evidence = analysis.get("evidence", {})
    action = evidence.get("action")
    if scenario_is_understood(action, evidence.get("targets") or []):
        return NO_FINDING_VERIFICATION.get(action, DEFAULT_NO_FINDING_VERIFICATION)
    return INSUFFICIENT_INFORMATION_VERIFICATION


def generate_output(user_input, analysis):
    explanation = explain_analysis(analysis)
    confidence = analysis.get("confidence", "low")
    evidence = analysis.get("evidence", {})
    vulnerability_indicated = analysis.get("vulnerability_indicated")

    print()
    print(REPORT_RULE)
    print("Security Analysis Report")
    print(REPORT_RULE)

    print_section("Scenario")
    print(user_input)

    print_section("Evidence Collected")
    print_labeled("Action:", title_case_label(evidence.get("action")))
    print_labeled("Target(s):", format_targets(evidence.get("targets")))
    print_labeled("Ownership:", ownership_label(evidence))
    print_labeled("Other User Referenced:", format_yes_no(evidence.get("other_user")))
    print_labeled("Confidence:", title_case_label(confidence))

    print_section("Assessment")
    print(assessment_title(analysis))
    print()
    print(assessment_scope_note(analysis))

    print_section("Why This Conclusion")
    print("Evidence used:")
    print(f"  {describe_evidence(evidence)}")
    print()
    print("Missing control:")
    print(f"  {explanation['missing_control']}")
    print()
    print("Broken trust:")
    print(f"  {explanation['broken_trust']}")
    print()
    print("System assumption:")
    print(f"  {explanation['assumption']}")

    print_section("Impact")
    print(explanation["impact"])

    if vulnerability_indicated:
        print_section("Recommended Remediation")
        print_bullets(RECOMMENDATIONS.get(analysis["issue_type"], []))
    else:
        print_section("Suggested Verification")
        print_bullets(verification_steps(analysis))

    questions = FOLLOW_UP_QUESTIONS.get(analysis["issue_type"], [])
    if confidence != "high" and questions:
        print_section("Follow-up questions:")
        print_bullets(questions)

    print()
    print(REPORT_RULE)
    print()
