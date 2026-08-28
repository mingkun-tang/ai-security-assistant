"""Map evidence documents to the existing engine input schema."""

from __future__ import annotations

from app.engine import empty_signals
from app.parser.evidence import EvidenceDocument, Fact, Location

UNSAFE_QUERY_CONSTRUCTION = {"concat", "fstring", "format"}
USER_DATA_RESOURCES = {"user_data", "user_email", "user_profile", "user_account"}


def evidence_to_engine_input(evidence: EvidenceDocument) -> dict:
    """Translate parser observations into the dict consumed by analyze()."""

    signals = empty_signals()
    facts_by_kind: dict[str, list[Fact]] = {}
    for fact in evidence.facts:
        facts_by_kind.setdefault(fact.kind, []).append(fact)

    input_facts = facts_by_kind.get("input_source", [])
    if input_facts:
        signals["input"]["user_controlled_input"] = True
        if any(
            fact.attrs.get("channel") in {"query", "form", "path", "json_body", "raw_body"}
            for fact in input_facts
        ):
            signals["input"]["parameter_reference"] = True

    _apply_database_signals(signals, facts_by_kind.get("database_query", []))
    _apply_render_signals(signals, facts_by_kind.get("rendered_output", []))
    _apply_network_signals(signals, facts_by_kind.get("network_request", []))
    _apply_upload_signals(signals, facts_by_kind.get("file_upload", []))
    _apply_auth_signals(signals, facts_by_kind.get("auth_context", []))

    action, targets, action_scores, ownership = _apply_access_signals(
        facts_by_kind.get("data_access", []),
        facts_by_kind.get("authorization_check", []),
        input_facts,
    )
    signals["ownership"]["other_user"] = ownership["other_user"]
    signals["ownership"]["self_reference"] = ownership["self_reference"]

    if ownership["role_change"]:
        signals["authorization"]["role_change"] = True

    control_point = "user account endpoint" if targets else None

    return {
        "action": action,
        "targets": targets,
        "actor": "user",
        "control_point": control_point,
        "signals": signals,
        "action_scores": action_scores,
    }


def _apply_database_signals(signals: dict, facts: list[Fact]) -> None:
    if not facts:
        return

    signals["injection"]["database_context"] = True
    signals["injection"]["sql_context"] = True
    signals["injection"]["query_context"] = True
    signals["database"]["database_context"] = True
    signals["sql_context"]["sql_language_context"] = True

    unsafe_with_input = False
    has_parameterized = False
    for fact in facts:
        construction = fact.attrs.get("construction")
        uses_input = bool(fact.attrs.get("uses_input_source_ids"))
        if construction == "parameterized":
            has_parameterized = True
        if construction in UNSAFE_QUERY_CONSTRUCTION and uses_input:
            unsafe_with_input = True

    if unsafe_with_input:
        signals["injection"]["unsafe_query_construction"] = True
        signals["injection"]["missing_validation"] = True
        signals["query_construction"]["unsafe_construction"] = True
    elif has_parameterized:
        signals["injection"]["parameterized_query_present"] = True
        signals["parameterization"]["parameterized_query_present"] = True


def _apply_render_signals(signals: dict, facts: list[Fact]) -> None:
    if not facts:
        return

    signals["rendering"]["rendered_output"] = True
    for fact in facts:
        sink = fact.attrs.get("sink")
        if sink in {"html", "template"}:
            signals["rendering"]["html_context"] = True
        if sink == "javascript":
            signals["rendering"]["javascript_context"] = True
        if fact.attrs.get("uses_input_source_ids"):
            if fact.attrs.get("escaping_observed") != "yes":
                signals["rendering"]["reflected_output"] = True
                signals["rendering"]["appears_in_output"] = True
        if fact.attrs.get("escaping_observed") == "no":
            signals["rendering"]["missing_escaping"] = True


def _apply_network_signals(signals: dict, facts: list[Fact]) -> None:
    if not facts:
        return

    signals["network"]["server_request"] = True
    signals["network"]["destination_reference"] = True
    for fact in facts:
        if fact.attrs.get("destination_validated"):
            continue
        destination_kind = fact.attrs.get("destination_kind")
        if destination_kind in {"from_input", "concat", "fstring", "format"}:
            signals["network"]["user_controlled_url"] = True
        if fact.attrs.get("uses_input_source_ids"):
            signals["network"]["user_controlled_url"] = True


def _apply_upload_signals(signals: dict, facts: list[Fact]) -> None:
    for fact in facts:
        if not fact.attrs.get("accepts_upload"):
            continue
        signals["upload"]["file_upload_action"] = True
        policy = fact.attrs.get("extension_policy")
        if policy == "allow_image":
            signals["upload"]["safe_file_type"] = True
        if fact.attrs.get("saved_to_web_root") == "yes":
            signals["upload"]["execution_context"] = True
        if _upload_fact_is_dangerous(fact):
            signals["upload"]["dangerous_file"] = True


def _upload_fact_is_dangerous(fact: Fact) -> bool:
    policy = fact.attrs.get("extension_policy")
    if policy in {"reject_executable", "allow_image", "checked"}:
        return False
    if not fact.attrs.get("saved"):
        return False
    filename_controlled = fact.attrs.get("filename_user_controlled")
    saved_to_web_root = fact.attrs.get("saved_to_web_root")
    if filename_controlled == "no" and saved_to_web_root != "yes":
        return False
    if policy == "unchecked" or filename_controlled == "yes" or saved_to_web_root == "yes":
        return True
    if policy in {None, "unknown"}:
        return filename_controlled == "yes" or saved_to_web_root == "yes"
    return policy == "allow_executable"


def _apply_auth_signals(signals: dict, facts: list[Fact]) -> None:
    for fact in facts:
        auth_kind = fact.attrs.get("auth_kind")
        if auth_kind in {"session", "cookie", "current_user", "request_user"}:
            signals["request"]["session_context"] = True
            signals["authentication"]["session_reference"] = True
        if auth_kind == "login_guard" and fact.attrs.get("guard_observed") == "yes":
            signals["request"]["session_context"] = True


def _apply_access_signals(
    data_facts: list[Fact],
    auth_facts: list[Fact],
    input_facts: list[Fact],
) -> tuple[str | None, list[str], dict[str, int], dict[str, bool]]:
    action_scores = {"read": 0, "modify": 0, "delete": 0, "inject": 0}
    targets: list[str] = []
    ownership = {
        "other_user": False,
        "self_reference": False,
        "role_change": False,
    }

    has_ownership_check = any(
        fact.attrs.get("check_kind") == "ownership"
        for fact in auth_facts
    )
    has_role_check = any(
        fact.attrs.get("check_kind") == "role"
        for fact in auth_facts
    )

    keyed_access = False
    primary_action: str | None = None

    for fact in data_facts:
        operation = fact.attrs.get("operation")
        resource = fact.attrs.get("resource")
        if operation in action_scores:
            action_scores[operation] += 1
            if primary_action is None:
                primary_action = operation
        if resource == "user_email":
            targets.append("user email")
        elif resource in {"user_data", "user_profile", "user_account"}:
            targets.append("user data")
        elif resource == "user_role":
            targets.append("user role")
        if fact.attrs.get("keyed_by_input"):
            keyed_access = True

    targets = list(dict.fromkeys(targets))

    if keyed_access and not has_ownership_check:
        ownership["other_user"] = True
    if has_ownership_check:
        ownership["self_reference"] = True
        ownership["other_user"] = False
    if any(fact.attrs.get("role_mutation") for fact in data_facts) and not has_role_check:
        ownership["role_change"] = True

    action = primary_action
    if action is None and action_scores["read"]:
        action = "read"
    if action is None and max(action_scores.values()) > 0:
        action = max(action_scores, key=action_scores.get)

    return action, targets, action_scores, ownership


def serialize_fact(fact: Fact, locations: dict[str, Location]) -> dict:
    location = locations.get(fact.location_id)
    payload = {
        "id": fact.id,
        "kind": fact.kind,
        "attrs": dict(fact.attrs),
        "notes": list(fact.notes),
    }
    if location is not None:
        payload["location"] = {
            "path": location.path,
            "line": location.line,
            "column": location.column,
            "snippet": location.snippet,
        }
    return payload


def facts_for_issue(issue_type: str, evidence: EvidenceDocument) -> list[dict]:
    """Return serialized facts that support a given engine issue type."""

    locations = {loc.id: loc for loc in evidence.locations}
    facts_by_id = {fact.id: fact for fact in evidence.facts}
    matched_facts: list[Fact] = []

    for fact in evidence.facts:
        if issue_type == "sql_injection" and fact.kind == "database_query":
            construction = fact.attrs.get("construction")
            if construction in UNSAFE_QUERY_CONSTRUCTION:
                matched_facts.append(fact)
        elif issue_type == "xss" and fact.kind == "rendered_output":
            if fact.attrs.get("uses_input_source_ids") or fact.attrs.get("escaping_observed") == "no":
                matched_facts.append(fact)
        elif issue_type == "ssrf" and fact.kind == "network_request":
            if fact.attrs.get("destination_kind") != "literal" or fact.attrs.get(
                "uses_input_source_ids"
            ):
                matched_facts.append(fact)
        elif issue_type == "file_upload" and fact.kind == "file_upload":
            if fact.attrs.get("accepts_upload") or fact.attrs.get("saved"):
                matched_facts.append(fact)
        elif issue_type in {"idor", "modify_data", "delete_action", "privilege_escalation"}:
            if fact.kind in {"data_access", "authorization_check", "input_source"}:
                matched_facts.append(fact)

    if not matched_facts:
        matched_facts = list(evidence.facts)

    linked_inputs: list[Fact] = []
    seen_ids: set[str] = set()
    for fact in matched_facts:
        for input_id in fact.attrs.get("uses_input_source_ids") or []:
            if input_id in seen_ids:
                continue
            source = facts_by_id.get(input_id)
            if source is not None and source.kind == "input_source":
                linked_inputs.append(source)
                seen_ids.add(input_id)

    ordered = linked_inputs + [
        fact for fact in matched_facts if fact.id not in seen_ids
    ]
    return [serialize_fact(fact, locations) for fact in ordered]
