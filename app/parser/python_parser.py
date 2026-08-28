"""Python AST parser. Records observations only; it does not classify."""

from __future__ import annotations

import ast
import re

from app.parser.evidence import EvidenceDocument, Fact, Location, empty_document

CONTAINER_ATTRS = {
    "args": ("flask", "query"),
    "form": ("flask", "form"),
    "headers": ("flask", "header"),
    "cookies": ("flask", "cookie"),
    "GET": ("django", "query"),
    "POST": ("django", "form"),
}

WHOLE_SOURCE_ATTRS = {
    "json": ("flask", "json_body"),
    "body": ("django", "raw_body"),
}

DB_RECEIVER_NAMES = {
    "cursor",
    "cur",
    "connection",
    "conn",
    "session",
    "db",
    "engine",
    "database",
}
ORM_RAW_RECEIVER_NAMES = {
    "objects",
    "query",
    "qs",
    "manager",
    "session",
    "db",
}
DB_API_NAMES = {
    "execute": "execute",
    "executemany": "executemany",
    "raw": "raw",
}
SQL_KEYWORD_PATTERN = re.compile(
    r"\b(?:select|insert|update|delete|from|where|join|drop|table|"
    r"into|values|create|alter|union|limit|offset|having|truncate|"
    r"merge|replace|pragma|returning)\b",
    re.IGNORECASE,
)
PARAM_KEYWORD_NAMES = {"params", "parameters", "args", "bindparams"}
HTML_MARKUP_PATTERN = re.compile(
    r"<\s*/?\s*[a-zA-Z]|<!DOCTYPE|&lt;",
    re.IGNORECASE,
)
HTML_ATTR_SINK_PATTERN = re.compile(
    r"(?:href|src|action)\s*=\s*['\"]",
    re.IGNORECASE,
)
PATH_PARAM_ATTRS = {"view_args"}
ABORT_APIS = {"abort", "exit"}
RENDER_TEMPLATE_APIS = {
    "render_template": "template",
    "render_template_string": "template",
}
UNSAFE_MARK_APIS = {
    "Markup": "html",
    "mark_safe": "html",
}
RESPONSE_APIS = {"HttpResponse", "HTMLResponse", "make_response"}
ESCAPE_APIS = {"escape", "html_escape", "format_html"}
TEMPLATE_RECEIVER_NAMES = {"template", "tmpl", "jinja"}
TEMPLATE_SUFFIXES = (".html", ".htm", ".jinja", ".jinja2", ".j2")
HTTP_METHOD_APIS = {"get", "post", "put", "patch", "delete", "request"}
HTTP_MODULE_NAMES = {"requests": "requests", "httpx": "httpx"}
HTTP_CLIENT_CTORS = {
    "Session": "requests",
    "session": "requests",
    "Client": "httpx",
    "AsyncClient": "httpx",
}
BARE_NETWORK_APIS = {
    "urlopen": ("urllib.request", "urlopen", None),
    "HTTPConnection": ("http.client", "HTTPConnection", None),
    "HTTPSConnection": ("http.client", "HTTPSConnection", None),
}
UPLOAD_CONTAINER_ATTRS = {
    "files": "flask",
    "FILES": "django",
}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}
EXECUTABLE_EXTENSIONS = {
    ".php",
    ".exe",
    ".jsp",
    ".asp",
    ".aspx",
    ".sh",
    ".cgi",
    ".py",
}
WEB_ROOT_FRAGMENTS = (
    "static/",
    "/static",
    "public/",
    "/public",
    "www/",
    "/www",
    "media/",
    "/media",
    "webroot",
)
NON_WEB_ROOT_FRAGMENTS = ("/var/", "/tmp/", "/opt/", "/home/", "/private/")
AUTH_HEADER_NAMES = {"authorization", "http_authorization"}
JWT_DECODE_APIS = {"decode_jwt", "verify_token", "decode_access_token"}
LOGIN_GUARD_APIS = {"login_required"}
DATA_ACCESS_APIS = {"get", "filter", "filter_by", "first"}
USER_RESOURCE_NAMES = {"user", "User", "profile", "Profile", "account", "email"}
OWNERSHIP_ATTRS = {"id", "owner_id", "user_id", "owner", "account_id"}
IDENTITY_NAMES = {"current_user", "request", "session"}


def parse(language: str, path: str, source: str) -> EvidenceDocument:
    """Parse source and return an evidence document of observations."""

    doc = empty_document(language=language, path=path)
    if language != "python":
        return doc

    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError):
        return doc

    visitor = PythonEvidenceVisitor(path=path, source=source)
    visitor.visit(tree)
    doc.facts = visitor.facts
    doc.locations = visitor.locations
    return doc


def _attr_chain(node: ast.AST) -> list[str] | None:
    parts: list[str] = []
    current = node
    while True:
        if isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        elif isinstance(current, ast.Name):
            parts.append(current.id)
            break
        else:
            return None
    parts.reverse()
    return parts


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _first_str_arg(call: ast.Call) -> str | None:
    if call.args:
        return _const_str(call.args[0])
    return None


def _request_suffix(chain: list[str]) -> list[str] | None:
    try:
        index = len(chain) - 1 - chain[::-1].index("request")
    except ValueError:
        return None
    return chain[index + 1 :]


def _container_from_chain(chain: list[str]) -> dict | None:
    if len(chain) >= 2 and chain[-2] == "os" and chain[-1] == "environ":
        return {"framework": None, "channel": "environment"}

    suffix = _request_suffix(chain)
    if suffix is not None and len(suffix) == 1 and suffix[0] in CONTAINER_ATTRS:
        framework, channel = CONTAINER_ATTRS[suffix[0]]
        return {"framework": framework, "channel": channel}
    return None


def _upload_container_from_chain(chain: list[str]) -> dict | None:
    suffix = _request_suffix(chain)
    if suffix is not None and len(suffix) == 1 and suffix[0] in UPLOAD_CONTAINER_ATTRS:
        return {"framework": UPLOAD_CONTAINER_ATTRS[suffix[0]]}
    return None


def _whole_source_from_chain(chain: list[str]) -> dict | None:
    if len(chain) >= 2 and chain[-2] == "sys" and chain[-1] == "argv":
        return {"framework": None, "channel": "argv", "name": None}

    suffix = _request_suffix(chain)
    if suffix is not None and len(suffix) == 1 and suffix[0] in WHOLE_SOURCE_ATTRS:
        framework, channel = WHOLE_SOURCE_ATTRS[suffix[0]]
        return {"framework": framework, "channel": channel, "name": None}
    return None


class PythonEvidenceVisitor(ast.NodeVisitor):
    """Collect language-neutral observations within a single function or module."""

    def __init__(self, *, path: str, source: str) -> None:
        self.path = path
        self.source = source
        self.facts: list[Fact] = []
        self.locations: list[Location] = []
        self.scopes: list[dict[str, tuple]] = [{}]
        self.extension_policies: list[str | None] = [None]
        self._facts_by_node: dict[int, Fact] = {}
        self._auth_emitted: set[int] = set()
        self._parents: dict[ast.AST, ast.AST] = {}
        self.validated_url_vars: set[str] = set()
        self.validated_url_input_ids: set[str] = set()

    def visit(self, node: ast.AST):
        if not self._parents:
            self._parents = _parent_map(node)
        return super().visit(node)

    def lookup(self, name: str) -> tuple | None:
        return self.scopes[-1].get(name)

    def match_container(self, node: ast.AST) -> dict | None:
        if isinstance(node, ast.Name):
            binding = self.lookup(node.id)
            if binding and binding[0] == "container":
                return dict(binding[1])
            return None
        chain = _attr_chain(node)
        if chain is None:
            return None
        return _container_from_chain(chain)

    def match_whole_source(self, node: ast.AST) -> dict | None:
        chain = _attr_chain(node)
        if chain is None:
            return None
        return _whole_source_from_chain(chain)

    def match_upload_container(self, node: ast.AST) -> dict | None:
        if isinstance(node, ast.Name):
            binding = self.lookup(node.id)
            if binding and binding[0] == "upload_container":
                return dict(binding[1])
            return None
        chain = _attr_chain(node)
        if chain is None:
            return None
        return _upload_container_from_chain(chain)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
            self._observe_login_guard(decorator)
        for default in node.args.defaults:
            self.visit(default)
        for default in node.args.kw_defaults:
            if default is not None:
                self.visit(default)
        self.scopes.append({})
        self.extension_policies.append(None)
        self.validated_url_vars = set()
        self.validated_url_input_ids = set()
        for arg in node.args.args:
            if arg.arg == "session":
                self.scopes[-1][arg.arg] = ("local_session", None)
        for stmt in node.body:
            self.visit(stmt)
        self.scopes.pop()
        self.extension_policies.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            self._bind(node.targets[0].id, node.value)
            return
        for target in node.targets:
            self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
            if isinstance(node.target, ast.Name):
                self._bind(node.target.id, node.value)
                return
        self.visit(node.target)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            self.visit(node.value)
            spec = self._match_returned_html_output(node.value)
            if spec is not None:
                self._emit_rendered_output_fact(node, spec)

    def visit_If(self, node: ast.If) -> None:
        self.generic_visit(node)
        if _if_body_aborts(node.body):
            self._observe_url_validation_if(node)
            if _endswith_executable_rejection_test(node.test):
                self.extension_policies[-1] = "reject_executable"

    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)
        spec = self._match_input_call(node)
        if spec is not None:
            self._emit_input_fact(node, spec)
        db_spec = self._match_database_call(node)
        if db_spec is not None:
            self._emit_database_fact(node, db_spec)
        render_spec = self._match_rendered_output(node)
        if render_spec is not None:
            self._emit_rendered_output_fact(node, render_spec)
        network_spec = self._match_network_call(node)
        if network_spec is not None:
            self._emit_network_fact(node, network_spec)
        self._observe_upload_call(node)
        self._observe_auth_call(node)
        self._observe_data_access_call(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        self.generic_visit(node)
        self._observe_authorization_compare(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            self._observe_auth_name(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        self.generic_visit(node)
        spec = self._match_input_subscript(node)
        if spec is not None:
            self._emit_input_fact(node, spec)
        upload = self.match_upload_container(node.value)
        if upload is not None:
            self._emit_file_upload_fact(
                node,
                framework=upload["framework"],
                field_name=_const_str(node.slice),
                saved=False,
            )
        self._observe_auth_subscript(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self.generic_visit(node)
        self._observe_auth_attribute(node)
        if self.match_container(node) is not None:
            return
        if self.match_upload_container(node) is not None:
            parent = self._parents.get(node)
            if isinstance(parent, ast.Subscript) and parent.value is node:
                return
            if (
                isinstance(parent, ast.Attribute)
                and parent.attr in {"get", "save"}
                and parent.value is node
            ):
                return
            self._emit_file_upload_fact(
                node,
                framework=self.match_upload_container(node)["framework"],
                field_name=None,
                saved=False,
            )
            return
        if node.attr == "filename":
            return
        spec = self.match_whole_source(node)
        if spec is None:
            return
        parent = self._parents.get(node)
        if isinstance(parent, ast.Subscript) and parent.value is node:
            return
        self._emit_input_fact(node, spec)

    def _match_input_call(self, node: ast.Call) -> dict | None:
        func = node.func
        if isinstance(func, ast.Name) and func.id == "input":
            return {"framework": None, "channel": "stdin", "name": None}

        chain = _attr_chain(func)
        if chain is None:
            return None

        if len(chain) >= 2 and chain[-2] == "os" and chain[-1] == "getenv":
            return {
                "framework": None,
                "channel": "environment",
                "name": _first_str_arg(node),
            }

        suffix = _request_suffix(chain)
        if suffix == ["get_json"]:
            return {"framework": "flask", "channel": "json_body", "name": None}

        if isinstance(func, ast.Attribute) and func.attr == "get":
            container = self.match_container(func.value)
            if container is not None:
                return {**container, "name": _first_str_arg(node)}
            path_spec = self._match_path_param_get(func.value)
            if path_spec is not None:
                return {**path_spec, "name": _first_str_arg(node)}
        return None

    def _match_path_param_get(self, node: ast.AST) -> dict | None:
        chain = _attr_chain(node)
        if chain is None:
            return None
        suffix = _request_suffix(chain)
        if suffix is not None and len(suffix) == 1 and suffix[0] in PATH_PARAM_ATTRS:
            return {
                "framework": "flask",
                "channel": "path",
                "name": None,
            }
        return None

    def _match_input_subscript(self, node: ast.Subscript) -> dict | None:
        container = self.match_container(node.value)
        if container is not None:
            return {**container, "name": _const_str(node.slice)}

        whole = self.match_whole_source(node.value)
        if whole is not None:
            return {**whole, "name": _const_str(node.slice)}

        chain = _attr_chain(node.value)
        if chain is not None:
            suffix = _request_suffix(chain)
            if suffix is not None and len(suffix) == 1 and suffix[0] in PATH_PARAM_ATTRS:
                return {
                    "framework": "flask",
                    "channel": "path",
                    "name": _const_str(node.slice),
                }
        return None

    def _bind(self, name: str, value_node: ast.AST) -> None:
        upload_container = self.match_upload_container(value_node)
        if upload_container is not None:
            self.scopes[-1][name] = ("upload_container", upload_container)
            return
        container = self.match_container(value_node)
        if container is not None:
            self.scopes[-1][name] = ("container", container)
            return
        fact = self._facts_by_node.get(id(value_node))
        if fact is not None and fact.kind == "input_source":
            fact.attrs["bound_name"] = name
            self.scopes[-1][name] = ("input", fact.id)
            return
        if fact is not None and fact.kind == "file_upload":
            self.scopes[-1][name] = ("upload", fact.id)
            return
        if self._expr_is_upload_filename(value_node):
            self.scopes[-1][name] = ("upload_filename", None)
            return
        http_binding = self._http_binding(value_node)
        if http_binding is not None:
            self.scopes[-1][name] = http_binding
            return
        if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
            self.scopes[-1][name] = ("string", value_node.value)
            return
        if _is_urlparse_call(value_node):
            url_arg = value_node.args[0] if value_node.args else None
            input_ids = self._input_ids_from(url_arg)
            url_var = _urlparse_url_var(url_arg)
            self.scopes[-1][name] = (
                "parsed_url",
                {"input_ids": input_ids, "url_var": url_var},
            )
            return
        session_framework = self._session_framework(value_node)
        if session_framework is not None:
            self.scopes[-1][name] = ("framework_session", session_framework)
            return
        if name == "session":
            self.scopes[-1][name] = ("local_session", None)

    def _match_database_call(self, node: ast.Call) -> dict | None:
        api = _database_api(node.func)
        if api is None:
            return None

        sql_expr = _sql_expression(node)
        looks_like_sql = _has_sql_keywords(sql_expr)
        receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
        db_receiver = _is_db_receiver(receiver)
        raw_receiver = _is_orm_raw_receiver(receiver)

        if api in {"execute", "executemany"} and not db_receiver and not looks_like_sql:
            return None
        if api == "raw" and not raw_receiver and not looks_like_sql:
            return None
        if sql_expr is None and not db_receiver and api != "raw":
            return None

        has_params = _has_query_params(node)
        construction = _query_construction(sql_expr, has_params=has_params)
        input_ids = self._input_ids_from(sql_expr, *node.args[1:], *[kw.value for kw in node.keywords])
        return {
            "api": api,
            "construction": construction,
            "sql_keywords_present": looks_like_sql,
            "uses_input_source_ids": input_ids,
        }

    def _match_rendered_output(self, node: ast.Call) -> dict | None:
        api = _callee_name(node.func)
        if api is None:
            return None

        content_nodes = list(node.args) + [keyword.value for keyword in node.keywords]
        input_ids = self._input_ids_from(*content_nodes)

        if api in RENDER_TEMPLATE_APIS:
            escaping = "unknown"
            if any(_is_escape_call(n) for n in content_nodes):
                escaping = "yes"
            return {
                "sink": RENDER_TEMPLATE_APIS[api],
                "escaping_observed": escaping,
                "uses_input_source_ids": input_ids,
            }

        if api in UNSAFE_MARK_APIS:
            return {
                "sink": UNSAFE_MARK_APIS[api],
                "escaping_observed": "no",
                "uses_input_source_ids": input_ids,
            }

        if api in RESPONSE_APIS:
            payload = node.args[0] if node.args else None
            escaped = _is_escape_call(payload)
            if not _looks_like_html(payload) and not input_ids and not escaped:
                return None
            if escaped:
                sink = "html"
                escaping = "yes"
            elif _looks_like_html(payload):
                sink = "html"
                escaping = _escaping_observed(payload)
            else:
                sink = "generic_response"
                escaping = _escaping_observed(payload)
            return {
                "sink": sink,
                "escaping_observed": escaping,
                "uses_input_source_ids": input_ids,
            }

        if api == "render":
            return self._match_render_call(node, input_ids)

        return None

    def _match_render_call(self, node: ast.Call, input_ids: list[str]) -> dict | None:
        receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
        receiver_name = _receiver_name(receiver)
        if receiver_name and receiver_name.lower() in TEMPLATE_RECEIVER_NAMES:
            return {
                "sink": "template",
                "escaping_observed": "unknown",
                "uses_input_source_ids": input_ids,
            }

        if (
            len(node.args) >= 2
            and _is_request_expr(node.args[0])
            and _looks_like_template(node.args[1])
        ):
            return {
                "sink": "template",
                "escaping_observed": "unknown",
                "uses_input_source_ids": input_ids,
            }
        return None

    def _http_binding(self, node: ast.AST) -> tuple | None:
        if isinstance(node, ast.Name) and node.id in HTTP_MODULE_NAMES:
            return ("http_module", HTTP_MODULE_NAMES[node.id])
        chain = _attr_chain(node)
        if chain == ["urllib", "request"]:
            return ("http_module", "urllib.request")
        if chain == ["http", "client"]:
            return ("http_module", "http.client")
        if not isinstance(node, ast.Call):
            return None
        ctor = _callee_name(node.func)
        module = HTTP_CLIENT_CTORS.get(ctor or "")
        if module is None:
            return None
        if isinstance(node.func, ast.Name):
            return ("http_client", module)
        if isinstance(node.func, ast.Attribute):
            receiver_chain = _attr_chain(node.func.value)
            if receiver_chain and receiver_chain[-1] in HTTP_MODULE_NAMES:
                return ("http_client", HTTP_MODULE_NAMES[receiver_chain[-1]])
            if isinstance(node.func.value, ast.Name):
                binding = self.lookup(node.func.value.id)
                if binding and binding[0] in {"http_module", "http_client"}:
                    return ("http_client", binding[1])
        return None

    def _match_network_call(self, node: ast.Call) -> dict | None:
        client = self._match_http_client(node.func)
        if client is None:
            return None
        module, api, default_method = client
        url_index = 1 if api == "request" and module in {"requests", "httpx"} else 0
        url_node = _keyword_or_arg(node, "url", url_index)
        if url_node is None and api in {"HTTPConnection", "HTTPSConnection"}:
            url_node = _keyword_or_arg(node, "host", 0)
        method = default_method
        if api == "request":
            method_node = _keyword_or_arg(node, "method", 0)
            method_text = _const_str(method_node)
            method = method_text.upper() if method_text else None
        input_ids = self._input_ids_from(
            url_node,
            *node.args,
            *[keyword.value for keyword in node.keywords],
        )
        destination_validated = self._url_destination_validated(url_node, input_ids)
        return {
            "api": api,
            "method": method,
            "destination_kind": self._destination_kind(url_node),
            "uses_input_source_ids": input_ids,
            "server_side": True,
            "module": module,
            "destination_validated": destination_validated,
        }

    def _match_http_client(self, func: ast.AST) -> tuple[str, str, str | None] | None:
        if isinstance(func, ast.Name) and func.id in BARE_NETWORK_APIS:
            return BARE_NETWORK_APIS[func.id]

        chain = _attr_chain(func)
        if chain:
            matched = _http_client_from_chain(chain)
            if matched is not None:
                return matched

        if not isinstance(func, ast.Attribute):
            return None
        api = func.attr
        binding = None
        if isinstance(func.value, ast.Name):
            binding = self.lookup(func.value.id)
            if binding and binding[0] == "local_session":
                method = None if api == "request" else api.upper()
                return ("requests", api, method)
        if not (binding and binding[0] in {"http_module", "http_client"}):
            return None
        module = binding[1]
        if api in HTTP_METHOD_APIS and module in {"requests", "httpx"}:
            method = None if api == "request" else api.upper()
            return (module, api, method)
        if api == "urlopen" and module == "urllib.request":
            return ("urllib.request", "urlopen", None)
        if api in {"HTTPConnection", "HTTPSConnection"} and module == "http.client":
            return ("http.client", api, None)
        if api == "request" and module == "http.client":
            return ("http.client", "request", None)
        return None

    def _destination_kind(self, url_node: ast.AST | None) -> str:
        construction = _string_construction(url_node)
        if construction in {"concat", "fstring", "format"}:
            return construction
        if self._expr_is_from_input(url_node):
            return "from_input"
        if construction == "literal":
            return "literal"
        if isinstance(url_node, ast.Name):
            binding = self.lookup(url_node.id)
            if binding and binding[0] == "string":
                return "literal"
        return "unknown"

    def _expr_is_from_input(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name):
            binding = self.lookup(node.id)
            return bool(binding and binding[0] == "input")
        nested = self._facts_by_node.get(id(node))
        return nested is not None and nested.kind == "input_source"

    def _observe_upload_call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            upload = self.match_upload_container(node.func.value)
            if upload is not None:
                self._emit_file_upload_fact(
                    node,
                    framework=upload["framework"],
                    field_name=_first_str_arg(node),
                    saved=False,
                )
                return
        if isinstance(node.func, ast.Attribute) and node.func.attr == "save":
            if not self._is_upload_expr(node.func.value):
                return
            dest = node.args[0] if node.args else None
            meta = self._upload_attrs_from(node.func.value)
            filename_controlled = self._filename_user_controlled(dest)
            policy = self.extension_policies[-1]
            if policy is None and filename_controlled == "yes":
                policy = "unchecked"
            elif policy is None:
                policy = "unknown"
            self._emit_file_upload_fact(
                node,
                framework=meta.get("framework"),
                field_name=meta.get("field_name"),
                saved=True,
                save_destination_kind=self._save_destination_kind(dest),
                saved_to_web_root=_saved_to_web_root(dest),
                extension_policy=policy,
                uses_input_source_ids=self._input_ids_from(dest),
                filename_user_controlled=filename_controlled,
            )
            return
        policy = _extension_policy_from_endswith(node)
        if policy is not None and self._endswith_targets_upload(node):
            self.extension_policies[-1] = policy

    def _is_upload_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            binding = self.lookup(node.id)
            return bool(binding and binding[0] == "upload")
        fact = self._facts_by_node.get(id(node))
        return fact is not None and fact.kind == "file_upload"

    def _expr_is_upload_filename(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name):
            binding = self.lookup(node.id)
            return bool(binding and binding[0] == "upload_filename")
        if isinstance(node, ast.Attribute) and node.attr == "filename":
            return self._is_upload_expr(node.value)
        return False

    def _endswith_targets_upload(self, node: ast.Call) -> bool:
        if not isinstance(node.func, ast.Attribute):
            return False
        return self._expr_is_upload_filename(node.func.value) or self._is_upload_expr(
            node.func.value
        )

    def _upload_attrs_from(self, node: ast.AST) -> dict:
        if isinstance(node, ast.Name):
            binding = self.lookup(node.id)
            if binding and binding[0] == "upload":
                for fact in self.facts:
                    if fact.id == binding[1] and fact.kind == "file_upload":
                        return dict(fact.attrs)
        fact = self._facts_by_node.get(id(node))
        if fact is not None and fact.kind == "file_upload":
            return dict(fact.attrs)
        return {}

    def _save_destination_kind(self, node: ast.AST | None) -> str:
        if (
            isinstance(node, ast.Call)
            and _callee_name(node.func) == "join"
        ):
            return "concat"
        construction = _string_construction(node)
        if construction in {"concat", "fstring", "format"}:
            return construction
        if self._expr_is_from_input(node) or self._expr_is_upload_filename(node):
            return "from_input"
        if construction == "literal":
            return "literal"
        if isinstance(node, ast.Name):
            binding = self.lookup(node.id)
            if binding and binding[0] == "string":
                return "literal"
        return "unknown"

    def _filename_user_controlled(self, node: ast.AST | None) -> str:
        if node is None:
            return "unknown"
        if self._expr_is_upload_filename(node) or self._expr_is_from_input(node):
            return "yes"
        for child in ast.walk(node):
            if self._expr_is_upload_filename(child) or self._expr_is_from_input(child):
                return "yes"
        if _string_construction(node) == "literal":
            return "no"
        if isinstance(node, ast.Name):
            binding = self.lookup(node.id)
            if binding and binding[0] == "string":
                return "no"
        return "unknown"

    def _emit_file_upload_fact(
        self,
        node: ast.AST,
        *,
        framework: str | None,
        field_name: str | None,
        saved: bool,
        save_destination_kind: str = "unknown",
        saved_to_web_root: str = "unknown",
        extension_policy: str = "unknown",
        uses_input_source_ids: list[str] | None = None,
        filename_user_controlled: str = "unknown",
    ) -> None:
        fact = self._emit_fact(
            node,
            kind="file_upload",
            attrs={
                "accepts_upload": True,
                "framework": framework,
                "field_name": field_name,
                "saved": saved,
                "save_destination_kind": save_destination_kind,
                "saved_to_web_root": saved_to_web_root,
                "extension_policy": extension_policy,
                "uses_input_source_ids": list(uses_input_source_ids or []),
                "filename_user_controlled": filename_user_controlled,
            },
        )
        self._facts_by_node[id(node)] = fact

    def _match_returned_html_output(self, node: ast.AST) -> dict | None:
        if _is_escape_call(node):
            return None
        input_ids = self._unescaped_input_ids_from(node)
        if not input_ids:
            return None
        has_html = _looks_like_html(node)
        has_attr_sink = _has_html_attribute_sink(node)
        if not has_html and not has_attr_sink:
            return None
        escaping = _escaping_observed(node)
        if escaping == "yes":
            return None
        sink = "html" if has_html or has_attr_sink else "generic_response"
        return {
            "sink": sink,
            "escaping_observed": escaping,
            "uses_input_source_ids": input_ids,
        }

    def _unescaped_input_ids_from(self, node: ast.AST | None) -> list[str]:
        if node is None:
            return []
        ids: list[str] = []
        seen: set[str] = set()
        stack = [node]
        while stack:
            current = stack.pop()
            if isinstance(current, ast.Call) and _is_escape_call(current):
                continue
            if isinstance(current, ast.Name):
                binding = self.lookup(current.id)
                if binding and binding[0] == "input" and binding[1] not in seen:
                    seen.add(binding[1])
                    ids.append(binding[1])
            nested = self._facts_by_node.get(id(current))
            if (
                nested is not None
                and nested.kind == "input_source"
                and nested.id not in seen
            ):
                seen.add(nested.id)
                ids.append(nested.id)
            for child in ast.iter_child_nodes(current):
                stack.append(child)
        return ids

    def _observe_url_validation_if(self, node: ast.If) -> None:
        for url_var, input_ids in self._url_validation_targets_from_test(node.test):
            if url_var:
                self.validated_url_vars.add(url_var)
            for input_id in input_ids:
                self.validated_url_input_ids.add(input_id)

    def _url_validation_targets_from_test(self, test: ast.AST) -> list[tuple[str | None, list[str]]]:
        results: list[tuple[str | None, list[str]]] = []
        if isinstance(test, ast.Compare):
            left: ast.AST = test.left
            for op, comparator in zip(test.ops, test.comparators):
                target = self._parsed_url_validation_target(left, op, comparator)
                if target is not None:
                    results.append(target)
                left = comparator
        return results

    def _parsed_url_validation_target(
        self,
        left: ast.AST,
        op: ast.cmpop,
        right: ast.AST,
    ) -> tuple[str | None, list[str]] | None:
        if not isinstance(left, ast.Attribute) or not isinstance(left.value, ast.Name):
            return None
        binding = self.lookup(left.value.id)
        if not binding or binding[0] != "parsed_url":
            return None
        meta = binding[1]
        url_var = meta.get("url_var")
        input_ids = list(meta.get("input_ids") or [])
        if left.attr == "scheme":
            if isinstance(op, ast.NotEq) and _const_str(right) == "https":
                return (url_var, input_ids)
            if isinstance(op, ast.Eq) and _const_str(right) == "http":
                return (url_var, input_ids)
        if left.attr == "hostname" and isinstance(op, ast.NotIn):
            return (url_var, input_ids)
        return None

    def _url_destination_validated(
        self,
        url_node: ast.AST | None,
        input_ids: list[str],
    ) -> bool:
        if isinstance(url_node, ast.Name) and url_node.id in self.validated_url_vars:
            return True
        if input_ids and set(input_ids).issubset(self.validated_url_input_ids):
            return True
        return False

    def _observe_data_access_call(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Attribute):
            return
        api = node.func.attr
        if api not in DATA_ACCESS_APIS:
            return
        if self.match_container(node.func.value) is not None:
            return
        if self.match_upload_container(node.func.value) is not None:
            return
        chain = _attr_chain(node.func.value) or []
        if _request_suffix(chain) is not None:
            return
        if "objects" not in chain and "query" not in chain and "manager" not in chain:
            if not any(part in USER_RESOURCE_NAMES for part in chain):
                return
        resource = self._infer_user_resource(chain)
        operation = "read"
        keyed = self._call_keyed_by_input(node)
        if keyed:
            self._emit_data_access_fact(
                node,
                operation=operation,
                resource=resource,
                keyed_by_input=True,
                role_mutation=False,
            )

    def _call_keyed_by_input(self, node: ast.Call) -> bool:
        nodes = list(node.args) + [kw.value for kw in node.keywords]
        for child in nodes:
            if self._expr_is_from_input(child):
                return True
            if isinstance(child, ast.Name):
                binding = self.lookup(child.id)
                if binding and binding[0] == "input":
                    return True
        return bool(self._input_ids_from(*nodes))

    def _infer_user_resource(self, chain: list[str]) -> str:
        lowered = [part.lower() for part in chain]
        if "email" in lowered:
            return "user_email"
        if "role" in lowered or "admin" in lowered:
            return "user_role"
        if any(part in USER_RESOURCE_NAMES for part in chain):
            return "user_data"
        return "user_data"

    def _observe_authorization_compare(self, node: ast.Compare) -> None:
        participants = list(node.comparators)
        if isinstance(node.left, ast.AST):
            participants.insert(0, node.left)
        has_owner = any(self._expr_has_owner_marker(part) for part in participants)
        has_identity = any(self._expr_has_identity_marker(part) for part in participants)
        if not (has_owner and has_identity):
            return
        self._emit_authorization_fact(
            node,
            check_kind="ownership",
            compared_to_session_user=any(
                self._expr_has_identity_marker(part) for part in participants
            ),
        )

    def _expr_has_owner_marker(self, node: ast.AST) -> bool:
        chain = _attr_chain(node)
        if chain and chain[-1] in OWNERSHIP_ATTRS:
            return True
        if isinstance(node, ast.Attribute) and node.attr in OWNERSHIP_ATTRS:
            return True
        return False

    def _expr_has_identity_marker(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name) and node.id in IDENTITY_NAMES:
            return True
        chain = _attr_chain(node)
        if not chain:
            return False
        if any(part in IDENTITY_NAMES for part in chain):
            return True
        if "request" in chain and chain[-1] == "user":
            return True
        return False

    def _emit_data_access_fact(
        self,
        node: ast.AST,
        *,
        operation: str,
        resource: str,
        keyed_by_input: bool,
        role_mutation: bool,
    ) -> None:
        self._emit_fact(
            node,
            kind="data_access",
            attrs={
                "operation": operation,
                "resource": resource,
                "keyed_by_input": keyed_by_input,
                "role_mutation": role_mutation,
            },
        )

    def _emit_authorization_fact(
        self,
        node: ast.AST,
        *,
        check_kind: str,
        compared_to_session_user: bool,
    ) -> None:
        self._emit_fact(
            node,
            kind="authorization_check",
            attrs={
                "check_kind": check_kind,
                "compared_to_session_user": compared_to_session_user,
            },
        )

    def _is_framework_session(self, node: ast.AST) -> bool:
        return self._session_framework(node) is not None

    def _session_framework(self, node: ast.AST | None) -> str | None:
        if node is None:
            return None
        if isinstance(node, ast.Name):
            binding = self.lookup(node.id)
            if binding and binding[0] == "local_session":
                return None
            if binding and binding[0] in {
                "http_client",
                "http_module",
                "container",
                "upload",
                "upload_container",
                "input",
            }:
                return None
            if binding and binding[0] == "framework_session":
                return binding[1]
            if node.id == "session" and binding is None:
                return "flask"
            return None
        chain = _attr_chain(node)
        if chain is None:
            return None
        if chain[-2:] == ["flask", "session"] or chain[-1] == "session" and chain[-2:] == ["session"]:
            if chain[-2:] == ["flask", "session"]:
                return "flask"
        suffix = _request_suffix(chain)
        if suffix == ["session"]:
            return "django"
        if chain[-1] == "session" and "flask" in chain:
            return "flask"
        return None

    def _observe_login_guard(self, node: ast.AST) -> None:
        func = node.func if isinstance(node, ast.Call) else node
        name = _callee_name(func) if not isinstance(func, ast.Name) else func.id
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        else:
            name = None
        if name not in LOGIN_GUARD_APIS:
            return
        self._emit_auth_fact(
            node,
            framework=None,
            auth_kind="login_guard",
            authenticated_context="yes",
            ambient_credentials="unknown",
            source_name=name,
            guard_observed="yes",
        )

    def _observe_auth_name(self, node: ast.Name) -> None:
        parent = self._parents.get(node)
        if isinstance(parent, ast.Call) and parent.func is node:
            return
        if node.id == "current_user":
            self._emit_auth_fact(
                node,
                framework="flask",
                auth_kind="current_user",
                authenticated_context="yes",
                ambient_credentials="yes",
                source_name="current_user",
                guard_observed="unknown",
            )

    def _observe_auth_attribute(self, node: ast.Attribute) -> None:
        parent = self._parents.get(node)
        skip_container = (
            isinstance(parent, ast.Subscript) and parent.value is node
        ) or (
            isinstance(parent, ast.Attribute)
            and parent.attr == "get"
            and parent.value is node
        )
        chain = _attr_chain(node)
        if chain and chain[-1] == "current_user":
            self._emit_auth_fact(
                node,
                framework="flask",
                auth_kind="current_user",
                authenticated_context="yes",
                ambient_credentials="yes",
                source_name="current_user",
                guard_observed="unknown",
            )
            return
        suffix = _request_suffix(chain) if chain else None
        if suffix == ["user"]:
            self._emit_auth_fact(
                node,
                framework="django",
                auth_kind="request_user",
                authenticated_context="yes",
                ambient_credentials="yes",
                source_name="request.user",
                guard_observed="unknown",
            )
            return
        if skip_container:
            return
        framework = self._session_framework(node)
        if framework is not None:
            self._emit_auth_fact(
                node,
                framework=framework,
                auth_kind="session",
                authenticated_context="unknown",
                ambient_credentials="yes",
                source_name="session",
                guard_observed="unknown",
            )
            return
        if suffix == ["cookies"] or suffix == ["COOKIES"]:
            self._emit_auth_fact(
                node,
                framework="flask" if suffix == ["cookies"] else "django",
                auth_kind="cookie",
                authenticated_context="unknown",
                ambient_credentials="yes",
                source_name="cookies" if suffix == ["cookies"] else "COOKIES",
                guard_observed="unknown",
            )

    def _observe_auth_subscript(self, node: ast.Subscript) -> None:
        framework = self._session_framework(node.value)
        if framework is not None:
            key = _const_str(node.slice)
            self._emit_auth_fact(
                node,
                framework=framework,
                auth_kind="session",
                authenticated_context="unknown",
                ambient_credentials="yes",
                source_name=key or "session",
                guard_observed="unknown",
            )
            return
        cookie_framework = self._cookie_framework(node.value)
        if cookie_framework is not None:
            key = _const_str(node.slice)
            self._emit_auth_fact(
                node,
                framework=cookie_framework,
                auth_kind="cookie",
                authenticated_context="unknown",
                ambient_credentials="yes",
                source_name=key or "cookies",
                guard_observed="unknown",
            )
            return
        self._observe_auth_header(node, node.value, node.slice)

    def _observe_auth_call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "get":
            framework = self._session_framework(func.value)
            if framework is not None:
                key = _first_str_arg(node)
                self._emit_auth_fact(
                    node,
                    framework=framework,
                    auth_kind="session",
                    authenticated_context="unknown",
                    ambient_credentials="yes",
                    source_name=key or "session",
                    guard_observed="unknown",
                    uses_input_source_ids=self._input_ids_from(*node.args),
                )
                return
            cookie_framework = self._cookie_framework(func.value)
            if cookie_framework is not None:
                key = _first_str_arg(node)
                self._emit_auth_fact(
                    node,
                    framework=cookie_framework,
                    auth_kind="cookie",
                    authenticated_context="unknown",
                    ambient_credentials="yes",
                    source_name=key or "cookies",
                    guard_observed="unknown",
                )
                return
            self._observe_auth_header(node, func.value, node.args[0] if node.args else None)
            return
        self._observe_login_guard(node)
        self._observe_jwt_call(node)

    def _cookie_framework(self, node: ast.AST) -> str | None:
        chain = _attr_chain(node)
        suffix = _request_suffix(chain) if chain else None
        if suffix == ["cookies"]:
            return "flask"
        if suffix == ["COOKIES"]:
            return "django"
        container = self.match_container(node)
        if container and container.get("channel") == "cookie":
            return container.get("framework") or "flask"
        return None

    def _observe_auth_header(
        self, node: ast.AST, container: ast.AST, key_node: ast.AST | None
    ) -> None:
        key = _const_str(key_node)
        if key is None or key.lower() not in AUTH_HEADER_NAMES:
            return
        chain = _attr_chain(container)
        suffix = _request_suffix(chain) if chain else None
        if suffix not in (["headers"], ["META"]):
            container_match = self.match_container(container)
            if not (container_match and container_match.get("channel") == "header"):
                return
        input_ids = []
        nested = self._facts_by_node.get(id(node))
        if nested is not None and nested.kind == "input_source":
            input_ids = [nested.id]
        self._emit_auth_fact(
            node,
            framework="django" if suffix == ["META"] else "flask",
            auth_kind="authorization_header",
            authenticated_context="unknown",
            ambient_credentials="no",
            source_name=key,
            guard_observed="unknown",
            uses_input_source_ids=input_ids,
        )

    def _observe_jwt_call(self, node: ast.Call) -> None:
        name = _callee_name(node.func)
        chain = _attr_chain(node.func)
        is_jwt = name in JWT_DECODE_APIS
        if chain and chain[-1] == "decode" and "jwt" in [part.lower() for part in chain]:
            is_jwt = True
        if chain and chain[-2:] in (["jose", "decode"], ["JWT", "decode"]):
            is_jwt = True
        if not is_jwt:
            return
        validated = _jwt_validation_observed(node)
        self._emit_auth_fact(
            node,
            framework=None,
            auth_kind="jwt",
            authenticated_context="yes" if validated else "unknown",
            ambient_credentials="no",
            source_name=name or "jwt.decode",
            guard_observed="yes" if validated else "unknown",
            uses_input_source_ids=self._input_ids_from(*node.args, *[kw.value for kw in node.keywords]),
        )

    def _emit_auth_fact(
        self,
        node: ast.AST,
        *,
        framework: str | None,
        auth_kind: str,
        authenticated_context: str,
        ambient_credentials: str,
        source_name: str | None,
        guard_observed: str,
        uses_input_source_ids: list[str] | None = None,
    ) -> None:
        if id(node) in self._auth_emitted:
            return
        self._auth_emitted.add(id(node))
        self._emit_fact(
            node,
            kind="auth_context",
            attrs={
                "framework": framework,
                "auth_kind": auth_kind,
                "authenticated_context": authenticated_context,
                "ambient_credentials": ambient_credentials,
                "source_name": source_name,
                "uses_input_source_ids": list(uses_input_source_ids or []),
                "guard_observed": guard_observed,
            },
        )

    def _input_ids_from(self, *nodes: ast.AST | None) -> list[str]:
        ids: list[str] = []
        seen: set[str] = set()
        for node in nodes:
            if node is None:
                continue
            for child in ast.walk(node):
                if isinstance(child, ast.Name):
                    binding = self.lookup(child.id)
                    if binding and binding[0] == "input" and binding[1] not in seen:
                        seen.add(binding[1])
                        ids.append(binding[1])
                nested = self._facts_by_node.get(id(child))
                if (
                    nested is not None
                    and nested.kind == "input_source"
                    and nested.id not in seen
                ):
                    seen.add(nested.id)
                    ids.append(nested.id)
        return ids

    def _emit_input_fact(self, node: ast.AST, spec: dict) -> None:
        if id(node) in self._facts_by_node:
            return
        fact = self._emit_fact(
            node,
            kind="input_source",
            attrs={
                "channel": spec["channel"],
                "name": spec.get("name"),
                "user_controlled": True,
                "framework": spec.get("framework"),
                "bound_name": None,
            },
        )
        self._facts_by_node[id(node)] = fact

    def _emit_database_fact(self, node: ast.Call, spec: dict) -> None:
        self._emit_fact(
            node,
            kind="database_query",
            attrs={
                "api": spec["api"],
                "construction": spec["construction"],
                "sql_keywords_present": spec["sql_keywords_present"],
                "uses_input_source_ids": list(spec["uses_input_source_ids"]),
            },
        )

    def _emit_rendered_output_fact(self, node: ast.Call, spec: dict) -> None:
        self._emit_fact(
            node,
            kind="rendered_output",
            attrs={
                "sink": spec["sink"],
                "escaping_observed": spec["escaping_observed"],
                "uses_input_source_ids": list(spec["uses_input_source_ids"]),
            },
        )

    def _emit_network_fact(self, node: ast.Call, spec: dict) -> None:
        attrs = {
            "api": spec["api"],
            "method": spec["method"],
            "destination_kind": spec["destination_kind"],
            "uses_input_source_ids": list(spec["uses_input_source_ids"]),
            "server_side": True,
            "module": spec["module"],
        }
        if spec.get("destination_validated"):
            attrs["destination_validated"] = True
        self._emit_fact(
            node,
            kind="network_request",
            attrs=attrs,
        )

    def _emit_fact(self, node: ast.AST, *, kind: str, attrs: dict) -> Fact:
        location_id = f"L{len(self.locations) + 1}"
        fact_id = f"F{len(self.facts) + 1}"
        location = Location(
            id=location_id,
            path=self.path,
            line=getattr(node, "lineno", None),
            column=getattr(node, "col_offset", None),
            snippet=ast.get_source_segment(self.source, node),
        )
        fact = Fact(
            id=fact_id,
            kind=kind,
            location_id=location_id,
            attrs=attrs,
        )
        self.locations.append(location)
        self.facts.append(fact)
        return fact


def _database_api(func: ast.AST) -> str | None:
    return DB_API_NAMES.get(_callee_name(func) or "")


def _callee_name(func: ast.AST) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _keyword_or_arg(call: ast.Call, name: str, index: int) -> ast.AST | None:
    if len(call.args) > index:
        return call.args[index]
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _http_client_from_chain(chain: list[str]) -> tuple[str, str, str | None] | None:
    if len(chain) >= 2 and chain[-2] in HTTP_MODULE_NAMES and chain[-1] in HTTP_METHOD_APIS:
        module = HTTP_MODULE_NAMES[chain[-2]]
        api = chain[-1]
        method = None if api == "request" else api.upper()
        return (module, api, method)
    if chain[-1] == "urlopen" and (
        chain == ["urlopen"]
        or "urllib" in chain
        or chain[-2:] == ["request", "urlopen"]
    ):
        return ("urllib.request", "urlopen", None)
    if len(chain) >= 2 and chain[-1] in {"HTTPConnection", "HTTPSConnection"}:
        if "client" in chain or "http" in chain:
            return ("http.client", chain[-1], None)
    return None


def _receiver_name(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return node.id
    chain = _attr_chain(node)
    if chain:
        return chain[-1]
    return None


def _is_db_receiver(node: ast.AST | None) -> bool:
    name = _receiver_name(node)
    return name is not None and name.lower() in DB_RECEIVER_NAMES


def _is_orm_raw_receiver(node: ast.AST | None) -> bool:
    name = _receiver_name(node)
    return name is not None and name.lower() in ORM_RAW_RECEIVER_NAMES


def _unwrap_sql_text(node: ast.AST) -> ast.AST:
    if isinstance(node, ast.Call) and node.args:
        chain = _attr_chain(node.func)
        if chain is None and isinstance(node.func, ast.Name):
            chain = [node.func.id]
        if chain and chain[-1] == "text":
            return node.args[0]
    return node


def _sql_expression(call: ast.Call) -> ast.AST | None:
    if not call.args:
        return None
    return _unwrap_sql_text(call.args[0])


def _has_query_params(call: ast.Call) -> bool:
    if len(call.args) >= 2:
        return True
    return any(keyword.arg in PARAM_KEYWORD_NAMES for keyword in call.keywords)


def _string_construction(node: ast.AST | None) -> str:
    if node is None:
        return "unknown"
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return "literal"
    if isinstance(node, ast.JoinedStr):
        return "fstring"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return "concat"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return "format"
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return "format"
    return "unknown"


def _query_construction(sql_expr: ast.AST | None, *, has_params: bool) -> str:
    kind = _string_construction(sql_expr)
    if kind in {"concat", "fstring", "format"}:
        return kind
    if has_params:
        return "parameterized"
    if kind == "literal":
        return "literal"
    return "unknown"


def _has_sql_keywords(node: ast.AST | None) -> bool:
    if node is None:
        return False
    for child in ast.walk(node):
        text = _const_str(child)
        if text and SQL_KEYWORD_PATTERN.search(text):
            return True
    return False


def _is_request_expr(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id == "request"
    chain = _attr_chain(node)
    return chain is not None and chain[-1] == "request"


def _looks_like_template(node: ast.AST) -> bool:
    text = _const_str(node)
    if text is None:
        return False
    lowered = text.lower()
    return lowered.endswith(TEMPLATE_SUFFIXES) or "/" in text


def _looks_like_html(node: ast.AST | None) -> bool:
    if node is None:
        return False
    for child in ast.walk(node):
        text = _const_str(child)
        if text and HTML_MARKUP_PATTERN.search(text):
            return True
    return False


def _has_html_attribute_sink(node: ast.AST | None) -> bool:
    if node is None:
        return False
    for child in ast.walk(node):
        text = _const_str(child)
        if text and HTML_ATTR_SINK_PATTERN.search(text):
            return True
    return False


def _is_urlparse_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    name = _callee_name(node.func)
    if name == "urlparse":
        return True
    chain = _attr_chain(node.func)
    return chain is not None and chain[-1] == "urlparse"


def _if_body_aborts(body: list[ast.stmt]) -> bool:
    for stmt in body:
        if isinstance(stmt, ast.Raise):
            return True
        call: ast.Call | None = None
        if isinstance(stmt, ast.Call):
            call = stmt
        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call = stmt.value
        if call is not None and _callee_name(call.func) in ABORT_APIS:
            return True
    return False


def _urlparse_url_var(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Or):
        return _urlparse_url_var(node.left)
    return None


def _endswith_executable_rejection_test(test: ast.AST) -> bool:
    for node in ast.walk(test):
        if not isinstance(node, ast.Call):
            continue
        policy = _extension_policy_from_endswith(node)
        if policy == "allow_executable":
            return True
    return False


def _is_escape_call(node: ast.AST | None) -> bool:
    if not isinstance(node, ast.Call):
        return False
    name = _callee_name(node.func)
    if name in ESCAPE_APIS:
        return True
    chain = _attr_chain(node.func)
    return chain is not None and chain[-2:] == ["html", "escape"]


def _escaping_observed(node: ast.AST | None) -> str:
    if _is_escape_call(node):
        return "yes"
    kind = _string_construction(node)
    if kind in {"concat", "fstring", "format"}:
        return "no"
    return "unknown"


def _collected_strings(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    texts: list[str] = []
    for child in ast.walk(node):
        text = _const_str(child)
        if text:
            texts.append(text)
    return texts


def _saved_to_web_root(node: ast.AST | None) -> str:
    blob = " ".join(_collected_strings(node)).replace("\\", "/").lower()
    if not blob:
        return "unknown"
    if any(fragment in blob for fragment in WEB_ROOT_FRAGMENTS):
        return "yes"
    if any(fragment in blob for fragment in NON_WEB_ROOT_FRAGMENTS):
        return "no"
    return "unknown"


def _endswith_extensions(call: ast.Call) -> list[str]:
    if not call.args:
        return []
    arg = call.args[0]
    values: list[str] = []
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        values.append(arg.value)
    elif isinstance(arg, (ast.Tuple, ast.List)):
        for elt in arg.elts:
            text = _const_str(elt)
            if text:
                values.append(text)
    return [value.lower() if value.startswith(".") else f".{value.lower()}" for value in values]


def _extension_policy_from_endswith(node: ast.Call) -> str | None:
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "endswith":
        return None
    exts = set(_endswith_extensions(node))
    if not exts:
        return "checked"
    if exts <= IMAGE_EXTENSIONS:
        return "allow_image"
    if exts <= EXECUTABLE_EXTENSIONS:
        return "allow_executable"
    return "checked"


def _jwt_validation_observed(call: ast.Call) -> bool:
    for keyword in call.keywords:
        if (
            keyword.arg == "verify"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is False
        ):
            return False
        if keyword.arg in {"algorithms", "key", "options", "audience", "issuer"}:
            return True
    return len(call.args) >= 2


def _parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    return parents
