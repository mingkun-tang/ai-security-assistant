"""Python network-request observation. Facts only; no SSRF classification."""

from app.engine import analyze, empty_signals
from app.parser.adapter import evidence_to_engine_input
from app.parser.python_parser import parse


def parse_network(source, path="net.py"):
    doc = parse("python", path, source)
    return doc, [fact for fact in doc.facts if fact.kind == "network_request"]


def test_requests_get_literal():
    source = """
def fetch():
    requests.get("https://example.com")
"""
    _doc, facts = parse_network(source)
    assert len(facts) == 1
    assert facts[0].attrs == {
        "api": "get",
        "method": "GET",
        "destination_kind": "literal",
        "uses_input_source_ids": [],
        "server_side": True,
        "module": "requests",
    }


def test_requests_get_user_controlled_variable():
    source = """
def fetch():
    url = request.args.get("url")
    requests.get(url)
"""
    doc, facts = parse_network(source)
    input_ids = [fact.id for fact in doc.facts if fact.kind == "input_source"]
    assert facts[0].attrs["destination_kind"] == "from_input"
    assert facts[0].attrs["uses_input_source_ids"] == input_ids
    assert facts[0].attrs["server_side"] is True


def test_fstring_url():
    source = """
def fetch(path):
    requests.get(f"https://example.com/{path}")
"""
    _doc, facts = parse_network(source)
    assert facts[0].attrs["destination_kind"] == "fstring"


def test_concatenated_url():
    source = """
def fetch(path):
    requests.get("https://example.com/" + path)
"""
    _doc, facts = parse_network(source)
    assert facts[0].attrs["destination_kind"] == "concat"


def test_urllib_urlopen():
    source = """
def fetch():
    urllib.request.urlopen("https://example.com")
"""
    _doc, facts = parse_network(source)
    assert facts[0].attrs["api"] == "urlopen"
    assert facts[0].attrs["module"] == "urllib.request"
    assert facts[0].attrs["destination_kind"] == "literal"
    assert facts[0].attrs["server_side"] is True


def test_httpx_get_and_post():
    source = """
def fetch():
    httpx.get("https://example.com")
    httpx.post("https://example.com/items")
    httpx.request("PUT", "https://example.com/items/1")
"""
    _doc, facts = parse_network(source)
    assert [fact.attrs["api"] for fact in facts] == ["get", "post", "request"]
    assert [fact.attrs["method"] for fact in facts] == ["GET", "POST", "PUT"]
    assert all(fact.attrs["module"] == "httpx" for fact in facts)


def test_requests_other_methods():
    source = """
def fetch():
    requests.post("https://example.com")
    requests.put("https://example.com")
    requests.patch("https://example.com")
    requests.delete("https://example.com")
    requests.request("GET", "https://example.com")
"""
    _doc, facts = parse_network(source)
    assert [fact.attrs["api"] for fact in facts] == [
        "post",
        "put",
        "patch",
        "delete",
        "request",
    ]
    assert [fact.attrs["method"] for fact in facts] == [
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "GET",
    ]


def test_http_client_connection():
    source = """
def fetch():
    http.client.HTTPSConnection("example.com")
"""
    _doc, facts = parse_network(source)
    assert facts[0].attrs["api"] == "HTTPSConnection"
    assert facts[0].attrs["module"] == "http.client"
    assert facts[0].attrs["destination_kind"] == "literal"


def test_unrelated_object_get_ignored():
    source = """
def view(config, values):
    config.get("url")
    values.get("path")
    request.args.get("id")
"""
    _doc, facts = parse_network(source)
    assert facts == []


def test_location_cites_path_line_and_snippet():
    source = """
def fetch():
    requests.get("https://example.com")
"""
    doc, facts = parse_network(source, path="client.py")
    location = next(loc for loc in doc.locations if loc.id == facts[0].location_id)
    assert location.path == "client.py"
    assert location.line == 3
    assert isinstance(location.column, int)
    assert "requests.get" in (location.snippet or "")


def test_session_alias_is_observed():
    source = """
def fetch():
    session = requests.Session()
    session.get("https://example.com")
"""
    _doc, facts = parse_network(source)
    assert len(facts) == 1
    assert facts[0].attrs["api"] == "get"
    assert facts[0].attrs["module"] == "requests"
    assert facts[0].attrs["destination_kind"] == "literal"


def test_network_request_is_not_classified():
    source = """
def fetch():
    url = request.args.get("url")
    requests.get(url)
"""
    doc, facts = parse_network(source)
    assert {fact.kind for fact in facts} == {"network_request"}
    data = evidence_to_engine_input(doc)
    assert data["signals"]["network"]["user_controlled_url"] is True
    assert analyze(data).get("vulnerability_indicated") is True
    assert "issue_type" not in data
