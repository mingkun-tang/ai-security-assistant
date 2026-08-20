"""Python rendered-output observation. Facts only; no XSS classification."""

from app.engine import analyze, empty_signals
from app.parser.adapter import evidence_to_engine_input
from app.parser.python_parser import parse


def parse_renders(source, path="views.py"):
    doc = parse("python", path, source)
    return doc, [fact for fact in doc.facts if fact.kind == "rendered_output"]


def test_flask_render_template():
    source = """
def view():
    return render_template("profile.html", name=name)
"""
    _doc, facts = parse_renders(source)
    assert len(facts) == 1
    assert facts[0].attrs["sink"] == "template"
    assert facts[0].attrs["escaping_observed"] == "unknown"
    assert facts[0].attrs["uses_input_source_ids"] == []


def test_flask_render_template_string():
    source = """
def view():
    return render_template_string("<p>{{ name }}</p>", name=name)
"""
    _doc, facts = parse_renders(source)
    assert facts[0].attrs["sink"] == "template"


def test_markup_is_unescaped_html():
    source = """
def view():
    return Markup(body)
"""
    _doc, facts = parse_renders(source)
    assert facts[0].attrs["sink"] == "html"
    assert facts[0].attrs["escaping_observed"] == "no"


def test_django_mark_safe():
    source = """
def view():
    return mark_safe(body)
"""
    _doc, facts = parse_renders(source)
    assert facts[0].attrs["sink"] == "html"
    assert facts[0].attrs["escaping_observed"] == "no"


def test_django_render():
    source = """
def view(request):
    return render(request, "index.html", {"q": q})
"""
    _doc, facts = parse_renders(source)
    assert len(facts) == 1
    assert facts[0].attrs["sink"] == "template"
    assert facts[0].attrs["escaping_observed"] == "unknown"


def test_template_object_render():
    source = """
def view():
    return template.render(name=name)
"""
    _doc, facts = parse_renders(source)
    assert facts[0].attrs["sink"] == "template"


def test_http_response_html():
    source = """
def view():
    return HttpResponse(f"<h1>{title}</h1>")
"""
    _doc, facts = parse_renders(source)
    assert facts[0].attrs["sink"] == "html"
    assert facts[0].attrs["escaping_observed"] == "no"


def test_http_response_escaped():
    source = """
def view():
    return HttpResponse(html.escape(title))
"""
    _doc, facts = parse_renders(source)
    assert facts[0].attrs["escaping_observed"] == "yes"


def test_non_render_ignored():
    source = """
def view(widget, image):
    widget.render()
    image.render()
    HttpResponse("ok")
    render(image)
"""
    _doc, facts = parse_renders(source)
    assert facts == []


def test_location_cites_path_line_and_snippet():
    source = """
def view():
    return render_template("index.html")
"""
    doc, facts = parse_renders(source, path="app.py")
    location = next(loc for loc in doc.locations if loc.id == facts[0].location_id)
    assert location.path == "app.py"
    assert location.line == 3
    assert isinstance(location.column, int)
    assert "render_template" in (location.snippet or "")


def test_uses_input_source_ids_without_classifying():
    source = """
def view():
    name = request.args.get("name")
    return render_template("hello.html", name=name)
"""
    doc, facts = parse_renders(source)
    input_ids = [fact.id for fact in doc.facts if fact.kind == "input_source"]
    assert facts[0].kind == "rendered_output"
    assert facts[0].attrs["uses_input_source_ids"] == input_ids
    data = evidence_to_engine_input(doc)
    assert data["signals"]["rendering"]["reflected_output"] is True
    assert analyze(data).get("vulnerability_indicated") is True
    assert "issue_type" not in data


def test_markup_of_input_is_still_not_a_finding():
    source = """
def view():
    body = request.args.get("body")
    return Markup(body)
"""
    doc, facts = parse_renders(source)
    assert facts[0].attrs["escaping_observed"] == "no"
    assert facts[0].attrs["uses_input_source_ids"]
    data = evidence_to_engine_input(doc)
    assert data["signals"]["rendering"]["missing_escaping"] is True
    assert analyze(data).get("vulnerability_indicated") is True
