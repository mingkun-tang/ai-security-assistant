"""Python file-upload observation. Facts only; no insecure-upload classification."""

from app.engine import analyze, empty_signals
from app.parser.adapter import evidence_to_engine_input
from app.parser.python_parser import parse


def parse_uploads(source, path="uploads.py"):
    doc = parse("python", path, source)
    return doc, [fact for fact in doc.facts if fact.kind == "file_upload"]


def test_flask_request_files_subscript():
    source = """
def view():
    uploaded = request.files["file"]
"""
    _doc, facts = parse_uploads(source)
    assert len(facts) == 1
    assert facts[0].attrs["accepts_upload"] is True
    assert facts[0].attrs["framework"] == "flask"
    assert facts[0].attrs["field_name"] == "file"
    assert facts[0].attrs["saved"] is False


def test_flask_request_files_get():
    source = """
def view():
    request.files.get("avatar")
"""
    _doc, facts = parse_uploads(source)
    assert facts[0].attrs["framework"] == "flask"
    assert facts[0].attrs["field_name"] == "avatar"
    assert facts[0].attrs["accepts_upload"] is True


def test_flask_request_files_attribute():
    source = """
def view():
    return request.files
"""
    _doc, facts = parse_uploads(source)
    assert facts[0].attrs["accepts_upload"] is True
    assert facts[0].attrs["framework"] == "flask"
    assert facts[0].attrs["field_name"] is None


def test_django_request_files():
    source = """
def view(request):
    request.FILES["file"]
    request.FILES.get("file")
"""
    _doc, facts = parse_uploads(source)
    assert len(facts) == 2
    assert all(fact.attrs["framework"] == "django" for fact in facts)
    assert [fact.attrs["field_name"] for fact in facts] == ["file", "file"]


def test_save_literal_destination():
    source = """
def view():
    uploaded = request.files["file"]
    uploaded.save("/var/uploads/photo.jpg")
"""
    _doc, facts = parse_uploads(source)
    save = [fact for fact in facts if fact.attrs["saved"] is True][0]
    assert save.attrs["save_destination_kind"] == "literal"
    assert save.attrs["filename_user_controlled"] == "no"
    assert save.attrs["saved_to_web_root"] == "no"
    assert save.attrs["field_name"] == "file"


def test_save_concatenated_destination():
    source = """
def view():
    uploaded = request.files["file"]
    uploaded.save("static/uploads/" + uploaded.filename)
"""
    _doc, facts = parse_uploads(source)
    save = [fact for fact in facts if fact.attrs["saved"] is True][0]
    assert save.attrs["saved"] is True
    assert save.attrs["save_destination_kind"] == "concat"
    assert save.attrs["filename_user_controlled"] == "yes"
    assert save.attrs["saved_to_web_root"] == "yes"
    assert save.attrs["extension_policy"] == "unchecked"


def test_user_controlled_filename_fstring():
    source = """
def view():
    uploaded = request.files.get("file")
    uploaded.save(f"/tmp/{uploaded.filename}")
"""
    _doc, facts = parse_uploads(source)
    save = [fact for fact in facts if fact.attrs["saved"] is True][0]
    assert save.attrs["save_destination_kind"] == "fstring"
    assert save.attrs["filename_user_controlled"] == "yes"


def test_extension_policy_image_check():
    source = """
def view():
    uploaded = request.files["file"]
    name = uploaded.filename
    if name.endswith(".jpg"):
        uploaded.save("/var/uploads/photo.jpg")
"""
    _doc, facts = parse_uploads(source)
    save = [fact for fact in facts if fact.attrs["saved"] is True][0]
    assert save.attrs["extension_policy"] == "allow_image"


def test_unrelated_files_attribute_ignored():
    source = """
def view(config, storage):
    config.files
    storage.files["file"]
    model.save("/tmp/out")
"""
    _doc, facts = parse_uploads(source)
    assert facts == []


def test_location_cites_path_line_and_snippet():
    source = """
def view():
    request.files["file"]
"""
    doc, facts = parse_uploads(source, path="views.py")
    location = next(loc for loc in doc.locations if loc.id == facts[0].location_id)
    assert location.path == "views.py"
    assert location.line == 3
    assert isinstance(location.column, int)
    assert "request.files" in (location.snippet or "")


def test_file_upload_is_not_classified():
    source = """
def view():
    uploaded = request.files["file"]
    uploaded.save("static/uploads/" + uploaded.filename)
"""
    doc, facts = parse_uploads(source)
    assert {fact.kind for fact in facts} == {"file_upload"}
    data = evidence_to_engine_input(doc)
    assert data["signals"]["upload"]["file_upload_action"] is True
    assert analyze(data).get("vulnerability_indicated") is True
    assert "issue_type" not in data
