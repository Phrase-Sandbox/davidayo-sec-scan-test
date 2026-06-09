"""Tests for upload_context.extract_upload_context.

Covers positive + negative cases for each UploadContext field:
- Extension allowlist present/absent
- MIME-only vs magic-byte
- Server-generated vs preserved filename
- Public vs outside-webroot path
- Size limit present/absent
- Archive extraction with/without containment check
"""

from __future__ import annotations

from security_scanner.shared.context.upload_context import extract_upload_context
from security_scanner.shared.context.upload_models import UploadContext, UploadHandler


def _make_handler(filepath: str = "app.py", line: int = 10) -> UploadHandler:
    return UploadHandler(file=filepath, line=line, function_name="upload", framework="flask")


# ---------------------------------------------------------------------------
# Extension allowlist
# ---------------------------------------------------------------------------


class TestExtensionAllowlist:
    def test_allowlist_detected(self):
        code = """\
def upload():
    f = request.files['file']
    ext = os.path.splitext(f.filename)[1]
    if ext not in ALLOWED_EXTENSIONS:
        abort(400)
    f.save('/data/' + uuid.uuid4().hex + ext)
"""
        ctx = extract_upload_context(_make_handler(), {"app.py": code})
        assert "extension-allowlist" in ctx.validation_signals

    def test_no_validation_when_absent(self):
        code = """\
def upload():
    f = request.files['file']
    f.save('/uploads/' + f.filename)
"""
        ctx = extract_upload_context(_make_handler(), {"app.py": code})
        assert "none" in ctx.validation_signals

    def test_mime_only_when_content_type_checked(self):
        code = """\
def upload():
    f = request.files['file']
    if f.mimetype not in ['image/png', 'image/jpeg']:
        abort(400)
    f.save('/uploads/' + f.filename)
"""
        ctx = extract_upload_context(_make_handler(), {"app.py": code})
        assert "MIME-only" in ctx.validation_signals

    def test_magic_bytes_detected(self):
        code = """\
import magic
def upload():
    f = request.files['file']
    header = f.read(16)
    mime = magic.from_buffer(header, mime=True)
    if mime not in ['image/png']:
        abort(400)
    f.seek(0)
    f.save('/data/' + secrets.token_hex(16))
"""
        ctx = extract_upload_context(_make_handler(), {"app.py": code})
        assert "magic-bytes" in ctx.validation_signals


# ---------------------------------------------------------------------------
# Filename handling
# ---------------------------------------------------------------------------


class TestFilenameHandling:
    def test_server_generated_uuid(self):
        code = """\
import uuid
def upload():
    f = request.files['file']
    safe_name = uuid.uuid4().hex + '.bin'
    f.save('/data/' + safe_name)
"""
        ctx = extract_upload_context(_make_handler(), {"app.py": code})
        assert "server-generated" in ctx.filename_handling

    def test_server_generated_secrets(self):
        code = """\
import secrets
def upload():
    f = request.files['file']
    name = secrets.token_hex(16)
    f.save('/data/' + name)
"""
        ctx = extract_upload_context(_make_handler(), {"app.py": code})
        assert "server-generated" in ctx.filename_handling

    def test_preserved_filename_detected(self):
        code = """\
def upload():
    f = request.files['file']
    f.save('/uploads/' + f.filename)
"""
        ctx = extract_upload_context(_make_handler(), {"app.py": code})
        assert "preserved-user-filename" in ctx.filename_handling

    def test_unknown_when_no_hint(self):
        code = """\
def upload():
    f = request.files['file']
    data = f.read()
"""
        ctx = extract_upload_context(_make_handler(), {"app.py": code})
        assert "unknown" in ctx.filename_handling


# ---------------------------------------------------------------------------
# Storage path
# ---------------------------------------------------------------------------


class TestStoragePath:
    def test_public_path_detected(self):
        code = """\
def upload():
    f = request.files['file']
    f.save(os.path.join('static', f.filename))
"""
        ctx = extract_upload_context(_make_handler(), {"app.py": code})
        assert "public-path" in ctx.storage_signals

    def test_outside_webroot_detected(self):
        code = """\
UPLOAD_FOLDER = '/var/data/uploads'
def upload():
    f = request.files['file']
    f.save(os.path.join(UPLOAD_FOLDER, uuid.uuid4().hex))
"""
        ctx = extract_upload_context(_make_handler(), {"app.py": code})
        assert "outside-webroot" in ctx.storage_signals

    def test_unknown_when_no_hint(self):
        code = """\
def upload():
    f = request.files['file']
    content = f.read()
"""
        ctx = extract_upload_context(_make_handler(), {"app.py": code})
        assert "unknown" in ctx.storage_signals


# ---------------------------------------------------------------------------
# Size limits
# ---------------------------------------------------------------------------


class TestSizeLimits:
    def test_size_limit_detected(self):
        code = """\
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

def upload():
    f = request.files['file']
    f.save('/data/' + f.filename)
"""
        ctx = extract_upload_context(_make_handler(), {"app.py": code})
        assert "yes" in ctx.size_limit_signals

    def test_no_size_limit_detected(self):
        code = """\
def upload():
    f = request.files['file']
    f.save('/uploads/' + f.filename)
"""
        ctx = extract_upload_context(_make_handler(), {"app.py": code})
        assert "none" in ctx.size_limit_signals


# ---------------------------------------------------------------------------
# Archive extraction
# ---------------------------------------------------------------------------


class TestArchiveExtraction:
    def test_zip_extractall_without_containment(self):
        code = """\
import zipfile
def upload():
    f = request.files['file']
    with zipfile.ZipFile(f) as zf:
        zf.extractall('/tmp/extract')
"""
        ctx = extract_upload_context(_make_handler(), {"app.py": code})
        assert "archive-extract" in ctx.post_processing_signals

    def test_zip_extractall_with_containment(self):
        code = """\
import zipfile, os
def upload():
    f = request.files['file']
    with zipfile.ZipFile(f) as zf:
        for member in zf.namelist():
            dest = os.path.realpath(os.path.join('/safe/', member))
            if os.path.commonpath(['/safe/', dest]) != '/safe/':
                raise ValueError('zip slip')
            zf.extract(member, '/safe/')
"""
        ctx = extract_upload_context(_make_handler(), {"app.py": code})
        assert "archive-extract-with-containment" in ctx.post_processing_signals

    def test_risky_yaml_parser(self):
        code = """\
import yaml
def upload():
    f = request.files['file']
    data = yaml.load(f, Loader=yaml.Loader)
"""
        ctx = extract_upload_context(_make_handler(), {"app.py": code})
        assert "risky-parser" in ctx.post_processing_signals

    def test_no_post_processing(self):
        code = """\
def upload():
    f = request.files['file']
    f.save('/data/' + uuid.uuid4().hex)
"""
        ctx = extract_upload_context(_make_handler(), {"app.py": code})
        assert "none" in ctx.post_processing_signals


# ---------------------------------------------------------------------------
# Overall summary
# ---------------------------------------------------------------------------


class TestOverallSummary:
    def test_summary_contains_key_labels(self):
        code = """\
def upload():
    f = request.files['file']
    f.save('/uploads/' + f.filename)
"""
        ctx = extract_upload_context(_make_handler(), {"app.py": code})
        assert "Validation:" in ctx.overall_summary
        assert "Naming:" in ctx.overall_summary
        assert "Storage:" in ctx.overall_summary
        assert "Limits:" in ctx.overall_summary
        assert "Processing:" in ctx.overall_summary

    def test_never_raises_on_bad_input(self):
        # Should not raise even with completely empty content
        handler = _make_handler("nosuchfile.py", 1)
        ctx = extract_upload_context(handler, {})
        assert isinstance(ctx, UploadContext)

    def test_returns_upload_context_instance(self):
        code = "def upload():\n    f = request.files['file']\n"
        ctx = extract_upload_context(_make_handler(), {"app.py": code})
        assert isinstance(ctx, UploadContext)
