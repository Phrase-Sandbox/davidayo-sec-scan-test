"""Tests for upload_finder.find_upload_handlers.

Covers:
- Flask / FastAPI / Django / Go / Express / multer detection
- Cross-language no false positives in plain non-upload code
- Handler function name extraction
"""

from __future__ import annotations

from security_scanner.shared.context.upload_finder import find_upload_handlers
from security_scanner.shared.context.upload_models import UploadHandler

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FLASK_CODE = """\
from flask import Flask, request
app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    f = request.files['file']
    f.save('/tmp/uploaded')
    return 'ok'
"""

FASTAPI_CODE = """\
from fastapi import FastAPI, File, UploadFile
app = FastAPI()

@app.post('/upload')
async def upload_file(file: UploadFile = File(...)):
    content = await file.read()
    return {'filename': file.filename}
"""

DJANGO_CODE = """\
from django.http import HttpResponse

def upload(request):
    if request.method == 'POST':
        uploaded = request.FILES['document']
        with open('/media/' + uploaded.name, 'wb+') as dest:
            for chunk in uploaded.chunks():
                dest.write(chunk)
    return HttpResponse('ok')
"""

EXPRESS_CODE = """\
const express = require('express');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const app = express();

app.post('/upload', upload.single('file'), (req, res) => {
  const file = req.file;
  res.json({ filename: file.originalname });
});
"""

BUSBOY_CODE = """\
const Busboy = require('busboy');

function handleUpload(req, res) {
  const busboy = new Busboy({ headers: req.headers });
  busboy.on('file', (fieldname, file, filename) => {
    file.pipe(fs.createWriteStream('./uploads/' + filename));
  });
  req.pipe(busboy);
}
"""

GO_CODE = """\
package main

import (
    "net/http"
    "io"
    "os"
)

func uploadHandler(w http.ResponseWriter, r *http.Request) {
    file, header, err := r.FormFile("file")
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    defer file.Close()
    dst, _ := os.Create("/uploads/" + header.Filename)
    io.Copy(dst, file)
}
"""

NON_UPLOAD_CODE = """\
def get_user(user_id):
    return db.query('SELECT * FROM users WHERE id = ?', user_id)

def delete_record(record_id):
    db.execute('DELETE FROM records WHERE id = ?', record_id)
"""

JS_NON_UPLOAD_CODE = """\
const express = require('express');
const app = express();

app.get('/users', (req, res) => {
  const users = db.query('SELECT * FROM users');
  res.json(users);
});
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestFlaskDetection:
    def test_detects_flask_request_files(self):
        files = {"views.py": FLASK_CODE}
        handlers = find_upload_handlers(files)
        assert len(handlers) >= 1
        h = handlers[0]
        assert h.file == "views.py"
        assert h.framework == "flask"

    def test_function_name_extracted(self):
        files = {"views.py": FLASK_CODE}
        handlers = find_upload_handlers(files)
        assert any(h.function_name == "upload_file" for h in handlers)


class TestFastAPIDetection:
    def test_detects_upload_file_param(self):
        files = {"main.py": FASTAPI_CODE}
        handlers = find_upload_handlers(files)
        assert len(handlers) >= 1
        frameworks = {h.framework for h in handlers}
        assert "fastapi" in frameworks

    def test_detects_file_ellipsis(self):
        files = {"main.py": FASTAPI_CODE}
        handlers = find_upload_handlers(files)
        # UploadFile and File(...) may both fire
        assert len(handlers) >= 1


class TestDjangoDetection:
    def test_detects_request_FILES(self):
        files = {"views.py": DJANGO_CODE}
        handlers = find_upload_handlers(files)
        assert len(handlers) >= 1
        assert any(h.framework == "django" for h in handlers)


class TestExpressMulterDetection:
    def test_detects_multer(self):
        files = {"app.js": EXPRESS_CODE}
        handlers = find_upload_handlers(files)
        assert len(handlers) >= 1
        frameworks = {h.framework for h in handlers}
        assert "multer" in frameworks

    def test_detects_req_file(self):
        files = {"app.js": EXPRESS_CODE}
        handlers = find_upload_handlers(files)
        assert any(h.framework in ("multer", "express") for h in handlers)


class TestBusboyDetection:
    def test_detects_busboy(self):
        files = {"handler.js": BUSBOY_CODE}
        handlers = find_upload_handlers(files)
        assert len(handlers) >= 1
        assert any(h.framework == "busboy" for h in handlers)


class TestGoDetection:
    def test_detects_r_FormFile(self):
        files = {"main.go": GO_CODE}
        handlers = find_upload_handlers(files)
        assert len(handlers) >= 1
        assert any(h.framework in ("gin", "go_multipart") for h in handlers)

    def test_function_name_extracted(self):
        files = {"main.go": GO_CODE}
        handlers = find_upload_handlers(files)
        assert any(h.function_name == "uploadHandler" for h in handlers)


class TestNoFalsePositives:
    def test_no_handlers_in_plain_python(self):
        files = {"db.py": NON_UPLOAD_CODE}
        handlers = find_upload_handlers(files)
        assert handlers == []

    def test_no_handlers_in_plain_js(self):
        files = {"api.js": JS_NON_UPLOAD_CODE}
        handlers = find_upload_handlers(files)
        assert handlers == []

    def test_empty_files(self):
        assert find_upload_handlers({}) == []

    def test_non_source_files_skipped(self):
        files = {"README.md": "request.files is interesting", "data.json": "{}"}
        handlers = find_upload_handlers(files)
        assert handlers == []


class TestMultipleFiles:
    def test_handles_multiple_languages(self):
        files = {
            "upload.py": FLASK_CODE,
            "upload.js": EXPRESS_CODE,
            "upload.go": GO_CODE,
        }
        handlers = find_upload_handlers(files)
        # Each file should contribute at least one handler
        seen_files = {h.file for h in handlers}
        assert "upload.py" in seen_files
        assert "upload.js" in seen_files
        assert "upload.go" in seen_files

    def test_handler_is_named_tuple(self):
        files = {"views.py": FLASK_CODE}
        handlers = find_upload_handlers(files)
        assert len(handlers) >= 1
        h = handlers[0]
        assert isinstance(h, UploadHandler)
        assert isinstance(h.file, str)
        assert isinstance(h.line, int)
        assert isinstance(h.function_name, str)
        assert isinstance(h.framework, str)
