"""Mini Python upload app — planted upload vulnerabilities for truth-set."""

import os
import secrets
import uuid

from flask import Flask, abort, request

app = Flask(__name__)


# -----------------------------------------------------------------------
# PLANTED BUG 1 (lines 15-25):
# Extension-only check via endswith('.png') — attacker can use '.php.png'
# Filename is preserved and stored under static/uploads/ (public path)
# -----------------------------------------------------------------------
@app.route("/upload1", methods=["POST"])
def upload_ext_only():  # line 15
    f = request.files["file"]
    if not f.filename.endswith(".png"):  # extension-only check
        abort(400)
    # Preserved attacker filename saved to public path
    dest = os.path.join("static", "uploads", f.filename)
    f.save(dest)
    return "ok"  # line 22


# -----------------------------------------------------------------------
# PLANTED BUG 2 (lines 28-38):
# MIME-only check via content_type — attacker sets Content-Type: image/png
# -----------------------------------------------------------------------
@app.route("/upload2", methods=["POST"])
def upload_mime_only():  # line 28
    f = request.files["file"]
    if f.content_type not in ["image/png", "image/jpeg"]:
        abort(400)
    # MIME validated but no extension or magic-byte check
    save_path = "/var/uploads/" + f.filename
    f.save(save_path)
    return "ok"  # line 35


# -----------------------------------------------------------------------
# PLANTED BUG 3 (lines 41-51):
# Attacker filename preserved directly into a static/uploads/ path
# No validation at all
# -----------------------------------------------------------------------
@app.route("/upload3", methods=["POST"])
def upload_preserved_filename():  # line 41
    f = request.files["file"]
    # Attacker-controlled filename directly in public web path — no rename
    filepath = os.path.join("static", "uploads", f.filename)
    f.save(filepath)
    return {"path": filepath}  # line 46


# -----------------------------------------------------------------------
# NEGATIVE CASE (lines 52-70):
# Proper: magic-byte check + UUID filename + outside-webroot storage
# -----------------------------------------------------------------------
UPLOAD_FOLDER = "/var/data/uploads"
ALLOWED_MAGIC = {b"\x89PNG", b"\xff\xd8\xff"}  # PNG, JPEG magic bytes


@app.route("/upload_safe", methods=["POST"])
def upload_safe():  # line 56
    f = request.files["file"]
    header = f.read(4)
    if not any(header.startswith(m) for m in ALLOWED_MAGIC):
        abort(400, "Invalid file type")
    f.seek(0)
    # Server-generated filename — attacker has no control
    safe_name = secrets.token_hex(16) + ".bin"
    dest = os.path.join(UPLOAD_FOLDER, safe_name)
    f.save(dest)
    return {"id": safe_name}  # line 65


# -----------------------------------------------------------------------
# NEGATIVE CASE 2 (lines 67-80):
# Proper: extension allowlist + server-generated name + outside webroot
# -----------------------------------------------------------------------
ALLOWED_EXTENSIONS = {"png", "jpg", "gif"}


@app.route("/upload_safe2", methods=["POST"])
def upload_safe2():  # line 70
    f = request.files["file"]
    ext = os.path.splitext(f.filename)[1].lower().lstrip(".")
    if ext not in ALLOWED_EXTENSIONS:
        abort(400)
    safe_name = uuid.uuid4().hex + "." + ext
    dest = os.path.join("/var/data/uploads", safe_name)
    f.save(dest)
    return {"filename": safe_name}  # line 77
