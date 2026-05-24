"""Mini archive-upload app — planted archive/parser vulnerabilities for truth-set."""

from flask import Flask, request, abort
import zipfile
import tarfile
import yaml
import os

app = Flask(__name__)

EXTRACT_BASE = '/tmp/extracted/'


# -----------------------------------------------------------------------
# PLANTED BUG 1 (lines 18-30):
# zipfile.extractall on uploaded zip without child-path validation (zip-slip)
# -----------------------------------------------------------------------
@app.route('/extract_zip', methods=['POST'])
def extract_zip():                                              # line 18
    f = request.files['archive']
    try:
        with zipfile.ZipFile(f) as zf:
            zf.extractall(EXTRACT_BASE)                        # line 22 — zip-slip
    except zipfile.BadZipFile:
        abort(400, 'Invalid zip file')
    return {'status': 'extracted'}                             # line 25


# -----------------------------------------------------------------------
# PLANTED BUG 2 (lines 30-42):
# tarfile.extractall on uploaded tar without child-path validation (tar-slip)
# -----------------------------------------------------------------------
@app.route('/extract_tar', methods=['POST'])
def extract_tar():                                             # line 30
    f = request.files['archive']
    try:
        with tarfile.open(fileobj=f) as tf:
            tf.extractall(EXTRACT_BASE)                        # line 34 — tar-slip
    except tarfile.TarError:
        abort(400, 'Invalid tar file')
    return {'status': 'extracted'}                             # line 37


# -----------------------------------------------------------------------
# PLANTED BUG 3 (lines 42-55):
# yaml.load with unsafe Loader on uploaded YAML content
# -----------------------------------------------------------------------
@app.route('/parse_yaml', methods=['POST'])
def parse_yaml():                                              # line 42
    f = request.files['config']
    content = f.read()
    try:
        data = yaml.load(content, Loader=yaml.Loader)          # line 46 — unsafe
    except yaml.YAMLError as e:
        abort(400, str(e))
    return {'keys': list(data.keys()) if isinstance(data, dict) else []}   # line 49


# -----------------------------------------------------------------------
# NEGATIVE CASE (lines 54-72):
# Safe extraction with os.path.commonpath containment check
# -----------------------------------------------------------------------
@app.route('/extract_zip_safe', methods=['POST'])
def extract_zip_safe():                                        # line 54
    f = request.files['archive']
    try:
        with zipfile.ZipFile(f) as zf:
            for member in zf.infolist():
                # Resolve destination and verify containment
                dest = os.path.realpath(
                    os.path.join(EXTRACT_BASE, member.filename)
                )
                # Containment check — prevents zip-slip
                if os.path.commonpath([EXTRACT_BASE, dest]) != os.path.realpath(EXTRACT_BASE):
                    abort(400, f'Zip slip detected for {member.filename}')
                zf.extract(member, EXTRACT_BASE)
    except zipfile.BadZipFile:
        abort(400, 'Invalid zip file')
    return {'status': 'extracted'}                             # line 68


# -----------------------------------------------------------------------
# NEGATIVE CASE 2 (lines 72-80):
# yaml.safe_load — safe
# -----------------------------------------------------------------------
@app.route('/parse_yaml_safe', methods=['POST'])
def parse_yaml_safe():                                         # line 72
    f = request.files['config']
    content = f.read()
    try:
        data = yaml.safe_load(content)                         # line 76 — safe
    except yaml.YAMLError as e:
        abort(400, str(e))
    return {'keys': list(data.keys()) if isinstance(data, dict) else []}
