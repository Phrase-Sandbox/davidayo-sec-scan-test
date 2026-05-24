"""Mini Python deserialization corpus.

Intentionally vulnerable — never deploy this code.
"""

import pickle
import yaml
import base64
from flask import Flask, request

app = Flask(__name__)


# VULN: pickle.loads on attacker-controlled data.
@app.route("/restore", methods=["POST"])
def restore_session():
    raw = request.data
    session = pickle.loads(raw)  # Arbitrary code execution.
    return str(session)


# VULN: yaml.load without Loader=SafeLoader.
@app.route("/config", methods=["POST"])
def load_config():
    content = request.data.decode("utf-8")
    config = yaml.load(content, Loader=yaml.Loader)  # noqa — intentionally vulnerable
    return str(config)


# VULN: base64-decode then pickle.
@app.route("/import", methods=["POST"])
def import_data():
    encoded = request.form.get("data", "")
    raw = base64.b64decode(encoded)
    obj = pickle.loads(raw)  # Arbitrary code execution.
    return str(obj)


# SAFE: yaml.safe_load — true negative.
@app.route("/safe-config", methods=["POST"])
def safe_config():
    content = request.data.decode("utf-8")
    config = yaml.safe_load(content)
    return str(config)
