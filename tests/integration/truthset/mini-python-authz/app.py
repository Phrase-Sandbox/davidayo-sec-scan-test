"""Mini Flask app with planted authz/IDOR vulnerabilities.

Vulnerabilities are annotated in truth.yaml. This file is intentionally
vulnerable for testing purposes — never deploy this code.
"""

from flask import Flask, abort, jsonify, request, session

app = Flask(__name__)
app.secret_key = "test-secret"

# Fake database.
USERS = {
    1: {"id": 1, "name": "alice", "role": "user"},
    2: {"id": 2, "name": "bob", "role": "admin"},
}
DOCUMENTS = {
    1: {"id": 1, "owner_id": 1, "title": "Alice doc", "content": "Secret!"},
    2: {"id": 2, "owner_id": 2, "title": "Bob doc", "content": "Also secret."},
}
PROFILES = {
    1: {"id": 1, "email": "alice@example.com", "phone": "555-0001"},
    2: {"id": 2, "email": "bob@example.com", "phone": "555-0002"},
}


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        abort(401)
    return USERS.get(user_id)


# VULN: IDOR-01 — document accessible by any authenticated user (no ownership check).
@app.route("/documents/<int:doc_id>", methods=["GET"])
def get_document(doc_id):
    # BUG: missing 'if doc["owner_id"] != current_user["id"]: abort(403)'
    doc = DOCUMENTS.get(doc_id)
    if not doc:
        abort(404)
    return jsonify(doc)


# VULN: IDOR-02 — profile update without auth; any user can update any profile.
@app.route("/profiles/<int:profile_id>", methods=["PUT"])
def update_profile(profile_id):
    # BUG: no authentication check at all (missing @login_required or session check)
    profile = PROFILES.get(profile_id)
    if not profile:
        abort(404)
    data = request.get_json()
    profile.update(data)
    return jsonify(profile)


# VULN: AUTH-01 — role bypass: admin check reads from user-controlled request body.
@app.route("/admin/action", methods=["POST"])
def admin_action():
    # BUG: role from body instead of from session/trusted source
    data = request.get_json()
    role = data.get("role", "user")  # attacker can pass role=admin
    if role != "admin":
        abort(403)
    return jsonify({"status": "done"})


# VULN: AUTH-02 — missing decorator on sensitive delete endpoint.
@app.route("/documents/<int:doc_id>", methods=["DELETE"])
def delete_document(doc_id):
    # BUG: no authentication check — any unauthenticated user can delete
    doc = DOCUMENTS.pop(doc_id, None)
    if not doc:
        abort(404)
    return jsonify({"deleted": doc_id})


# Safe endpoint (true negative — has ownership check).
@app.route("/my-documents", methods=["GET"])
def my_documents():
    current_user = get_current_user()
    docs = [d for d in DOCUMENTS.values() if d["owner_id"] == current_user["id"]]
    return jsonify(docs)


# VULN: IDOR-03 — nested resource: invoice accessible by any user.
@app.route("/users/<int:user_id>/invoices", methods=["GET"])
def get_user_invoices(user_id):
    # BUG: no check that user_id == current_user["id"]
    # Any logged-in user can see any user's invoices
    current_user = get_current_user()
    # Missing: if user_id != current_user["id"]: abort(403)
    invoices = []  # would query DB in real app
    return jsonify({"user_id": user_id, "invoices": invoices})
