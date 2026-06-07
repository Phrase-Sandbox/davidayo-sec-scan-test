"""Comprehensive vulnerable Python fixture for scanner quality-gate tests.

Each function plants ONE distinct OWASP-mapped vulnerability.
Nine mandatory findings are defined in
  tests/integration/truthset/multi-vuln-9/truth.yaml
covering A01–A08:2021 and two SECRET-001 entries.

DO NOT USE IN PRODUCTION.  This file exists solely to ensure the scanner
reliably finds >= 9 issues on a known payload.
"""
import hashlib
import os
import pickle
import random
import subprocess
import xml.etree.ElementTree as ET

import yaml

# ── Finding #1 ────────────────────────────────────────────────────────────────
# SECRET-001 (A02:2021) — hardcoded database password
DB_PASSWORD = "prod-db-secret-9x2kZ"  # noqa: S105

# ── Finding #2 ────────────────────────────────────────────────────────────────
# SECRET-001 (A02:2021) — hardcoded API key
STRIPE_SECRET_KEY = "sk_live_abc123XYZ789defGHI012"  # noqa: S105


# ── Finding #3 ────────────────────────────────────────────────────────────────
# A03:2021 — SQL injection via f-string interpolation
def get_user(conn, user_id: str):
    return conn.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    ).fetchone()


# ── Finding #4 ────────────────────────────────────────────────────────────────
# A03:2021 — SQL injection via % string formatting
def search_products(conn, keyword: str):
    return conn.execute(
        "SELECT * FROM products WHERE name LIKE '%%%s%%'" % keyword
    ).fetchall()


# ── Finding #5 ────────────────────────────────────────────────────────────────
# A03:2021 — Command injection via os.system with user input
def ping_host(host: str) -> int:
    return os.system(f"ping -c 1 {host}")


# ── Finding #6 ────────────────────────────────────────────────────────────────
# A03:2021 — Command injection via subprocess with shell=True
def generate_report(report_name: str) -> str:
    result = subprocess.run(
        "generate_report " + report_name, shell=True, capture_output=True, text=True
    )
    return result.stdout


# ── Finding #7 ────────────────────────────────────────────────────────────────
# A02:2021 — Weak cryptography: MD5 used for password hashing
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


# ── Finding #8 ────────────────────────────────────────────────────────────────
# A02:2021 — Insecure random for session token generation
def generate_session_token() -> str:
    token = random.randint(0, 9999999)  # not cryptographically secure
    return f"sess_{token}"


# ── Finding #9 ────────────────────────────────────────────────────────────────
# A08:2021 — Insecure deserialization via pickle.loads
def load_user_preferences(raw_bytes: bytes) -> dict:
    return pickle.loads(raw_bytes)  # noqa: S301


# ── Finding #10 (bonus) ───────────────────────────────────────────────────────
# A05:2021 — XXE via xml.etree.ElementTree (not defusedxml)
def parse_config(xml_path: str):
    return ET.parse(xml_path).getroot()


# ── Finding #11 (bonus) ───────────────────────────────────────────────────────
# A08:2021 — yaml.load without SafeLoader allows arbitrary object instantiation
def load_app_config(config_path: str) -> dict:
    with open(config_path) as f:
        return yaml.load(f)  # noqa: S506
