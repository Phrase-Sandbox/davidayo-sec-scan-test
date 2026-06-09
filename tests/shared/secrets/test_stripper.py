"""BR-003 mandatory coverage suite for the secret stripper.

Every test in ``TestBR003Coverage`` exists because §4.1 BR-003 says so:
    "A unit test suite must confirm each type in this list is stripped before
     any Claude API call."

All six tests must pass before this phase is considered complete.
Test fixtures use realistic FAKE credentials — never real ones.
"""

from __future__ import annotations

import os
import time

import pytest

from security_scanner.shared.secrets.stripper import (
    REDACTED,
    SecretStripResult,
    strip,
)

# --- API shape ----------------------------------------------------------------


def test_returns_secret_strip_result_dataclass():
    result = strip({"file.py": "x = 1"})
    assert isinstance(result, SecretStripResult)
    assert isinstance(result.cleaned_files, dict)
    assert isinstance(result.secrets_found, bool)
    assert isinstance(result.affected_files, list)


def test_clean_files_pass_through_unchanged():
    files = {"a.py": "x = 1\n", "b.txt": "hello world\n"}
    result = strip(files)
    assert result.cleaned_files == files
    assert result.secrets_found is False
    assert result.affected_files == []


def test_input_dict_is_not_mutated():
    files = {"a.py": 'KEY = "ghp_' + "X" * 36 + '"'}
    original_value = files["a.py"]
    strip(files)
    assert files["a.py"] == original_value


def test_affected_files_only_contains_files_with_secrets():
    files = {
        "clean.py": "def hello(): return 1\n",
        "secret.py": 'TOKEN = "ghp_' + "X" * 36 + '"',
    }
    result = strip(files)
    assert result.affected_files == ["secret.py"]
    assert result.secrets_found is True


# --- BR-003 minimum coverage — six MANDATORY tests ----------------------------


class TestBR003Coverage:
    """Each test corresponds to one item in the BR-003 minimum coverage list."""

    def test_br003_type_1_generic_high_entropy_api_key(self):
        # 28-char random-looking string in a quoted assignment. High Shannon
        # entropy (~4.7 bits/char) — above the 4.0 threshold.
        fake_key = "aB3xQ7nP9kL2mZ8vR5tY1wE4uI6o"
        content = f'API_KEY = "{fake_key}"'
        result = strip({"app.py": content})
        assert result.secrets_found is True
        assert fake_key not in result.cleaned_files["app.py"]
        assert REDACTED in result.cleaned_files["app.py"]

    def test_br003_type_2_oauth_token(self):
        fake_token = "abc123XYZ_4567890def_GHIjklMNOpqrsTUVwxyZ"
        content = f"Authorization: Bearer {fake_token}\n"
        result = strip({"client.py": content})
        assert result.secrets_found is True
        assert fake_token not in result.cleaned_files["client.py"]
        # The "Bearer" context word is preserved for the analysis model.
        assert "Bearer" in result.cleaned_files["client.py"]

    def test_br003_type_3_jwt(self):
        # Canonical jwt.io example JWT (HS256, fake payload, fake signature).
        fake_jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        content = f"const token = '{fake_jwt}';"
        result = strip({"app.js": content})
        assert result.secrets_found is True
        assert fake_jwt not in result.cleaned_files["app.js"]

    def test_br003_type_3_jwt_with_bearer_prefix(self):
        # Variant: Bearer-prefixed JWT (covers the spec's "Bearer prefix + ..." wording).
        fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.dummy_signature_value_for_test"
        content = f"Authorization: Bearer {fake_jwt}"
        result = strip({"req.txt": content})
        assert result.secrets_found is True
        assert fake_jwt not in result.cleaned_files["req.txt"]

    def test_br003_type_4_pem_private_key(self):
        fake_pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA1aBcDeFgHiJkLmNoPqRsTuVwXyZ\n"
            "1234567890abcdefghijklmnopqrstuvwxyz==\n"
            "-----END RSA PRIVATE KEY-----"
        )
        content = f"# Server signing key\n{fake_pem}\n# end of key\n"
        result = strip({"server_key.pem": content})
        assert result.secrets_found is True
        cleaned = result.cleaned_files["server_key.pem"]
        # Both the body and the BEGIN/END markers are redacted as a single unit.
        assert "MIIEowIBAAKCAQEA" not in cleaned
        assert "BEGIN RSA PRIVATE KEY" not in cleaned
        assert REDACTED in cleaned

    def test_br003_type_4_pem_variants(self):
        # The PEM regex must cover *all* common label variants:
        # "RSA PRIVATE", "EC PRIVATE", "PRIVATE" (PKCS#8), "OPENSSH PRIVATE".
        for label in ("RSA PRIVATE", "EC PRIVATE", "PRIVATE", "OPENSSH PRIVATE"):
            fake_pem = (
                f"-----BEGIN {label} KEY-----\n"
                "AbCdEfGhIjKlMnOpQrStUvWxYz==\n"
                f"-----END {label} KEY-----"
            )
            result = strip({f"{label.replace(' ', '_')}.pem": fake_pem})
            assert result.secrets_found is True, f"Failed to strip {label} key"
            assert "AbCdEfGhIjKlMnOpQrStUvWxYz" not in next(iter(result.cleaned_files.values()))

    def test_br003_type_5_config_password_secret_token(self):
        contents = {
            ".env": "password=hunter2_secure_pwd",
            "config.yaml": 'secret: "topsecret_value_42"',
            "settings.ini": "api_key = my_api_key_abcdef_123456",
            "tokens.cfg": "auth_token: bearer_xyz_abc_987654",
        }
        result = strip(contents)
        assert result.secrets_found is True
        assert "hunter2_secure_pwd" not in result.cleaned_files[".env"]
        assert "topsecret_value_42" not in result.cleaned_files["config.yaml"]
        assert "my_api_key_abcdef_123456" not in result.cleaned_files["settings.ini"]
        assert "bearer_xyz_abc_987654" not in result.cleaned_files["tokens.cfg"]
        assert set(result.affected_files) == set(contents)
        # Key + separator preserved so the analysis model still has context.
        assert "password=" in result.cleaned_files[".env"]
        assert "secret:" in result.cleaned_files["config.yaml"]

    @pytest.mark.parametrize(
        ("filename", "fake_credential"),
        [
            ("github_classic_pat.py", "ghp_" + "X" * 36),
            ("github_oauth.py", "gho_" + "Y" * 36),
            ("github_user_to_server.py", "ghu_" + "Z" * 36),
            ("github_server_to_server.py", "ghs_" + "W" * 36),
            ("github_refresh.py", "ghr_" + "V" * 36),
            ("github_fine_grained.py", "github_pat_" + "U" * 82),
            ("anthropic.py", "sk-ant-api03-" + "A" * 40 + "_test_xyz"),
            ("aws_long_lived.py", "AKIA" + "I" * 16),
            ("aws_sts_temporary.py", "ASIA" + "J" * 16),
        ],
    )
    def test_br003_type_6_github_anthropic_aws_credentials(
        self, filename: str, fake_credential: str
    ):
        content = f'TOKEN = "{fake_credential}"'
        result = strip({filename: content})
        assert result.secrets_found is True, (
            f"Failed to detect credential format used in {filename}"
        )
        assert fake_credential not in result.cleaned_files[filename]
        assert REDACTED in result.cleaned_files[filename]


# --- False-positive resistance ------------------------------------------------


def test_short_strings_not_redacted():
    content = 'name = "Alice"\ngreeting = "Hello"\n'
    result = strip({"app.py": content})
    assert result.cleaned_files["app.py"] == content
    assert result.secrets_found is False


def test_low_entropy_long_strings_not_redacted():
    # 30 identical chars — entropy is 0, well below the 4.0 threshold.
    content = 'placeholder = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n'
    result = strip({"app.py": content})
    assert result.cleaned_files["app.py"] == content
    assert result.secrets_found is False


def test_urls_with_punctuation_not_falsely_matched():
    content = (
        '"https://owasp.org/Top10/A03_2021-Injection/"\n'
        'docs = "https://api.example.com/v1/users/list"\n'
    )
    result = strip({"refs.py": content})
    # URLs contain '.' and ':' which are not in the high-entropy char class,
    # so the QUOTED_STRING_PATTERN will not flag them.
    assert result.cleaned_files["refs.py"] == content


# --- False-positive suppression for runtime-bound values --------------------


def test_token_assigned_from_function_call_is_not_flagged():
    """`token = input(...)` is a runtime input, not a hardcoded credential."""
    content = 'token = input("Token: ").strip()\n'
    result = strip({"cli.py": content})
    assert result.secrets_found is False
    assert result.cleaned_files["cli.py"] == content


def test_token_assigned_from_attribute_lookup_is_not_flagged():
    """Assignment from `obj.attr` reads a runtime value, not a literal."""
    content = "token = _CallbackHandler.received_token\n"
    result = strip({"cli.py": content})
    assert result.secrets_found is False
    assert result.cleaned_files["cli.py"] == content


def test_unquoted_low_entropy_token_value_is_not_flagged():
    """`token = some_identifier` is a variable reference, not a credential."""
    content = "token = some_identifier\n"
    result = strip({"cli.py": content})
    assert result.secrets_found is False
    assert result.cleaned_files["cli.py"] == content


def test_token_from_indexed_lookup_is_not_flagged():
    """`token = params.get("token", [None])[0]` is runtime indexing."""
    content = 'token = params.get("token", [None])[0]\n'
    result = strip({"cli.py": content})
    assert result.secrets_found is False
    assert result.cleaned_files["cli.py"] == content


def test_all_caps_constant_in_code_file_is_not_flagged():
    """`HTTP_401_UNAUTHORIZED` is a Python constant reference, not a credential."""
    content = "response.status_code = status.HTTP_401_UNAUTHORIZED\n"
    result = strip({"app.py": content})
    assert result.secrets_found is False
    assert result.cleaned_files["app.py"] == content


def test_docstring_prose_in_code_file_is_not_flagged():
    """Long English words in docstrings have no digits — shape check kills them."""
    content = '"""Local-dev bypass: when settings.bypass is enabled."""\n'
    result = strip({"app.py": content})
    assert result.secrets_found is False
    assert result.cleaned_files["app.py"] == content


def test_credential_forgotten_in_comment_is_still_flagged():
    """A forgotten real-shape key in a comment must still be redacted."""
    content = "# leftover: sk_test_4eC39HqLyjWDarjtT1zdp7dc\n"
    result = strip({"app.py": content})
    assert result.secrets_found is True
    assert "sk_test_4eC39HqLyjWDarjtT1zdp7dc" not in result.cleaned_files["app.py"]


# --- Performance (§10) -------------------------------------------------------


@pytest.mark.skipif(
    os.getenv("RUNNER_ENVIRONMENT") == "github-hosted",
    reason=(
        "§10 wall-clock perf NFR is unreliable on GitHub's shared 2-vCPU "
        "hosted runners (false ~20s readings). Still enforced when run "
        "locally and on the Phrase self-hosted Launchpad runner "
        "(RUNNER_ENVIRONMENT != 'github-hosted')."
    ),
)
def test_strips_500_file_repo_under_10_seconds():
    """BR-003 / §10: pre-scan completes in <10 s for a 500-file repo."""
    base = "def f():\n    return 42\n" * 50  # ~1.2 KB per file
    files = {f"src/file_{i}.py": base for i in range(500)}
    # Sprinkle a real-looking secret into every 50th file.
    fake_key = "aB3xQ7nP9kL2mZ8vR5tY1wE4uI6oH"
    for i in range(0, 500, 50):
        files[f"src/file_{i}.py"] += f'\nAPI_KEY = "{fake_key}"\n'

    start = time.monotonic()
    result = strip(files)
    elapsed = time.monotonic() - start

    assert elapsed < 10.0, f"strip() took {elapsed:.2f}s — must be <10s per §10"
    assert result.secrets_found is True
    assert len(result.affected_files) == 10


# --- Logging safety (§12 "What NOT to Do" #1) --------------------------------


def test_secret_value_never_appears_in_log_output(capsys):
    fake_anthropic_key = "sk-ant-api03-" + "A" * 40
    content = f'KEY = "{fake_anthropic_key}"'
    strip({"app.py": content})
    captured = capsys.readouterr()
    assert fake_anthropic_key not in captured.out
    assert fake_anthropic_key not in captured.err


def test_log_message_uses_required_format(capsys):
    fake_token = "ghp_" + "X" * 36
    content = f'TOKEN = "{fake_token}"'
    strip({"src/handlers/login.py": content})
    out = capsys.readouterr().out
    # Per BR-003: log only "[secret stripped from file: {filename}]".
    assert "[secret stripped from file: src/handlers/login.py]" in out
    assert fake_token not in out


def test_no_log_emitted_for_clean_files(capsys):
    strip({"clean.py": "def hello(): return 1\n"})
    out = capsys.readouterr().out
    assert "secret stripped" not in out


# --- detect-secrets supplementary path ---------------------------------------


def test_detect_secrets_supplementary_path_executes_without_error():
    """Smoke-test that the detect-secrets fallback runs end-to-end.

    The regex layer may catch the test value first (which is correct behaviour);
    this test only verifies that ``_detect_secrets_values`` is reachable and
    does not throw on real input.
    """
    content = 'CREDENTIAL = "AbCdEfGhIjKlMnOpQrSt0123456789+/=BcDeFgHiJkLmNoPqRsTu"'
    result = strip({"app.py": content})
    assert result.secrets_found is True


# --- Extended detection: URL credentials, env-var suffixes, SQL literals -----


def test_url_with_basic_auth_credentials_is_flagged():
    """`postgres://user:pw@host` carries a real credential — must not be dropped."""
    content = 'db = "postgres://app_user:s3cret_passw0rd@db.example.com:5432/prod"\n'
    result = strip({"config.py": content})
    assert result.secrets_found is True


def test_plain_url_is_not_flagged():
    """Bare URLs (no user:pw@ segment) remain FPs and must stay suppressed."""
    content = 'api = "https://api.example.com/v1/users/list"\n'
    result = strip({"app.py": content})
    assert result.secrets_found is False


def test_filesystem_path_is_not_flagged():
    content = 'log_path = "/var/log/app/requests.log"\n'
    result = strip({"app.py": content})
    assert result.secrets_found is False


def test_env_var_key_suffix_is_flagged():
    """STRIPE_KEY = "..." now matches the widened keyword arm."""
    content = 'STRIPE_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"\n'
    result = strip({"settings.py": content})
    assert result.secrets_found is True


def test_env_var_password_suffix_is_flagged():
    content = 'DB_PASSWORD = "supersecretpw"\n'
    result = strip({"settings.py": content})
    assert result.secrets_found is True


def test_private_key_keyword_is_flagged():
    content = 'private_key: "abc123def456ghi"\n'
    result = strip({"conf.yaml": content})
    assert result.secrets_found is True


def test_sql_md5_password_literal_is_flagged():
    """`md5('password')` — the dvpwa fixture shape — must be flagged."""
    content = "INSERT INTO users (name, pwd_hash) VALUES ('admin', md5('hunter2'));\n"
    result = strip({"migrations/001-fixtures.sql": content})
    assert result.secrets_found is True


def test_sql_update_password_literal_is_flagged():
    content = "UPDATE users SET password='hunter2' WHERE id=1;\n"
    result = strip({"fixture.sql": content})
    assert result.secrets_found is True


def test_is_template_file_recognises_common_suffixes():
    from security_scanner.shared.secrets.stripper import _is_template_file

    yes = [
        ".env.example",
        ".env.local.example",
        "config.yaml.sample",
        "docker-compose.template",
        "app.config.tmpl",
        "Makefile.dist",
        "PATH/TO/.env.Local.EXAMPLE",  # case-insensitive
    ]
    no = [
        "app.py",
        ".env.local",
        ".env",
        "config.yaml",
        "README.md",
        "tests/sample_data.txt",  # ``sample`` in path, not as suffix
    ]
    for f in yes:
        assert _is_template_file(f) is True, f
    for f in no:
        assert _is_template_file(f) is False, f


def test_slack_webhook_is_flagged_and_redacted():
    """Slack incoming-webhook URLs are credentials — caught by the Layer-1 regex."""
    url = "https://hooks.slack.com/services/T01234567/B89ABCDEF/aBcDeFgHiJkLmNoPqRsTuVwX"
    content = f'WEBHOOK = "{url}"\n'
    result = strip({"alerts.py": content})
    assert result.secrets_found is True
    assert url not in result.cleaned_files["alerts.py"]
    assert REDACTED in result.cleaned_files["alerts.py"]


def test_slack_webhook_partial_match_is_not_flagged():
    """An incomplete Slack URL (no bot/token segments) must not be flagged."""
    content = 'doc = "https://hooks.slack.com/services/T01234567"\n'
    result = strip({"app.py": content})
    assert result.secrets_found is False


def test_dotted_vendor_token_is_flagged():
    """SendGrid-style ``SG.aaa.bbb`` tokens — ``.`` must be in value class."""
    content = "SENDGRID_TOKEN=SG.aB1cD2eF3gH4iJ5kL6mN7oP.qR8sT9uV0wX1yZ2aB3cD4eF5gH6iJ7kL8mN9oP\n"
    result = strip({"prod.env": content})
    assert result.secrets_found is True


def test_sql_literal_pattern_does_not_fire_on_python_file():
    """The SQL detector is scoped to .sql files only — guards the scoping."""
    content = '''sql = """
INSERT INTO users (name, pwd_hash) VALUES ('a', md5('hunter2'));
"""\n'''
    result = strip({"app.py": content})
    # The SQL-literal detector must NOT fire here; the only other detectors
    # that could possibly match (high_entropy, config_secret) won't because
    # 'hunter2' is short and the surrounding shape isn't keyword=value.
    assert result.secrets_found is False
