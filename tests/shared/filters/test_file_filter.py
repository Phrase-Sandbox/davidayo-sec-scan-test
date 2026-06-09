"""Tests for the source-file filter (spec §2.2 step 3)."""

from __future__ import annotations

import pytest

from security_scanner.shared.filters.file_filter import filter as file_filter
from security_scanner.shared.filters.file_filter import scanner_filter

# --- Exclusions ---------------------------------------------------------------


class TestExcludeEnvFiles:
    def test_exact_env_file_excluded(self):
        assert file_filter({".env": "FOO=bar"}) == {}

    @pytest.mark.parametrize("path", [".env.local", ".env.production", ".env.staging"])
    def test_dotted_env_variants_excluded(self, path):
        assert file_filter({path: "FOO=bar"}) == {}

    @pytest.mark.parametrize("path", ["production.env", "database.env"])
    def test_dotenv_suffix_excluded(self, path):
        assert file_filter({path: "FOO=bar"}) == {}


class TestExcludeLockFiles:
    @pytest.mark.parametrize(
        "filename",
        [
            "package-lock.json",
            "yarn.lock",
            "Pipfile.lock",
            "poetry.lock",
            "Gemfile.lock",
        ],
    )
    def test_named_lock_files_excluded(self, filename):
        assert file_filter({filename: "{}"}) == {}

    def test_any_dot_lock_extension_excluded(self):
        assert file_filter({"app.lock": "data"}) == {}


class TestExcludeBuildOutput:
    @pytest.mark.parametrize(
        "directory",
        ["dist", "build", ".next", "__pycache__", "node_modules", ".venv", "venv"],
    )
    def test_top_level_build_dir_excluded(self, directory):
        assert file_filter({f"{directory}/file.js": "x"}) == {}

    def test_nested_build_dir_excluded(self):
        assert file_filter({"frontend/dist/bundle.js": "x"}) == {}

    def test_pycache_anywhere_in_tree_excluded(self):
        assert file_filter({"a/b/c/__pycache__/foo.cpython-312.pyc": "x"}) == {}

    def test_dir_name_must_be_exact_match(self):
        """``my-dist/foo.py`` is fine — only exact dir-name matches."""
        result = file_filter({"my-dist/foo.py": "x = 1"})
        assert result == {"my-dist/foo.py": "x = 1"}


class TestExcludeVendorAndStaticDirs:
    """Vendored/static directories anywhere in the path are rejected."""

    @pytest.mark.parametrize(
        "path",
        [
            "sqli/static/css/materialize.css",
            "web/vendor/jquery.js",
            "app/assets/img/logo.svg",
            "project/vendored/lib.py",
            "src/third_party/utils.go",
            "src/third-party/utils.go",
        ],
    )
    def test_vendor_static_asset_dirs_rejected(self, path):
        assert file_filter({path: "content"}) == {}

    def test_static_as_filename_prefix_not_rejected(self):
        """``static_config.py`` is a file name prefix, not a path segment."""
        result = file_filter({"src/api/static_config.py": "x = 1"})
        assert result == {"src/api/static_config.py": "x = 1"}

    def test_static_hyphen_suffix_not_rejected(self):
        """``app/static-config.py`` — hyphenated name, not a bare segment."""
        result = file_filter({"app/static-config.py": "x = 1"})
        assert result == {"app/static-config.py": "x = 1"}

    def test_static_py_at_root_not_rejected(self):
        """``static.py`` at repository root is a file, not a directory segment."""
        result = file_filter({"static.py": "x = 1"})
        assert result == {"static.py": "x = 1"}


class TestExcludeAssetFiles:
    @pytest.mark.parametrize(
        "filename",
        [
            "logo.png", "photo.jpg", "image.jpeg", "anim.gif",
            "icon.svg", "favicon.ico",
            "font.woff", "font.woff2", "font.ttf", "font.eot",
            "spec.pdf",
        ],
    )
    def test_asset_extension_excluded(self, filename):
        assert file_filter({filename: "binarydata"}) == {}


class TestExcludeMinifiedFiles:
    @pytest.mark.parametrize("filename", ["app.min.js", "styles.min.css"])
    def test_minified_files_excluded(self, filename):
        assert file_filter({filename: "/* min */"}) == {}


class TestExcludeGeneratedFiles:
    @pytest.mark.parametrize(
        "filename",
        [
            "service.pb.go",         # protoc -> Go
            "model_pb2.py",          # protoc -> Python
            "schema.generated.ts",
            "types.generated.d.ts",
        ],
    )
    def test_generated_files_excluded(self, filename):
        assert file_filter({filename: "// generated"}) == {}


class TestExcludeBinaryContent:
    def test_content_with_null_byte_excluded_even_with_source_extension(self):
        """A `.py` file containing null bytes is still dropped — defence in depth."""
        result = file_filter({"sketchy.py": "x = 1\x00\x00binary garbage"})
        assert result == {}

    def test_only_first_8192_chars_inspected_for_null_bytes(self):
        """A null byte beyond the 8192-char window must not exclude the file."""
        content = "x = 1\n" * 2000 + "\x00"  # ~12 KB; null at index ~12000
        result = file_filter({"large.py": content})
        assert result == {"large.py": content}


class TestExcludeUnknownExtensions:
    def test_unknown_extension_dropped(self):
        # Not on the include list, not binary — still excluded.
        assert file_filter({"data.parquet": "PARquetData"}) == {}

    def test_markdown_excluded_because_not_on_include_list(self):
        assert file_filter({"README.md": "# Hello"}) == {}


# --- Inclusions (at least 5 explicit cases, plus full extension coverage) -----


class TestIncludeSourceFiles:
    def test_python(self):
        assert file_filter({"app.py": "def f(): pass"}) == {"app.py": "def f(): pass"}

    def test_typescript_tsx(self):
        result = file_filter({"src/component.tsx": "export default {}"})
        assert "src/component.tsx" in result

    def test_go(self):
        result = file_filter({"cmd/main.go": "package main"})
        assert "cmd/main.go" in result

    def test_yaml_config(self):
        result = file_filter({"docker-compose.yml": "version: '3'"})
        assert "docker-compose.yml" in result

    def test_terraform(self):
        result = file_filter({"infra/main.tf": "resource ..."})
        assert "infra/main.tf" in result

    def test_dockerfile_exact(self):
        result = file_filter({"Dockerfile": "FROM python:3.12"})
        assert "Dockerfile" in result

    def test_dockerfile_with_suffix(self):
        result = file_filter({"Dockerfile.prod": "FROM python:3.12"})
        assert "Dockerfile.prod" in result

    def test_makefile(self):
        result = file_filter({"Makefile": "test:\n\tpytest"})
        assert "Makefile" in result

    def test_shell_script(self):
        result = file_filter({"scripts/deploy.sh": "#!/bin/bash\n"})
        assert "scripts/deploy.sh" in result

    @pytest.mark.parametrize(
        "filename",
        [
            "x.py", "x.js", "x.ts", "x.tsx", "x.jsx",
            "x.go", "x.rb", "x.java", "x.cs", "x.php", "x.rs", "x.swift", "x.kt",
            "x.yml", "x.yaml", "x.toml", "x.xml", "x.tf", "x.hcl",
            "x.sh", "x.bash", "x.zsh",
        ],
    )
    def test_every_listed_source_extension_is_kept(self, filename):
        assert file_filter({filename: "code"}) == {filename: "code"}


# --- Mixed input & invariants ------------------------------------------------


def test_mixed_input_filters_correctly():
    files = {
        "src/app.py": "def main(): pass",
        ".env": "API_KEY=x",
        "node_modules/express/index.js": "module.exports = ...",
        "Dockerfile": "FROM python:3.12",
        "package-lock.json": "{}",
        "logo.png": "PNGDATA",
        "src/handlers/login.ts": "export ...",
        "frontend/dist/bundle.min.js": "/* minified */",
        "infra/main.tf": "resource ...",
        "README.md": "# Docs",
    }
    kept = set(file_filter(files))
    assert kept == {"src/app.py", "Dockerfile", "src/handlers/login.ts", "infra/main.tf"}


def test_input_dict_not_mutated():
    files = {"app.py": "x = 1", ".env": "K=v"}
    file_filter(files)
    assert files == {"app.py": "x = 1", ".env": "K=v"}


def test_empty_input_returns_empty_dict():
    assert file_filter({}) == {}


def test_json_kept_but_lock_named_json_excluded():
    files = {
        "config.json": "{}",
        "package-lock.json": "{}",
    }
    assert file_filter(files) == {"config.json": "{}"}


# --- SQL in LLM filter --------------------------------------------------------


def test_llm_filter_includes_sql_files():
    assert file_filter({"migrations/001_init.sql": "CREATE TABLE users (id INT);"}) == {
        "migrations/001_init.sql": "CREATE TABLE users (id INT);"
    }


def test_llm_filter_excludes_jinja2_files():
    assert file_filter({"templates/index.jinja2": "{{ name }}"}) == {}


def test_llm_filter_excludes_html_files():
    assert file_filter({"templates/index.html": "<h1>Hello</h1>"}) == {}


# --- scanner_filter: template includes ----------------------------------------


def test_scanner_filter_includes_jinja2_files():
    result = scanner_filter({"templates/course.jinja2": "{{ review.review_text }}"})
    assert result == {"templates/course.jinja2": "{{ review.review_text }}"}


def test_scanner_filter_includes_html_files():
    result = scanner_filter({"views/index.html": "<p>{{ name }}</p>"})
    assert result == {"views/index.html": "<p>{{ name }}</p>"}


def test_scanner_filter_includes_htm_files():
    result = scanner_filter({"views/page.htm": "<p>content</p>"})
    assert result == {"views/page.htm": "<p>content</p>"}


def test_scanner_filter_excludes_jinja2_in_vendor_dir():
    result = scanner_filter({"vendor/jinja2/base.jinja2": "{% block %}"})
    assert result == {}


def test_scanner_filter_excludes_jinja2_in_static_dir():
    result = scanner_filter({"static/templates/email.jinja2": "Hello {{ name }}"})
    assert result == {}


def test_scanner_filter_still_includes_py_files():
    result = scanner_filter({"app.py": "autoescape=False"})
    assert result == {"app.py": "autoescape=False"}


def test_scanner_filter_includes_sql_files():
    result = scanner_filter({"db/queries.sql": "SELECT * FROM users"})
    assert result == {"db/queries.sql": "SELECT * FROM users"}


def test_scanner_filter_not_mutate_input():
    files = {"app.jinja2": "{{ x }}", ".env": "K=v"}
    scanner_filter(files)
    assert files == {"app.jinja2": "{{ x }}", ".env": "K=v"}
