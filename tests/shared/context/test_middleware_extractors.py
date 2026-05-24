"""Tests for middleware / decorator extractors."""

from __future__ import annotations

from security_scanner.shared.context.middleware_extractors import (
    extract_django_middleware,
    extract_express_middleware,
    extract_fastapi_depends,
    extract_middleware,
    extract_python_decorators,
)

# ---------------------------------------------------------------------------
# Python stacked decorators
# ---------------------------------------------------------------------------

PYTHON_DECORATOR_CONTENT = """\
from functools import wraps

@login_required
@require_admin
def admin_panel(request):
    pass

@authenticated
def profile(request):
    pass

def public_view(request):
    pass
"""


def test_python_stacked_auth_decorators():
    matches = extract_python_decorators("views.py", PYTHON_DECORATOR_CONTENT)
    names = [m.name for m in matches]
    assert "login_required" in names
    assert "require_admin" in names
    assert "authenticated" in names


def test_python_decorators_kind():
    matches = extract_python_decorators("views.py", PYTHON_DECORATOR_CONTENT)
    assert all(m.kind == "decorator" for m in matches)


def test_python_no_decorator_on_public_view():
    # public_view has no auth decorator — should not produce extra results
    matches = extract_python_decorators("views.py", PYTHON_DECORATOR_CONTENT)
    names = [m.name for m in matches]
    # Should NOT include non-auth decorators
    assert "wraps" not in names


# ---------------------------------------------------------------------------
# FastAPI Depends
# ---------------------------------------------------------------------------

FASTAPI_DEPENDS_CONTENT = """\
from fastapi import Depends

async def list_items(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    pass
"""


def test_fastapi_depends_extracted():
    matches = extract_fastapi_depends("routes.py", FASTAPI_DEPENDS_CONTENT)
    names = [m.name for m in matches]
    assert any("get_current_user" in n for n in names)
    assert any("get_db" in n for n in names)


def test_fastapi_depends_kind():
    matches = extract_fastapi_depends("routes.py", FASTAPI_DEPENDS_CONTENT)
    assert all(m.kind == "Depends" for m in matches)


# ---------------------------------------------------------------------------
# Express app.use
# ---------------------------------------------------------------------------

EXPRESS_USE_CONTENT = """\
const express = require('express');
const app = express();

app.use(cors());
app.use(authMiddleware);
router.use(rateLimiter);
"""


def test_express_use_middleware():
    matches = extract_express_middleware("app.js", EXPRESS_USE_CONTENT)
    names = [m.name for m in matches]
    assert "authMiddleware" in names


def test_express_use_kind():
    matches = extract_express_middleware("app.js", EXPRESS_USE_CONTENT)
    assert all(m.kind == "app.use" for m in matches)


# ---------------------------------------------------------------------------
# Django MIDDLEWARE list
# ---------------------------------------------------------------------------

DJANGO_SETTINGS_CONTENT = """\
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'myapp.middleware.AuthTokenMiddleware',
]
"""


def test_django_middleware_list():
    matches = extract_django_middleware("settings.py", DJANGO_SETTINGS_CONTENT)
    names = [m.name for m in matches]
    assert "django.middleware.security.SecurityMiddleware" in names
    assert "myapp.middleware.AuthTokenMiddleware" in names


def test_django_middleware_kind():
    matches = extract_django_middleware("settings.py", DJANGO_SETTINGS_CONTENT)
    assert all(m.kind == "django_middleware" for m in matches)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def test_dispatch_py_includes_decorators():
    matches = extract_middleware("views.py", PYTHON_DECORATOR_CONTENT)
    names = [m.name for m in matches]
    assert "login_required" in names


def test_dispatch_settings_includes_django_mw():
    matches = extract_middleware("settings.py", DJANGO_SETTINGS_CONTENT)
    names = [m.name for m in matches]
    assert "django.middleware.security.SecurityMiddleware" in names


def test_dispatch_js_includes_express():
    matches = extract_middleware("app.js", EXPRESS_USE_CONTENT)
    names = [m.name for m in matches]
    assert "authMiddleware" in names
