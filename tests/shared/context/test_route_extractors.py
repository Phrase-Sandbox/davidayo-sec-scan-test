"""Tests for heuristic route extractors (one fixture per framework)."""

from __future__ import annotations

import pytest

from security_scanner.shared.context.route_extractors import (
    extract_aiohttp_routes,
    extract_django_routes,
    extract_express_routes,
    extract_fastapi_routes,
    extract_flask_routes,
    extract_gin_routes,
    extract_routes,
)

# ---------------------------------------------------------------------------
# Flask
# ---------------------------------------------------------------------------

FLASK_CONTENT = """\
from flask import Flask, request
app = Flask(__name__)

@app.route('/users', methods=['GET', 'POST'])
def list_users():
    pass

@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    pass

@blueprint.route('/admin', methods=['DELETE'])
def admin_delete():
    pass
"""


def test_flask_basic_routes():
    matches = extract_flask_routes("app.py", FLASK_CONTENT)
    paths = {(m.method, m.path, m.handler) for m in matches}
    assert ("GET", "/users", "list_users") in paths
    assert ("POST", "/users", "list_users") in paths
    assert ("GET", "/users/<int:user_id>", "get_user") in paths
    assert ("DELETE", "/admin", "admin_delete") in paths


def test_flask_route_line_numbers():
    matches = extract_flask_routes("app.py", FLASK_CONTENT)
    by_path = {(m.path, m.method): m.line for m in matches}
    # @app.route('/users', ...) is on line 4
    assert by_path[("/users", "GET")] == 4
    assert by_path[("/users/<int:user_id>", "GET")] == 8


def test_flask_no_routes_in_empty_file():
    assert extract_flask_routes("app.py", "") == []


# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------

FASTAPI_CONTENT = """\
from fastapi import APIRouter
router = APIRouter()

@router.get('/items')
async def list_items():
    pass

@router.post('/items')
async def create_item():
    pass

@router.delete('/items/{item_id}')
async def delete_item(item_id: int):
    pass
"""


def test_fastapi_routes():
    matches = extract_fastapi_routes("routes.py", FASTAPI_CONTENT)
    triplets = {(m.method, m.path, m.handler) for m in matches}
    assert ("GET", "/items", "list_items") in triplets
    assert ("POST", "/items", "create_item") in triplets
    assert ("DELETE", "/items/{item_id}", "delete_item") in triplets


# ---------------------------------------------------------------------------
# aiohttp
# ---------------------------------------------------------------------------

AIOHTTP_CONTENT = """\
from aiohttp import web
routes = web.RouteTableDef()

@routes.get('/health')
async def health_check(request):
    pass

app.router.add_route('POST', '/submit', submit_handler)
app.router.add_get('/status', status_handler)
"""


def test_aiohttp_table_def():
    matches = extract_aiohttp_routes("server.py", AIOHTTP_CONTENT)
    triplets = {(m.method, m.path) for m in matches}
    assert ("GET", "/health") in triplets


def test_aiohttp_add_route():
    matches = extract_aiohttp_routes("server.py", AIOHTTP_CONTENT)
    triplets = {(m.method, m.path, m.handler) for m in matches}
    assert ("POST", "/submit", "submit_handler") in triplets


def test_aiohttp_add_get():
    matches = extract_aiohttp_routes("server.py", AIOHTTP_CONTENT)
    triplets = {(m.method, m.path, m.handler) for m in matches}
    assert ("GET", "/status", "status_handler") in triplets


# ---------------------------------------------------------------------------
# Django
# ---------------------------------------------------------------------------

DJANGO_CONTENT = """\
from django.urls import path, re_path
from . import views

urlpatterns = [
    path('articles/', views.article_list),
    path('articles/<int:pk>/', views.article_detail),
    re_path(r'^comments/(?P<pk>[0-9]+)/$', views.comment_detail),
]
"""


def test_django_path_routes():
    matches = extract_django_routes("urls.py", DJANGO_CONTENT)
    triplets = {(m.path, m.handler) for m in matches}
    assert ("articles/", "views.article_list") in triplets
    assert ("articles/<int:pk>/", "views.article_detail") in triplets


def test_django_re_path_routes():
    matches = extract_django_routes("urls.py", DJANGO_CONTENT)
    handlers = {m.handler for m in matches}
    assert "views.comment_detail" in handlers


def test_django_routes_method_is_any():
    matches = extract_django_routes("urls.py", DJANGO_CONTENT)
    assert all(m.method == "ANY" for m in matches)


# ---------------------------------------------------------------------------
# Express
# ---------------------------------------------------------------------------

EXPRESS_CONTENT = """\
const express = require('express');
const router = express.Router();

router.get('/users', listUsers);
router.post('/users', createUser);
app.delete('/users/:id', deleteUser);
"""


def test_express_routes():
    matches = extract_express_routes("routes.js", EXPRESS_CONTENT)
    triplets = {(m.method, m.path) for m in matches}
    assert ("GET", "/users") in triplets
    assert ("POST", "/users") in triplets
    assert ("DELETE", "/users/:id") in triplets


def test_express_handler_name():
    matches = extract_express_routes("routes.js", EXPRESS_CONTENT)
    by = {(m.method, m.path): m.handler for m in matches}
    assert by[("GET", "/users")] == "listUsers"
    assert by[("POST", "/users")] == "createUser"


# ---------------------------------------------------------------------------
# Gin (Go)
# ---------------------------------------------------------------------------

GIN_CONTENT = """\
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.GET("/ping", PingHandler)
    r.POST("/users", CreateUserHandler)
    r.DELETE("/users/:id", DeleteUserHandler)
}
"""


def test_gin_routes():
    matches = extract_gin_routes("main.go", GIN_CONTENT)
    triplets = {(m.method, m.path, m.handler) for m in matches}
    assert ("GET", "/ping", "PingHandler") in triplets
    assert ("POST", "/users", "CreateUserHandler") in triplets
    assert ("DELETE", "/users/:id", "DeleteUserHandler") in triplets


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def test_dispatch_py_uses_flask():
    matches = extract_routes("app.py", FLASK_CONTENT)
    assert any(m.path == "/users" for m in matches)


def test_dispatch_go_uses_gin():
    matches = extract_routes("main.go", GIN_CONTENT)
    assert any(m.path == "/ping" for m in matches)


def test_dispatch_js_uses_express():
    matches = extract_routes("routes.js", EXPRESS_CONTENT)
    assert any(m.path == "/users" for m in matches)
