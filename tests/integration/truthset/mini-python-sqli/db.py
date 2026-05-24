"""Mini Python SQLi corpus — for class-coverage testing.

Intentionally vulnerable — never deploy this code.
"""

import sqlite3


def get_user_by_name(username):
    # VULN: SQL injection — username directly interpolated into query string.
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def get_order(order_id):
    # VULN: SQL injection via f-string.
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM orders WHERE id = {order_id}")
    return cursor.fetchone()


def search_products(name):
    # VULN: SQL injection using % formatting.
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name LIKE '%%%s%%'" % name)
    return cursor.fetchall()


def safe_get_user(user_id):
    # SAFE: parameterised query — true negative.
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
