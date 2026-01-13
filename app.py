#!/usr/bin/env python3
"""Inventory web app (stdlib-only).

Features
- Products with pictures (no description)
- Stock tracking, sales, returns
- Weekly & monthly summaries (CEO-only dashboard)
- Employee view: daily sales + current stock balance
- Role-based login (CEO vs EMPLOYEE)
- CEO can create employees, reset passwords
- Activity log (CEO can view)

Storage
- SQLite database: inventory.db (auto-created / auto-migrated)
- Uploaded images: ./uploads (served at /uploads/<filename>)

Deployment
- Binds to PORT env var (Render-compatible)

Security note
- Passwords are hashed (PBKDF2-HMAC-SHA256).
- Sessions stored server-side in SQLite, referenced by an HttpOnly cookie.
"""

from __future__ import annotations

import cgi
import base64
import hashlib
import hmac
import html
import os
import secrets
import sqlite3
import time
import urllib.parse
from datetime import date, datetime, timedelta
from http import cookies
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

APP_DIR = Path(__file__).resolve().parent
DB_PATH = str(APP_DIR / 'inventory.db')
UPLOAD_DIR = APP_DIR / 'uploads'
UPLOAD_DIR.mkdir(exist_ok=True)

ROLE_CEO = 'CEO'
ROLE_EMPLOYEE = 'EMPLOYEE'

SESSION_COOKIE = 'INVSESS'
SESSION_TTL_SECONDS = 60 * 60 * 12  # 12h

ALLOWED_IMAGE_EXT = {'.jpg', '.jpeg', '.png', '.webp'}
MAX_UPLOAD_BYTES = 2 * 1024 * 1024  # 2MB


# ----------------------------
# Database
# ----------------------------

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute('PRAGMA foreign_keys = ON;')
    return conn


def init_db() -> None:
    conn = db()
    c = conn.cursor()

    # Core tables
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sku TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            cost_price REAL NOT NULL,
            selling_price REAL NOT NULL,
            image_path TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS stock (
            product_id INTEGER PRIMARY KEY,
            quantity INTEGER NOT NULL DEFAULT 0,
            reorder_level INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
        )
        """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sale_date TEXT NOT NULL,
            total_amount REAL NOT NULL,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
        """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS sale_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sale_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            line_total REAL NOT NULL,
            FOREIGN KEY(sale_id) REFERENCES sales(id) ON DELETE CASCADE,
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
        """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS returns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            return_date TEXT NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            reason TEXT,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY(product_id) REFERENCES products(id),
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
        """
    )

    # Auth tables
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    conn.commit()

    # Lightweight migration: add image_path if missing (older DBs)
    c.execute("PRAGMA table_info(products)")
    cols = {row[1] for row in c.fetchall()}
    if 'image_path' not in cols:
        c.execute("ALTER TABLE products ADD COLUMN image_path TEXT")
        conn.commit()

    conn.close()


def has_ceo() -> bool:
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users WHERE role = ?", (ROLE_CEO,))
    count = cur.fetchone()[0]
    conn.close()
    return (count or 0) > 0


# ----------------------------
# Password hashing
# ----------------------------

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')


def _b64d(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode('ascii'))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    iters = 200_000
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters, dklen=32)
    return f"pbkdf2_sha256${iters}${_b64e(salt)}${_b64e(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters_s, salt_s, hash_s = stored.split('$', 3)
        if algo != 'pbkdf2_sha256':
            return False
        iters = int(iters_s)
        salt = _b64d(salt_s)
        expected = _b64d(hash_s)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters, dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# ----------------------------
# Sessions
# ----------------------------

def create_session(user_id: int) -> str:
    sid = secrets.token_urlsafe(32)
    now = int(time.time())
    exp = now + SESSION_TTL_SECONDS
    conn = db()
    conn.execute(
        "INSERT INTO sessions(session_id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (sid, user_id, exp, now),
    )
    conn.commit()
    conn.close()
    return sid


def delete_session(sid: str) -> None:
    conn = db()
    conn.execute("DELETE FROM sessions WHERE session_id = ?", (sid,))
    conn.commit()
    conn.close()


def cleanup_sessions() -> None:
    now = int(time.time())
    conn = db()
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
    conn.commit()
    conn.close()


def get_user_by_session(sid: str) -> Optional[Tuple[int, str, str]]:
    cleanup_sessions()
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT u.id, u.username, u.role
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.session_id = ? AND s.expires_at >= ?
        """,
        (sid, int(time.time())),
    )
    row = cur.fetchone()
    conn.close()
    return row if row else None


# ----------------------------
# Activity log
# ----------------------------

def log_action(user_id: Optional[int], action: str, details: str = '') -> None:
    conn = db()
    conn.execute(
        "INSERT INTO activity_log(created_at, user_id, action, details) VALUES (?, ?, ?, ?)",
        (datetime.utcnow().isoformat(timespec='seconds'), user_id, action, details[:500]),
    )
    conn.commit()
    conn.close()


# ----------------------------
# Business logic
# ----------------------------

def add_product(data: Dict[str, str], image_rel_path: Optional[str], user_id: Optional[int]) -> None:
    now = datetime.utcnow().isoformat(timespec='seconds')
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO products(sku, name, cost_price, selling_price, image_path, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            data['sku'].strip(),
            data['name'].strip(),
            float(data['cost_price']),
            float(data['selling_price']),
            image_rel_path,
            now,
        ),
    )
    pid = cur.lastrowid
    cur.execute(
        "INSERT OR REPLACE INTO stock(product_id, quantity, reorder_level) VALUES (?, ?, ?)",
        (pid, int(data.get('initial_quantity', '0') or 0), int(data.get('reorder_level', '0') or 0)),
    )
    conn.commit()
    conn.close()
    log_action(user_id, 'ADD_PRODUCT', f"sku={data['sku']}, name={data['name']}")


def record_sale(data: Dict[str, str], user_id: Optional[int]) -> None:
    sale_date = data.get('sale_date') or date.today().isoformat()
    product_id = int(data['product_id'])
    quantity = int(data['quantity'])

    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT selling_price FROM products WHERE id = ?", (product_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise ValueError('Product not found')
    unit_price = float(row[0])
    line_total = unit_price * quantity

    cur.execute(
        "INSERT INTO sales(sale_date, total_amount, created_by, created_at) VALUES (?, ?, ?, ?)",
        (sale_date, line_total, user_id, datetime.utcnow().isoformat(timespec='seconds')),
    )
    sale_id = cur.lastrowid
    cur.execute(
        "INSERT INTO sale_items(sale_id, product_id, quantity, unit_price, line_total) VALUES (?, ?, ?, ?, ?)",
        (sale_id, product_id, quantity, unit_price, line_total),
    )

    # Deduct from stock
    cur.execute("UPDATE stock SET quantity = quantity - ? WHERE product_id = ?", (quantity, product_id))

    conn.commit()
    conn.close()
    log_action(user_id, 'RECORD_SALE', f"product_id={product_id}, qty={quantity}, total={line_total:.2f}")


def record_return(data: Dict[str, str], user_id: Optional[int]) -> None:
    return_date = data.get('return_date') or date.today().isoformat()
    product_id = int(data['product_id'])
    quantity = int(data['quantity'])
    reason = (data.get('reason') or '').strip()

    conn = db()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO returns(return_date, product_id, quantity, reason, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (return_date, product_id, quantity, reason, user_id, datetime.utcnow().isoformat(timespec='seconds')),
    )

    # Add back to stock
    cur.execute("UPDATE stock SET quantity = quantity + ? WHERE product_id = ?", (quantity, product_id))

    conn.commit()
    conn.close()
    log_action(user_id, 'RECORD_RETURN', f"product_id={product_id}, qty={quantity}")


def get_weekly_sales(last_n_weeks: int = 4):
    conn = db()
    cur = conn.cursor()
    today = date.today()
    weekly = []
    for i in range(0, last_n_weeks):
        start = today - timedelta(days=today.weekday()) - timedelta(weeks=i)
        end = start + timedelta(days=6)
        cur.execute(
            "SELECT SUM(total_amount) FROM sales WHERE sale_date BETWEEN ? AND ?",
            (start.isoformat(), end.isoformat()),
        )
        total = cur.fetchone()[0] or 0.0
        label = f"{start.strftime('%Y-%m-%d')} – {end.strftime('%Y-%m-%d')}"
        weekly.append((label, total))
    conn.close()
    return weekly


def get_monthly_sales(last_n_months: int = 12):
    conn = db()
    cur = conn.cursor()
    today = date.today()
    year = today.year
    month = today.month
    monthly = []
    for _ in range(last_n_months):
        start = date(year, month, 1)
        if month == 12:
            end = date(year + 1, 1, 1) - timedelta(days=1)
        else:
            end = date(year, month + 1, 1) - timedelta(days=1)
        cur.execute(
            "SELECT SUM(total_amount) FROM sales WHERE sale_date BETWEEN ? AND ?",
            (start.isoformat(), end.isoformat()),
        )
        total = cur.fetchone()[0] or 0.0
        label = start.strftime('%B %Y')
        monthly.append((label, total))
        if month == 1:
            month = 12
            year -= 1
        else:
            month -= 1
    conn.close()
    return monthly


def get_low_stock():
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT p.id, p.sku, p.name, p.image_path, s.quantity, s.reorder_level
        FROM stock s
        JOIN products p ON p.id = s.product_id
        WHERE s.quantity <= s.reorder_level
        ORDER BY s.quantity ASC
        """
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def get_slow_moving(days: int = 30):
    conn = db()
    cur = conn.cursor()
    threshold = (date.today() - timedelta(days=days)).isoformat()
    cur.execute(
        """
        SELECT p.id, p.sku, p.name, p.image_path
        FROM products p
        LEFT JOIN sale_items si ON p.id = si.product_id
        LEFT JOIN sales s ON s.id = si.sale_id AND s.sale_date > ?
        WHERE s.id IS NULL
        ORDER BY p.name
        """,
        (threshold,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def list_products_with_stock():
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT p.id, p.sku, p.name, p.image_path, s.quantity, s.reorder_level
        FROM products p
        JOIN stock s ON s.product_id = p.id
        ORDER BY p.name
        """
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def get_today_sales():
    today = date.today().isoformat()
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT s.id, s.sale_date, s.total_amount, u.username
        FROM sales s
        LEFT JOIN users u ON u.id = s.created_by
        WHERE s.sale_date = ?
        ORDER BY s.id DESC
        """,
        (today,),
    )
    rows = cur.fetchall()
    cur.execute("SELECT SUM(total_amount) FROM sales WHERE sale_date = ?", (today,))
    total = cur.fetchone()[0] or 0.0
    conn.close()
    return total, rows


def get_activity(limit: int = 200):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT a.created_at, COALESCE(u.username, '-'), a.action, a.details
        FROM activity_log a
        LEFT JOIN users u ON u.id = a.user_id
        ORDER BY a.id DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


# ----------------------------
# HTML helpers
# ----------------------------

def esc(s: Any) -> str:
    return html.escape(str(s))


def img_tag(image_path: Optional[str], size: int = 42) -> str:
    if not image_path:
        return '<div style="width:%dpx;height:%dpx;background:#eee;border-radius:6px;"></div>' % (size, size)
    return f'<img src="/uploads/{esc(image_path)}" style="width:{size}px;height:{size}px;object-fit:cover;border-radius:6px;" />'


def layout(title: str, user: Optional[Tuple[int, str, str]], body: str) -> str:
    nav = ''
    if user:
        uid, uname, role = user
        links = []
        if role == ROLE_CEO:
            links += [
                ('/','Dashboard'),
                ('/add_product','Add Product'),
                ('/employees','Employees'),
                ('/activity','Activity Log'),
            ]
        else:
            links += [
                ('/daily','Daily'),
                ('/stock','Stock Balance'),
                ('/add_sale','Record Sale'),
                ('/add_return','Record Return'),
            ]
        links.append(('/logout', 'Logout'))
        nav = ' | '.join(f'<a href="{h}">{esc(t)}</a>' for h, t in links)
        nav = f'<div class="nav">Logged in as <b>{esc(uname)}</b> ({esc(role)}) — {nav}</div>'

    return f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{esc(title)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 18px; color: #111; }}
    .nav {{ margin-bottom: 16px; font-size: 14px; }}
    .card {{ border:1px solid #ddd; border-radius:10px; padding:12px; margin: 12px 0; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
    th {{ background: #f6f6f6; }}
    input, select, button, textarea {{ padding: 8px; font-size: 14px; }}
    .row {{ display:flex; gap:12px; flex-wrap:wrap; }}
    .row > div {{ flex: 1 1 240px; }}
    .danger {{ color:#b00020; font-weight:600; }}
    .ok {{ color:#0b7a2b; font-weight:600; }}
    a {{ color:#0b57d0; text-decoration:none; }}
    a:hover {{ text-decoration:underline; }}
  </style>
</head>
<body>
  {nav}
  <h1>{esc(title)}</h1>
  {body}
</body>
</html>
"""


def redirect_to(handler: BaseHTTPRequestHandler, location: str) -> None:
    handler.send_response(303)
    handler.send_header('Location', location)
    handler.end_headers()


# ----------------------------
# HTTP handler
# ----------------------------

class InventoryHandler(BaseHTTPRequestHandler):
    def get_current_user(self) -> Optional[Tuple[int, str, str]]:
        cookie_header = self.headers.get('Cookie', '')
        jar = cookies.SimpleCookie()
        jar.load(cookie_header)
        if SESSION_COOKIE in jar:
            sid = jar[SESSION_COOKIE].value
            return get_user_by_session(sid)
        return None

    def set_session_cookie(self, sid: str) -> None:
        ck = cookies.SimpleCookie()
        ck[SESSION_COOKIE] = sid
        ck[SESSION_COOKIE]['path'] = '/'
        ck[SESSION_COOKIE]['httponly'] = True
        # If behind HTTPS, Render will be HTTPS; you can uncomment secure.
        # ck[SESSION_COOKIE]['secure'] = True
        self.send_header('Set-Cookie', ck.output(header=''))

    def clear_session_cookie(self) -> None:
        ck = cookies.SimpleCookie()
        ck[SESSION_COOKIE] = ''
        ck[SESSION_COOKIE]['path'] = '/'
        ck[SESSION_COOKIE]['max-age'] = 0
        self.send_header('Set-Cookie', ck.output(header=''))

    def require_login(self) -> Optional[Tuple[int, str, str]]:
        user = self.get_current_user()
        if not user:
            redirect_to(self, '/login')
            return None
        return user

    def require_role(self, role: str) -> Optional[Tuple[int, str, str]]:
        user = self.require_login()
        if not user:
            return None
        if user[2] != role:
            self.send_error(403, 'Forbidden')
            return None
        return user

    def parse_post(self) -> Tuple[Dict[str, str], Optional[Dict[str, Any]]]:
        """Return (fields, fileinfo).
        fileinfo is dict {filename, content(bytes)} for 'image' if present.
        """
        ctype = self.headers.get('Content-Type', '')
        if ctype.startswith('multipart/form-data'):
            env = {'REQUEST_METHOD': 'POST'}
            fs = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ=env, keep_blank_values=True)
            fields: Dict[str, str] = {}
            fileinfo = None
            for key in fs.keys():
                item = fs[key]
                if isinstance(item, list):
                    item = item[0]
                if item.filename:
                    if key == 'image':
                        raw = item.file.read()
                        fileinfo = {'filename': item.filename, 'content': raw}
                else:
                    fields[key] = item.value
            return fields, fileinfo

        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace')
        data = urllib.parse.parse_qs(body)
        fields = {k: v[0] if isinstance(v, list) else str(v) for k, v in data.items()}
        return fields, None

    def serve_upload(self, rel_path: str) -> None:
        safe_name = os.path.basename(rel_path)
        fpath = UPLOAD_DIR / safe_name
        if not fpath.exists() or not fpath.is_file():
            self.send_error(404, 'Not found')
            return
        ext = fpath.suffix.lower()
        ctype = 'application/octet-stream'
        if ext in ('.jpg', '.jpeg'):
            ctype = 'image/jpeg'
        elif ext == '.png':
            ctype = 'image/png'
        elif ext == '.webp':
            ctype = 'image/webp'
        data = fpath.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        # First-time setup
        if self.path.startswith('/uploads/'):
            return self.serve_upload(self.path[len('/uploads/'):])

        if not has_ceo() and self.path not in ('/setup', '/login'):
            return redirect_to(self, '/setup')

        if self.path == '/setup':
            return self.page_setup()
        if self.path == '/login':
            return self.page_login()
        if self.path == '/logout':
            return self.handle_logout()

        # CEO pages
        if self.path == '/':
            return self.page_ceo_dashboard()
        if self.path == '/add_product':
            return self.page_add_product()
        if self.path == '/employees':
            return self.page_employees()
        if self.path.startswith('/reset_password'):
            return self.page_reset_password()
        if self.path == '/activity':
            return self.page_activity()

        # Employee pages
        if self.path == '/daily':
            return self.page_daily()
        if self.path == '/stock':
            return self.page_stock()
        if self.path == '/add_sale':
            return self.page_add_sale()
        if self.path == '/add_return':
            return self.page_add_return()

        self.send_error(404, 'Page not found')

    def do_POST(self):
        if self.path == '/setup':
            return self.handle_setup()
        if self.path == '/login':
            return self.handle_login()

        # CEO actions
        if self.path == '/add_product':
            return self.handle_add_product()
        if self.path == '/employees':
            return self.handle_add_employee()
        if self.path == '/reset_password':
            return self.handle_reset_password()

        # Employee actions
        if self.path == '/add_sale':
            return self.handle_add_sale()
        if self.path == '/add_return':
            return self.handle_add_return()

        self.send_error(404, 'Page not found')

    # ---------- Auth pages ----------

    def page_setup(self):
        if has_ceo():
            return redirect_to(self, '/login')
        body = """
        <div class="card">
          <p><b>First-time setup:</b> create the CEO account.</p>
          <form method="post" action="/setup">
            <div class="row">
              <div><label>CEO Username<br><input name="username" required></label></div>
              <div><label>CEO Password<br><input type="password" name="password" required></label></div>
            </div>
            <p><button type="submit">Create CEO Account</button></p>
          </form>
        </div>
        """
        self.respond_html(layout('Setup CEO', None, body))

    def handle_setup(self):
        if has_ceo():
            return redirect_to(self, '/login')
        fields, _ = self.parse_post()
        username = (fields.get('username') or '').strip()
        password = fields.get('password') or ''
        if not username or not password:
            return self.respond_html(layout('Setup CEO', None, '<p class="danger">Username and password required.</p>'))
        conn = db()
        try:
            conn.execute(
                "INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (username, hash_password(password), ROLE_CEO, datetime.utcnow().isoformat(timespec='seconds')),
            )
            conn.commit()
        finally:
            conn.close()
        log_action(None, 'CREATE_CEO', f"username={username}")
        return redirect_to(self, '/login')

    def page_login(self):
        body = """
        <div class="card">
          <form method="post" action="/login">
            <div class="row">
              <div><label>Username<br><input name="username" required></label></div>
              <div><label>Password<br><input type="password" name="password" required></label></div>
            </div>
            <p><button type="submit">Login</button></p>
          </form>
        </div>
        """
        self.respond_html(layout('Login', None, body))

    def handle_login(self):
        fields, _ = self.parse_post()
        username = (fields.get('username') or '').strip()
        password = fields.get('password') or ''

        conn = db()
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash, role FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()

        if not row or not verify_password(password, row[1]):
            log_action(None, 'LOGIN_FAIL', f"username={username}")
            return self.respond_html(layout('Login', None, '<p class="danger">Invalid username or password.</p>'))

        user_id, _, role = row
        sid = create_session(int(user_id))

        self.send_response(303)
        self.set_session_cookie(sid)
        self.send_header('Location', '/' if role == ROLE_CEO else '/daily')
        self.end_headers()

        log_action(int(user_id), 'LOGIN_OK', f"role={role}")

    def handle_logout(self):
        cookie_header = self.headers.get('Cookie', '')
        jar = cookies.SimpleCookie()
        jar.load(cookie_header)
        sid = jar[SESSION_COOKIE].value if SESSION_COOKIE in jar else None
        self.send_response(303)
        if sid:
            delete_session(sid)
        self.clear_session_cookie()
        self.send_header('Location', '/login')
        self.end_headers()

    # ---------- CEO pages ----------

    def page_ceo_dashboard(self):
        user = self.require_role(ROLE_CEO)
        if not user:
            return
        weekly = get_weekly_sales(4)
        monthly = get_monthly_sales(12)
        low = get_low_stock()
        slow = get_slow_moving(30)

        weekly_rows = ''.join(f'<tr><td>{esc(label)}</td><td>{total:.2f}</td></tr>' for label, total in weekly)
        monthly_rows = ''.join(f'<tr><td>{esc(label)}</td><td>{total:.2f}</td></tr>' for label, total in monthly)

        low_rows = ''
        for pid, sku, name, image_path, qty, level in low:
            status = '<span class="danger">LOW</span>' if qty > 0 else '<span class="danger">OUT</span>'
            low_rows += (
                f'<tr><td>{img_tag(image_path)}</td><td>{esc(sku)}</td><td>{esc(name)}</td>'
                f'<td>{qty}</td><td>{level}</td><td>{status}</td></tr>'
            )

        slow_rows = ''
        for pid, sku, name, image_path in slow:
            slow_rows += f'<tr><td>{img_tag(image_path)}</td><td>{esc(sku)}</td><td>{esc(name)}</td></tr>'

        body = f"""
        <div class="card">
          <h2>Weekly Sales (last 4 weeks)</h2>
          <table><tr><th>Week</th><th>Total (NGN)</th></tr>{weekly_rows}</table>
        </div>

        <div class="card">
          <h2>Monthly Sales (Jan–Dec view, last 12 months)</h2>
          <table><tr><th>Month</th><th>Total (NGN)</th></tr>{monthly_rows}</table>
        </div>

        <div class="card">
          <h2>Low Stock Alerts</h2>
          <table><tr><th>Image</th><th>SKU</th><th>Name</th><th>Qty</th><th>Reorder Level</th><th>Status</th></tr>
          {low_rows or '<tr><td colspan="6">No low-stock items.</td></tr>'}
          </table>
        </div>

        <div class="card">
          <h2>Slow Moving (no sales in last 30 days)</h2>
          <table><tr><th>Image</th><th>SKU</th><th>Name</th></tr>
          {slow_rows or '<tr><td colspan="3">No slow-moving items.</td></tr>'}
          </table>
        </div>
        """
        self.respond_html(layout('CEO Dashboard', user, body))

    def page_add_product(self):
        user = self.require_role(ROLE_CEO)
        if not user:
            return
        body = """
        <div class="card">
          <form method="post" action="/add_product" enctype="multipart/form-data">
            <div class="row">
              <div><label>SKU<br><input name="sku" required></label></div>
              <div><label>Name<br><input name="name" required></label></div>
            </div>
            <div class="row">
              <div><label>Cost Price (NGN)<br><input name="cost_price" type="number" step="0.01" required></label></div>
              <div><label>Selling Price (NGN)<br><input name="selling_price" type="number" step="0.01" required></label></div>
            </div>
            <div class="row">
              <div><label>Reorder Level<br><input name="reorder_level" type="number" min="0" value="0" required></label></div>
              <div><label>Initial Quantity<br><input name="initial_quantity" type="number" min="0" value="0" required></label></div>
            </div>
            <div class="row">
              <div><label>Product Picture (JPG/PNG/WEBP, max 2MB)<br><input name="image" type="file" accept="image/*" required></label></div>
            </div>
            <p><button type="submit">Save Product</button></p>
          </form>
        </div>
        """
        self.respond_html(layout('Add Product', user, body))

    def _save_upload(self, fileinfo: Dict[str, Any]) -> Optional[str]:
        filename = os.path.basename(fileinfo.get('filename') or '')
        raw: bytes = fileinfo.get('content') or b''
        if not filename or not raw:
            return None
        if len(raw) > MAX_UPLOAD_BYTES:
            raise ValueError('Image too large (max 2MB).')
        ext = Path(filename).suffix.lower()
        if ext not in ALLOWED_IMAGE_EXT:
            raise ValueError('Unsupported image type. Use JPG/PNG/WEBP.')
        safe = f"{secrets.token_hex(8)}{ext}"
        (UPLOAD_DIR / safe).write_bytes(raw)
        return safe

    def handle_add_product(self):
        user = self.require_role(ROLE_CEO)
        if not user:
            return
        fields, fileinfo = self.parse_post()
        try:
            if not fileinfo:
                raise ValueError('Product picture is required.')
            rel = self._save_upload(fileinfo)
            add_product(fields, rel, user[0])
        except sqlite3.IntegrityError:
            return self.respond_html(layout('Add Product', user, '<p class="danger">SKU already exists.</p>'))
        except Exception as e:
            return self.respond_html(layout('Add Product', user, f'<p class="danger">{esc(e)}</p>'))
        return redirect_to(self, '/')

    def page_employees(self):
        user = self.require_role(ROLE_CEO)
        if not user:
            return
        conn = db()
        cur = conn.cursor()
        cur.execute("SELECT id, username, role, created_at FROM users ORDER BY id ASC")
        rows = cur.fetchall()
        conn.close()

        rows_html = ''
        for uid, uname, role, created_at in rows:
            if role == ROLE_EMPLOYEE:
                rows_html += (
                    f'<tr><td>{esc(uname)}</td><td>{esc(role)}</td><td>{esc(created_at)}</td>'
                    f'<td><a href="/reset_password?user_id={uid}">Reset Password</a></td></tr>'
                )
            else:
                rows_html += f'<tr><td>{esc(uname)}</td><td>{esc(role)}</td><td>{esc(created_at)}</td><td>-</td></tr>'

        body = f"""
        <div class="card">
          <h2>Create Employee</h2>
          <form method="post" action="/employees">
            <div class="row">
              <div><label>Username<br><input name="username" required></label></div>
              <div><label>Temp Password<br><input type="password" name="password" required></label></div>
            </div>
            <p><button type="submit">Create Employee</button></p>
          </form>
        </div>

        <div class="card">
          <h2>Users</h2>
          <table><tr><th>Username</th><th>Role</th><th>Created</th><th>Action</th></tr>
            {rows_html}
          </table>
        </div>
        """
        self.respond_html(layout('Employees', user, body))

    def handle_add_employee(self):
        user = self.require_role(ROLE_CEO)
        if not user:
            return
        fields, _ = self.parse_post()
        username = (fields.get('username') or '').strip()
        password = fields.get('password') or ''
        if not username or not password:
            return self.respond_html(layout('Employees', user, '<p class="danger">Username and password required.</p>'))
        conn = db()
        try:
            conn.execute(
                "INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (username, hash_password(password), ROLE_EMPLOYEE, datetime.utcnow().isoformat(timespec='seconds')),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return self.respond_html(layout('Employees', user, '<p class="danger">Username already exists.</p>'))
        conn.close()
        log_action(user[0], 'CREATE_EMPLOYEE', f"username={username}")
        return redirect_to(self, '/employees')

    def page_reset_password(self):
        user = self.require_role(ROLE_CEO)
        if not user:
            return
        qs = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(qs)
        target_id = int(params.get('user_id', ['0'])[0])

        conn = db()
        cur = conn.cursor()
        cur.execute("SELECT id, username, role FROM users WHERE id = ?", (target_id,))
        row = cur.fetchone()
        conn.close()
        if not row or row[2] != ROLE_EMPLOYEE:
            return self.respond_html(layout('Reset Password', user, '<p class="danger">Employee not found.</p>'))

        body = f"""
        <div class="card">
          <p>Reset password for employee: <b>{esc(row[1])}</b></p>
          <form method="post" action="/reset_password">
            <input type="hidden" name="user_id" value="{row[0]}">
            <div class="row">
              <div><label>New Password<br><input type="password" name="password" required></label></div>
            </div>
            <p><button type="submit">Reset Password</button></p>
          </form>
        </div>
        """
        self.respond_html(layout('Reset Password', user, body))

    def handle_reset_password(self):
        user = self.require_role(ROLE_CEO)
        if not user:
            return
        fields, _ = self.parse_post()
        target_id = int(fields.get('user_id', '0') or 0)
        new_pw = fields.get('password') or ''
        if not target_id or not new_pw:
            return self.respond_html(layout('Reset Password', user, '<p class="danger">Missing fields.</p>'))
        conn = db()
        cur = conn.cursor()
        cur.execute("SELECT username, role FROM users WHERE id = ?", (target_id,))
        row = cur.fetchone()
        if not row or row[1] != ROLE_EMPLOYEE:
            conn.close()
            return self.respond_html(layout('Reset Password', user, '<p class="danger">Employee not found.</p>'))
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new_pw), target_id))
        conn.commit()
        conn.close()
        log_action(user[0], 'RESET_PASSWORD', f"employee={row[0]}")
        return redirect_to(self, '/employees')

    def page_activity(self):
        user = self.require_role(ROLE_CEO)
        if not user:
            return
        rows = get_activity(200)
        rows_html = ''.join(
            f'<tr><td>{esc(ts)}</td><td>{esc(uname)}</td><td>{esc(action)}</td><td>{esc(details)}</td></tr>'
            for ts, uname, action, details in rows
        )
        body = f"""
        <div class="card">
          <h2>Recent Activity</h2>
          <table><tr><th>Time (UTC)</th><th>User</th><th>Action</th><th>Details</th></tr>
          {rows_html or '<tr><td colspan="4">No activity yet.</td></tr>'}
          </table>
        </div>
        """
        self.respond_html(layout('Activity Log', user, body))

    # ---------- Employee pages ----------

    def page_daily(self):
        user = self.require_role(ROLE_EMPLOYEE)
        if not user:
            return
        total, rows = get_today_sales()
        rows_html = ''.join(
            f'<tr><td>{sid}</td><td>{esc(sdate)}</td><td>{amt:.2f}</td><td>{esc(uname or "-")}</td></tr>'
            for sid, sdate, amt, uname in rows
        )
        body = f"""
        <div class="card">
          <h2>Today Sales Total: NGN {total:.2f}</h2>
          <p><a href="/add_sale">Record Sale</a> | <a href="/add_return">Record Return</a> | <a href="/stock">View Stock Balance</a></p>
        </div>

        <div class="card">
          <h2>Today Sales Records</h2>
          <table><tr><th>ID</th><th>Date</th><th>Amount</th><th>Recorded By</th></tr>
            {rows_html or '<tr><td colspan="4">No sales recorded today.</td></tr>'}
          </table>
        </div>
        """
        self.respond_html(layout('Daily Records', user, body))

    def page_stock(self):
        user = self.require_role(ROLE_EMPLOYEE)
        if not user:
            return
        rows = list_products_with_stock()
        rows_html = ''
        for pid, sku, name, image_path, qty, level in rows:
            tag = '<span class="danger">LOW</span>' if qty <= level else '<span class="ok">OK</span>'
            rows_html += f'<tr><td>{img_tag(image_path)}</td><td>{esc(sku)}</td><td>{esc(name)}</td><td>{qty}</td><td>{tag}</td></tr>'
        body = f"""
        <div class="card">
          <h2>Current Stock Balance</h2>
          <table><tr><th>Image</th><th>SKU</th><th>Name</th><th>Qty</th><th>Status</th></tr>
            {rows_html or '<tr><td colspan="5">No products found.</td></tr>'}
          </table>
        </div>
        """
        self.respond_html(layout('Stock Balance', user, body))

    def page_add_sale(self):
        user = self.require_role(ROLE_EMPLOYEE)
        if not user:
            return
        products = list_products_with_stock()
        options = ''.join(
            f'<option value="{pid}">{esc(name)} ({esc(sku)}) — Stock {qty}</option>'
            for pid, sku, name, image_path, qty, level in products
        )
        body = f"""
        <div class="card">
          <form method="post" action="/add_sale">
            <div class="row">
              <div><label>Date<br><input name="sale_date" type="date" value="{date.today().isoformat()}" required></label></div>
              <div><label>Product<br><select name="product_id" required>{options}</select></label></div>
            </div>
            <div class="row">
              <div><label>Quantity<br><input name="quantity" type="number" min="1" value="1" required></label></div>
            </div>
            <p><button type="submit">Save Sale</button></p>
          </form>
        </div>
        """
        self.respond_html(layout('Record Sale', user, body))

    def handle_add_sale(self):
        user = self.require_role(ROLE_EMPLOYEE)
        if not user:
            return
        fields, _ = self.parse_post()
        try:
            record_sale(fields, user[0])
        except Exception as e:
            return self.respond_html(layout('Record Sale', user, f'<p class="danger">{esc(e)}</p>'))
        return redirect_to(self, '/daily')

    def page_add_return(self):
        user = self.require_role(ROLE_EMPLOYEE)
        if not user:
            return
        products = list_products_with_stock()
        options = ''.join(
            f'<option value="{pid}">{esc(name)} ({esc(sku)})</option>'
            for pid, sku, name, image_path, qty, level in products
        )
        body = f"""
        <div class="card">
          <form method="post" action="/add_return">
            <div class="row">
              <div><label>Date<br><input name="return_date" type="date" value="{date.today().isoformat()}" required></label></div>
              <div><label>Product<br><select name="product_id" required>{options}</select></label></div>
            </div>
            <div class="row">
              <div><label>Quantity<br><input name="quantity" type="number" min="1" value="1" required></label></div>
              <div><label>Reason (optional)<br><input name="reason"></label></div>
            </div>
            <p><button type="submit">Save Return</button></p>
          </form>
        </div>
        """
        self.respond_html(layout('Record Return', user, body))

    def handle_add_return(self):
        user = self.require_role(ROLE_EMPLOYEE)
        if not user:
            return
        fields, _ = self.parse_post()
        try:
            record_return(fields, user[0])
        except Exception as e:
            return self.respond_html(layout('Record Return', user, f'<p class="danger">{esc(e)}</p>'))
        return redirect_to(self, '/daily')

    # ---------- Response helpers ----------

    def respond_html(self, content: str, status: int = 200):
        data = content.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def run_server(port: int) -> None:
    init_db()
    server = HTTPServer(('0.0.0.0', port), InventoryHandler)
    print(f"Inventory app running on http://0.0.0.0:{port}")
    server.serve_forever()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', '8000'))
    run_server(port)
