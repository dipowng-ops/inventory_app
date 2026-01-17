#!/usr/bin/env python3
"""
Dipower Stores — Inventory, Sales & Returns Tracker (stdlib-only)

Features
- One CEO only (first registered becomes CEO). All other registrations become Employees (Pending) until CEO approves.
- Role-based dashboards:
  - CEO: approvals, analytics (weekly/monthly), low-stock + slow movers, activity logs, full CRUD.
  - Employee: daily sales & returns entry + view stock balances.
- Products with images (upload), stock-in, daily sales, returns -> auto updates stock balance.
- Alerts:
  - Low stock threshold per product
  - Slow movers (no sales in X days)
- Reports:
  - Weekly + Monthly totals (Jan–Dec months)
- Password reset:
  - Request reset -> token link (no email dependency). In production you can add email later.
- Persistent storage:
  - Uses DATA_DIR (Render persistent disk) for SQLite + uploads
"""

import os
import re
import io
import sys
import hmac
import json
import time
import base64
import hashlib
import secrets
import sqlite3
import datetime as dt
from urllib.parse import parse_qs, urlparse, quote, unquote
from http.server import BaseHTTPRequestHandler, HTTPServer

# ---------------------------
# Configuration
# ---------------------------
APP_NAME = "Dipower Stores"
DATA_DIR = os.environ.get("DATA_DIR") or os.path.join(os.path.dirname(__file__), "data")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
DB_PATH = os.path.join(DATA_DIR, "inventory.db")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

SESSION_COOKIE = "dp_session"
SESSION_TTL_SECONDS = 60 * 60 * 8  # 8 hours
SECRET_KEY = os.environ.get("SECRET_KEY") or "CHANGE_ME_TO_A_LONG_RANDOM_VALUE"

MAX_UPLOAD_MB = 8
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024

def now_utc():
    return dt.datetime.utcnow()

def today_local():
    # simple: use server time; you can change to Africa/Lagos if desired
    return dt.date.today()

def start_of_week(d: dt.date) -> dt.date:
    return d - dt.timedelta(days=d.weekday())  # Monday

def month_name(m: int) -> str:
    return dt.date(2000, m, 1).strftime("%B")

# ---------------------------
# DB
# ---------------------------
def db():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.executescript("""
        PRAGMA foreign_keys=ON;

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('CEO','EMPLOYEE')),
            status TEXT NOT NULL CHECK(status IN ('ACTIVE','PENDING','DISABLED')),
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sku TEXT UNIQUE,
            name TEXT NOT NULL,
            image_path TEXT,
            low_stock_threshold INTEGER NOT NULL DEFAULT 5,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS stock_movements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            movement_type TEXT NOT NULL CHECK(movement_type IN ('IN','SALE','RETURN')),
            qty INTEGER NOT NULL,
            unit_price INTEGER NOT NULL DEFAULT 0, -- store in kobo/naira minor units if you want; here just integer Naira
            ref TEXT,
            occurred_on TEXT NOT NULL,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE,
            FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            meta TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        """)
    # ensure one CEO max is enforced by code, but we can also enforce by trigger:
    # (SQLite partial unique indexes are supported)
    with db() as conn:
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_one_ceo ON users(role) WHERE role='CEO';")

def log_action(user_id, action, meta=None):
    with db() as conn:
        conn.execute(
            "INSERT INTO activity_log(user_id, action, meta, created_at) VALUES(?,?,?,?)",
            (user_id, action, json.dumps(meta or {}), now_utc().isoformat())
        )

# ---------------------------
# Auth helpers
# ---------------------------
def pbkdf2_hash(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return base64.b64encode(salt + dk).decode("ascii")

def pbkdf2_verify(password: str, stored: str) -> bool:
    raw = base64.b64decode(stored.encode("ascii"))
    salt, dk = raw[:16], raw[16:]
    dk2 = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return hmac.compare_digest(dk, dk2)

def sign_session(payload: dict) -> str:
    data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(SECRET_KEY.encode(), data, hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(data).decode() + "." + sig

def verify_session(token: str) -> dict | None:
    try:
        b64, sig = token.rsplit(".", 1)
        data = base64.urlsafe_b64decode(b64.encode())
        expected = hmac.new(SECRET_KEY.encode(), data, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None
        payload = json.loads(data.decode())
        if payload.get("exp", 0) < int(time.time()):
            return None
        return payload
    except Exception:
        return None

def get_user_by_id(user_id: int):
    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

def get_user_by_username(username: str):
    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

def ceo_exists() -> bool:
    with db() as conn:
        r = conn.execute("SELECT 1 FROM users WHERE role='CEO' LIMIT 1").fetchone()
        return r is not None

# ---------------------------
# Inventory helpers
# ---------------------------
def product_balance(product_id: int) -> int:
    with db() as conn:
        r = conn.execute("""
            SELECT COALESCE(SUM(CASE
                WHEN movement_type='IN' THEN qty
                WHEN movement_type='SALE' THEN -qty
                WHEN movement_type='RETURN' THEN qty
            END),0) AS bal
            FROM stock_movements WHERE product_id=?
        """, (product_id,)).fetchone()
        return int(r["bal"] or 0)

def product_last_sale_date(product_id: int):
    with db() as conn:
        r = conn.execute("""
            SELECT occurred_on FROM stock_movements
            WHERE product_id=? AND movement_type='SALE'
            ORDER BY occurred_on DESC LIMIT 1
        """, (product_id,)).fetchone()
        return dt.date.fromisoformat(r["occurred_on"]) if r else None

def totals_between(start_date: dt.date, end_date: dt.date):
    # inclusive start, inclusive end
    with db() as conn:
        sales = conn.execute("""
            SELECT COALESCE(SUM(qty*unit_price),0) as total
            FROM stock_movements
            WHERE movement_type='SALE' AND occurred_on BETWEEN ? AND ?
        """, (start_date.isoformat(), end_date.isoformat())).fetchone()["total"]
        returns = conn.execute("""
            SELECT COALESCE(SUM(qty*unit_price),0) as total
            FROM stock_movements
            WHERE movement_type='RETURN' AND occurred_on BETWEEN ? AND ?
        """, (start_date.isoformat(), end_date.isoformat())).fetchone()["total"]
        return int(sales or 0), int(returns or 0)

# ---------------------------
# HTTP Handler
# ---------------------------
class AppHandler(BaseHTTPRequestHandler):
    def send_html(self, html: str, status=200, cookies=None):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if cookies:
            for c in cookies:
                self.send_header("Set-Cookie", c)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location: str, cookies=None):
        self.send_response(302)
        self.send_header("Location", location)
        if cookies:
            for c in cookies:
                self.send_header("Set-Cookie", c)
        self.end_headers()

    def parse_body(self):
        ctype = self.headers.get("Content-Type", "")
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > MAX_UPLOAD_BYTES:
            return ("", {}, "File too large")
        raw = self.rfile.read(length) if length else b""
        if ctype.startswith("application/x-www-form-urlencoded"):
            data = parse_qs(raw.decode("utf-8"))
            return ("form", {k: v[0] for k, v in data.items()}, None)
        if ctype.startswith("multipart/form-data"):
            # very small multipart parser (handles file uploads + fields)
            boundary = None
            m = re.search(r'boundary=(.+)', ctype)
            if m:
                boundary = m.group(1)
            if not boundary:
                return ("", {}, "Missing boundary")
            boundary_bytes = ("--" + boundary).encode()
            parts = raw.split(boundary_bytes)
            fields = {}
            files = {}
            for p in parts:
                p = p.strip()
                if not p or p == b"--":
                    continue
                if p.startswith(b"\r\n"):
                    p = p[2:]
                header_blob, _, content = p.partition(b"\r\n\r\n")
                headers = header_blob.decode("utf-8", errors="ignore").split("\r\n")
                disp = ""
                ctype_part = ""
                for h in headers:
                    if h.lower().startswith("content-disposition:"):
                        disp = h
                    if h.lower().startswith("content-type:"):
                        ctype_part = h.split(":",1)[1].strip()
                content = content.rstrip(b"\r\n")
                name_m = re.search(r'name="([^"]+)"', disp)
                if not name_m:
                    continue
                name = name_m.group(1)
                file_m = re.search(r'filename="([^"]*)"', disp)
                if file_m and file_m.group(1):
                    filename = os.path.basename(file_m.group(1))
                    files[name] = {"filename": filename, "content_type": ctype_part, "data": content}
                else:
                    fields[name] = content.decode("utf-8", errors="ignore")
            return ("multipart", {"fields": fields, "files": files}, None)
        return ("raw", {"raw": raw}, None)

    def get_cookie(self, name: str):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if not part:
                continue
            if part.startswith(name + "="):
                return part.split("=", 1)[1]
        return None

    def current_user(self):
        token = self.get_cookie(SESSION_COOKIE)
        if not token:
            return None
        payload = verify_session(token)
        if not payload:
            return None
        user = get_user_by_id(int(payload["uid"]))
        if not user:
            return None
        if user["status"] != "ACTIVE":
            return None
        return user

    def require_login(self):
        u = self.current_user()
        if not u:
            self.redirect("/login")
            return None
        return u

    def serve_file(self, path, base_dir, content_type=None):
        safe = os.path.normpath(path).lstrip(os.sep)
        full = os.path.join(base_dir, safe)
        if not os.path.abspath(full).startswith(os.path.abspath(base_dir)):
            self.send_response(403); self.end_headers(); return
        if not os.path.exists(full) or not os.path.isfile(full):
            self.send_response(404); self.end_headers(); return
        with open(full, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type or (mimetypes.guess_type(full)[0] or "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        init_db()
        user = self.current_user()
        url = urlparse(self.path)
        path = url.path

        if path.startswith("/static/"):
            return self.serve_file(path[len("/static/"):], STATIC_DIR)
        if path.startswith("/uploads/"):
            return self.serve_file(path[len("/uploads/"):], UPLOAD_DIR)

        if path == "/":
            return self.page_home(user)

        if path == "/login":
            return self.page_login()
        if path == "/register":
            return self.page_register()
        if path == "/logout":
            return self.handle_logout()

        if path == "/reset":
            return self.page_reset_request()
        if path.startswith("/reset/"):
            token = path.split("/", 2)[2]
            return self.page_reset_form(token)

        # Auth-required pages
        if path == "/dashboard":
            u = self.require_login()
            if not u:
                return
            if u["role"] == "CEO":
                return self.page_ceo_dashboard(u)
            return self.page_employee_dashboard(u)

        if path == "/products":
            u = self.require_login()
            if not u: return
            return self.page_products(u)

        if path == "/products/add":
            u = self.require_login()
            if not u: return
            return self.page_add_product(u)

        if path.startswith("/products/edit/"):
            u = self.require_login()
            if not u: return
            pid = int(path.split("/")[-1])
            return self.page_edit_product(u, pid)

        if path == "/stock/in":
            u = self.require_login()
            if not u: return
            return self.page_stock_in(u)

        if path == "/sales/daily":
            u = self.require_login()
            if not u: return
            return self.page_daily_sales(u)

        if path == "/returns":
            u = self.require_login()
            if not u: return
            return self.page_returns(u)

        if path == "/activity":
            u = self.require_login()
            if not u: return
            if u["role"] != "CEO":
                return self.send_html(self.layout(u, "<h2>Forbidden</h2>"), 403)
            return self.page_activity(u)

        if path == "/approvals":
            u = self.require_login()
            if not u: return
            if u["role"] != "CEO":
                return self.send_html(self.layout(u, "<h2>Forbidden</h2>"), 403)
            return self.page_approvals(u)

        if path == "/reports":
            u = self.require_login()
            if not u: return
            if u["role"] != "CEO":
                return self.send_html(self.layout(u, "<h2>Forbidden</h2>"), 403)
            return self.page_reports(u)

        self.send_response(404); self.end_headers()

    def do_POST(self):
        init_db()
        user = self.current_user()
        url = urlparse(self.path)
        path = url.path

        kind, payload, err = self.parse_body()
        if err:
            return self.send_html(self.simple_page("Error", f"<p class='err'>{err}</p>"), 400)

        fields = payload.get("fields", payload) if kind == "multipart" else payload
        files = payload.get("files", {}) if kind == "multipart" else {}

        if path == "/login":
            return self.handle_login(fields)
        if path == "/register":
            return self.handle_register(fields)
        if path == "/reset":
            return self.handle_reset_request(fields)
        if path.startswith("/reset/"):
            token = path.split("/", 2)[2]
            return self.handle_reset_submit(token, fields)

        # Auth required actions
        u = self.require_login()
        if not u: return

        if path == "/products/add":
            return self.handle_add_product(u, fields, files)
        if path.startswith("/products/edit/"):
            pid = int(path.split("/")[-1])
            return self.handle_edit_product(u, pid, fields, files)
        if path == "/stock/in":
            return self.handle_stock_in(u, fields)
        if path == "/sales/daily":
            return self.handle_daily_sales(u, fields)
        if path == "/returns":
            return self.handle_returns(u, fields)
        if path == "/approvals/approve":
            if u["role"] != "CEO":
                return self.send_html(self.layout(u, "<h2>Forbidden</h2>"), 403)
            return self.handle_approve(u, fields)
        if path == "/approvals/disable":
            if u["role"] != "CEO":
                return self.send_html(self.layout(u, "<h2>Forbidden</h2>"), 403)
            return self.handle_disable(u, fields)

        self.send_response(404); self.end_headers()

    # ---------------------------
    # Pages & layouts
    # ---------------------------
    def styles(self):
        return """
<style>
:root{
  --bg:#0b1220;
  --card:#0f1b33;
  --card2:#111c36;
  --text:#e8eefc;
  --muted:#a9b4d0;
  --accent:#1f4fff;
  --accent2:#00d4ff;
  --danger:#ff4d4d;
  --ok:#22c55e;
}
*{box-sizing:border-box}
body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;background:#f6f7fb;color:#111827}
a{color:inherit}
.topbar{
  position:sticky;top:0;z-index:10;
  display:flex;justify-content:space-between;align-items:center;
  padding:14px 20px;background:white;border-bottom:1px solid #eaeaf2
}
.brand{display:flex;align-items:center;gap:12px}
.brand img{height:44px}
.brand .name{font-weight:900}
.brand .tag{font-size:12px;color:#6b7280}
.nav a{margin-left:10px;text-decoration:none;padding:9px 12px;border-radius:10px;background:#eef2ff;font-weight:800;color:#1f2937}
.nav a.primary{background:var(--accent);color:white}
.container{max-width:1100px;margin:0 auto;padding:18px}
.hero{
  border-radius:18px;overflow:hidden;
  background:linear-gradient(120deg,var(--bg),#182a52);
  color:var(--text);
  box-shadow:0 14px 34px rgba(17,24,39,.18);
}
.hero-inner{padding:34px 22px;display:grid;grid-template-columns:1.1fr .9fr;gap:18px}
@media (max-width: 900px){.hero-inner{grid-template-columns:1fr}}
.hero h1{margin:0 0 10px;font-size:38px}
.hero p{margin:0;color:var(--muted);line-height:1.6}
.flash{
  display:inline-block;padding:6px 12px;border-radius:999px;
  background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.15);
  animation:flashGlow 1.4s infinite;
}
@keyframes flashGlow{
  0%{box-shadow:0 0 0 rgba(0,212,255,0)}
  50%{box-shadow:0 0 28px rgba(0,212,255,.55)}
  100%{box-shadow:0 0 0 rgba(0,212,255,0)}
}
.hero-card{
  background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.15);
  border-radius:16px;padding:14px
}
.hero video{width:100%;border-radius:14px;display:block;background:#000}
.btn{
  display:inline-block;text-decoration:none;font-weight:900;
  padding:11px 16px;border-radius:12px;border:0;cursor:pointer
}
.btn.primary{background:var(--accent);color:white}
.btn.light{background:#eef2ff;color:#111827}
.btn.danger{background:var(--danger);color:white}
.btn.outline{background:transparent;color:white;border:2px solid rgba(255,255,255,.6)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;margin-top:16px}
.card{background:white;border:1px solid #eef0f6;border-radius:16px;padding:14px;box-shadow:0 10px 24px rgba(17,24,39,.06)}
.card h3{margin:0 0 8px}
.muted{color:#6b7280}
.err{color:var(--danger);font-weight:800}
.ok{color:var(--ok);font-weight:800}
table{width:100%;border-collapse:collapse}
th,td{padding:10px;border-bottom:1px solid #eef0f6;text-align:left;vertical-align:top}
th{font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em}
.badge{display:inline-block;padding:4px 10px;border-radius:999px;font-weight:900;font-size:12px}
.badge.low{background:#fff1f2;color:#b91c1c;border:1px solid #fecdd3}
.badge.ok{background:#ecfdf5;color:#047857;border:1px solid #bbf7d0}
.badge.pending{background:#fff7ed;color:#9a3412;border:1px solid #fed7aa}
form .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:780px){form .row{grid-template-columns:1fr}}
input,select{
  width:100%;padding:11px 12px;border:1px solid #e5e7eb;border-radius:12px
}
label{font-size:13px;font-weight:800;color:#374151}
small{color:#6b7280}
.footer{padding:18px;text-align:center;color:#6b7280}
</style>
"""

    def layout(self, user, content_html, title=""):
        nav = ""
        if user:
            if user["role"] == "CEO":
                nav = f"""
                <div class="nav">
                  <a href="/dashboard">Dashboard</a>
                  <a href="/products">Products</a>
                  <a href="/stock/in">Stock In</a>
                  <a href="/reports">Reports</a>
                  <a href="/approvals" class="primary">Approvals</a>
                  <a href="/activity">Activity</a>
                  <a href="/logout">Logout</a>
                </div>
                """
            else:
                nav = f"""
                <div class="nav">
                  <a href="/dashboard">Dashboard</a>
                  <a href="/products">Products</a>
                  <a href="/sales/daily" class="primary">Daily Sales</a>
                  <a href="/returns">Returns</a>
                  <a href="/logout">Logout</a>
                </div>
                """
        else:
            nav = f"""
            <div class="nav">
              <a href="/login">Login</a>
              <a href="/register" class="primary">Register</a>
            </div>
            """
        html = f"""
<!doctype html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{APP_NAME}{(" — " + title) if title else ""}</title>
{self.styles()}
</head>
<body>
  <div class="topbar">
    <div class="brand">
      <img src="/static/logo.svg" alt="Dipower logo">
      <div>
        <div class="name">{APP_NAME}</div>
        <div class="tag">Inventory • Sales • Returns • Stock Control</div>
      </div>
    </div>
    {nav}
  </div>
  <div class="container">
    {content_html}
  </div>
  <div class="footer">© {now_utc().year} Dipower Stores</div>
</body></html>
"""
        return html

    def simple_page(self, title, body_html):
        return f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>{title}</title>{self.styles()}</head><body><div class='container'>{body_html}</div></body></html>"

    def page_home(self, user):
        # HTML5 video placeholder: user can upload static/welcome.mp4 later
        video = """
<video autoplay muted loop playsinline>
  <source src="/static/welcome.mp4" type="video/mp4">
</video>
<small>Tip: upload <b>static/welcome.mp4</b> to enable the welcome video.</small>
"""
        content = f"""
<div class="hero">
  <div class="hero-inner">
    <div>
      <div class="flash">Welcome</div>
      <h1>Welcome to {APP_NAME}</h1>
      <p>Track your stock, daily sales, returns, low-stock alerts, and slow-moving items — all in one secure app.</p>
      <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap">
        <a class="btn primary" href="/login">Login</a>
        <a class="btn outline" href="/register">Register</a>
      </div>
      <div class="grid" style="margin-top:18px">
        <div class="hero-card"><b>CEO Portal</b><div class="muted">Approvals, analytics, alerts, reports.</div></div>
        <div class="hero-card"><b>Employee Portal</b><div class="muted">Daily sales + returns, stock view.</div></div>
        <div class="hero-card"><b>Safety</b><div class="muted">CEO controls who gets access.</div></div>
      </div>
    </div>
    <div class="hero-card">
      {video}
    </div>
  </div>
</div>
"""
        return self.send_html(self.layout(user, content, "Home"))

    def page_login(self, error=""):
        msg = f"<p class='err'>{error}</p>" if error else ""
        content = f"""
<div class="card">
  <h2>Login</h2>
  {msg}
  <form method="POST" action="/login">
    <div class="row">
      <div><label>Username</label><input name="username" required></div>
      <div><label>Password</label><input type="password" name="password" required></div>
    </div>
    <div style="margin-top:12px;display:flex;gap:10px;flex-wrap:wrap">
      <button class="btn primary" type="submit">Login</button>
      <a class="btn light" href="/register">Register</a>
      <a class="btn light" href="/reset">Forgot Password</a>
    </div>
  </form>
</div>
"""
        return self.send_html(self.layout(None, content, "Login"))

    def page_register(self, error=""):
        msg = f"<p class='err'>{error}</p>" if error else ""
        ceo_note = "First ever account becomes CEO automatically." if not ceo_exists() else "New accounts become Employees and require CEO approval."
        content = f"""
<div class="card">
  <h2>Create Account</h2>
  <p class="muted">{ceo_note}</p>
  {msg}
  <form method="POST" action="/register">
    <div class="row">
      <div><label>Username</label><input name="username" required></div>
      <div><label>Password</label><input type="password" name="password" required></div>
    </div>
    <div style="margin-top:12px;display:flex;gap:10px;flex-wrap:wrap">
      <button class="btn primary" type="submit">Create account</button>
      <a class="btn light" href="/login">Back to login</a>
    </div>
  </form>
</div>
"""
        return self.send_html(self.layout(None, content, "Register"))

    def page_reset_request(self, msg=""):
        hint = f"<p class='ok'>{msg}</p>" if msg else ""
        content = f"""
<div class="card">
  <h2>Reset Password</h2>
  <p class="muted">Enter your username. A reset link will be generated (for now it displays on screen).</p>
  {hint}
  <form method="POST" action="/reset">
    <label>Username</label>
    <input name="username" required>
    <div style="margin-top:12px">
      <button class="btn primary" type="submit">Generate reset link</button>
      <a class="btn light" href="/login">Back</a>
    </div>
  </form>
</div>
"""
        return self.send_html(self.layout(None, content, "Reset"))

    def page_reset_form(self, token, error=""):
        msg = f"<p class='err'>{error}</p>" if error else ""
        content = f"""
<div class="card">
  <h2>Set New Password</h2>
  {msg}
  <form method="POST" action="/reset/{token}">
    <label>New password</label>
    <input type="password" name="password" required>
    <div style="margin-top:12px">
      <button class="btn primary" type="submit">Update password</button>
    </div>
  </form>
</div>
"""
        return self.send_html(self.layout(None, content, "Reset"))

    def page_ceo_dashboard(self, u):
        # Alerts: low stock + slow movers
        low, slow = self.compute_alerts()
        today = today_local()
        wstart = start_of_week(today)
        wend = today
        sales_w, returns_w = totals_between(wstart, wend)

        sales_m = []
        year = today.year
        for m in range(1, 13):
            ms = dt.date(year, m, 1)
            me = (dt.date(year+1, 1, 1) - dt.timedelta(days=1)) if m==12 else (dt.date(year, m+1, 1) - dt.timedelta(days=1))
            s, r = totals_between(ms, me)
            sales_m.append((month_name(m), s, r))

        content = f"""
<div class="grid">
  <div class="card">
    <h3>This Week</h3>
    <div class="muted">{wstart} → {wend}</div>
    <p><b>Sales:</b> ₦{sales_w:,}</p>
    <p><b>Returns:</b> ₦{returns_w:,}</p>
  </div>
  <div class="card">
    <h3>Alerts</h3>
    <p><span class="badge low">{len(low)} Low stock</span></p>
    <p><span class="badge pending">{len(slow)} Slow movers</span></p>
    <div class="muted">See below for details.</div>
  </div>
  <div class="card">
    <h3>Access Control</h3>
    <p class="muted">Only you (CEO) can approve employee accounts.</p>
    <a class="btn primary" href="/approvals">Approve employees</a>
  </div>
</div>

<div class="card" style="margin-top:14px">
  <h3>Low Stock</h3>
  {self.table_products(low, show_alert=True)}
</div>

<div class="card" style="margin-top:14px">
  <h3>Slow Movers</h3>
  <p class="muted">Products with no sales in the last 30 days.</p>
  {self.table_products(slow, show_last_sale=True)}
</div>

<div class="card" style="margin-top:14px">
  <h3>Monthly Summary ({year})</h3>
  <table>
    <thead><tr><th>Month</th><th>Sales</th><th>Returns</th></tr></thead>
    <tbody>
      {''.join([f"<tr><td><b>{m}</b></td><td>₦{s:,}</td><td>₦{r:,}</td></tr>" for (m,s,r) in sales_m])}
    </tbody>
  </table>
</div>
"""
        log_action(u["id"], "VIEW_CEO_DASHBOARD")
        return self.send_html(self.layout(u, content, "CEO Dashboard"))

    def page_employee_dashboard(self, u):
        # employee can see products + balances quickly
        with db() as conn:
            products = conn.execute("SELECT * FROM products ORDER BY id DESC LIMIT 50").fetchall()
        rows = []
        for p in products:
            bal = product_balance(p["id"])
            badge = "<span class='badge low'>LOW</span>" if bal <= int(p["low_stock_threshold"]) else "<span class='badge ok'>OK</span>"
            rows.append(f"<tr><td>{badge}</td><td><b>{p['name']}</b><div class='muted'>SKU: {p['sku'] or '-'}</div></td><td>{bal}</td></tr>")
        content = f"""
<div class="grid">
  <div class="card">
    <h3>Daily Work</h3>
    <p class="muted">Record sales and returns daily. Stock balances update automatically.</p>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <a class="btn primary" href="/sales/daily">Record Daily Sales</a>
      <a class="btn light" href="/returns">Record Returns</a>
    </div>
  </div>
  <div class="card">
    <h3>Stock Balance</h3>
    <p class="muted">Quick view of current balances.</p>
  </div>
</div>

<div class="card" style="margin-top:14px">
  <h3>Products & Balances</h3>
  <table>
    <thead><tr><th>Status</th><th>Product</th><th>Balance</th></tr></thead>
    <tbody>
      {''.join(rows) if rows else "<tr><td colspan='3' class='muted'>No products yet. Ask CEO to add products.</td></tr>"}
    </tbody>
  </table>
</div>
"""
        log_action(u["id"], "VIEW_EMPLOYEE_DASHBOARD")
        return self.send_html(self.layout(u, content, "Employee Dashboard"))

    def page_products(self, u):
        with db() as conn:
            products = conn.execute("SELECT * FROM products ORDER BY id DESC").fetchall()
        cards = []
        for p in products:
            bal = product_balance(p["id"])
            img = f"<img src='/uploads/{quote(p['image_path'])}' style='width:72px;height:72px;object-fit:cover;border-radius:14px;border:1px solid #eef0f6' alt=''>" if p["image_path"] else "<div style='width:72px;height:72px;border-radius:14px;background:#eef2ff;display:flex;align-items:center;justify-content:center;font-weight:900'>DP</div>"
            low = bal <= int(p["low_stock_threshold"])
            badge = "<span class='badge low'>LOW</span>" if low else "<span class='badge ok'>OK</span>"
            edit = f"<a class='btn light' href='/products/edit/{p['id']}'>Edit</a>" if u["role"]=="CEO" else ""
            cards.append(f"""
<div class="card" style="display:flex;gap:12px;align-items:center">
  {img}
  <div style="flex:1">
    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
      <div><b>{p['name']}</b></div>
      {badge}
    </div>
    <div class="muted">SKU: {p['sku'] or '-'} • Low threshold: {p['low_stock_threshold']}</div>
  </div>
  <div style="text-align:right">
    <div class="muted">Balance</div>
    <div style="font-size:22px;font-weight:900">{bal}</div>
    {edit}
  </div>
</div>
""")
        add_btn = "<a class='btn primary' href='/products/add'>Add Product</a>" if u["role"]=="CEO" else ""
        content = f"""
<div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
  <h2 style="margin:0">Products</h2>
  {add_btn}
</div>
<div class="grid" style="grid-template-columns:1fr; margin-top:12px">
  {''.join(cards) if cards else "<div class='card'><p class='muted'>No products yet.</p></div>"}
</div>
"""
        return self.send_html(self.layout(u, content, "Products"))

    def page_add_product(self, u):
        if u["role"] != "CEO":
            return self.send_html(self.layout(u, "<h2>Forbidden</h2>"), 403)
        content = """
<div class="card">
  <h2>Add Product</h2>
  <form method="POST" action="/products/add" enctype="multipart/form-data">
    <div class="row">
      <div><label>Product name</label><input name="name" required></div>
      <div><label>SKU (optional)</label><input name="sku"></div>
    </div>
    <div class="row" style="margin-top:10px">
      <div><label>Low stock threshold</label><input name="low_stock_threshold" type="number" min="0" value="5"></div>
      <div><label>Product image (optional)</label><input type="file" name="image" accept="image/*"></div>
    </div>
    <div style="margin-top:12px">
      <button class="btn primary" type="submit">Save</button>
      <a class="btn light" href="/products">Cancel</a>
    </div>
  </form>
</div>
"""
        return self.send_html(self.layout(u, content, "Add Product"))

    def page_edit_product(self, u, pid):
        if u["role"] != "CEO":
            return self.send_html(self.layout(u, "<h2>Forbidden</h2>"), 403)
        with db() as conn:
            p = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
        if not p:
            return self.send_html(self.layout(u, "<h2>Not found</h2>"), 404)
        img = f"<img src='/uploads/{quote(p['image_path'])}' style='width:120px;height:120px;object-fit:cover;border-radius:18px;border:1px solid #eef0f6' alt=''>" if p["image_path"] else "<div class='muted'>No image yet.</div>"
        content = f"""
<div class="card">
  <h2>Edit Product</h2>
  <div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin-bottom:12px">
    {img}
    <div class="muted">Upload a new image to replace the old one.</div>
  </div>
  <form method="POST" action="/products/edit/{pid}" enctype="multipart/form-data">
    <div class="row">
      <div><label>Product name</label><input name="name" value="{html_escape(p['name'])}" required></div>
      <div><label>SKU (optional)</label><input name="sku" value="{html_escape(p['sku'] or '')}"></div>
    </div>
    <div class="row" style="margin-top:10px">
      <div><label>Low stock threshold</label><input name="low_stock_threshold" type="number" min="0" value="{p['low_stock_threshold']}"></div>
      <div><label>New image (optional)</label><input type="file" name="image" accept="image/*"></div>
    </div>
    <div style="margin-top:12px">
      <button class="btn primary" type="submit">Update</button>
      <a class="btn light" href="/products">Back</a>
    </div>
  </form>
</div>
"""
        return self.send_html(self.layout(u, content, "Edit Product"))

    def page_stock_in(self, u):
        if u["role"] != "CEO":
            return self.send_html(self.layout(u, "<h2>Forbidden</h2>"), 403)
        opts = self.product_options()
        content = f"""
<div class="card">
  <h2>Stock Upload (Stock In)</h2>
  <form method="POST" action="/stock/in">
    <div class="row">
      <div><label>Product</label>
        <select name="product_id" required>
          <option value="">Select product…</option>
          {opts}
        </select>
      </div>
      <div><label>Quantity</label><input type="number" min="1" name="qty" required></div>
    </div>
    <div class="row" style="margin-top:10px">
      <div><label>Reference (optional)</label><input name="ref" placeholder="e.g., China shipment #"></div>
      <div><label>Date</label><input type="date" name="date" value="{today_local().isoformat()}"></div>
    </div>
    <div style="margin-top:12px">
      <button class="btn primary" type="submit">Add Stock</button>
      <a class="btn light" href="/products">Back</a>
    </div>
  </form>
</div>
"""
        return self.send_html(self.layout(u, content, "Stock In"))

    def page_daily_sales(self, u):
        if u["role"] not in ("CEO","EMPLOYEE"):
            return self.send_html(self.layout(u, "<h2>Forbidden</h2>"), 403)
        opts = self.product_options()
        content = f"""
<div class="card">
  <h2>Record Daily Sales</h2>
  <p class="muted">Enter sales for a product. Stock balance will reduce automatically.</p>
  <form method="POST" action="/sales/daily">
    <div class="row">
      <div><label>Product</label>
        <select name="product_id" required>
          <option value="">Select product…</option>
          {opts}
        </select>
      </div>
      <div><label>Quantity</label><input type="number" min="1" name="qty" required></div>
    </div>
    <div class="row" style="margin-top:10px">
      <div><label>Unit price (₦)</label><input type="number" min="0" name="unit_price" value="0"></div>
      <div><label>Date</label><input type="date" name="date" value="{today_local().isoformat()}"></div>
    </div>
    <div style="margin-top:12px">
      <button class="btn primary" type="submit">Save Sale</button>
      <a class="btn light" href="/dashboard">Back</a>
    </div>
  </form>
</div>
"""
        return self.send_html(self.layout(u, content, "Daily Sales"))

    def page_returns(self, u):
        opts = self.product_options()
        content = f"""
<div class="card">
  <h2>Record Returns</h2>
  <p class="muted">Enter returned quantity. Stock balance will increase automatically.</p>
  <form method="POST" action="/returns">
    <div class="row">
      <div><label>Product</label>
        <select name="product_id" required>
          <option value="">Select product…</option>
          {opts}
        </select>
      </div>
      <div><label>Quantity</label><input type="number" min="1" name="qty" required></div>
    </div>
    <div class="row" style="margin-top:10px">
      <div><label>Unit price (₦)</label><input type="number" min="0" name="unit_price" value="0"></div>
      <div><label>Date</label><input type="date" name="date" value="{today_local().isoformat()}"></div>
    </div>
    <div style="margin-top:12px">
      <button class="btn primary" type="submit">Save Return</button>
      <a class="btn light" href="/dashboard">Back</a>
    </div>
  </form>
</div>
"""
        return self.send_html(self.layout(u, content, "Returns"))

    def page_approvals(self, u):
        with db() as conn:
            pending = conn.execute("SELECT * FROM users WHERE role='EMPLOYEE' AND status='PENDING' ORDER BY created_at").fetchall()
            active = conn.execute("SELECT * FROM users WHERE role='EMPLOYEE' AND status='ACTIVE' ORDER BY created_at").fetchall()
        def rows(users, allow_disable=False):
            out=[]
            for x in users:
                btn = ""
                if allow_disable:
                    btn = f"""
                    <form method="POST" action="/approvals/disable" style="display:inline">
                      <input type="hidden" name="user_id" value="{x['id']}">
                      <button class="btn danger" type="submit">Disable</button>
                    </form>
                    """
                else:
                    btn = f"""
                    <form method="POST" action="/approvals/approve" style="display:inline">
                      <input type="hidden" name="user_id" value="{x['id']}">
                      <button class="btn primary" type="submit">Approve</button>
                    </form>
                    """
                out.append(f"<tr><td><b>{html_escape(x['username'])}</b></td><td><span class='badge pending'>{x['status']}</span></td><td>{btn}</td></tr>")
            return "".join(out) if out else "<tr><td colspan='3' class='muted'>None</td></tr>"
        content = f"""
<div class="card">
  <h2>Employee Approvals</h2>
  <h3>Pending</h3>
  <table><thead><tr><th>Employee</th><th>Status</th><th>Action</th></tr></thead><tbody>{rows(pending)}</tbody></table>
  <h3 style="margin-top:16px">Active Employees</h3>
  <table><thead><tr><th>Employee</th><th>Status</th><th>Action</th></tr></thead><tbody>{rows(active, allow_disable=True)}</tbody></table>
</div>
"""
        return self.send_html(self.layout(u, content, "Approvals"))

    def page_activity(self, u):
        with db() as conn:
            logs = conn.execute("""
              SELECT a.*, u.username FROM activity_log a
              LEFT JOIN users u ON u.id=a.user_id
              ORDER BY a.created_at DESC LIMIT 200
            """).fetchall()
        rows=[]
        for l in logs:
            meta = ""
            try:
                m = json.loads(l["meta"] or "{}")
                meta = html_escape(json.dumps(m, ensure_ascii=False))
            except Exception:
                meta = html_escape(l["meta"] or "")
            rows.append(f"<tr><td>{html_escape(l['created_at'])}</td><td>{html_escape(l['username'] or 'system')}</td><td><b>{html_escape(l['action'])}</b><div class='muted'>{meta}</div></td></tr>")
        content = f"""
<div class="card">
  <h2>Activity Log</h2>
  <table><thead><tr><th>Time</th><th>User</th><th>Action</th></tr></thead><tbody>
    {''.join(rows) if rows else "<tr><td colspan='3' class='muted'>No logs yet.</td></tr>"}
  </tbody></table>
</div>
"""
        return self.send_html(self.layout(u, content, "Activity"))

    def page_reports(self, u):
        today = today_local()
        year = today.year
        # weekly
        ws = start_of_week(today)
        we = today
        sales_w, returns_w = totals_between(ws, we)

        # month-to-date
        ms = dt.date(year, today.month, 1)
        sales_mtd, returns_mtd = totals_between(ms, today)

        content = f"""
<div class="grid">
  <div class="card">
    <h3>Weekly (Mon → Today)</h3>
    <div class="muted">{ws} → {we}</div>
    <p><b>Sales:</b> ₦{sales_w:,}</p>
    <p><b>Returns:</b> ₦{returns_w:,}</p>
  </div>
  <div class="card">
    <h3>Month-to-date ({month_name(today.month)})</h3>
    <p><b>Sales:</b> ₦{sales_mtd:,}</p>
    <p><b>Returns:</b> ₦{returns_mtd:,}</p>
  </div>
  <div class="card">
    <h3>Export</h3>
    <p class="muted">You can add CSV export later (recommended).</p>
  </div>
</div>
"""
        return self.send_html(self.layout(u, content, "Reports"))

    # ---------------------------
    # Actions
    # ---------------------------
    def handle_login(self, fields):
        username = (fields.get("username") or "").strip()
        password = fields.get("password") or ""
        user = get_user_by_username(username)
        if not user or not pbkdf2_verify(password, user["password_hash"]):
            return self.page_login("Invalid username or password.")
        if user["status"] == "PENDING":
            return self.page_login("Your account is pending CEO approval.")
        if user["status"] != "ACTIVE":
            return self.page_login("Your account is disabled.")
        payload = {"uid": int(user["id"]), "exp": int(time.time()) + SESSION_TTL_SECONDS}
        cookie = f"{SESSION_COOKIE}={sign_session(payload)}; HttpOnly; Path=/; SameSite=Lax"
        log_action(int(user["id"]), "LOGIN")
        return self.redirect("/dashboard", cookies=[cookie])

    def handle_logout(self):
        cookie = f"{SESSION_COOKIE}=deleted; Path=/; Max-Age=0"
        return self.redirect("/", cookies=[cookie])

    def handle_register(self, fields):
        username = (fields.get("username") or "").strip()
        password = fields.get("password") or ""
        if not re.fullmatch(r"[A-Za-z0-9_\\-\\.]{3,32}", username):
            return self.page_register("Username must be 3–32 chars (letters, numbers, _, -, .)")
        if len(password) < 6:
            return self.page_register("Password must be at least 6 characters.")

        role = "CEO" if not ceo_exists() else "EMPLOYEE"
        status = "ACTIVE" if role == "CEO" else "PENDING"

        try:
            with db() as conn:
                conn.execute(
                    "INSERT INTO users(username,password_hash,role,status,created_at) VALUES(?,?,?,?,?)",
                    (username, pbkdf2_hash(password), role, status, now_utc().isoformat())
                )
                user_id = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
            log_action(user_id, "REGISTER", {"role": role, "status": status})
        except sqlite3.IntegrityError:
            return self.page_register("Username already exists. Choose another.")

        if role == "CEO":
            return self.send_html(self.simple_page("CEO created",
                f"<div class='card'><h2>CEO Account Created</h2><p class='ok'>You are now the CEO.</p><a class='btn primary' href='/login'>Login</a></div>"))
        return self.send_html(self.simple_page("Registered",
            "<div class='card'><h2>Registration submitted</h2><p class='ok'>Your account is pending CEO approval.</p><a class='btn primary' href='/login'>Login</a></div>"))

    def handle_reset_request(self, fields):
        username = (fields.get("username") or "").strip()
        user = get_user_by_username(username)
        if not user:
            return self.page_reset_request("If that username exists, a reset link is generated.")
        token = secrets.token_urlsafe(24)
        expires = now_utc() + dt.timedelta(minutes=30)
        with db() as conn:
            conn.execute(
                "INSERT INTO reset_tokens(user_id, token, expires_at, used, created_at) VALUES(?,?,?,?,?)",
                (int(user["id"]), token, expires.isoformat(), 0, now_utc().isoformat())
            )
        log_action(int(user["id"]), "RESET_REQUEST")
        link = f"/reset/{token}"
        return self.send_html(self.simple_page("Reset link",
            f"<div class='card'><h2>Reset link generated</h2><p class='muted'>Open this link:</p><p><a href='{link}'>{link}</a></p><a class='btn light' href='/login'>Back</a></div>"))

    def handle_reset_submit(self, token, fields):
        password = fields.get("password") or ""
        if len(password) < 6:
            return self.page_reset_form(token, "Password must be at least 6 characters.")
        with db() as conn:
            row = conn.execute("SELECT * FROM reset_tokens WHERE token=?", (token,)).fetchone()
            if not row:
                return self.page_reset_form(token, "Invalid token.")
            if int(row["used"]) == 1:
                return self.page_reset_form(token, "Token already used.")
            if dt.datetime.fromisoformat(row["expires_at"]) < now_utc():
                return self.page_reset_form(token, "Token expired.")
            conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                         (pbkdf2_hash(password), int(row["user_id"])))
            conn.execute("UPDATE reset_tokens SET used=1 WHERE id=?", (int(row["id"]),))
        log_action(int(row["user_id"]), "RESET_DONE")
        return self.send_html(self.simple_page("Password updated",
            "<div class='card'><h2>Password updated</h2><a class='btn primary' href='/login'>Login</a></div>"))

    def handle_add_product(self, u, fields, files):
        name = (fields.get("name") or "").strip()
        sku = (fields.get("sku") or "").strip() or None
        low_thr = int(fields.get("low_stock_threshold") or 5)
        image_path = None

        if "image" in files and files["image"]["data"]:
            image_path = self.save_upload(files["image"]["filename"], files["image"]["data"])

        with db() as conn:
            conn.execute("""
                INSERT INTO products(sku,name,image_path,low_stock_threshold,created_at,updated_at)
                VALUES(?,?,?,?,?,?)
            """, (sku, name, image_path, low_thr, now_utc().isoformat(), now_utc().isoformat()))
            pid = conn.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
        log_action(u["id"], "ADD_PRODUCT", {"product_id": pid, "name": name})
        return self.redirect("/products")

    def handle_edit_product(self, u, pid, fields, files):
        with db() as conn:
            p = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
        if not p:
            return self.send_html(self.layout(u, "<h2>Not found</h2>"), 404)
        name = (fields.get("name") or "").strip()
        sku = (fields.get("sku") or "").strip() or None
        low_thr = int(fields.get("low_stock_threshold") or p["low_stock_threshold"])
        image_path = p["image_path"]

        if "image" in files and files["image"]["data"]:
            image_path = self.save_upload(files["image"]["filename"], files["image"]["data"])

        with db() as conn:
            conn.execute("""
                UPDATE products SET sku=?, name=?, image_path=?, low_stock_threshold=?, updated_at=?
                WHERE id=?
            """, (sku, name, image_path, low_thr, now_utc().isoformat(), pid))
        log_action(u["id"], "EDIT_PRODUCT", {"product_id": pid})
        return self.redirect("/products")

    def handle_stock_in(self, u, fields):
        pid = int(fields.get("product_id") or 0)
        qty = int(fields.get("qty") or 0)
        ref = (fields.get("ref") or "").strip() or None
        date = fields.get("date") or today_local().isoformat()
        if pid <= 0 or qty <= 0:
            return self.send_html(self.layout(u, "<p class='err'>Invalid input.</p>"), 400)
        with db() as conn:
            conn.execute("""
              INSERT INTO stock_movements(product_id,movement_type,qty,unit_price,ref,occurred_on,created_by,created_at)
              VALUES(?,?,?,?,?,?,?,?)
            """, (pid, "IN", qty, 0, ref, date, u["id"], now_utc().isoformat()))
        log_action(u["id"], "STOCK_IN", {"product_id": pid, "qty": qty})
        return self.redirect("/products")

    def handle_daily_sales(self, u, fields):
        pid = int(fields.get("product_id") or 0)
        qty = int(fields.get("qty") or 0)
        unit_price = int(fields.get("unit_price") or 0)
        date = fields.get("date") or today_local().isoformat()
        if pid <= 0 or qty <= 0:
            return self.send_html(self.layout(u, "<p class='err'>Invalid input.</p>"), 400)
        bal = product_balance(pid)
        if qty > bal:
            return self.send_html(self.layout(u, "<p class='err'>Not enough stock for this sale.</p>"), 400)
        with db() as conn:
            conn.execute("""
              INSERT INTO stock_movements(product_id,movement_type,qty,unit_price,ref,occurred_on,created_by,created_at)
              VALUES(?,?,?,?,?,?,?,?)
            """, (pid, "SALE", qty, unit_price, None, date, u["id"], now_utc().isoformat()))
        log_action(u["id"], "SALE", {"product_id": pid, "qty": qty, "unit_price": unit_price})
        return self.redirect("/dashboard")

    def handle_returns(self, u, fields):
        pid = int(fields.get("product_id") or 0)
        qty = int(fields.get("qty") or 0)
        unit_price = int(fields.get("unit_price") or 0)
        date = fields.get("date") or today_local().isoformat()
        if pid <= 0 or qty <= 0:
            return self.send_html(self.layout(u, "<p class='err'>Invalid input.</p>"), 400)
        with db() as conn:
            conn.execute("""
              INSERT INTO stock_movements(product_id,movement_type,qty,unit_price,ref,occurred_on,created_by,created_at)
              VALUES(?,?,?,?,?,?,?,?)
            """, (pid, "RETURN", qty, unit_price, None, date, u["id"], now_utc().isoformat()))
        log_action(u["id"], "RETURN", {"product_id": pid, "qty": qty, "unit_price": unit_price})
        return self.redirect("/dashboard")

    def handle_approve(self, u, fields):
        uid = int(fields.get("user_id") or 0)
        with db() as conn:
            conn.execute("UPDATE users SET status='ACTIVE' WHERE id=? AND role='EMPLOYEE'", (uid,))
        log_action(u["id"], "APPROVE_EMPLOYEE", {"user_id": uid})
        return self.redirect("/approvals")

    def handle_disable(self, u, fields):
        uid = int(fields.get("user_id") or 0)
        with db() as conn:
            conn.execute("UPDATE users SET status='DISABLED' WHERE id=? AND role='EMPLOYEE'", (uid,))
        log_action(u["id"], "DISABLE_EMPLOYEE", {"user_id": uid})
        return self.redirect("/approvals")

    # ---------------------------
    # Utilities
    # ---------------------------
    def save_upload(self, filename, data: bytes):
        ext = os.path.splitext(filename)[1].lower()
        if ext not in (".png",".jpg",".jpeg",".webp",".gif"):
            ext = ".png"
        safe = secrets.token_hex(10) + ext
        out = os.path.join(UPLOAD_DIR, safe)
        with open(out, "wb") as f:
            f.write(data)
        return safe

    def product_options(self):
        with db() as conn:
            products = conn.execute("SELECT id,name FROM products ORDER BY name").fetchall()
        return "".join([f"<option value='{p['id']}'>{html_escape(p['name'])}</option>" for p in products])

    def compute_alerts(self):
        with db() as conn:
            products = conn.execute("SELECT * FROM products").fetchall()
        low=[]
        slow=[]
        cutoff = today_local() - dt.timedelta(days=30)
        for p in products:
            bal = product_balance(p["id"])
            if bal <= int(p["low_stock_threshold"]):
                low.append(p)
            last_sale = product_last_sale_date(p["id"])
            if last_sale is None or last_sale < cutoff:
                slow.append(p)
        return low, slow

    def table_products(self, products, show_alert=False, show_last_sale=False):
        rows=[]
        for p in products:
            bal = product_balance(p["id"])
            badge = ""
            if show_alert:
                badge = "<span class='badge low'>LOW</span>" if bal <= int(p["low_stock_threshold"]) else "<span class='badge ok'>OK</span>"
            last_sale = product_last_sale_date(p["id"])
            last_sale_txt = last_sale.isoformat() if last_sale else "Never"
            rows.append(f"<tr><td><b>{html_escape(p['name'])}</b><div class='muted'>SKU: {html_escape(p['sku'] or '-')}</div></td><td>{bal}</td><td>{badge}</td><td>{last_sale_txt if show_last_sale else ''}</td></tr>")
        if not rows:
            return "<p class='muted'>None</p>"
        head_extra = "<th>Last Sale</th>" if show_last_sale else "<th></th>"
        return f"""
<table>
  <thead><tr><th>Product</th><th>Balance</th><th>Alert</th>{head_extra}</tr></thead>
  <tbody>{''.join(rows)}</tbody>
</table>
"""

def html_escape(s: str) -> str:
    return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;").replace("'","&#39;")

def run():
    init_db()
    port = int(os.environ.get("PORT", "8000"))
    server = HTTPServer(("0.0.0.0", port), AppHandler)
    print(f"Listening on 0.0.0.0:{port}")
    server.serve_forever()

if __name__ == "__main__":
    run()
