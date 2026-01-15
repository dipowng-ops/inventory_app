import os
import sqlite3
import urllib.parse
import uuid
import hashlib
import http.cookies
import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
import cgi
import mimetypes

DB_PATH = os.path.join(os.environ.get('DATA_DIR', '/var/data') if os.path.isdir('/var/data') else os.path.dirname(__file__), 'inventory.db')
UPLOAD_DIR = os.path.join(os.path.dirname(DB_PATH), 'uploads')
STATIC_DIR = os.path.join(os.path.dirname(__file__), 'static')
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Initialize database with required tables
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        role TEXT,
        approved INTEGER DEFAULT 0
    )''')
    # sessions table
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        user_id INTEGER,
        expires_at INTEGER
    )''')
    # products table
    c.execute('''CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sku TEXT UNIQUE,
        name TEXT,
        image_filename TEXT,
        cost_price REAL,
        selling_price REAL,
        reorder_level INTEGER
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS stock (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER,
        quantity_on_hand INTEGER
    )''')
    # sales
    c.execute('''CREATE TABLE IF NOT EXISTS sales (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        sale_date TEXT,
        total REAL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS sale_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sale_id INTEGER,
        product_id INTEGER,
        quantity INTEGER,
        price REAL
    )''')
    # returns
    c.execute('''CREATE TABLE IF NOT EXISTS returns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        return_date TEXT,
        product_id INTEGER,
        quantity INTEGER,
        amount_refunded REAL
    )''')
    conn.commit()
    conn.close()

# Utility functions

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_session(user_id: int) -> str:
    session_id = uuid.uuid4().hex
    expires_at = int((datetime.datetime.utcnow() + datetime.timedelta(days=7)).timestamp())
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)", (session_id, user_id, expires_at))
    conn.commit()
    conn.close()
    return session_id

def get_user_by_session(session_id: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT users.id, users.username, users.role, users.approved FROM sessions JOIN users ON sessions.user_id = users.id WHERE sessions.session_id = ? AND sessions.expires_at > ?", (session_id, int(datetime.datetime.utcnow().timestamp())))
    user = c.fetchone()
    conn.close()
    return user  # tuple: (id, username, role, approved)

# HTTP Handler
class InventoryHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        # serve static assets
        if path.startswith('/static/'):
            return self.serve_static(path)
        if path.startswith('/uploads/'):
            return self.serve_uploads(path)

        # get current user from session cookie
        cookies = http.cookies.SimpleCookie(self.headers.get('Cookie'))
        session_id = cookies.get('session_id').value if cookies.get('session_id') else None
        user = get_user_by_session(session_id) if session_id else None

        if path == '/':
            return self.redirect('/login')
        elif path == '/register':
            return self.render_register(user)
        elif path == '/login':
            return self.render_login()
        elif path == '/logout':
            self.clear_session()
            return self.redirect('/login')
        elif path == '/dashboard':
            return self.render_dashboard(user)
        elif path == '/approve_user':
            if user and user[2] == 'CEO':
                user_id = int(params.get('id',[0])[0])
                self.approve_user(user_id)
                return self.redirect('/dashboard')
            else:
                return self.forbidden()
        else:
            return self.not_found()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        cookies = http.cookies.SimpleCookie(self.headers.get('Cookie'))
        session_id = cookies.get('session_id').value if cookies.get('session_id') else None
        user = get_user_by_session(session_id) if session_id else None

        if path == '/register':
            return self.handle_register()
        elif path == '/login':
            return self.handle_login()
        else:
            return self.not_found()

    # Rendering functions
    def render_login(self):
        content = f"""
        <html><head><title>Login - Dipower Stores</title>{self.styles()}</head>
        <body><div class='container'>
        <img src='/static/logo.png' alt='Dipower logo' class='logo'>
        <h1>Login</h1>
        <form method='POST' action='/login'>
            <label>Username: <input type='text' name='username' required></label><br>
            <label>Password: <input type='password' name='password' required></label><br>
            <button type='submit'>Login</button>
        </form>
        <p>Don't have an account? <a href='/register'>Register</a></p>
        </div></body></html>
        """
        self.respond(content)

    def render_register(self, user):
        # CEO registration only if no CEO exists
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM users WHERE role = 'CEO'")
        has_ceo = c.fetchone()[0] > 0
        conn.close()
        if has_ceo and (not user or user[2] != 'CEO'):
            role_field = ""  # employees cannot choose role
        else:
            role_field = "<label>Role: <select name='role'><option value='CEO'>CEO</option><option value='employee'>Employee</option></select></label><br>"
        content = f"""
        <html><head><title>Register - Dipower Stores</title>{self.styles()}</head>
        <body><div class='container'>
        <img src='/static/logo.png' alt='Dipower logo' class='logo'>
        <h1>Register</h1>
        <form method='POST' action='/register'>
            <label>Username: <input type='text' name='username' required></label><br>
            <label>Password: <input type='password' name='password' required></label><br>
            {role_field}
            <button type='submit'>Register</button>
        </form>
        <p>Already have an account? <a href='/login'>Login</a></p>
        </div></body></html>
        """
        self.respond(content)

    def render_dashboard(self, user):
        if not user:
            return self.redirect('/login')
        if user[3] == 0:  # not approved
            content = f"""
            <html><head><title>Account Pending - Dipower Stores</title>{self.styles()}</head><body><div class='container'>
            <h1>Account Pending Approval</h1>
            <p>Your account is awaiting approval by the CEO.</p>
            <p><a href='/logout'>Logout</a></p>
            </div></body></html>
            """
            return self.respond(content)
        # user is approved
        role = user[2]
        if role == 'CEO':
            # show CEO dashboard: pending users list and summary (simple)
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT id, username FROM users WHERE approved = 0 AND role='employee'")
            pending = c.fetchall()
            conn.close()
            pending_html = "".join([f"<li>{u[1]} <a href='/approve_user?id={u[0]}'>Approve</a></li>" for u in pending])
            if not pending_html:
                pending_html = '<li>No pending users</li>'
            content = f"""
            <html><head><title>CEO Dashboard - Dipower Stores</title>{self.styles()}</head><body><div class='container'>
            <img src='/static/header.png' class='header'>
            <h1>Welcome, CEO {user[1]}</h1>
            <h2>Pending Employee Approvals</h2>
            <ul>{pending_html}</ul>
            <p><a href='/logout'>Logout</a></p>
            </div></body></html>
            """
            return self.respond(content)
        else:
            # employee dashboard
            content = f"""
            <html><head><title>Employee Dashboard - Dipower Stores</title>{self.styles()}</head><body><div class='container'>
            <img src='/static/header.png' class='header'>
            <h1>Welcome, {user[1]}</h1>
            <p>Your role: {role}</p>
            <p>More employee features to be added.</p>
            <p><a href='/logout'>Logout</a></p>
            </div></body></html>
            """
            return self.respond(content)
        
    # handle registration POST
    def handle_register(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        params = urllib.parse.parse_qs(post_data.decode())
        username = params.get('username',[""])[0].strip()
        password = params.get('password',[""])[0]
        role = params.get('role', ['employee'])[0]
        # if CEO exists, force role employee except if CEO creation hasn't happened
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM users WHERE role='CEO'")
        has_ceo = c.fetchone()[0] > 0
        if has_ceo and role == 'CEO':
            role = 'employee'
        password_hash = hash_password(password)
        try:
            c.execute("INSERT INTO users (username, password_hash, role, approved) VALUES (?, ?, ?, ?)" , (username, password_hash, role, 1 if role=='CEO' else 0))
            conn.commit()
            conn.close()
            # if CEO registered, login directly
            if role == 'CEO':
                user_id = c.lastrowid
                session_id = create_session(user_id)
                self.send_response(HTTPStatus.SEE_OTHER)
                self.send_header('Location', '/dashboard')
                self.send_header('Set-Cookie', f'session_id={session_id}; Path=/')
                self.end_headers()
            else:
                self.send_response(HTTPStatus.SEE_OTHER)
                self.send_header('Location', '/login')
                self.end_headers()
        except sqlite3.IntegrityError:
            conn.close()
            content = f"""
            <html><head><title>Registration Error</title>{self.styles()}</head><body><div class='container'>
            <h1>Registration Error</h1>
            <p>Username already exists. Please go back and choose a different username.</p>
            <p><a href='/register'>Back to register</a></p>
            </div></body></html>
            """
            self.respond(content)

    def handle_login(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        params = urllib.parse.parse_qs(post_data.decode())
        username = params.get('username',[""])[0]
        password = params.get('password',[""])[0]
        password_hash = hash_password(password)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, role, approved FROM users WHERE username=? AND password_hash=?", (username, password_hash))
        row = c.fetchone()
        conn.close()
        if row:
            user_id, role, approved = row
            session_id = create_session(user_id)
            # set cookie and redirect
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header('Location', '/dashboard')
            self.send_header('Set-Cookie', f'session_id={session_id}; Path=/')
            self.end_headers()
        else:
            content = f"""
            <html><head><title>Login Error</title>{self.styles()}</head><body><div class='container'>
            <h1>Login Failed</h1>
            <p>Invalid username or password.</p>
            <p><a href='/login'>Try again</a></p>
            </div></body></html>
            """
            self.respond(content)

    def approve_user(self, user_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE users SET approved=1 WHERE id=?", (user_id,))
        conn.commit()
        conn.close()

    # Response helpers
    def styles(self):
        return """
        <style>
        body { font-family: Arial, sans-serif; background-color: #f4f5f8; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 40px auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #2a4a7b; margin-top: 0; }
        form label { display:block; margin-bottom:10px; }
        form input[type='text'], form input[type='password'], select { width:100%; padding:8px; margin-top:4px; border:1px solid #ccc; border-radius:4px; }
        button { background:#2a4a7b; color:white; padding:10px 20px; border:none; border-radius:4px; cursor:pointer; }
        button:hover { background:#1d345b; }
        a { color:#2a4a7b; }
        .logo { max-width:200px; margin-bottom:20px; }
        .header { width:100%; border-radius:8px; margin-bottom:20px; }
        ul { list-style: none; padding-left:0; }
        li { margin-bottom:8px; }
        </style>
        """

    def respond(self, content, status=HTTPStatus.OK):
        content_bytes = content.encode()
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(content_bytes)))
        self.end_headers()
        self.wfile.write(content_bytes)

    def redirect(self, location):
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header('Location', location)
        self.end_headers()

    def forbidden(self):
        self.send_response(HTTPStatus.FORBIDDEN)
        self.end_headers()
        self.wfile.write(b'Forbidden')

    def not_found(self):
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()
        self.wfile.write(b'Not Found')

    # Serving static files
    def serve_static(self, path):
        rel = path[len('/static/'):]
        file_path = os.path.join(STATIC_DIR, rel)
        if not os.path.isfile(file_path):
            return self.not_found()
        ctype = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
        self.send_response(HTTPStatus.OK)
        self.send_header('Content-Type', ctype)
        fs = os.stat(file_path)
        self.send_header('Content-Length', str(fs.st_size))
        self.end_headers()
        with open(file_path, 'rb') as f:
            self.wfile.write(f.read())

    def serve_uploads(self, path):
        rel = path[len('/uploads/'):]
        file_path = os.path.join(UPLOAD_DIR, rel)
        if not os.path.isfile(file_path):
            return self.not_found()
        ctype = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
        self.send_response(HTTPStatus.OK)
        self.send_header('Content-Type', ctype)
        fs = os.stat(file_path)
        self.send_header('Content-Length', str(fs.st_size))
        self.end_headers()
        with open(file_path, 'rb') as f:
            self.wfile.write(f.read())

    def clear_session(self):
        # remove session from DB and clear cookie
        cookies = http.cookies.SimpleCookie(self.headers.get('Cookie'))
        session_id = cookies.get('session_id').value if cookies.get('session_id') else None
        if session_id:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
            conn.commit()
            conn.close()
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header('Location', '/login')
        self.send_header('Set-Cookie', 'session_id=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/')
        self.end_headers()


def run_server(port=8000):
    init_db()
    server_address = ('', port)
    httpd = HTTPServer(server_address, InventoryHandler)
    print(f"Server running on port {port} ...")
    httpd.serve_forever()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', '8000'))
    run_server(port)
