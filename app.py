#!/usr/bin/env python3
"""
Simple inventory management web application.

This application provides a minimal web interface for tracking products,
stock, sales and returns.  It uses Python's standard library only and
stores data in a SQLite database (`inventory.db`).  The server exposes
several endpoints:

  * `/` – summary dashboard with weekly/monthly sales, low stock alerts and slow‑moving items.
  * `/add_product` – form to add a new product.
  * `/add_sale` – form to record a sale (single product).
  * `/add_return` – form to record a return (linked to a sale item).

For demonstration purposes, the application runs on localhost:8000 and
does not implement user authentication.  In a production system you
should add proper authentication, input validation and CSRF protection.

To run the app: `python3 app.py` then navigate to http://localhost:8000

Note: This code is kept simple due to the environment's restrictions
(no external packages).  It is intended as a proof of concept rather
than a production‑ready application.
"""

import html
import sqlite3
import os
import urllib.parse
from datetime import datetime, date, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer


DB_PATH = os.path.join(os.path.dirname(__file__), 'inventory.db')


def init_db():
    """Create database tables if they do not already exist."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Create tables
    c.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sku TEXT UNIQUE,
            name TEXT,
            description TEXT,
            cost_price REAL,
            selling_price REAL,
            reorder_level INTEGER DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS stores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            platform TEXT,
            location TEXT,
            currency TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS stock (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            store_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            reorder_level INTEGER,
            FOREIGN KEY(store_id) REFERENCES stores(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            store_id INTEGER,
            sale_date TEXT,
            total_amount REAL,
            FOREIGN KEY(store_id) REFERENCES stores(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS sale_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sale_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            selling_price REAL,
            FOREIGN KEY(sale_id) REFERENCES sales(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS returns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sale_item_id INTEGER,
            product_id INTEGER,
            return_date TEXT,
            quantity INTEGER,
            reason TEXT,
            restocked INTEGER,
            FOREIGN KEY(sale_item_id) REFERENCES sale_items(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    """)
    # Insert a default store if none exists
    c.execute("SELECT COUNT(*) FROM stores")
    if c.fetchone()[0] == 0:
        c.execute(
            "INSERT INTO stores (name, platform, location, currency) VALUES (?, ?, ?, ?)",
            ("Main Warehouse", "offline", "", "NGN"),
        )
    conn.commit()
    conn.close()


def add_product(data):
    """Add a product to the database and create initial stock entry."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    sku = data.get('sku')
    name = data.get('name')
    description = data.get('description', '')
    try:
        cost_price = float(data.get('cost_price') or 0)
        selling_price = float(data.get('selling_price') or 0)
        reorder_level = int(data.get('reorder_level') or 0)
        quantity = int(data.get('quantity') or 0)
    except ValueError:
        cost_price = selling_price = 0.0
        reorder_level = quantity = 0
    # Insert product
    c.execute(
        "INSERT INTO products (sku, name, description, cost_price, selling_price, reorder_level) VALUES (?, ?, ?, ?, ?, ?)",
        (sku, name, description, cost_price, selling_price, reorder_level),
    )
    product_id = c.lastrowid
    # Get default store id
    c.execute("SELECT id FROM stores ORDER BY id LIMIT 1")
    store_id = c.fetchone()[0]
    # Insert stock record
    c.execute(
        "INSERT INTO stock (store_id, product_id, quantity, reorder_level) VALUES (?, ?, ?, ?)",
        (store_id, product_id, quantity, reorder_level),
    )
    conn.commit()
    conn.close()


def record_sale(data):
    """Record a sale and update stock."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    product_id = int(data.get('product_id'))
    try:
        quantity = int(data.get('quantity'))
    except ValueError:
        quantity = 0
    # Determine selling price from product record
    c.execute("SELECT selling_price FROM products WHERE id=?", (product_id,))
    row = c.fetchone()
    if row:
        price = row[0]
    else:
        price = 0.0
    total_amount = price * quantity
    sale_date = date.today().isoformat()
    # Use default store
    c.execute("SELECT id FROM stores ORDER BY id LIMIT 1")
    store_id = c.fetchone()[0]
    c.execute(
        "INSERT INTO sales (store_id, sale_date, total_amount) VALUES (?, ?, ?)",
        (store_id, sale_date, total_amount),
    )
    sale_id = c.lastrowid
    # Insert sale item
    c.execute(
        "INSERT INTO sale_items (sale_id, product_id, quantity, selling_price) VALUES (?, ?, ?, ?)",
        (sale_id, product_id, quantity, price),
    )
    # Update stock quantity
    c.execute(
        "UPDATE stock SET quantity = quantity - ? WHERE product_id=? AND store_id=?",
        (quantity, product_id, store_id),
    )
    conn.commit()
    conn.close()


def record_return(data):
    """Record a return and update stock. Expects sale_item_id and quantity."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        sale_item_id = int(data.get('sale_item_id'))
        quantity = int(data.get('quantity'))
        restocked = int(data.get('restocked', 0))  # 1 if restocked
    except (ValueError, TypeError):
        sale_item_id = 0
        quantity = 0
        restocked = 0
    reason = data.get('reason', '')
    return_date = date.today().isoformat()
    # Get product ID from sale item
    c.execute("SELECT product_id, sale_id FROM sale_items WHERE id=?", (sale_item_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return
    product_id, sale_id = row
    # Insert return
    c.execute(
        "INSERT INTO returns (sale_item_id, product_id, return_date, quantity, reason, restocked) VALUES (?, ?, ?, ?, ?, ?)",
        (sale_item_id, product_id, return_date, quantity, reason, restocked),
    )
    # If restocked, increase stock quantity
    if restocked:
        # Use default store
        c.execute("SELECT id FROM stores ORDER BY id LIMIT 1")
        store_id = c.fetchone()[0]
        c.execute(
            "UPDATE stock SET quantity = quantity + ? WHERE product_id=? AND store_id=?",
            (quantity, product_id, store_id),
        )
    conn.commit()
    conn.close()


def get_summary():
    """Return summary data: weekly sales, monthly sales, low stock, slow moving."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    today = date.today()
    # Weekly sales for last 4 weeks
    weekly_sales = []
    for i in range(0, 4):
        start = today - timedelta(days=today.weekday()) - timedelta(weeks=i)
        end = start + timedelta(days=6)
        c.execute(
            "SELECT SUM(total_amount) FROM sales WHERE sale_date BETWEEN ? AND ?",
            (start.isoformat(), end.isoformat()),
        )
        total = c.fetchone()[0] or 0.0
        label = f"{start.strftime('%Y-%m-%d')} – {end.strftime('%Y-%m-%d')}"
        weekly_sales.append((label, total))
    # Monthly sales for last 6 months
    monthly_sales = []
    year = today.year
    month = today.month
    for _ in range(6):
        start = date(year, month, 1)
        if month == 12:
            end = date(year + 1, 1, 1) - timedelta(days=1)
        else:
            end = date(year, month + 1, 1) - timedelta(days=1)
        c.execute(
            "SELECT SUM(total_amount) FROM sales WHERE sale_date BETWEEN ? AND ?",
            (start.isoformat(), end.isoformat()),
        )
        total = c.fetchone()[0] or 0.0
        label = start.strftime('%Y-%m')
        monthly_sales.append((label, total))
        # Move to previous month
        if month == 1:
            month = 12
            year -= 1
        else:
            month -= 1
    # Low stock items
    c.execute("""
        SELECT p.sku, p.name, s.quantity, s.reorder_level
        FROM stock s
        JOIN products p ON p.id = s.product_id
        WHERE s.quantity <= s.reorder_level
    """)
    low_stock = c.fetchall()
    # Slow‑moving items: no sales in last 30 days
    threshold_date = (today - timedelta(days=30)).isoformat()
    c.execute("""
        SELECT p.sku, p.name
        FROM products p
        LEFT JOIN sale_items si ON p.id = si.product_id
        LEFT JOIN sales s ON s.id = si.sale_id AND s.sale_date > ?
        WHERE s.id IS NULL
    """, (threshold_date,))
    slow_moving = c.fetchall()
    conn.close()
    return weekly_sales, monthly_sales, low_stock, slow_moving


class InventoryHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the inventory app."""

    def do_GET(self):  # noqa: N802
        if self.path == '/':
            self.serve_dashboard()
        elif self.path == '/add_product':
            self.serve_add_product()
        elif self.path == '/add_sale':
            self.serve_add_sale()
        elif self.path == '/add_return':
            self.serve_add_return()
        else:
            self.send_error(404, 'Page not found')

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode()
        data = urllib.parse.parse_qs(body)
        # Convert list values to single values
        data = {k: v[0] if isinstance(v, list) else v for k, v in data.items()}
        if self.path == '/add_product':
            add_product(data)
            self.redirect('/')
        elif self.path == '/add_sale':
            record_sale(data)
            self.redirect('/')
        elif self.path == '/add_return':
            record_return(data)
            self.redirect('/')
        else:
            self.send_error(404, 'Page not found')

    def serve_dashboard(self):
        weekly_sales, monthly_sales, low_stock, slow_moving = get_summary()
        rows_weekly = ''.join(
            f'<tr><td>{html.escape(label)}</td><td>{total:.2f}</td></tr>' for label, total in weekly_sales
        )
        rows_monthly = ''.join(
            f'<tr><td>{html.escape(label)}</td><td>{total:.2f}</td></tr>' for label, total in monthly_sales
        )
        rows_low = ''.join(
            f'<tr><td>{html.escape(sku)}</td><td>{html.escape(name)}</td><td>{qty}</td><td>{level}</td></tr>'
            for sku, name, qty, level in low_stock
        )
        rows_slow = ''.join(
            f'<tr><td>{html.escape(sku)}</td><td>{html.escape(name)}</td></tr>' for sku, name in slow_moving
        )
        content = f"""
        <html><head><title>Inventory Dashboard</title><style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            h2 {{ margin-top: 40px; }}
            a.button {{ display: inline-block; padding: 8px 12px; margin-right: 10px; background-color: #007bff;
                        color: #fff; text-decoration: none; border-radius: 4px; }}
        </style></head><body>
        <h1>Inventory Dashboard</h1>
        <a class="button" href="/add_product">Add Product</a>
        <a class="button" href="/add_sale">Record Sale</a>
        <a class="button" href="/add_return">Record Return</a>

        <h2>Weekly Sales (last 4 weeks)</h2>
        <table><tr><th>Week</th><th>Total Amount (NGN)</th></tr>
            {rows_weekly}
        </table>
        <h2>Monthly Sales (last 6 months)</h2>
        <table><tr><th>Month</th><th>Total Amount (NGN)</th></tr>
            {rows_monthly}
        </table>
        <h2>Low Stock Alerts</h2>
        <table><tr><th>SKU</th><th>Name</th><th>Quantity</th><th>Reorder Level</th></tr>
            {rows_low or '<tr><td colspan="4">No low stock items</td></tr>'}
        </table>
        <h2>Slow‑Moving Items (no sales in last 30 days)</h2>
        <table><tr><th>SKU</th><th>Name</th></tr>
            {rows_slow or '<tr><td colspan="2">No slow‑moving items</td></tr>'}
        </table>
        </body></html>
        """
        self.respond(content)

    def serve_add_product(self):
        content = """
        <html><head><title>Add Product</title><style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            label { display: block; margin-top: 10px; }
            input[type=text], input[type=number] { width: 300px; padding: 4px; }
            button { margin-top: 10px; padding: 8px 12px; }
        </style></head><body>
        <h1>Add Product</h1>
        <form method="POST" action="/add_product">
            <label>SKU: <input type="text" name="sku" required></label>
            <label>Name: <input type="text" name="name" required></label>
            <label>Description: <input type="text" name="description"></label>
            <label>Cost Price (NGN): <input type="number" step="0.01" name="cost_price"></label>
            <label>Selling Price (NGN): <input type="number" step="0.01" name="selling_price"></label>
            <label>Reorder Level: <input type="number" name="reorder_level" value="0"></label>
            <label>Initial Quantity: <input type="number" name="quantity" value="0"></label>
            <button type="submit">Add Product</button>
        </form>
        <p><a href="/">Back to dashboard</a></p>
        </body></html>
        """
        self.respond(content)

    def serve_add_sale(self):
        # Fetch product list
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, sku, name FROM products ORDER BY name")
        products = c.fetchall()
        conn.close()
        options = ''.join(
            f'<option value="{pid}">{html.escape(sku)} – {html.escape(name)}</option>'
            for pid, sku, name in products
        )
        content = f"""
        <html><head><title>Record Sale</title><style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            label {{ display: block; margin-top: 10px; }}
            select, input[type=number] {{ width: 300px; padding: 4px; }}
            button {{ margin-top: 10px; padding: 8px 12px; }}
        </style></head><body>
        <h1>Record Sale</h1>
        <form method="POST" action="/add_sale">
            <label>Product:
                <select name="product_id" required>
                    {options}
                </select>
            </label>
            <label>Quantity: <input type="number" name="quantity" value="1" min="1" required></label>
            <button type="submit">Record Sale</button>
        </form>
        <p><a href="/">Back to dashboard</a></p>
        </body></html>
        """
        self.respond(content)

    def serve_add_return(self):
        # Fetch sale items for selection
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT si.id, p.sku, p.name, si.quantity, s.sale_date
            FROM sale_items si
            JOIN products p ON p.id = si.product_id
            JOIN sales s ON s.id = si.sale_id
            ORDER BY s.sale_date DESC
        """)
        sale_items = c.fetchall()
        conn.close()
        options = ''.join(
            f'<option value="{sid}">{html.escape(sku)} – {html.escape(name)} (Qty {qty}, {sale_date})</option>'
            for sid, sku, name, qty, sale_date in sale_items
        )
        content = f"""
        <html><head><title>Record Return</title><style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            label {{ display: block; margin-top: 10px; }}
            select, input[type=number], input[type=text] {{ width: 400px; padding: 4px; }}
            button {{ margin-top: 10px; padding: 8px 12px; }}
        </style></head><body>
        <h1>Record Return</h1>
        <form method="POST" action="/add_return">
            <label>Sale Item:
                <select name="sale_item_id" required>
                    {options}
                </select>
            </label>
            <label>Quantity: <input type="number" name="quantity" value="1" min="1" required></label>
            <label>Reason: <input type="text" name="reason"></label>
            <label>Restock?<nobr> <input type="checkbox" name="restocked" value="1"></nobr></label>
            <button type="submit">Record Return</button>
        </form>
        <p><a href="/">Back to dashboard</a></p>
        </body></html>
        """
        self.respond(content)

    def respond(self, content: str, code: int = 200):
        encoded = content.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def redirect(self, location: str):
        self.send_response(303)
        self.send_header('Location', location)
        self.end_headers()


def run_server(port: int = 8000):
    init_db()
    server_address = ('', port)
    httpd = HTTPServer(server_address, InventoryHandler)
    print(f"Starting inventory server on port {port}…")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")


if __name__ == '__main__':
    run_server()
