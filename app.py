
from http.server import HTTPServer, BaseHTTPRequestHandler
import os, sqlite3

DATA_DIR = os.environ.get("DATA_DIR", ".")
DB = os.path.join(DATA_DIR, "dipower.db")

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, qty INTEGER)")
    conn.commit()
    conn.close()

class App(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type","text/html")
            self.end_headers()
            self.wfile.write(b'''
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{margin:0;font-family:Arial}
.sidebar{height:100%;width:200px;position:fixed;background:#1e3a8a;padding:20px;color:white}
.content{margin-left:220px;padding:20px}
a{color:white;display:block;margin:10px 0;text-decoration:none}
@media(max-width:768px){.sidebar{width:100%;height:auto;position:relative}.content{margin:0}}
</style>
</head>
<body>
<div class="sidebar">
<h2>Dipower</h2>
<a href="/">Dashboard</a>
<a href="/add">Add Product</a>
</div>
<div class="content">
<h1>Inventory Dashboard</h1>
<p>Mobile friendly fresh deployment</p>
</div>
</body>
</html>
''')
        elif self.path == "/add":
            self.send_response(200)
            self.send_header("Content-type","text/html")
            self.end_headers()
            self.wfile.write(b'''
<form method="post">
<input name="name" placeholder="Product name"><br>
<input name="qty" type="number" placeholder="Quantity"><br>
<button>Add</button>
</form>
''')
    def do_POST(self):
        length = int(self.headers.get("Content-Length"))
        data = self.rfile.read(length).decode()
        name = data.split("&")[0].split("=")[1]
        qty = int(data.split("&")[1].split("=")[1])
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("INSERT INTO products(name,qty) VALUES(?,?)",(name,qty))
        conn.commit()
        conn.close()
        self.send_response(302)
        self.send_header("Location","/")
        self.end_headers()

if __name__ == "__main__":
    init_db()
    HTTPServer(("0.0.0.0", int(os.environ.get("PORT",8000))), App).serve_forever()
