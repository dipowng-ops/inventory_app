import os
import json
from datetime import datetime

# --- CORE MODELS ---

class User:
    def __init__(self, username, role='Employee'):
        self.username = username
        self.role = role # Roles: 'Main CEO', 'Manager', 'Employee'

    def appoint_manager(self, employee):
        """Allows the Main CEO to appoint an operational Manager."""
        if self.role != 'Main CEO':
            return "Access Denied: Only the Main CEO can appoint a Manager."
        employee.role = 'Manager'
        return f"{employee.username} is now a Manager with full CEO-level operational access."

class Product:
    def __init__(self, name, sku, cost_price, selling_price, stock=0):
        self.name = name
        self.sku = sku
        self.cost_price = float(cost_price)
        self.selling_price = float(selling_price)
        self.stock = int(stock)
        self.profit_per_unit = self.selling_price - self.cost_price

class InventoryManager:
    def __init__(self):
        self.products = {} # Store products by normalized name (lowercase)
        self.sales_log = []
        self.returns_log = []
        self.training_videos = []
        self.report_dir = "download_portal"
        
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

    # --- UPDATED: PRODUCT MANAGEMENT WITH PRICES & DUPLICATE CHECK ---
    def add_or_update_product(self, name, sku, cost, sale, qty):
        clean_name = name.strip().lower()
        
        # Duplicate Verification
        if clean_name in self.products:
            return f"Error: A product named '{name}' already exists. Use 'Stock In' to add more."
        
        new_prod = Product(name, sku, cost, sale, qty)
        self.products[clean_name] = new_prod
        return "Product added successfully with price tracking."

    # --- TRAINING PORTAL ---
    def upload_training(self, user, title, url):
        if user.role not in ['Main CEO', 'Manager']:
            return "Unauthorized"
        self.training_videos.append({"title": title, "url": url, "date": datetime.now()})
        return "Training video posted."

    # --- DOWNLOAD PORTAL & PROFIT TRACKING ---
    def generate_weekly_report(self):
        total_sales_value = sum(s['revenue'] for s in self.sales_log)
        total_profit = sum(s['profit'] for s in self.sales_log)
        total_returns = len(self.returns_log)
        
        report_data = {
            "week_ending": datetime.now().strftime("%Y-%m-%d"),
            "metrics": {
                "total_sales_naira": total_sales_value,
                "total_net_profit": total_profit,
                "total_returns": total_returns
            },
            "stock_status": [
                {"item": p.name, "balance": p.stock} for p in self.products.values()
            ]
        }
        
        # Save to portal
        filename = f"Report_Week_{datetime.now().strftime('%U_%Y')}.json"
        with open(os.path.join(self.report_dir, filename), 'w') as f:
            json.dump(report_data, f, indent=4)
        
        return f"Report saved to {filename}"

# --- FRONTEND/UI UPDATES (HTML) ---
# To see the prices on your screen, ensure your "Add Product" HTML page 
# includes the following two inputs:
"""
<input type="number" name="cost_price" placeholder="Cost Price (₦)" required>
<input type="number" name="selling_price" placeholder="Selling Price (₦)" required>
"""

# --- AGENT SUMMARY ---
"""
1. CEO SUCCESSION: Use 'user.appoint_manager(staff)' to grant permissions.
2. PRICE TRACKING: Every product now saves 'cost_price' and 'selling_price'.
3. DUPLICATE CHECK: System blocks product creation if a similar name exists.
4. DOWNLOAD PORTAL: Weekly reports now include calculated Profit and Sales.
"""
