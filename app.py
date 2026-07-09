import json
import os
from datetime import datetime

class InventoryApp:
    def __init__(self):
        self.products = {}  
        self.report_dir = "download_portal"
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

    def add_product(self, name, cost_price, selling_price, quantity):
        """
        Includes prices in the product creation. 
        Verifies similar names to prevent duplicates.
        """
        # 1. Verification (Check if name exists regardless of caps)
        clean_name = name.strip().lower()
        if clean_name in self.products:
            return f"❌ Error: '{name}' already exists. Use a different name."

        # 2. Price and Profit Calculation
        cp = float(cost_price)
        sp = float(selling_price)
        profit_per_unit = sp - cp

        # 3. Storage (Now includes price fields)
        self.products[clean_name] = {
            "display_name": name,
            "cost_price": cp,
            "selling_price": sp,
            "quantity": int(quantity),
            "profit_per_unit": profit_per_unit
        }
        return f"✅ Added '{name}': Cost ${cp} | Sale ${sp} | Profit/Unit ${profit_per_unit}"

    def view_inventory(self):
        """Displays all products with their cost and selling prices."""
        print("\n--- Current Inventory & Pricing ---")
        if not self.products:
            print("Inventory is empty.")
            return

        for key, p in self.products.items():
            print(f"Product: {p['display_name']}")
            print(f"   [Stock: {p['quantity']}]")
            print(f"   [Cost Price: ${p['cost_price']}]")
            print(f"   [Selling Price: ${p['selling_price']}]")
            print(f"   [Margin: ${p['profit_per_unit']}]")
            print("-" * 30)

# --- How to use the upgraded pricing ---
app = InventoryApp()

# When you add a product now, you MUST provide 4 things: 
# Name, Cost Price, Selling Price, and Quantity.
app.add_product("Office Chair", 45.00, 89.99, 10)
app.add_product("Desk Lamp", 15.00, 35.00, 25)

# This will show you the prices you just added
app.view_inventory()
