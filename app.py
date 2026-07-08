import json
import os
from datetime import datetime

class User:
    def __init__(self, username, role='Employee'):
        self.username = username
        self.role = role

    def appoint_successor(self, employee):
        """Allows CEO to appoint a new CEO from the employee pool."""
        if self.role != 'CEO':
            return "Access Denied: Only the CEO can appoint a successor."
        
        if not isinstance(employee, User):
            return "Error: Target must be a valid User object."

        employee.role = 'CEO'
        self.role = 'Employee'  # Current CEO steps down to Employee
        return f"Succession Complete: {employee.username} is now the CEO. {self.username} has been demoted."

class InventoryApp:
    def __init__(self):
        self.products = {}  # key: lowercase name, value: details
        self.sales_log = []
        self.returns_log = []
        self.report_dir = "download_portal"
        
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

    def add_product(self, name, cost_price, selling_price, quantity):
        """Adds a product with profit tracking and duplicate verification."""
        name_key = name.strip().lower()
        
        if name_key in self.products:
            return f"Error: A product with the name '{name}' already exists."
        
        self.products[name_key] = {
            "name": name,
            "cost_price": float(cost_price),
            "selling_price": float(selling_price),
            "quantity": int(quantity),
            "profit_per_unit": float(selling_price) - float(cost_price)
        }
        return f"Product '{name}' added successfully."

    def record_sale(self, name, quantity):
        name_key = name.strip().lower()
        if name_key in self.products and self.products[name_key]['quantity'] >= quantity:
            self.products[name_key]['quantity'] -= quantity
            sale_entry = {
                "name": self.products[name_key]['name'],
                "quantity": quantity,
                "revenue": self.products[name_key]['selling_price'] * quantity,
                "date": datetime.now().strftime("%Y-%m-%d")
            }
            self.sales_log.append(sale_entry)
            return "Sale recorded."
        return "Insufficient stock or product not found."

    def record_return(self, name, quantity):
        name_key = name.strip().lower()
        if name_key in self.products:
            self.products[name_key]['quantity'] += quantity
            self.returns_log.append({
                "name": name,
                "quantity": quantity,
                "date": datetime.now().strftime("%Y-%m-%d")
            })
            return "Return processed."
        return "Product not found."

    def generate_weekly_report(self):
        """Compiles stats and saves a report to the download portal."""
        total_sales_value = sum(item['revenue'] for item in self.sales_log)
        total_returns = sum(item['quantity'] for item in self.returns_log)
        
        report_data = {
            "report_date": datetime.now().strftime("%Y-%m-%d"),
            "weekly_summary": {
                "total_sales_revenue": total_sales_value,
                "total_items_returned": total_returns,
                "current_inventory_status": [
                    {
                        "product": p['name'],
                        "in_stock": p['quantity'],
                        "potential_profit_remaining": p['quantity'] * p['profit_per_unit']
                    } for p in self.products.values()
                ]
            }
        }
        
        # Save to Download Portal
        filename = f"report_week_{datetime.now().strftime('%U_%Y')}.json"
        filepath = os.path.join(self.report_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=4)
        
        return f"Weekly report stored in download portal: {filepath}"

# --- Example Usage ---
if __name__ == "__main__":
    # Initialize App
    app = InventoryApp()
    
    # 1. Setup Users
    ceo = User("Alice", role="CEO")
    employee = User("Bob", role="Employee")
    
    # 2. Add Products (with duplicate verification)
    print(app.add_product("Widget A", 10.00, 15.00, 100))
    print(app.add_product("widget a", 10.00, 15.00, 100)) # Should fail
    
    # 3. Operations
    app.record_sale("Widget A", 5)
    app.record_return("Widget A", 1)
    
    # 4. Generate Report
    print(app.generate_weekly_report())
    
    # 5. CEO Succession
    print(ceo.appoint_successor(employee))
    print(f"New CEO Name: {employee.username}, Role: {employee.role}")
