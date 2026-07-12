import os
import json
from datetime import datetime

class User:
    def __init__(self, username, role='Employee'):
        self.username = username
        self.role = role
        # Auto-generate work email based on username
        self.work_email = f"{username.lower().replace(' ', '.')}@dipowerstores.live"
        self.is_approved = False  # New employees start unapproved

class StaffManager:
    def __init__(self):
        self.employees = {}  # Store by lowercase name to prevent duplicates
        self.pending_approvals = []

    def register_employee(self, username):
        """Prevents duplicate names and puts employee in the approval queue."""
        clean_name = username.strip().lower()
        if clean_name in self.employees:
            return f"Error: An employee named '{username}' is already in the system."
        
        new_user = User(username)
        self.employees[clean_name] = new_user
        self.pending_approvals.append(new_user)
        return f"Registration submitted. Work email generated: {new_user.work_email}"

    def process_application(self, admin_user, employee_username, action):
        """
        CEO can Approve or Reject.
        Action should be 'APPROVE' or 'REJECT'.
        """
        if admin_user.role != 'Main CEO':
            return "Access Denied."

        clean_name = employee_username.strip().lower()
        user = self.employees.get(clean_name)

        if not user:
            return "Employee not found."

        if action == "APPROVE":
            user.is_approved = True
            if user in self.pending_approvals:
                self.pending_approvals.remove(user)
            return f"Access Granted: {user.username} is now active."
        
        elif action == "REJECT":
            # Remove from system entirely if rejected
            del self.employees[clean_name]
            if user in self.pending_approvals:
                self.pending_approvals.remove(user)
            return f"Application Denied: {employee_username} has been removed."

# --- INTEGRATING INTO YOUR EXISTING APP ---

class InventoryApp:
    def __init__(self):
        self.staff_system = StaffManager()
        # ... other existing app initializations ...

    def add_new_staff(self, name):
        return self.staff_system.register_employee(name)

    def review_staff(self, ceo, name, decision):
        # decision is "APPROVE" or "REJECT"
        return self.staff_system.process_application(ceo, name, decision)
