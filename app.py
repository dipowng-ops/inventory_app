import json
import os
from datetime import datetime

class User:
    def __init__(self, username, role='Employee'):
        self.username = username
        self.role = role

class TrainingPortal:
    def __init__(self):
        self.videos = []

    def upload_video(self, uploader, title, video_url, description):
        """Only the Main CEO or Manager can upload training videos."""
        if uploader.role not in ['Main CEO', 'Manager']:
            return "Access Denied: Only leadership can upload training materials."
        
        video_entry = {
            "title": title,
            "url": video_url,
            "description": description,
            "uploaded_by": uploader.username,
            "date": datetime.now().strftime("%Y-%m-%d")
        }
        self.videos.append(video_entry)
        return f"Training video '{title}' uploaded successfully for staff."

    def get_training_list(self):
        """Allows all staff to see available training."""
        if not self.videos:
            return "No training videos available yet."
        return self.videos

class InventoryApp:
    def __init__(self):
        self.products = {}
        self.sales_log = []
        self.training = TrainingPortal() # Integration of Training Portal
        self.report_dir = "download_portal"
        
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

    # ... [Existing Inventory functions: add_product, record_sale, etc.] ...

# --- Operational Flow ---
if __name__ == "__main__":
    app = InventoryApp()
    
    # Setup Roles
    ceo = User("Executive_Director", role="Main CEO")
    staff = User("Staff_Member", role="Employee")

    # 1. CEO uploads a training video (e.g., hosted on YouTube, Vimeo, or a private server)
    print(app.training.upload_video(
        ceo, 
        "Customer Service 101", 
        "[company-server.com](https://company-server.com/videos/training01.mp4)", 
        "How to handle returns effectively."
    ))

    # 2. Staff views the training list
    available_videos = app.training.get_training_list()
    for vid in available_videos:
        print(f"Watch: {vid['title']} | Link: {vid['url']}")

    # 3. Staff tries to upload (Should be blocked)
    print(app.training.upload_video(staff, "Hack", "url", "desc"))
