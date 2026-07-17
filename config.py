import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
REPORT_FOLDER = os.path.join(BASE_DIR, "reports")

ALLOWED_EXTENSIONS = {"txt", "py", "js", "exe", "jpg", "jpeg", "png"}

SECRET_KEY = "supersecretkey"
DATABASE = os.path.join(BASE_DIR, "instance", "users.db")