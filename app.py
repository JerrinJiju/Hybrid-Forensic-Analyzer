from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import hashlib
import os
from datetime import datetime
from PIL import Image, ExifTags, ImageChops
import cv2
import numpy as np
# FACE DETECTION SETUP
face_cascade = cv2.CascadeClassifier("haarcascade_frontalface_default.xml")
import imagehash

app = Flask(__name__)
app.secret_key = "forensic_secret"

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
REPORT_FOLDER = os.path.join(BASE_DIR, "reports")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)


# ---------------- USER DATABASE ----------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))


# ---------------- HOME ----------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET","POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            return "User already exists. Please login."

        hashed_password = generate_password_hash(password)

        new_user = User(username=username, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("register.html")


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET","POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):

            session["user"] = username
            return redirect(url_for("dashboard"))

        else:
            return "Invalid login"

    return render_template("login.html")


# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect(url_for("login"))

    return render_template("dashboard.html")

# ---------------- DOWNLOAD REPORT ----------------

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(REPORT_FOLDER, filename, as_attachment=True)


# ---------------- FILE ANALYZER ----------------

@app.route("/file-analyzer", methods=["GET","POST"])
def file_analyzer():

    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        file = request.files["file"]
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        with open(filepath, "r", errors="ignore") as f:
            content = f.read()

        sha256 = hashlib.sha256(content.encode()).hexdigest()

        patterns = {
            "os.system": "System command execution",
            "rm -rf": "Dangerous delete command",
            "cmd.exe": "Windows command execution",
            "powershell": "PowerShell execution",
            "base64": "Encoded payload detected"
        }

        threats = []

        for key in patterns:
            if key in content:
                threats.append(patterns[key])

        if len(threats) == 0:
            risk = "Low"
            recommendation = "File appears safe but always verify source."

        elif len(threats) < 3:
            risk = "Medium"
            recommendation = "Suspicious commands found. Avoid executing this file."

        else:
            risk = "High"
            recommendation = "Dangerous commands detected. Do NOT run this file."

        # ---------------- PDF GENERATION ----------------
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet

        now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        username = session['user']

        report_name = f"{username}_{now}_file_report.pdf"
        pdf_path = os.path.join(REPORT_FOLDER, report_name)

        doc = SimpleDocTemplate(pdf_path)
        styles = getSampleStyleSheet()

        content_list = []

        content_list.append(Paragraph("Hybrid Forensic Analyzer Report", styles["Title"]))
        content_list.append(Spacer(1, 12))

        content_list.append(Paragraph(f"User: {session['user']}", styles["Normal"]))
        content_list.append(Paragraph(f"File Name: {file.filename}", styles["Normal"]))
        content_list.append(Paragraph(f"SHA256: {sha256}", styles["Normal"]))
        content_list.append(Spacer(1, 12))

        content_list.append(Paragraph("Threats Detected:", styles["Heading2"]))
        if threats:
            for t in threats:
                content_list.append(Paragraph(f"- {t}", styles["Normal"]))
        else:
            content_list.append(Paragraph("No threats detected.", styles["Normal"]))

        content_list.append(Spacer(1, 12))

        content_list.append(Paragraph(f"Risk Level: {risk}", styles["Normal"]))
        content_list.append(Paragraph(f"Recommendation: {recommendation}", styles["Normal"]))
        content_list.append(Spacer(1, 12))

        content_list.append(Paragraph(f"Generated: {datetime.now()}", styles["Normal"]))

        doc.build(content_list)

        print("Saved file report at:", pdf_path)
        # ------------------------------------------------

        return render_template(
            "file_report.html",
            filename=file.filename,
            sha256=sha256,
            threats=threats,
            risk=risk,
            recommendation=recommendation,
            report_name=report_name
        )

    return render_template("file_analyzer.html")

# ---------------- IMAGE ANALYZER ----------------

@app.route("/image-analyzer", methods=["GET","POST"])
def image_analyzer():

    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        image = request.files["image"]
        path = os.path.join(UPLOAD_FOLDER, image.filename)
        image.save(path)

        sha256 = hashlib.sha256(open(path,"rb").read()).hexdigest()

        camera = "Unknown"
        timestamp = "Unknown"
        gps = "Not available"

        try:
            img = Image.open(path)
            exif = img._getexif()

            if exif:
                exif_data = {}

                for tag,value in exif.items():
                    decoded = ExifTags.TAGS.get(tag,tag)
                    exif_data[decoded] = value

                camera = exif_data.get("Model","Unknown")
                timestamp = exif_data.get("DateTime","Unknown")

                if "GPSInfo" in exif_data:
                    gps = "GPS Data Present"

        except:
            pass

        if camera == "Unknown":
            metadata_warning = "Metadata missing. Image may be modified."
        else:
            metadata_warning = "Metadata appears normal."

        # -------- ELA --------

        ela_path = os.path.join(UPLOAD_FOLDER,"ela_"+image.filename)

        original = Image.open(path).convert("RGB")
        temp_path = os.path.join(UPLOAD_FOLDER,"temp.jpg")

        original.save(temp_path,"JPEG",quality=90)

        compressed = Image.open(temp_path)

        ela_image = ImageChops.difference(original,compressed)
        ela_image.save(ela_path)

        # -------- LSB CHECK --------

        img_cv = cv2.imread(path)

        if img_cv is None:
            stego_result = "Image could not be processed"
        else:
            blue_channel = img_cv[:,:,0]
            lsb = blue_channel & 1

            ones = np.sum(lsb)
            zeros = lsb.size - ones

            if abs(ones - zeros) < 1000:
                stego_result = "Possible hidden data detected"
            else:
                stego_result = "No steganography patterns detected"

        # -------- REVERSE IMAGE CHECK --------

        uploaded_hash = imagehash.phash(Image.open(path))
        similarity_result = "No similar image found in database"

        for file in os.listdir(UPLOAD_FOLDER):

            if not file.lower().endswith((".jpg",".jpeg",".png")):
                continue

            if file == image.filename or file.startswith("temp") or file.startswith("ela_"):
                continue

            try:
                compare_path = os.path.join(UPLOAD_FOLDER,file)
                compare_hash = imagehash.phash(Image.open(compare_path))

                diff = uploaded_hash - compare_hash

                if diff < 5:
                    similarity_result = f"Similar image detected: {file}"

            except:
                pass

        # -------- ADVANCED EVIDENCE DETECTION --------

        evidence_detected = []

        img_cv2 = cv2.imread(path)

        if img_cv2 is not None:

            gray = cv2.cvtColor(img_cv2, cv2.COLOR_BGR2GRAY)

            faces = face_cascade.detectMultiScale(gray, 1.3, 5)
            if len(faces) > 0:
                evidence_detected.append(f"{len(faces)} person(s) detected")

            edges = cv2.Canny(gray, 50, 150)
            contours, _ = cv2.findContours(edges, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)

            large_objects = [cnt for cnt in contours if cv2.contourArea(cnt) > 5000]
            if len(large_objects) > 5:
                evidence_detected.append("Possible vehicle detected")

            for cnt in contours:
                approx = cv2.approxPolyDP(cnt, 0.02 * cv2.arcLength(cnt, True), True)
                if len(approx) > 8:
                    evidence_detected.append("Possible weapon-like object detected")
                    break

            hsv = cv2.cvtColor(img_cv2, cv2.COLOR_BGR2HSV)

            lower_red1 = np.array([0, 120, 70])
            upper_red1 = np.array([10, 255, 255])
            lower_red2 = np.array([170,120,70])
            upper_red2 = np.array([180,255,255])

            mask1 = cv2.inRange(hsv, lower_red1, upper_red1)
            mask2 = cv2.inRange(hsv, lower_red2, upper_red2)

            red_pixels = np.sum(mask1 + mask2)

            if red_pixels > 5000:
                evidence_detected.append("Possible blood-like region detected")

            if len(evidence_detected) == 0:
                evidence_detected.append("No critical objects detected")

        else:
            evidence_detected.append("Image processing failed")

        # -------- RECOMMENDATION --------

        recommendation = "No suspicious indicators detected."

        if "Possible" in stego_result or "Similar" in similarity_result:
            recommendation = "Suspicious patterns detected."

        if "Possible" in str(evidence_detected):
            recommendation = "Suspicious objects detected."

        # -------- PDF REPORT (FIXED INDENTATION) --------

        now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        username = session['user']

        report_name = f"{username}_{now}_image_report.pdf"
        report_path = os.path.join(REPORT_FOLDER, report_name)

        doc = SimpleDocTemplate(report_path)
        styles = getSampleStyleSheet()

        content = []

        content.append(Paragraph("Hybrid Forensic Image Report", styles['Title']))
        content.append(Spacer(1, 12))

        content.append(Paragraph(f"User: {session['user']}", styles['Normal']))
        content.append(Paragraph(f"File Name: {image.filename}", styles['Normal']))
        content.append(Paragraph(f"SHA256: {sha256}", styles['Normal']))
        content.append(Paragraph(f"Camera: {camera}", styles['Normal']))
        content.append(Paragraph(f"Timestamp: {timestamp}", styles['Normal']))
        content.append(Paragraph(f"GPS: {gps}", styles['Normal']))
        content.append(Spacer(1, 12))

        content.append(Paragraph("Advanced Forensic Checks", styles['Heading2']))
        content.append(Paragraph(f"Metadata: {metadata_warning}", styles['Normal']))
        content.append(Paragraph(f"Hidden Data: {stego_result}", styles['Normal']))
        content.append(Paragraph(f"Reverse Image: {similarity_result}", styles['Normal']))
        content.append(Spacer(1, 12))

        content.append(Paragraph("AI Evidence Detection", styles['Heading2']))
        for item in evidence_detected:
            content.append(Paragraph(f"- {item}", styles['Normal']))

        content.append(Spacer(1, 12))
        content.append(Paragraph("Recommendation", styles['Heading2']))
        content.append(Paragraph(recommendation, styles['Normal']))

        content.append(Spacer(1, 12))
        content.append(Paragraph(f"Generated: {datetime.now()}", styles['Normal']))

        doc.build(content)

        print("Saved image report at:", report_path)

        return render_template("image_report.html",
                               filename=image.filename,
                               sha256=sha256,
                               camera=camera,
                               timestamp=timestamp,
                               gps=gps,
                               metadata_warning=metadata_warning,
                               stego_result=stego_result,
                               similarity_result=similarity_result,
                               evidence_detected=evidence_detected,
                               recommendation=recommendation,
                               report_name=report_name)

    return render_template("image_analyzer.html")

# ---------------- DOWNLOAD REPORT ----------------

@app.route("/download/<path:filename>")
def download_report(filename):

    file_path = os.path.join(REPORT_FOLDER, filename)

    if os.path.exists(file_path):
        return send_from_directory(REPORT_FOLDER, filename, as_attachment=True)
    else:
        return "File not found"


# ---------------- DOWNLOAD ALL REPORTS ----------------

@app.route("/download-all")
def download_all():

    if "user" not in session and "admin" not in session:
        return redirect(url_for("login"))

    reports = os.listdir(REPORT_FOLDER)

    combined_text = ""

    for r in reports:

        file_path = os.path.join(REPORT_FOLDER, r)

        if os.path.isfile(file_path) and r.endswith(".txt"):

            with open(file_path, "r", errors="ignore") as f:
                combined_text += f.read()
                combined_text += "\n\n-----------------------------\n\n"

    combined_file = "combined_report.txt"

    with open(os.path.join(REPORT_FOLDER, combined_file), "w") as c:
        c.write(combined_text)

    return send_from_directory(REPORT_FOLDER, combined_file, as_attachment=True)


# ---------------- INVESTIGATOR LOGIN ----------------

@app.route("/investigator-login", methods=["GET","POST"])
def investigator_login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        if username == "admin" and password == "1234":

            session["admin"] = True
            return redirect(url_for("investigator_dashboard"))

        else:
            return "Invalid admin login"

    return render_template("investigator_login.html")


# ---------------- INVESTIGATOR DASHBOARD ----------------

@app.route("/investigator-dashboard")
def investigator_dashboard():

    if "admin" not in session:
        return redirect(url_for("investigator_login"))

    reports = [f for f in os.listdir(REPORT_FOLDER) if f.endswith(".pdf")]
    
    print("REPORTS:", reports)

    return render_template("investigator_dashboard.html", reports=reports)

# ---------------- INVESTIGATOR LOGOUT ----------------

@app.route("/investigator-logout")
def investigator_logout():

    session.pop("admin", None)
    return redirect(url_for("index"))


# ---------------- USER LOGOUT ----------------

@app.route("/logout")
def logout():

    session.pop("user", None)
    return redirect(url_for("index"))


if __name__ == "__main__":

    with app.app_context():
        db.create_all()

    app.run(debug=True)