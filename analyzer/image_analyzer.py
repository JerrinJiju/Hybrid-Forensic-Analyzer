from PIL import Image, ExifTags
import cv2
import numpy as np

# ---------------- ADVANCED IMAGE ANALYZER ----------------
@app.route("/image-analyzer", methods=["GET", "POST"])
def image_analyzer():

    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        image = request.files.get("image")
        if not image:
            return "No image selected"

        filepath = os.path.join("uploads", image.filename)
        image.save(filepath)

        filename = image.filename
        file_size = os.path.getsize(filepath)

        # ---------------- HASH ----------------
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()

        # ---------------- EXIF METADATA ----------------
        img_pil = Image.open(filepath)
        exif_data = {}
        gps_info = "Not Available"

        try:
            exif_raw = img_pil._getexif()
            if exif_raw:
                for tag, value in exif_raw.items():
                    decoded = ExifTags.TAGS.get(tag, tag)
                    exif_data[decoded] = value

                if "GPSInfo" in exif_data:
                    gps_info = "GPS Data Present"
        except:
            exif_data = {}

        camera_model = exif_data.get("Model", "Unknown")
        timestamp = exif_data.get("DateTime", "Unknown")

        # ---------------- OPENCV LOAD ----------------
        img_cv = cv2.imread(filepath)

        # ---------------- RED REGION DETECTION ----------------
        hsv = cv2.cvtColor(img_cv, cv2.COLOR_BGR2HSV)
        lower_red1 = np.array([0,120,70])
        upper_red1 = np.array([10,255,255])
        mask1 = cv2.inRange(hsv, lower_red1, upper_red1)
        red_pixels = np.sum(mask1 > 0)

        # ---------------- EDGE DETECTION ----------------
        gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
        edges = cv2.Canny(gray, 100, 200)
        edge_pixels = np.sum(edges > 0)

        # ---------------- HUMAN DETECTION ----------------
        face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
        )
        faces = face_cascade.detectMultiScale(gray, 1.3, 5)
        human_count = len(faces)

        # ---------------- SCENE DISORDER SCORE ----------------
        total_pixels = img_cv.shape[0] * img_cv.shape[1]
        disorder_score = int((edge_pixels / total_pixels) * 100)

        # ---------------- RISK ENGINE ----------------
        risk_score = 0

        if red_pixels > 500:
            risk_score += 30

        if disorder_score > 20:
            risk_score += 30

        if human_count > 0:
            risk_score += 20

        if gps_info != "Not Available":
            risk_score += 10

        if risk_score > 100:
            risk_score = 100

        if risk_score < 30:
            risk_level = "Low Risk"
            recommendation = "No major forensic indicators detected."

        elif risk_score < 70:
            risk_level = "Medium Risk"
            recommendation = "Image contains suspicious visual patterns."

        else:
            risk_level = "High Risk"
            recommendation = "Multiple forensic indicators detected. Further investigation recommended."

        # SAVE TO DATABASE
        conn = sqlite3.connect("instance/users.db")
        conn.execute("""
        INSERT INTO reports (investigator_id, filename, file_hash, risk_score, risk_level)
        VALUES (?, ?, ?, ?, ?)
        """, (
            session["investigator_id"],
            filename,
            file_hash,
            risk_score,
            risk_level
        ))
        conn.commit()
        conn.close()

        return render_template(
            "image_report.html",
            filename=filename,
            file_hash=file_hash,
            camera_model=camera_model,
            timestamp=timestamp,
            gps_info=gps_info,
            red_pixels=red_pixels,
            disorder_score=disorder_score,
            human_count=human_count,
            risk_score=risk_score,
            risk_level=risk_level,
            recommendation=recommendation
        )

    return render_template("image_analyzer.html")