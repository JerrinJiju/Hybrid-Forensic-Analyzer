# 🔍 Hybrid Forensic Analyzer

A Flask-based Digital Forensic Analysis Platform developed to assist investigators in analyzing digital evidence through file forensics, image forensics, and basic crime scene detection. The application integrates multiple forensic techniques into a single platform, enabling investigators to examine evidence, detect suspicious content, generate forensic reports, and support digital investigations.

---

## 📌 Features

### 🔐 User Management
- Secure User Registration and Login
- Investigator Dashboard
- Role-based Access

### 📂 File Forensics
- File Metadata Extraction
- SHA-256 Hash Generation
- File Integrity Verification
- File Risk Assessment
- Automated PDF Report Generation

### 🖼️ Image Forensics
- EXIF Metadata Extraction
- Error Level Analysis (ELA)
- Hidden Data Detection
- Face Detection
- Image Hash Comparison

### 🚔 Basic Crime Scene Detection
The application includes a basic computer vision module capable of identifying potential evidence from uploaded crime scene images.

Current detection capabilities include:
- 🔫 Weapon-like Object Detection
- 🚗 Vehicle Detection
- 🩸 Blood-like Region Detection
- 👤 Face Detection
- Evidence Highlighting for Investigative Review

This feature is designed to demonstrate the application of image processing techniques in assisting digital forensic investigations.

---

## 🛠️ Technology Stack

### Backend
- Python
- Flask
- SQLAlchemy
- SQLite

### Frontend
- HTML5
- CSS3
- JavaScript

### Libraries
- OpenCV
- Pillow (PIL)
- ReportLab
- ImageHash
- Werkzeug

---

## Key Modules

- User Authentication
- File Analyzer
- Image Analyzer
- Crime Scene Detection
- Investigator Dashboard
- PDF Report Generator

---

## Project Structure

```
Hybrid-Forensic-Analyzer/

│── analyzer/
│── instance/
│── static/
│── templates/
│── utils/
│── app.py
│── config.py
│── requirements.txt
│── README.md
│── LICENSE
```

---

## Installation

```bash
git clone https://github.com/JerrinJiju/Hybrid-Forensic-Analyzer.git

cd Hybrid-Forensic-Analyzer

pip install -r requirements.txt

python app.py
```

---

## Project Workflow

1. User Login
2. Upload File or Image
3. Perform File or Image Analysis
4. Execute Crime Scene Detection (for images)
5. Generate Risk Assessment
6. Generate PDF Investigation Report
7. Investigator Review

---

## Future Enhancements

- AI-based Crime Scene Detection
- Object Detection using YOLO
- Cloud Forensics Support
- Malware Analysis Module
- SIEM Integration
- Real-time Threat Intelligence
- Multi-user Investigator Collaboration

---


## Author

**Jerrin Jiju**

B.Sc. Cyber Forensics Graduate

GitHub:
https://github.com/JerrinJiju

LinkedIn:
https://www.linkedin.com/in/jerrin-jiju-71bb74370

---

## License

This project is licensed under the MIT License.
