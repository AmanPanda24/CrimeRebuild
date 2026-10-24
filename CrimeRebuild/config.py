# Created by: Aman Kumar Panda
"""CrimeRebuild configuration.

Everything runs locally. Evidence copies, the SQLite database and generated
reports live under DATA_DIR (default: ./data next to this file).
"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.environ.get("CRIMEREBUILD_DATA", os.path.join(BASE_DIR, "data"))
SECRET_KEY = os.environ.get("CRIMEREBUILD_SECRET", "crimerebuild-dev-key-change-me")
MAX_UPLOAD_MB = 500

# Shown on the About page and in the PDF report footer. Edit freely.
PROJECT_META = {
    "title": "CrimeRebuild",
    "subtitle": "A Digital Crime Scene Reconstruction System",
    "program": "MCA (Cybersecurity & Forensics Science) - Minor Project 2025-26",
    "institute": "Parul University",
    "author": "Aman Kumar Panda",
}
