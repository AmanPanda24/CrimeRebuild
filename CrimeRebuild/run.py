# Created by: Aman Kumar Panda
"""Start the CrimeRebuild web app:  python run.py   ->  http://127.0.0.1:5000"""
import argparse

from crimerebuild import create_app

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="CrimeRebuild - digital crime scene reconstruction")
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default: local machine only)")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()
    create_app().run(host=args.host, port=args.port, debug=args.debug)
