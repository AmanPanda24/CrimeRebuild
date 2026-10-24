# Created by: Aman Kumar Panda
"""Evidence intake: hash, preserve a read-only copy, parse, record chain of custody.

Original files are never modified. Each evidence file is copied into the case
folder, hashed (SHA-256) before and after the copy, and marked read-only. The
hash can be re-checked at any time to prove the evidence has not changed.
"""
import hashlib
import os
import shutil
import stat
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from werkzeug.utils import secure_filename

from . import constants as C
from . import db
from .converter import convert_to_json, detect_format
from .parsers import ParseError, parse_file


class DuplicateEvidence(Exception):
    pass


@dataclass
class IngestResult:
    evidence_id: int
    filename: str
    kind: str
    parsed: int = 0
    skipped: int = 0
    status: str = "parsed"
    warnings: list = field(default_factory=list)
    error: str = ""


def sha256_file(path, chunk=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def add_evidence(store, case_id, src_path, original_name=None, kind="auto", origin="upload",
                 default_user="", since_days=None, actor="investigator", note=""):
    """Preserve + parse one evidence file and store its events. Returns IngestResult."""
    original_name = original_name or os.path.basename(src_path)
    digest = sha256_file(src_path)
    size = os.path.getsize(src_path)

    with store.session() as conn:
        dup = conn.execute("SELECT filename FROM evidence WHERE case_id=? AND sha256=?",
                           (case_id, digest)).fetchone()
        if dup:
            raise DuplicateEvidence(f"'{original_name}' is identical to '{dup['filename']}' already in this case.")
        seq = conn.execute("SELECT COUNT(*) FROM evidence WHERE case_id=?", (case_id,)).fetchone()[0] + 1

        ev_dir = store.case_dir(case_id, "evidence")
        stored = os.path.join(ev_dir, f"{seq:03d}_{secure_filename(original_name) or 'evidence.bin'}")
        shutil.copyfile(src_path, stored)
        if sha256_file(stored) != digest:
            os.remove(stored)
            raise IOError("Copy verification failed - evidence hash changed during copy.")
        try:
            os.chmod(stored, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
        except OSError:
            pass

        db.log_custody(conn, case_id, "Evidence received",
                       f"{original_name} | {size:,} bytes | SHA-256 {digest} | origin: {origin}", actor)

        result = IngestResult(0, original_name, kind or "auto")
        rows = []
        try:
            # every format is converted to JSON first (JSON uploads are already JSON), then parsed
            parse_path = stored
            if detect_format(stored) != "json":
                conv_dir = store.case_dir(case_id, "converted")
                parse_path = os.path.join(conv_dir, f"{seq:03d}_{secure_filename(original_name) or 'evidence'}.json")
                fmt, n_rec = convert_to_json(stored, parse_path, original_name)
                db.log_custody(conn, case_id, "Converted to JSON",
                               f"{original_name} ({fmt}) -> {os.path.basename(parse_path)} | {n_rec:,} records | "
                               f"SHA-256 {sha256_file(parse_path)}", "system")
            parsed = parse_file(parse_path, kind, default_user)
            result.kind = parsed.kind
            rows = parsed.rows
            result.skipped = parsed.skipped
            result.warnings = parsed.warnings
            if since_days:
                cutoff = (datetime.now() - timedelta(days=int(since_days))).strftime("%Y-%m-%d %H:%M:%S")
                before = len(rows)
                rows = [r for r in rows if r["ts"] >= cutoff]
                if before != len(rows):
                    result.warnings.append(f"{before - len(rows)} events older than {since_days} days were left out.")
        except ParseError as exc:
            result.status = "failed"
            result.error = str(exc)
            if result.kind == "auto":
                result.kind = ""

        cur = conn.execute(
            "INSERT INTO evidence(case_id, filename, stored_path, kind, origin, sha256, size, added_at, "
            "rows_parsed, rows_skipped, status, note) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (case_id, original_name, stored, result.kind, origin, digest, size, db.now_str(),
             len(rows), result.skipped, result.status, result.error or note))
        result.evidence_id = cur.lastrowid
        result.parsed = len(rows)

        if rows:
            conn.executemany(
                "INSERT INTO events(case_id, evidence_id, ts, source, category, action, user, target, dest, details) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                [(case_id, result.evidence_id, r["ts"], r["source"], r["category"], r["action"],
                  r["user"], r["target"], r["dest"], r["details"]) for r in rows])
        if result.status == "failed":
            db.log_custody(conn, case_id, "Parse failed", f"{original_name}: {result.error}", "system")
        else:
            db.log_custody(conn, case_id, "Evidence parsed",
                           f"{original_name} ({C.SOURCES.get(result.kind, result.kind)}): "
                           f"{len(rows)} events, {result.skipped} rows skipped", "system")
    return result


def verify_case(store, case_id, actor="investigator"):
    """Recompute every stored hash. Returns a list of dicts with status OK / MODIFIED / MISSING."""
    out = []
    with store.session() as conn:
        for ev in conn.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY id", (case_id,)).fetchall():
            if not os.path.exists(ev["stored_path"]):
                status, actual = "MISSING", ""
            else:
                actual = sha256_file(ev["stored_path"])
                status = "OK" if actual == ev["sha256"] else "MODIFIED"
            out.append({"id": ev["id"], "filename": ev["filename"], "expected": ev["sha256"],
                        "actual": actual, "status": status})
        bad = [o for o in out if o["status"] != "OK"]
        detail = (f"All {len(out)} evidence file(s) match their recorded SHA-256 hash." if not bad else
                  "INTEGRITY PROBLEM: " + ", ".join(f"{o['filename']} ({o['status']})" for o in bad))
        db.log_custody(conn, case_id, "Integrity check", detail, actor)
    return out
