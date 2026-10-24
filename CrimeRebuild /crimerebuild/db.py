# Created by: Aman Kumar Panda
"""SQLite storage: schema, connection helper, detection settings."""
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    investigator TEXT DEFAULT '',
    description TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    risk_score INTEGER DEFAULT 0,
    risk_level TEXT DEFAULT 'None',
    is_demo INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    kind TEXT,
    origin TEXT DEFAULT 'upload',
    sha256 TEXT NOT NULL,
    size INTEGER DEFAULT 0,
    added_at TEXT NOT NULL,
    rows_parsed INTEGER DEFAULT 0,
    rows_skipped INTEGER DEFAULT 0,
    status TEXT DEFAULT 'parsed',
    note TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id INTEGER REFERENCES evidence(id) ON DELETE CASCADE,
    ts TEXT NOT NULL,
    source TEXT,
    category TEXT,
    action TEXT,
    user TEXT DEFAULT '',
    target TEXT DEFAULT '',
    dest TEXT DEFAULT '',
    details TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_case_ts ON events(case_id, ts);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    rule TEXT,
    title TEXT,
    severity TEXT,
    points INTEGER,
    description TEXT,
    user TEXT DEFAULT '',
    first_ts TEXT,
    last_ts TEXT,
    mitre TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS alert_events (
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL,
    PRIMARY KEY (alert_id, event_id)
);
CREATE TABLE IF NOT EXISTS custody (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    ts TEXT NOT NULL,
    actor TEXT DEFAULT 'system',
    action TEXT,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""

# key, label, default, type, help text
SETTING_DEFS = [
    ("mass_delete_count", "Mass deletion: file count", "10", "int",
     "Flag when at least this many files are deleted by one user inside the time window."),
    ("mass_delete_window_min", "Mass deletion: window (minutes)", "5", "int",
     "Length of the sliding time window."),
    ("deletion_ignore_paths", "Mass deletion: ignored paths", "/temp/, /tmp/, /cache/, inetcache", "list",
     "Comma-separated fragments. Deletions inside these paths are treated as housekeeping noise."),
    ("brute_force_count", "Failed logins: attempt count", "5", "int",
     "Flag when one account (or one source address) fails this many times inside the window."),
    ("brute_force_window_min", "Failed logins: window (minutes)", "10", "int",
     "Length of the sliding time window."),
    ("night_start_hour", "Off-hours login: start hour (0-23)", "0", "int",
     "Logins from this hour onward are unusual. Use equal start and end to disable the rule."),
    ("night_end_hour", "Off-hours login: end hour (0-23)", "5", "int",
     "Logins before this hour are unusual. The end hour itself is not included."),
    ("usb_bulk_files", "USB: bulk copy size", "5", "int",
     "Copying at least this many files to a removable drive is rated high even if none look sensitive."),
    ("usb_session_max_hours", "USB: assumed session length (hours)", "12", "int",
     "Used when a USB device has no recorded disconnect event."),
    ("sensitive_keywords", "Sensitive file keywords", "confidential, secret, password, credential, salary, payroll, financial, private, .kdbx, .pem, .pfx, .key", "list",
     "A file is treated as sensitive when its name contains any of these fragments."),
    ("protected_paths", "Protected path fragments", "windows/system32, windows/syswow64, drivers/etc/hosts, program files, ntuser.dat, /audit/", "list",
     "Modifying files under these paths raises a file-tampering alert."),
    ("cover_window_min", "Cover-tracks window (minutes)", "60", "int",
     "A sensitive file deleted this soon after being copied is flagged as evidence destruction."),
]


def default_settings():
    return {k: d for k, _l, d, _t, _h in SETTING_DEFS}


def get_settings(conn):
    """Return the typed settings dict (ints / lists) merged with defaults."""
    raw = default_settings()
    for row in conn.execute("SELECT key, value FROM settings"):
        if row["key"] in raw:
            raw[row["key"]] = row["value"]
    typed = {}
    for key, _label, default, typ, _help in SETTING_DEFS:
        val = raw[key]
        if typ == "int":
            try:
                typed[key] = int(val)
            except (TypeError, ValueError):
                typed[key] = int(default)
        elif typ == "list":
            typed[key] = [p.strip().lower() for p in str(val).split(",") if p.strip()]
        else:
            typed[key] = val
    return typed


def get_raw_settings(conn):
    raw = default_settings()
    for row in conn.execute("SELECT key, value FROM settings"):
        if row["key"] in raw:
            raw[row["key"]] = row["value"]
    return raw


def save_settings(conn, form):
    for key, *_ in SETTING_DEFS:
        if key in form:
            conn.execute("INSERT INTO settings(key, value) VALUES(?, ?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                         (key, str(form[key]).strip()))


def reset_settings(conn):
    conn.execute("DELETE FROM settings")


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class Store:
    """Owns the data directory and hands out SQLite sessions."""

    def __init__(self, data_dir):
        self.data_dir = os.path.abspath(data_dir)
        os.makedirs(os.path.join(self.data_dir, "cases"), exist_ok=True)
        self.db_path = os.path.join(self.data_dir, "crimerebuild.db")
        with self.session() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def session(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def case_dir(self, case_id, *parts):
        path = os.path.join(self.data_dir, "cases", str(int(case_id)), *parts)
        os.makedirs(path, exist_ok=True)
        return path


# --- small query helpers shared by views / pipeline ---------------------------
def create_case(conn, name, investigator="", description="", is_demo=False):
    cur = conn.execute(
        "INSERT INTO cases(name, investigator, description, created_at, is_demo) VALUES(?,?,?,?,?)",
        (name.strip() or "Untitled case", investigator.strip(), description.strip(), now_str(), int(is_demo)))
    case_id = cur.lastrowid
    log_custody(conn, case_id, "Case opened", f"Case '{name.strip() or 'Untitled case'}' created", actor=investigator or "investigator")
    return case_id


def get_case(conn, case_id):
    return conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()


def log_custody(conn, case_id, action, detail="", actor="system"):
    conn.execute("INSERT INTO custody(case_id, ts, actor, action, detail) VALUES(?,?,?,?,?)",
                 (case_id, now_str(), actor, action, detail))
