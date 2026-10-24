# Created by: Aman Kumar Panda
"""Module 2 - Evidence Parser.

Every parser turns one raw artifact (CSV / JSON / SQLite) into a list of events
that share a single schema:

    ts, source, category, action, user, target, dest, details

Timestamps are normalised to UTC and written as 'YYYY-MM-DD HH:MM:SS'.
Timestamps without a timezone are assumed to already be UTC.
"""
import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd

from . import constants as C


class ParseError(Exception):
    """Raised when a file cannot be understood as the requested evidence type."""


@dataclass
class ParseResult:
    kind: str
    rows: list = field(default_factory=list)
    skipped: int = 0
    warnings: list = field(default_factory=list)


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def _norm_col(name):
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def read_table(path):
    """Load a CSV or JSON file into a DataFrame of strings with normalised column names."""
    ext = os.path.splitext(path)[1].lower()
    if ext in (".json", ".jsonl", ".ndjson"):
        with open(path, encoding="utf-8-sig") as fh:
            text = fh.read()
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            try:
                data = [json.loads(line) for line in text.splitlines() if line.strip()]
            except json.JSONDecodeError as exc:
                raise ParseError(f"Invalid JSON: {exc}") from exc
        if isinstance(data, dict):
            for key in ("events", "records", "data", "items", "entries"):
                if isinstance(data.get(key), list):
                    data = data[key]
                    break
            else:
                data = [data]
        df = pd.json_normalize(data)
    else:
        df = None
        for enc in ("utf-8-sig", "utf-16", "latin-1"):
            try:
                df = pd.read_csv(path, dtype=str, keep_default_na=False, encoding=enc)
                if df.shape[1] == 1:   # maybe a ; or tab separated export
                    df = pd.read_csv(path, dtype=str, keep_default_na=False, encoding=enc,
                                     sep=None, engine="python")
                break
            except (UnicodeError, UnicodeDecodeError):
                continue
            except pd.errors.EmptyDataError:
                df = pd.DataFrame()
                break
            except pd.errors.ParserError as exc:
                raise ParseError(f"Could not read CSV: {exc}") from exc
        if df is None:
            raise ParseError("Could not decode the file as text.")
    df.columns = [_norm_col(c) for c in df.columns]
    return df.fillna("").astype(str)


def pick(df, *aliases):
    """Return the first matching column as a stripped string Series (or empty strings)."""
    for name in aliases:
        if name in df.columns:
            return df[name].astype(str).str.strip()
    return pd.Series([""] * len(df), index=df.index, dtype="object")


def parse_ts(series):
    """Parse a Series of date strings -> naive UTC datetimes (NaT where unparseable)."""
    s = series.astype(str).str.strip()
    try:
        out = pd.to_datetime(s, errors="coerce", utc=True, format="mixed")
    except (TypeError, ValueError):
        out = pd.to_datetime(s, errors="coerce", utc=True)
    return out.dt.tz_localize(None)


def normalize_user(value):
    value = (value or "").strip()
    if value in ("-", "N/A", "n/a", "nan", "None"):
        return ""
    if "\\" in value:
        value = value.rsplit("\\", 1)[-1]
    return value


def normalize_drive(value):
    m = re.match(r"^\s*([A-Za-z]):?", value or "")
    return f"{m.group(1).upper()}:" if m else ""


def _iso(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def make_row(ts, kind, action, user="", target="", dest="", details=""):
    return {
        "ts": _iso(ts) if not isinstance(ts, str) else ts,
        "source": C.SOURCES[kind],
        "category": C.category_of(action),
        "action": action,
        "user": normalize_user(user),
        "target": (target or "")[:500],
        "dest": (dest or "")[:300],
        "details": (details or "")[:600],
    }


def _rx(text, pattern):
    m = re.search(pattern, text or "", flags=re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _int(value):
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None


def classify_url(url):
    host = (urlparse(url).hostname or "").lower()
    for h in C.WEBMAIL_HOSTS:
        if host == h or host.endswith("." + h):
            return "Webmail Opened"
    for h in C.CLOUD_HOSTS:
        if host == h or host.endswith("." + h):
            return "Cloud Storage Visited"
    return "URL Visited"


# ----------------------------------------------------------------------------
# kind detection
# ----------------------------------------------------------------------------
def sniff_kind(path):
    with open(path, "rb") as fh:
        head = fh.read(16)
    if head.startswith(b"SQLite format 3"):
        return "browser"
    df = read_table(path)
    cols = set(df.columns)
    if cols & {"eventid", "eventidentifier"} or ("id" in cols and cols & {"message", "providername", "provider"}):
        return "eventlog"
    if cols & {"serial", "serialnumber", "devicename", "vendor", "friendlyname", "driveletter"}:
        return "usb"
    if "url" in cols:
        return "browser"
    if cols & {"result", "status", "outcome"} and cols & {"logontype", "sourceip", "ipaddress", "sourceaddress"}:
        return "login"
    if cols & {"path", "filepath", "filename", "file", "target"}:
        return "file"
    if cols & {"result", "status", "outcome"} and cols & {"user", "username", "account"}:
        return "login"
    raise ParseError("Could not detect the evidence type from the column names. "
                     "Choose the type manually. Columns found: " + ", ".join(sorted(cols)[:12]))


# ----------------------------------------------------------------------------
# event log
# ----------------------------------------------------------------------------
LOCAL_ADDRS = {"", "-", "::1", "127.0.0.1", "localhost"}


def parse_eventlog(df, default_user=""):
    res = ParseResult("eventlog")
    ts = parse_ts(pick(df, "timecreated", "dateandtime", "datetime", "timestamp", "timegenerated",
                       "systemtime", "time", "date"))
    eid = pick(df, "eventid", "id", "eventidentifier")
    user = pick(df, "account", "user", "username", "targetusername", "subjectusername", "accountname")
    obj = pick(df, "objectname", "file", "path")
    mask = pick(df, "accessmask")
    ltype = pick(df, "logontype")
    ip = pick(df, "ipaddress", "sourcenetworkaddress", "sourceip", "clientaddress")
    msg = pick(df, "message", "description")
    proc = pick(df, "processname", "newprocessname", "image")
    cmd = pick(df, "commandline", "processcommandline")
    comp = pick(df, "computer", "computername", "machinename")

    for i in range(len(df)):
        when = ts.iat[i]
        event_id = _int(eid.iat[i])
        if pd.isna(when) or event_id is None:
            res.skipped += 1
            continue
        message = msg.iat[i]
        who = user.iat[i] or _rx(message, r"Account Name:\s*(\S+)") or default_user
        target = obj.iat[i] or _rx(message, r"Object Name:\s*(.+)")
        process = proc.iat[i] or _rx(message, r"Process Name:\s*(.+)")
        address = ip.iat[i] or _rx(message, r"Source Network Address:\s*(\S+)")
        address = "" if address in LOCAL_ADDRS else address

        if event_id in (4663, 4660):
            m = _int(mask.iat[i]) or _int(_rx(message, r"Access Mask:\s*(\S+)")) or 0
            if event_id == 4660 or m & 0x10000:
                action = "File Deleted"
            elif m & 0x6:
                action = "File Modified"
            else:
                action = "File Accessed"
            row = make_row(when, "eventlog", action, who, target, "", f"via {process}" if process else "")
        elif event_id in (4624, 4648):
            lt = ltype.iat[i] or _rx(message, r"Logon Type:\s*(\d+)")
            note = f"Logon type {lt}" if lt else ""
            if address:
                note += f" from {address}"
            row = make_row(when, "eventlog", "Login Success", who, comp.iat[i], address, note.strip())
        elif event_id == 4625:
            lt = ltype.iat[i] or _rx(message, r"Logon Type:\s*(\d+)")
            note = "Failed logon" + (f" (type {lt})" if lt else "") + (f" from {address}" if address else "")
            row = make_row(when, "eventlog", "Login Failed", who, comp.iat[i], address, note)
        elif event_id == 4688:
            row = make_row(when, "eventlog", "Process Started", who, process or target, "", cmd.iat[i])
        elif event_id in (4720, 4726, 4732, 4698, 7045):
            action = C.EVENT_ID_ACTIONS[event_id]
            row = make_row(when, "eventlog", action, who, target, "", cmd.iat[i] or message[:200])
        elif event_id in (1102, 104):
            row = make_row(when, "eventlog", "Audit Log Cleared", who, target or "Security log", "",
                           "The event log was cleared")
        elif event_id in C.EVENT_ID_ACTIONS:
            row = make_row(when, "eventlog", C.EVENT_ID_ACTIONS[event_id], who, comp.iat[i], "", message[:200])
        else:
            row = make_row(when, "eventlog", f"Event {event_id}", who, target or comp.iat[i], "", message[:200])
        res.rows.append(row)
    return res


# ----------------------------------------------------------------------------
# browser history
# ----------------------------------------------------------------------------
_WEBKIT_EPOCH_US = 11644473600 * 1_000_000   # microseconds between 1601 and 1970


def _from_webkit(us):
    try:
        us = int(us)
        if us <= 0:
            return None
        return datetime(1970, 1, 1) + timedelta(microseconds=us - _WEBKIT_EPOCH_US)
    except (TypeError, ValueError, OverflowError):
        return None


def _from_unix_us(us):
    try:
        return datetime(1970, 1, 1) + timedelta(microseconds=int(us))
    except (TypeError, ValueError, OverflowError):
        return None


def parse_browser_sqlite(path, default_user=""):
    """Chrome / Edge `History` or Firefox `places.sqlite` (opened read-only)."""
    res = ParseResult("browser")
    uri = Path(path).resolve().as_uri() + "?mode=ro&immutable=1"
    try:
        con = sqlite3.connect(uri, uri=True)
        con.row_factory = sqlite3.Row
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    except sqlite3.DatabaseError as exc:
        raise ParseError(f"Not a readable SQLite database: {exc}") from exc

    try:
        if {"urls", "visits"} <= tables:                       # Chrome / Edge / Brave
            q = "SELECT v.visit_time AS t, u.url AS url, u.title AS title FROM visits v JOIN urls u ON u.id = v.url"
            for r in con.execute(q):
                when = _from_webkit(r["t"])
                if when is None or not r["url"]:
                    res.skipped += 1
                    continue
                res.rows.append(make_row(when, "browser", classify_url(r["url"]), default_user,
                                         r["url"], "", r["title"] or ""))
            if "downloads" in tables:
                for r in con.execute("SELECT * FROM downloads"):
                    keys = r.keys()
                    when = _from_webkit(r["start_time"]) if "start_time" in keys else None
                    target = (r["target_path"] if "target_path" in keys else "") or ""
                    if when is None or not target:
                        res.skipped += 1
                        continue
                    src = (r["tab_url"] if "tab_url" in keys else "") or ""
                    res.rows.append(make_row(when, "browser", "File Downloaded", default_user, target, "",
                                             f"Downloaded from {src}" if src else "Downloaded file"))
        elif {"moz_places", "moz_historyvisits"} <= tables:      # Firefox
            q = ("SELECT v.visit_date AS t, p.url AS url, p.title AS title "
                 "FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id")
            for r in con.execute(q):
                when = _from_unix_us(r["t"])
                if when is None or not r["url"]:
                    res.skipped += 1
                    continue
                res.rows.append(make_row(when, "browser", classify_url(r["url"]), default_user,
                                         r["url"], "", r["title"] or ""))
        else:
            raise ParseError("SQLite file has no recognised browser-history tables "
                             "(expected Chrome/Edge 'urls'+'visits' or Firefox 'moz_places').")
    except sqlite3.DatabaseError as exc:
        raise ParseError(f"Could not read browser database: {exc}") from exc
    finally:
        con.close()
    return res


def parse_browser_table(df, default_user=""):
    res = ParseResult("browser")
    ts = parse_ts(pick(df, "timestamp", "time", "visittime", "lastvisittime", "datetime", "date"))
    url = pick(df, "url", "address", "link")
    title = pick(df, "title", "pagetitle")
    user = pick(df, "user", "username", "profile")
    dl = pick(df, "downloadpath", "targetpath", "download")
    for i in range(len(df)):
        when = ts.iat[i]
        if pd.isna(when) or not (url.iat[i] or dl.iat[i]):
            res.skipped += 1
            continue
        who = user.iat[i] or default_user
        if dl.iat[i]:
            res.rows.append(make_row(when, "browser", "File Downloaded", who, dl.iat[i], "",
                                     f"Downloaded from {url.iat[i]}" if url.iat[i] else "Downloaded file"))
        else:
            res.rows.append(make_row(when, "browser", classify_url(url.iat[i]), who, url.iat[i], "", title.iat[i]))
    return res


# ----------------------------------------------------------------------------
# USB log
# ----------------------------------------------------------------------------
def parse_usb(df, default_user=""):
    res = ParseResult("usb")
    ts = parse_ts(pick(df, "timestamp", "time", "datetime", "date", "lastwrite", "firstinstall"))
    ev = pick(df, "event", "action", "status", "type")
    name = pick(df, "devicename", "friendlyname", "device", "name", "product")
    serial = pick(df, "serial", "serialnumber", "deviceid")
    vendor = pick(df, "vendor", "manufacturer")
    drive = pick(df, "driveletter", "drive", "mount")
    user = pick(df, "user", "username", "account")
    for i in range(len(df)):
        when = ts.iat[i]
        if pd.isna(when):
            res.skipped += 1
            continue
        e = ev.iat[i].lower()
        if any(k in e for k in ("disc", "remov", "unplug", "eject", "depart")):
            action = "USB Disconnected"
        elif any(k in e for k in ("conn", "insert", "plug", "arriv", "mount", "install", "attach", "present")):
            action = "USB Connected"
        else:
            action = "USB Activity"
        bits = []
        if serial.iat[i]:
            bits.append(f"Serial {serial.iat[i]}")
        if vendor.iat[i]:
            bits.append(f"Vendor {vendor.iat[i]}")
        if ev.iat[i] and action == "USB Activity":
            bits.append(ev.iat[i])
        res.rows.append(make_row(when, "usb", action, user.iat[i] or default_user,
                                 name.iat[i] or "USB storage device", normalize_drive(drive.iat[i]), "; ".join(bits)))
    return res


# ----------------------------------------------------------------------------
# file access log
# ----------------------------------------------------------------------------
def _file_action(text):
    t = text.lower()
    if "copy" in t or "copied" in t:
        return "File Copied"
    if any(k in t for k in ("delet", "remov", "recycle", "unlink")):
        return "File Deleted"
    if any(k in t for k in ("renam", "move")):
        return "File Renamed"
    if any(k in t for k in ("modif", "write", "change", "edit", "overwr", "save")):
        return "File Modified"
    if any(k in t for k in ("creat", "new")):
        return "File Created"
    return "File Accessed"


def parse_file_log(df, default_user=""):
    res = ParseResult("file")
    ts = parse_ts(pick(df, "timestamp", "time", "datetime", "date", "accessed", "modified"))
    act = pick(df, "action", "event", "operation", "type")
    path = pick(df, "path", "filepath", "filename", "file", "target")
    user = pick(df, "user", "username", "account", "owner")
    proc = pick(df, "process", "processname", "application", "app")
    dest = pick(df, "destination", "dest", "copiedto", "to")
    size = pick(df, "sizekb", "size", "bytes")
    for i in range(len(df)):
        when = ts.iat[i]
        if pd.isna(when) or not path.iat[i]:
            res.skipped += 1
            continue
        action = _file_action(act.iat[i])
        bits = []
        if proc.iat[i]:
            bits.append(f"via {proc.iat[i]}")
        if size.iat[i]:
            bits.append(f"size {size.iat[i]}")
        if action == "File Copied" and dest.iat[i]:
            bits.insert(0, f"copied to {dest.iat[i]}")
        res.rows.append(make_row(when, "file", action, user.iat[i] or default_user,
                                 path.iat[i], dest.iat[i], ", ".join(bits)))
    return res


# ----------------------------------------------------------------------------
# login log
# ----------------------------------------------------------------------------
def parse_login(df, default_user=""):
    res = ParseResult("login")
    ts = parse_ts(pick(df, "timestamp", "time", "datetime", "date"))
    user = pick(df, "user", "username", "account", "targetusername")
    result = pick(df, "result", "status", "outcome", "event", "action")
    ip = pick(df, "sourceip", "ipaddress", "sourceaddress", "clientip", "host")
    lt = pick(df, "logontype", "type", "method")
    for i in range(len(df)):
        when = ts.iat[i]
        if pd.isna(when):
            res.skipped += 1
            continue
        r = result.iat[i].lower()
        if any(k in r for k in ("fail", "denied", "invalid", "bad", "wrong", "reject", "4625")):
            action = "Login Failed"
        elif any(k in r for k in ("logoff", "logout", "log off", "sign out", "signout", "disconnect")):
            action = "Logoff"
        elif "boot" in r or "startup" in r:
            action = "System Boot"
        elif any(k in r for k in ("shutdown", "power off")):
            action = "System Shutdown"
        else:
            action = "Login Success"
        address = ip.iat[i]
        address = "" if address in LOCAL_ADDRS else address
        bits = []
        if lt.iat[i]:
            bits.append(f"Logon type {lt.iat[i]}")
        if address:
            bits.append(f"from {address}")
        res.rows.append(make_row(when, "login", action, user.iat[i] or default_user, "", address, " ".join(bits)))
    return res


# ----------------------------------------------------------------------------
# entry point
# ----------------------------------------------------------------------------
TABLE_PARSERS = {
    "eventlog": parse_eventlog,
    "browser": parse_browser_table,
    "usb": parse_usb,
    "file": parse_file_log,
    "login": parse_login,
}


def parse_file(path, kind="auto", default_user=""):
    """Parse an evidence file. Returns a ParseResult (kind is resolved if 'auto')."""
    if kind in (None, "", "auto"):
        kind = sniff_kind(path)
    if kind not in C.SOURCES:
        raise ParseError(f"Unknown evidence type '{kind}'.")
    with open(path, "rb") as fh:
        is_sqlite = fh.read(15) == b"SQLite format 3"
    if kind == "browser" and is_sqlite:
        return parse_browser_sqlite(path, default_user)
    if is_sqlite:
        raise ParseError("This is a SQLite database - only browser history databases are supported.")
    df = read_table(path)
    if df.empty:
        raise ParseError("The file contains no rows.")
    return TABLE_PARSERS[kind](df, default_user)
