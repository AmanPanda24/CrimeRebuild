# Created by: Aman Kumar Panda
"""Module 1b - Universal evidence converter.

Whatever the extension of an uploaded file, it is first converted into ONE common
format - a JSON document of records - and only then parsed and analysed:

    upload (.zip / .csv / .tsv / .xlsx / .evtx / .sqlite / History / .json ...)
        --> expand archives
        --> convert_to_json()   ->  {"source_file", "source_format", "record_count", "records": [...]}
        --> parsers.parse_file()  (existing pipeline)  -->  timeline  -->  detection

The original file is never touched; the JSON is a derived copy.
Supported inputs:
    .zip (PK)          unpacked, every file inside is converted (nested up to 2 levels)
    .csv .tsv .txt     delimiter sniffed; FTK Imager / Autopsy file lists are expanded into
                       one Created / Modified / Accessed event per timestamp
    .xlsx .xls         every sheet (Autopsy / FTK reports exported to Excel)
    .json .jsonl       passed through
    .evtx              Windows event logs (needs the 'evtx' package)
    SQLite (no ext.)   Chrome/Edge/Brave History, Firefox places.sqlite, Autopsy autopsy.db (tsk_files)
Not supported (clear message is shown): raw disk/memory images (.E01 .AD1 .dd .raw .mem ...)
and network captures (.pcap/.pcapng) - export them from the forensic tool first.
"""
import csv
import json
import os
import re
import shutil
import sqlite3
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from .parsers import ParseError, _from_webkit, _from_unix_us

MAX_ARCHIVE_FILES = 500
MAX_ARCHIVE_BYTES = 2 * 1024 ** 3      # total uncompressed size allowed per archive
MAX_DEPTH = 2
SKIP_NAMES = {".ds_store", "thumbs.db", "desktop.ini"}

IMAGE_EXTS = {".e01", ".ex01", ".ad1", ".l01", ".lx01", ".s01", ".dd", ".raw", ".img", ".001",
              ".vmem", ".mem", ".dmp", ".lime", ".vhd", ".vhdx", ".vmdk", ".aut"}
PCAP_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\n\r\r\n")


class ConvertError(ParseError):
    """The file could not be converted to JSON (shown to the investigator)."""


# ----------------------------------------------------------------------------
# format detection
# ----------------------------------------------------------------------------
def detect_format(path):
    with open(path, "rb") as fh:
        head = fh.read(16)
    ext = os.path.splitext(path)[1].lower()
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        # .xlsx/.docx are also ZIP containers - tell them apart by extension
        return "xlsx" if ext in (".xlsx", ".xlsm") else "zip"
    if head.startswith(b"SQLite format 3"):
        return "sqlite"
    if head.startswith(b"ElfFile\x00"):
        return "evtx"
    if head.startswith(PCAP_MAGICS):
        return "pcap"
    if head.startswith(b"EVF") or head.startswith(b"ADSEGMENTEDFILE") or ext in IMAGE_EXTS:
        return "image"
    if head.startswith(b"\xd0\xcf\x11\xe0") and ext == ".xls":
        return "xlsx"
    if ext in (".json", ".jsonl", ".ndjson"):
        return "json"
    return "text"


# ----------------------------------------------------------------------------
# archives
# ----------------------------------------------------------------------------
def expand_archives(path, dest_dir, display_name=None, depth=0):
    """Return [(display_name, file_path)] for `path`.

    A ZIP is unpacked (safely: no path traversal, size/count limits) and nested ZIPs are
    expanded too. Any other file is returned unchanged.
    """
    display_name = display_name or os.path.basename(path)
    if detect_format(path) != "zip":
        return [(display_name, path)]
    if depth >= MAX_DEPTH:
        raise ConvertError(f"{display_name}: archives nested more than {MAX_DEPTH} levels deep are not unpacked.")
    out = []
    os.makedirs(dest_dir, exist_ok=True)
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise ConvertError(f"{display_name}: not a valid ZIP archive ({exc}).") from exc
    with zf:
        members = [m for m in zf.infolist() if not m.is_dir()
                   and "__macosx" not in m.filename.lower().split("/")
                   and os.path.basename(m.filename).lower() not in SKIP_NAMES]
        if len(members) > MAX_ARCHIVE_FILES:
            raise ConvertError(f"{display_name}: contains {len(members)} files (limit {MAX_ARCHIVE_FILES}).")
        if sum(m.file_size for m in members) > MAX_ARCHIVE_BYTES:
            raise ConvertError(f"{display_name}: uncompressed size is too large "
                               f"(limit {MAX_ARCHIVE_BYTES // 1024 ** 3} GB).")
        for i, m in enumerate(members, 1):
            if m.flag_bits & 0x1:
                raise ConvertError(f"{display_name}: the archive is password-protected.")
            base = re.sub(r"[^\w.\-]+", "_", os.path.basename(m.filename)) or f"file{i}"
            target = os.path.join(dest_dir, f"{i:03d}_{base}")      # flat + numbered: no path traversal
            written = 0
            with zf.open(m) as src, open(target, "wb") as dst:
                for block in iter(lambda: src.read(1024 * 1024), b""):
                    written += len(block)
                    if written > m.file_size + 1024:               # lying header -> zip bomb
                        raise ConvertError(f"{display_name}: corrupt or malicious archive entry '{m.filename}'.")
                    dst.write(block)
            inner = f"{display_name}/{m.filename}"
            out.extend(expand_archives(target, target + "_x", inner, depth + 1))
    return out


# ----------------------------------------------------------------------------
# readers: every one returns a list of plain dicts
# ----------------------------------------------------------------------------
def _read_delimited(path):
    for enc in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            df = pd.read_csv(path, dtype=str, keep_default_na=False, encoding=enc)
            if df.shape[1] == 1:
                df = pd.read_csv(path, dtype=str, keep_default_na=False, encoding=enc, sep=None, engine="python")
            return df
        except (UnicodeError, UnicodeDecodeError):
            continue
        except pd.errors.EmptyDataError:
            return pd.DataFrame()
        except (pd.errors.ParserError, csv.Error) as exc:
            raise ConvertError(f"Could not read as a table: {exc}") from exc
    raise ConvertError("Could not decode the file as text.")


def _read_excel(path):
    try:
        sheets = pd.read_excel(path, sheet_name=None, dtype=str, keep_default_na=False)
    except ImportError as exc:
        raise ConvertError("Reading Excel files needs the 'openpyxl' package (pip install openpyxl).") from exc
    except Exception as exc:                     # noqa: BLE001 - xlrd/openpyxl raise assorted errors
        raise ConvertError(f"Could not read the spreadsheet: {exc}") from exc
    frames = [df for df in sheets.values() if not df.empty]
    return pd.concat(frames, ignore_index=True).fillna("") if frames else pd.DataFrame()


def _read_json(path):
    with open(path, encoding="utf-8-sig") as fh:
        text = fh.read()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            data = [json.loads(line) for line in text.splitlines() if line.strip()]
        except json.JSONDecodeError as exc:
            raise ConvertError(f"Invalid JSON: {exc}") from exc
    if isinstance(data, dict):
        for key in ("records", "events", "data", "items", "entries"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    return data


def _iso(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else ""


def _epoch(seconds):
    try:
        s = int(seconds)
        return datetime(1970, 1, 1) + timedelta(seconds=s) if s > 0 else None
    except (TypeError, ValueError, OverflowError):
        return None


def _read_sqlite(path):
    uri = Path(path).resolve().as_uri() + "?mode=ro&immutable=1"
    try:
        con = sqlite3.connect(uri, uri=True)
        con.row_factory = sqlite3.Row
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    except sqlite3.DatabaseError as exc:
        raise ConvertError(f"Not a readable SQLite database: {exc}") from exc
    recs = []
    try:
        if {"urls", "visits"} <= tables:                                   # Chrome / Edge / Brave
            for r in con.execute("SELECT v.visit_time t, u.url url, u.title title "
                                 "FROM visits v JOIN urls u ON u.id = v.url"):
                when = _from_webkit(r["t"])
                if when and r["url"]:
                    recs.append({"Timestamp": _iso(when), "Url": r["url"], "Title": r["title"] or ""})
            if "downloads" in tables:
                for r in con.execute("SELECT * FROM downloads"):
                    k = r.keys()
                    when = _from_webkit(r["start_time"]) if "start_time" in k else None
                    tgt = r["target_path"] if "target_path" in k else ""
                    if when and tgt:
                        recs.append({"Timestamp": _iso(when), "Url": (r["tab_url"] if "tab_url" in k else "") or "",
                                     "DownloadPath": tgt})
        elif {"moz_places", "moz_historyvisits"} <= tables:                # Firefox
            for r in con.execute("SELECT v.visit_date t, p.url url, p.title title FROM moz_historyvisits v "
                                 "JOIN moz_places p ON p.id = v.place_id"):
                when = _from_unix_us(r["t"])
                if when and r["url"]:
                    recs.append({"Timestamp": _iso(when), "Url": r["url"], "Title": r["title"] or ""})
        elif "tsk_files" in tables:                                        # Autopsy case database
            cols = {r[1] for r in con.execute("PRAGMA table_info(tsk_files)")}
            want = [c for c in ("name", "parent_path", "size", "crtime", "mtime", "atime", "ctime") if c in cols]
            for r in con.execute(f"SELECT {', '.join(want)} FROM tsk_files "
                                 "WHERE name NOT IN ('.', '..')"):
                d = dict(zip(want, r))
                recs.append({"Path": (d.get("parent_path") or "") + (d.get("name") or ""),
                             "Size": str(d.get("size") or ""),
                             "Created": _iso(_epoch(d.get("crtime"))),
                             "Modified": _iso(_epoch(d.get("mtime"))),
                             "Accessed": _iso(_epoch(d.get("atime"))),
                             "Changed": _iso(_epoch(d.get("ctime")))})
        else:
            raise ConvertError("SQLite database not recognised. Supported: Chrome/Edge/Brave History, "
                               "Firefox places.sqlite, Autopsy autopsy.db. Tables found: "
                               + ", ".join(sorted(tables)[:10]))
    except sqlite3.DatabaseError as exc:
        raise ConvertError(f"Could not read the database: {exc}") from exc
    finally:
        con.close()
    return recs


def _evtx_value(v):
    if isinstance(v, dict):
        return str(v.get("#text", ""))
    return "" if v is None else str(v)


def _read_evtx(path):
    try:
        from evtx import PyEvtxParser
    except ImportError as exc:
        raise ConvertError("Reading .evtx files needs the 'evtx' package (pip install evtx).") from exc
    recs = []
    try:
        for rec in PyEvtxParser(path).records_json():
            ev = json.loads(rec["data"]).get("Event", {})
            sysd, data = ev.get("System", {}), ev.get("EventData") or ev.get("UserData") or {}
            if not isinstance(data, dict):
                data = {}
            if len(data) == 1 and isinstance(next(iter(data.values())), dict):      # UserData wrapper
                data = next(iter(data.values()))
            flat = {k: _evtx_value(v) for k, v in data.items() if k != "#attributes"}
            eid = _evtx_value(sysd.get("EventID"))
            tc = sysd.get("TimeCreated", {})
            when = (tc.get("#attributes", {}) or {}).get("SystemTime", "") if isinstance(tc, dict) else ""
            subject = flat.get("SubjectUserName", "")
            target = flat.get("TargetUserName", "")
            account = target if eid in ("4624", "4625", "4648", "4720", "4726") and target else (subject or target)
            recs.append({
                "TimeCreated": when,
                "EventID": eid,
                "Computer": _evtx_value(sysd.get("Computer")),
                "Account": account,
                "ObjectName": flat.get("ObjectName", ""),
                "AccessMask": flat.get("AccessMask", ""),
                "LogonType": flat.get("LogonType", ""),
                "IpAddress": flat.get("IpAddress", "") or flat.get("SourceNetworkAddress", ""),
                "ProcessName": flat.get("NewProcessName", "") or flat.get("ProcessName", ""),
                "CommandLine": flat.get("CommandLine", ""),
                "Message": "; ".join(f"{k}={v}" for k, v in flat.items() if v)[:600],
            })
    except Exception as exc:                      # noqa: BLE001 - parser raises RuntimeError for bad files
        raise ConvertError(f"Could not read the .evtx file: {exc}") from exc
    return recs


# ----------------------------------------------------------------------------
# FTK Imager / Autopsy file listings: one row has Created + Modified + Accessed columns.
# Turn each timestamp into its own event so it lands on the timeline.
# ----------------------------------------------------------------------------
_MAC = (("creat", "Created"), ("crtime", "Created"), ("modif", "Modified"), ("mtime", "Modified"),
        ("access", "Accessed"), ("atime", "Accessed"), ("changed", "Changed"), ("ctime", "Changed"))
_PATH_COLS = ("fullpath", "filepath", "path", "pathname", "filename", "name")
_TIME_COLS = {"timestamp", "time", "datetime", "date", "timecreated", "dateandtime", "visittime"}


def _norm(name):
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def expand_mac_times(records):
    """If `records` look like a file listing with MAC-time columns, return one record per timestamp."""
    if not records or not isinstance(records[0], dict):
        return records
    cols = {_norm(c): c for c in records[0]}
    if _TIME_COLS & set(cols):
        return records
    time_cols = {}
    for norm, orig in cols.items():
        if norm in _PATH_COLS or norm in ("size", "sizekb", "bytes", "md5", "sha1", "sha256"):
            continue
        for needle, label in _MAC:
            if needle in norm:
                time_cols.setdefault(label, orig)
                break
    path_col = next((cols[c] for c in _PATH_COLS if c in cols), None)
    if not time_cols or not path_col:
        return records
    name_col = next((cols[c] for c in ("filename", "name") if c in cols and cols[c] != path_col), None)
    size_col = next((cols[c] for c in ("size", "sizekb", "bytes") if c in cols), None)
    hash_col = next((cols[c] for c in ("sha256", "sha1", "md5") if c in cols), None)
    out = []
    for r in records:
        path = str(r.get(path_col, "")).strip()
        nm = str(r.get(name_col, "")).strip() if name_col else ""
        if nm and path and not path.lower().endswith(nm.lower()):
            path = path.rstrip("\\/") + ("\\" if "\\" in path else "/") + nm
        if not path:
            continue
        for label, col in time_cols.items():
            stamp = str(r.get(col, "")).strip()
            if stamp and not stamp.startswith("0000") and stamp not in ("-", "N/A", "0"):
                rec = {"Timestamp": stamp, "Action": label, "Path": path}
                if size_col:
                    rec["Size"] = r.get(size_col, "")
                if hash_col:
                    rec["Hash"] = r.get(hash_col, "")
                out.append(rec)
    return out


# ----------------------------------------------------------------------------
# entry point
# ----------------------------------------------------------------------------
def convert_to_json(src_path, out_path, source_name=None):
    """Convert one evidence file to JSON at `out_path`. Returns (format, record_count)."""
    source_name = source_name or os.path.basename(src_path)
    fmt = detect_format(src_path)
    if fmt == "image":
        raise ConvertError("Disk/memory images (.E01, .AD1, .dd, .raw, .mem ...) cannot be read directly. "
                           "Open the image in FTK Imager or Autopsy, export the file list / timeline / "
                           "event logs (CSV, JSON, .evtx) and upload those instead.")
    if fmt == "pcap":
        raise ConvertError("Network captures (.pcap/.pcapng) are not supported yet. In Wireshark use "
                           "File > Export Packet Dissections > As CSV (or JSON) and upload that file.")
    if fmt == "zip":
        raise ConvertError("Archive was not unpacked - call expand_archives() first.")

    if fmt == "sqlite":
        records = _read_sqlite(src_path)
    elif fmt == "evtx":
        records = _read_evtx(src_path)
    elif fmt == "json":
        records = _read_json(src_path)
    elif fmt == "xlsx":
        records = _read_excel(src_path).to_dict("records")
    else:
        df = _read_delimited(src_path)
        records = df.to_dict("records")
        if df.shape[1] < 2:
            raise ConvertError("The file is not a table (CSV/TSV) - no delimiter-separated columns were found.")
    records = expand_mac_times(records)
    if not records:
        raise ConvertError("The file contains no usable records.")

    doc = {"source_file": source_name, "source_format": fmt,
           "converted_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S") + " UTC",
           "record_count": len(records), "records": records}
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, default=str)
    return fmt, len(records)
