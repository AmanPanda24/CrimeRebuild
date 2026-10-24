# Created by: Aman Kumar Panda
"""Module 1 - Evidence Collector (live collection from a Windows machine).

Collects artifacts from the machine this tool runs on and writes them as CSV /
SQLite files in the same formats the upload path accepts. The files then go
through exactly the same intake -> parser -> timeline -> detector pipeline.

Artifacts collected
    Event logs      Security + System channels via pywin32 (win32evtlog)
    USB history     HKLM\\SYSTEM\\...\\Enum\\USBSTOR, setupapi.dev.log,
                    removable drives mounted right now (psutil)
    File activity   Recycle Bin $I records (original path + deletion time),
                    Recent Items shortcuts (last-opened time)
    Logins          interactive sessions and boot time (psutil)
    Browser history Chrome / Edge / Firefox databases (copied, never opened live)

Run as Administrator to read the Security log and other users' profiles.
Use only on machines you are authorised to investigate.

The pure parsing helpers at the top work on any OS (and are unit-tested);
everything that touches the Windows API is imported lazily.
"""
import csv
import glob
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

IS_WINDOWS = sys.platform.startswith("win")
EVT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

SECURITY_IDS = [4624, 4625, 4634, 4647, 4648, 4663, 4660, 4688, 4698, 4720, 4726, 4732, 1102]
SYSTEM_IDS = [7045, 6005, 6006, 104]
INTERACTIVE_LOGON_TYPES = {"2", "7", "10", "11"}
SKIP_ACCOUNTS = {"system", "local service", "network service", "anonymous logon", "-"}
MAX_EVENTS_PER_CHANNEL = 50_000

EVENTLOG_HEADER = ["TimeCreated", "EventID", "Channel", "Computer", "Account", "LogonType", "IpAddress",
                   "ObjectName", "AccessMask", "ProcessName", "CommandLine", "Message"]


class CollectorUnavailable(Exception):
    pass


@dataclass
class CollectedFile:
    path: str
    kind: str
    user: str = ""
    note: str = ""


# ----------------------------------------------------------------------------
# pure helpers (testable on any OS)
# ----------------------------------------------------------------------------
def filetime_to_dt(filetime):
    """Windows FILETIME (100 ns ticks since 1601-01-01 UTC) -> naive UTC datetime."""
    return datetime(1601, 1, 1) + timedelta(microseconds=int(filetime) // 10)


def utc_str(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def epoch_to_utc_str(epoch):
    return utc_str(datetime.fromtimestamp(epoch, timezone.utc))


def parse_recycle_i(data):
    """Parse a Recycle Bin `$I` metadata record -> (deleted_at_utc, size_bytes, original_path)."""
    if len(data) < 28:
        raise ValueError("record too short")
    version, size, deleted = struct.unpack_from("<qqq", data, 0)
    if version == 2:
        (n_chars,) = struct.unpack_from("<i", data, 24)
        raw = data[28:28 + n_chars * 2]
    elif version == 1:
        raw = data[24:24 + 520]
    else:
        raise ValueError(f"unknown $I version {version}")
    path = raw.decode("utf-16le", errors="ignore").split("\x00")[0]
    return filetime_to_dt(deleted), size, path


_SETUPAPI_HDR = re.compile(r">>>\s+\[Device Install \(Hardware initiated\) - (USBSTOR\\[^\]]+)\]", re.I)
_SETUPAPI_START = re.compile(r">>>\s+Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", re.I)


def parse_setupapi(text):
    """Yield (local_datetime, device_instance_id) for first-time USB storage installs."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = _SETUPAPI_HDR.search(line)
        if not m:
            continue
        for nxt in lines[i + 1:i + 4]:
            t = _SETUPAPI_START.search(nxt)
            if t:
                yield datetime.strptime(t.group(1), "%Y/%m/%d %H:%M:%S"), m.group(1)
                break


def _local_to_utc_str(naive_local):
    return utc_str(naive_local.astimezone(timezone.utc))      # naive datetimes are treated as local time


def _local_name(tag):
    return tag.rsplit("}", 1)[-1]


def event_xml_to_row(xml):
    """Convert one rendered Windows event (XML) into an EVENTLOG_HEADER row (or None to skip)."""
    root = ET.fromstring(xml)
    system = root.find(EVT_NS + "System")
    eid = int(system.findtext(EVT_NS + "EventID"))
    stamp = system.find(EVT_NS + "TimeCreated").get("SystemTime")
    when = datetime.strptime(stamp[:19], "%Y-%m-%dT%H:%M:%S")
    data = {}
    for el in root.iter():
        name = el.get("Name")
        if _local_name(el.tag) == "Data" and name:
            data[name] = (el.text or "").strip()
        elif len(el) == 0 and el.text and _local_name(el.tag) in ("SubjectUserName", "TargetUserName"):
            data.setdefault(_local_name(el.tag), el.text.strip())      # UserData events such as 1102

    logon_type = data.get("LogonType", "")
    if eid in (4624, 4648):
        account = data.get("TargetUserName", "")
        if eid == 4624 and logon_type not in INTERACTIVE_LOGON_TYPES:
            return None
    elif eid == 4625:
        account = data.get("TargetUserName", "")
    else:
        account = data.get("SubjectUserName", "")
    if account.lower() in SKIP_ACCOUNTS or account.endswith("$") or account.upper().startswith(("DWM-", "UMFD-")):
        if eid in (4624, 4648, 4625, 4634, 4647):
            return None

    obj = {4663: data.get("ObjectName", ""), 4660: data.get("ObjectName", ""),
           4720: data.get("TargetUserName", ""), 4726: data.get("TargetUserName", ""),
           4732: data.get("TargetUserName", ""), 4698: data.get("TaskName", ""),
           7045: data.get("ServiceName", ""), 1102: "Security", 104: "System"}.get(eid, "")
    if eid == 4663 and data.get("ObjectType", "File") != "File":
        return None
    process = data.get("NewProcessName") or data.get("ProcessName", "")
    command = data.get("CommandLine") or data.get("ImagePath", "")
    return [utc_str(when), eid, system.findtext(EVT_NS + "Channel") or "", system.findtext(EVT_NS + "Computer") or "",
            account, logon_type, data.get("IpAddress", ""), obj, data.get("AccessMask", ""), process, command, ""]


# ----------------------------------------------------------------------------
# Windows-only collectors
# ----------------------------------------------------------------------------
def is_admin():
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _profiles():
    root = os.environ.get("SystemDrive", "C:") + "\\Users"
    skip = {"public", "default", "default user", "all users", "defaultuser0"}
    try:
        return [(n, os.path.join(root, n)) for n in os.listdir(root)
                if n.lower() not in skip and os.path.isdir(os.path.join(root, n))]
    except OSError:
        return []


def collect_event_logs(out_dir, since, warnings, log):
    try:
        import win32evtlog
    except ImportError:
        warnings.append("pywin32 is not installed - event logs were skipped (pip install pywin32).")
        return None
    rows = []
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    for channel, ids in (("Security", SECURITY_IDS), ("System", SYSTEM_IDS)):
        cond = " or ".join(f"EventID={i}" for i in ids)
        query = f"*[System[({cond}) and TimeCreated[@SystemTime>='{since_iso}']]]"
        try:
            handle = win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryChannelPath |
                                          win32evtlog.EvtQueryReverseDirection, query, None)
        except Exception as exc:
            hint = " (run as Administrator to read the Security log)" if channel == "Security" else ""
            warnings.append(f"Could not read the {channel} log: {exc}{hint}")
            continue
        count = 0
        while count < MAX_EVENTS_PER_CHANNEL:
            batch = win32evtlog.EvtNext(handle, 200)
            if not batch:
                break
            for ev in batch:
                try:
                    row = event_xml_to_row(win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml))
                except Exception:
                    continue
                if row:
                    rows.append(row)
                    count += 1
        log(f"  {channel} log: {count} relevant events")
    if not rows:
        warnings.append("No event-log records were collected. Object-access events (4663) only exist if "
                        "file-system auditing is enabled; see the README.")
        return None
    rows.sort(key=lambda r: r[0])
    path = os.path.join(out_dir, f"{socket.gethostname()}_eventlog.csv")
    _write(path, EVENTLOG_HEADER, rows)
    return CollectedFile(path, "eventlog", note="live collection: win32evtlog")


def collect_usb(out_dir, warnings, log):
    rows = []
    try:
        import winreg
        base = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as root:
            for i in range(winreg.QueryInfoKey(root)[0]):
                dev = winreg.EnumKey(root, i)                        # Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00
                ven = re.search(r"Ven_([^&]+)", dev)
                prod = re.search(r"Prod_([^&]+)", dev)
                with winreg.OpenKey(root, dev) as dk:
                    for j in range(winreg.QueryInfoKey(dk)[0]):
                        serial = winreg.EnumKey(dk, j)
                        with winreg.OpenKey(dk, serial) as sk:
                            last_write = winreg.QueryInfoKey(sk)[2]  # key last-write time ~ last connection
                            try:
                                friendly = winreg.QueryValueEx(sk, "FriendlyName")[0]
                            except OSError:
                                friendly = (prod.group(1).replace("_", " ") if prod else "USB storage device")
                        rows.append([utc_str(filetime_to_dt(last_write)), "Connected (registry last-write)",
                                     friendly, serial.split("&")[0], ven.group(1) if ven else "", "", ""])
    except OSError as exc:
        warnings.append(f"USBSTOR registry key not readable: {exc}")
    except ImportError:
        pass

    setupapi = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "INF", "setupapi.dev.log")
    try:
        with open(setupapi, "r", errors="ignore") as fh:
            for when, instance in parse_setupapi(fh.read()):
                parts = instance.split("\\")
                rows.append([_local_to_utc_str(when), "First installed (setupapi.dev.log)",
                             parts[1].replace("&", " ").replace("_", " ") if len(parts) > 1 else "USB storage device",
                             parts[-1].split("&")[0], "", "", ""])
    except OSError:
        warnings.append("setupapi.dev.log could not be read (needs Administrator).")

    try:
        import psutil
        for part in psutil.disk_partitions(all=False):
            if "removable" in part.opts.lower() or part.fstype.lower() == "cdrom":
                letter = (part.device or part.mountpoint)[:2]
                rows.append([utc_str(datetime.now(timezone.utc).replace(tzinfo=None)), "Present at collection time",
                             f"Removable drive {letter}", "", "", letter, ""])
    except Exception:
        pass
    if not rows:
        return None
    rows.sort(key=lambda r: r[0])
    log(f"  USB history: {len(rows)} records")
    path = os.path.join(out_dir, f"{socket.gethostname()}_usb.csv")
    _write(path, ["Timestamp", "Event", "DeviceName", "Serial", "Vendor", "DriveLetter", "User"], rows)
    return CollectedFile(path, "usb", note="live collection: USBSTOR, setupapi.dev.log, psutil")


def _sid_to_name(sid):
    try:
        import win32security
        return win32security.LookupAccountSid(None, win32security.ConvertStringSidToSid(sid))[0]
    except Exception:
        return sid


def collect_file_artifacts(out_dir, since, warnings, log):
    rows = []
    cutoff = since.timestamp()
    # Recycle Bin: original path + deletion time
    rb_root = os.environ.get("SystemDrive", "C:") + "\\$Recycle.Bin"
    try:
        for sid_dir in glob.glob(os.path.join(rb_root, "S-*")):
            user = _sid_to_name(os.path.basename(sid_dir))
            for meta in glob.glob(os.path.join(sid_dir, "$I*")):
                try:
                    with open(meta, "rb") as fh:
                        deleted, size, path = parse_recycle_i(fh.read())
                except (OSError, ValueError):
                    continue
                if deleted.replace(tzinfo=timezone.utc).timestamp() >= cutoff:
                    rows.append([utc_str(deleted), "Deleted", path, user, "Recycle Bin", "", size // 1024])
    except OSError:
        warnings.append("Recycle Bin could not be read (needs Administrator to see other users).")
    # Recent Items: last-opened time of each shortcut
    for name, home in _profiles():
        recent = os.path.join(home, "AppData", "Roaming", "Microsoft", "Windows", "Recent")
        for lnk in glob.glob(os.path.join(recent, "*.lnk")):
            try:
                mtime = os.path.getmtime(lnk)
            except OSError:
                continue
            if mtime >= cutoff:
                rows.append([epoch_to_utc_str(mtime), "Accessed", os.path.basename(lnk)[:-4], name,
                             "Windows Recent Items", "", ""])
    if not rows:
        return None
    rows.sort(key=lambda r: r[0])
    log(f"  File activity (Recycle Bin + Recent Items): {len(rows)} records")
    path = os.path.join(out_dir, f"{socket.gethostname()}_file_activity.csv")
    _write(path, ["Timestamp", "Action", "Path", "User", "Process", "Destination", "SizeKB"], rows)
    return CollectedFile(path, "file", note="live collection: Recycle Bin $I, Recent Items")


def collect_logins(out_dir, warnings, log):
    try:
        import psutil
    except ImportError:
        warnings.append("psutil is not installed - session information was skipped.")
        return None
    rows = [[epoch_to_utc_str(psutil.boot_time()), "System", "Boot", "", ""]]
    for u in psutil.users():
        rows.append([epoch_to_utc_str(u.started), u.name, "Success", u.host if u.host not in ("", "0.0.0.0") else "",
                     "interactive session (active at collection)"])
    log(f"  Sessions: {len(rows)} records")
    path = os.path.join(out_dir, f"{socket.gethostname()}_sessions.csv")
    _write(path, ["Timestamp", "User", "Result", "SourceIP", "LogonType"], rows)
    return CollectedFile(path, "login", note="live collection: psutil users + boot time")


def _safe_copy(src, dst, warnings):
    try:
        shutil.copy2(src, dst)
        return True
    except OSError:
        pass
    try:                                    # esentutl can read files that another process holds open
        subprocess.run(["esentutl.exe", "/y", src, "/d", dst, "/o"], check=True, capture_output=True, timeout=120)
        return os.path.exists(dst)
    except Exception:
        warnings.append(f"Could not copy {src} (browser may be open - close it and collect again).")
        return False


def collect_browsers(out_dir, warnings, log):
    found = []
    for user, home in _profiles():
        local, roaming = os.path.join(home, "AppData", "Local"), os.path.join(home, "AppData", "Roaming")
        candidates = []
        for label, base in (("Chrome", os.path.join(local, "Google", "Chrome", "User Data")),
                            ("Edge", os.path.join(local, "Microsoft", "Edge", "User Data")),
                            ("Brave", os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data"))):
            for prof in glob.glob(os.path.join(base, "Default")) + glob.glob(os.path.join(base, "Profile *")):
                candidates.append((label, os.path.basename(prof), os.path.join(prof, "History")))
        for prof in glob.glob(os.path.join(roaming, "Mozilla", "Firefox", "Profiles", "*")):
            candidates.append(("Firefox", os.path.basename(prof), os.path.join(prof, "places.sqlite")))
        for label, prof, src in candidates:
            if not os.path.exists(src):
                continue
            safe = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{user}_{label}_{prof}")
            dst = os.path.join(out_dir, f"{safe}_history.sqlite")
            if _safe_copy(src, dst, warnings):
                log(f"  Browser history: {user} / {label} / {prof}")
                found.append(CollectedFile(dst, "browser", user, f"live collection: {label} profile {prof}"))
    return found


def _write(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


# ----------------------------------------------------------------------------
# public entry points
# ----------------------------------------------------------------------------
def collect_all(out_dir, days=14, log=print):
    """Collect everything into out_dir. Returns (list[CollectedFile], list[warning str])."""
    if not IS_WINDOWS:
        raise CollectorUnavailable("Live collection works on Windows only. Upload the evidence files instead.")
    warnings = []
    if not is_admin():
        warnings.append("Not running as Administrator: the Security log, other users' profiles and the "
                        "Recycle Bin will be incomplete.")
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
    log(f"Collecting evidence from {socket.gethostname()} for the last {days} day(s)...")
    files = []
    for fn in (lambda: collect_event_logs(out_dir, since, warnings, log),
               lambda: collect_usb(out_dir, warnings, log),
               lambda: collect_file_artifacts(out_dir, since, warnings, log),
               lambda: collect_logins(out_dir, warnings, log)):
        try:
            item = fn()
            if item:
                files.append(item)
        except Exception as exc:                       # one failing artifact must not stop the others
            warnings.append(f"A collector step failed: {exc}")
    files.extend(collect_browsers(out_dir, warnings, log))
    return files, warnings


def collect_into_case(store, case_id, days=14, actor="collector", log=print):
    """Collect from this machine and run the files through the normal evidence intake."""
    from . import db, evidence
    summary = {"ingested": [], "warnings": [], "duplicates": 0}
    with tempfile.TemporaryDirectory() as tmp:
        files, warnings = collect_all(tmp, days, log)
        summary["warnings"].extend(warnings)
        with store.session() as conn:
            db.log_custody(conn, case_id, "Live collection started",
                           f"Host {socket.gethostname()}, last {days} day(s), administrator={is_admin()}", actor)
        for f in files:
            try:
                res = evidence.add_evidence(store, case_id, f.path, os.path.basename(f.path), kind=f.kind,
                                            origin="live collection", default_user=f.user, actor=actor, note=f.note)
                summary["ingested"].append(res)
            except evidence.DuplicateEvidence:
                summary["duplicates"] += 1
    return summary
