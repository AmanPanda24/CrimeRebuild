# Created by: Aman Kumar Panda
"""Demo scenarios.

These generate *synthetic but realistic* evidence files (CSV event log, login
log, USB log, file-access log and a Chrome-format `History` SQLite database)
and push them through exactly the same pipeline as a real upload. Nothing is
hard-coded into the database, so the demo proves the whole system works.

    insider    - the scenario from the project slides: a confidential PDF is
                 accessed, copied to a USB stick, a webmail tab is opened and
                 the original file is deleted - all within nine minutes.
    intrusion  - a night-time attack: password guessing, off-hours login, new
                 admin account, USB theft, mass deletion, hosts-file change and
                 the audit log being cleared. Triggers all five detectors.
"""
import csv
import os
import random
import sqlite3
import tempfile
from datetime import datetime, timedelta

from . import db, detector, evidence

SCENARIOS = {
    "insider": {
        "title": "Insider data theft",
        "blurb": "A confidential PDF is opened, copied to a USB stick and deleted within nine minutes.",
        "case_name": "Demo: Insider data theft (DESKTOP-FIN01)",
        "detects": "USB exfiltration, evidence destruction",
    },
    "intrusion": {
        "title": "Full attack chain",
        "blurb": "Password guessing, a 00:03 login, USB theft, mass deletion and a cleared audit log.",
        "case_name": "Demo: Night-time intrusion (DESKTOP-HR07)",
        "detects": "All five detection rules",
    },
}


def _dt(day, hms):
    return datetime.strptime(f"{day} {hms}", "%Y-%m-%d %H:%M:%S")


def _fmt(d):
    return d.strftime("%Y-%m-%d %H:%M:%S")


def _write_csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def _webkit(d):
    return int((d - datetime(1601, 1, 1)).total_seconds() * 1_000_000)


def make_chrome_history(path, visits, downloads=()):
    """Create a minimal but genuine Chrome/Edge-format History database."""
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE urls(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER DEFAULT 0,
                          typed_count INTEGER DEFAULT 0, last_visit_time INTEGER, hidden INTEGER DEFAULT 0);
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER,
                            transition INTEGER DEFAULT 0, segment_id INTEGER, visit_duration INTEGER DEFAULT 0);
        CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid VARCHAR, current_path LONGVARCHAR, target_path LONGVARCHAR,
                               start_time INTEGER, end_time INTEGER, received_bytes INTEGER, total_bytes INTEGER,
                               state INTEGER, danger_type INTEGER, interrupt_reason INTEGER, tab_url LONGVARCHAR,
                               tab_referrer_url LONGVARCHAR);
    """)
    url_ids = {}
    for when, url, title in sorted(visits):
        if url not in url_ids:
            cur = con.execute("INSERT INTO urls(url, title, visit_count, last_visit_time) VALUES(?,?,?,?)",
                              (url, title, 1, _webkit(when)))
            url_ids[url] = cur.lastrowid
        con.execute("INSERT INTO visits(url, visit_time) VALUES(?,?)", (url_ids[url], _webkit(when)))
    for when, target, from_url, size in downloads:
        con.execute("INSERT INTO downloads(guid, current_path, target_path, start_time, end_time, received_bytes, "
                    "total_bytes, state, tab_url) VALUES(?,?,?,?,?,?,?,1,?)",
                    (os.path.basename(target), target, target, _webkit(when), _webkit(when + timedelta(seconds=3)),
                     size, size, from_url))
    con.commit()
    con.close()


EVENTLOG_HEADER = ["TimeCreated", "EventID", "Channel", "Computer", "Account", "LogonType", "IpAddress",
                   "ObjectName", "AccessMask", "ProcessName", "CommandLine", "Message"]
LOGIN_HEADER = ["Timestamp", "User", "Result", "SourceIP", "LogonType"]
USB_HEADER = ["Timestamp", "Event", "DeviceName", "Serial", "Vendor", "DriveLetter", "User"]
FILE_HEADER = ["Timestamp", "Action", "Path", "User", "Process", "Destination", "SizeKB"]


def _proc(when, computer, user, exe, cmd=""):
    return [_fmt(when), 4688, "Security", computer, user, "", "", "", "", exe, cmd, "A new process has been created."]


# ----------------------------------------------------------------------------
# scenario 1: insider data theft  (the slide-4 story)
# ----------------------------------------------------------------------------
def build_insider(out_dir):
    day, pc = "2026-09-14", "DESKTOP-FIN01"
    rnd = random.Random(14)
    pdf = r"C:\Finance\Confidential.pdf"

    login = [
        [f"{day} 08:52:10", "priya", "Success", "", 2],
        [f"{day} 09:01:44", "aman", "Failed", "", 2],         # a typo - below any threshold
        [f"{day} 09:02:03", "aman", "Success", "", 2],
        [f"{day} 12:05:00", "priya", "Logoff", "", 2],
    ]
    _write_csv(os.path.join(out_dir, "login_log.csv"), LOGIN_HEADER, login)

    ev = [[f"{day} 08:50:02", 6005, "System", pc, "", "", "", "", "", "", "", "The Event log service was started."]]
    ev.append(_proc(_dt(day, "09:05:11"), pc, "aman", r"C:\Program Files\Google\Chrome\Application\chrome.exe"))
    ev.append(_proc(_dt(day, "09:20:30"), pc, "aman", r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
                    r'"EXCEL.EXE" "C:\Finance\Q3_Budget.xlsx"'))
    ev.append(_proc(_dt(day, "10:03:18"), pc, "aman", r"C:\Program Files\Adobe\Acrobat Reader\AcroRd32.exe",
                    r'"AcroRd32.exe" "C:\Finance\Confidential.pdf"'))
    ev.append(_proc(_dt(day, "10:04:40"), pc, "aman", r"C:\Windows\explorer.exe"))
    ev.append(_proc(_dt(day, "11:15:02"), pc, "priya", r"C:\Windows\System32\notepad.exe"))
    _write_csv(os.path.join(out_dir, "security_events.csv"), EVENTLOG_HEADER, ev)

    usb = [
        [f"{day} 10:01:12", "Connected", "SanDisk Cruzer Blade", "4C530001230615114212", "SanDisk", "E:", "aman"],
        [f"{day} 10:12:40", "Disconnected", "SanDisk Cruzer Blade", "4C530001230615114212", "SanDisk", "E:", "aman"],
    ]
    _write_csv(os.path.join(out_dir, "usb_activity.csv"), USB_HEADER, usb)

    files = [
        [f"{day} 09:10:05", "Accessed", r"C:\Users\aman\Documents\Meeting_Notes.docx", "aman", "WINWORD.EXE", "", 88],
        [f"{day} 09:20:41", "Accessed", r"C:\Finance\Q3_Budget.xlsx", "aman", "EXCEL.EXE", "", 412],
        [f"{day} 09:41:09", "Modified", r"C:\Finance\Q3_Budget.xlsx", "aman", "EXCEL.EXE", "", 415],
        [f"{day} 09:55:30", "Accessed", r"C:\Users\aman\Documents\Invoice_1042.pdf", "aman", "AcroRd32.exe", "", 150],
        [f"{day} 09:30:12", "Accessed", r"C:\Finance\Payroll_Aug.xlsx", "priya", "EXCEL.EXE", "", 530],
        [f"{day} 10:03:20", "Accessed", pdf, "aman", "AcroRd32.exe", "", 2480],
        [f"{day} 10:05:05", "Copied", pdf, "aman", "explorer.exe", r"E:\Confidential.pdf", 2480],
        [f"{day} 10:09:30", "Deleted", pdf, "aman", "explorer.exe", "", 2480],
        [f"{day} 11:20:00", "Accessed", r"C:\Finance\Vendor_List.xlsx", "priya", "EXCEL.EXE", "", 96],
    ]
    for k in range(3):   # ordinary temp-file housekeeping (should NOT raise an alert)
        files.append([f"{day} 09:4{k}:50", "Deleted", rf"C:\Users\aman\AppData\Local\Temp\~tmp{k}A1.tmp", "aman",
                      "EXCEL.EXE", "", 4])
    _write_csv(os.path.join(out_dir, "file_access.csv"), FILE_HEADER, files)

    sites = [("https://intranet.company.local/", "Company Intranet"),
             ("https://www.google.com/search?q=q3+budget+template", "q3 budget template - Google Search"),
             ("https://stackoverflow.com/questions/excel-vlookup", "VLOOKUP help - Stack Overflow"),
             ("https://news.ycombinator.com/", "Hacker News"),
             ("https://www.youtube.com/watch?v=lofi", "lofi beats - YouTube")]
    visits = []
    for hms in ("09:05:30", "09:12:10", "09:31:00", "09:48:20", "10:20:15", "10:44:05", "11:02:00"):
        url, title = rnd.choice(sites)
        visits.append((_dt(day, hms), url, title))
    visits.append((_dt(day, "10:07:20"), "https://mail.google.com/mail/u/0/#inbox", "Inbox - Gmail"))
    visits.append((_dt(day, "10:07:52"), "https://mail.google.com/mail/u/0/#compose", "Compose - Gmail"))
    make_chrome_history(os.path.join(out_dir, "Chrome_History"), visits,
                        [(_dt(day, "09:14:00"), r"C:\Users\aman\Downloads\Q3_Budget_template.xlsx",
                          "https://intranet.company.local/templates", 41233)])
    return [
        {"file": "security_events.csv", "kind": "eventlog", "user": ""},
        {"file": "login_log.csv", "kind": "login", "user": ""},
        {"file": "usb_activity.csv", "kind": "usb", "user": ""},
        {"file": "file_access.csv", "kind": "file", "user": ""},
        {"file": "Chrome_History", "kind": "browser", "user": "aman"},
    ]


# ----------------------------------------------------------------------------
# scenario 2: night-time intrusion (all five detectors)
# ----------------------------------------------------------------------------
def build_intrusion(out_dir):
    d1, d2, pc, ip = "2026-09-14", "2026-09-15", "DESKTOP-HR07", "192.168.1.77"

    login = [
        [f"{d1} 17:32:08", "meera", "Success", "", 2],
        [f"{d1} 17:58:20", "rohan", "Success", "", 2],
        [f"{d1} 18:40:11", "rohan", "Logoff", "", 2],
        [f"{d1} 19:05:30", "meera", "Logoff", "", 2],
    ]
    t = _dt(d1, "23:44:05")                       # spraying: a few guesses against several accounts
    for acct in ("administrator", "hr", "backup"):
        for _ in range(4 if acct == "administrator" else 3):
            login.append([_fmt(t), acct, "Failed", ip, 3])
            t += timedelta(seconds=14)
    t = _dt(d1, "23:50:10")                       # then 14 guesses against one real account
    for _ in range(14):
        login.append([_fmt(t), "rohan", "Failed", ip, 10])
        t += timedelta(seconds=18)
    login.append([f"{d2} 00:03:05", "rohan", "Success", ip, 10])
    login.append([f"{d2} 00:35:40", "rohan", "Logoff", ip, 10])
    _write_csv(os.path.join(out_dir, "login_log.csv"), LOGIN_HEADER, login)

    ev = [[f"{d1} 17:28:00", 6005, "System", pc, "", "", "", "", "", "", "", "The Event log service was started."]]
    ev += [
        _proc(_dt(d2, "00:04:10"), pc, "rohan", r"C:\Windows\System32\cmd.exe", "whoami /all"),
        _proc(_dt(d2, "00:04:32"), pc, "rohan", r"C:\Windows\System32\net.exe", "net user"),
        _proc(_dt(d2, "00:05:15"), pc, "rohan", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0A..."),
        [f"{d2} 00:09:00", 4720, "Security", pc, "rohan", "", "", "support_tmp", "", "", "",
         "A user account was created."],
        [f"{d2} 00:09:40", 4732, "Security", pc, "rohan", "", "", "support_tmp -> Administrators", "", "", "",
         "A member was added to a security-enabled local group."],
        [f"{d2} 00:11:02", 7045, "System", pc, "rohan", "", "", "WinUpdateSvc", "", "", r"C:\ProgramData\upd\svc.exe",
         "A service was installed in the system."],
        _proc(_dt(d2, "00:34:20"), pc, "rohan", r"C:\Windows\System32\wevtutil.exe", "wevtutil.exe cl Security"),
        [f"{d2} 00:34:25", 1102, "Security", pc, "rohan", "", "", "Security", "", "", "",
         "The audit log was cleared."],
    ]
    _write_csv(os.path.join(out_dir, "security_events.csv"), EVENTLOG_HEADER, ev)

    usb = [
        [f"{d2} 00:20:15", "Connected", "Kingston DataTraveler 3.0", "0019E06B0123B1F0A5B2", "Kingston", "F:", "rohan"],
        [f"{d2} 00:31:00", "Disconnected", "Kingston DataTraveler 3.0", "0019E06B0123B1F0A5B2", "Kingston", "F:", "rohan"],
    ]
    _write_csv(os.path.join(out_dir, "usb_activity.csv"), USB_HEADER, usb)

    hr = r"C:\HR"
    files = [
        [f"{d1} 17:40:00", "Accessed", rf"{hr}\Salary_Sheet_2026.xlsx", "meera", "EXCEL.EXE", "", 220],
        [f"{d1} 17:59:30", "Accessed", r"C:\Users\rohan\Documents\Timesheet.xlsx", "rohan", "EXCEL.EXE", "", 60],
    ]
    loot = [("Salary_Sheet_2026.xlsx", 220), ("Employee_Database.accdb", 9100), ("Passwords_Backup.kdbx", 48),
            ("Offer_Letters_2026.docx", 130), ("Org_Chart.pdf", 310), ("Appraisals_2025.xlsx", 270),
            ("Payroll_Aug.xlsx", 520)]
    t = _dt(d2, "00:12:10")
    for name, kb in loot[:4]:
        files.append([_fmt(t), "Accessed", rf"{hr}\{name}", "rohan", "explorer.exe", "", kb])
        t += timedelta(seconds=40)
    t = _dt(d2, "00:21:00")
    for name, kb in loot:
        files.append([_fmt(t), "Copied", rf"{hr}\{name}", "rohan", "robocopy.exe", rf"F:\{name}", kb])
        t += timedelta(seconds=35)
    t = _dt(d2, "00:26:40")
    for k in range(1, 17):                       # 16 archive files removed in about 90 seconds
        files.append([_fmt(t), "Deleted", rf"{hr}\Archive\Appraisal_2019_{k:02d}.xlsx", "rohan", "cmd.exe", "", 80])
        t += timedelta(seconds=6)
    files.append([f"{d2} 00:28:20", "Deleted", rf"{hr}\Salary_Sheet_2026.xlsx", "rohan", "cmd.exe", "", 220])
    files.append([f"{d2} 00:32:10", "Modified", r"C:\Windows\System32\drivers\etc\hosts", "rohan", "notepad.exe", "", 2])
    _write_csv(os.path.join(out_dir, "file_access.csv"), FILE_HEADER, files)

    visits = [(_dt(d1, "17:58:50"), "https://intranet.company.local/", "Company Intranet"),
              (_dt(d2, "00:07:30"), "https://www.google.com/search?q=disable+windows+event+logging",
               "disable windows event logging - Google Search"),
              (_dt(d2, "00:18:30"), "https://mega.nz/start", "MEGA"),
              (_dt(d2, "00:19:10"), "https://mega.nz/fm", "MEGA - File Manager")]
    make_chrome_history(os.path.join(out_dir, "Chrome_History"), visits)
    return [
        {"file": "security_events.csv", "kind": "eventlog", "user": ""},
        {"file": "login_log.csv", "kind": "login", "user": ""},
        {"file": "usb_activity.csv", "kind": "usb", "user": ""},
        {"file": "file_access.csv", "kind": "file", "user": ""},
        {"file": "Chrome_History", "kind": "browser", "user": "rohan"},
    ]


BUILDERS = {"insider": build_insider, "intrusion": build_intrusion}


def generate(name, out_dir):
    """Write the scenario's evidence files into out_dir; return their manifest."""
    os.makedirs(out_dir, exist_ok=True)
    return BUILDERS[name](out_dir)


def load_demo(store, name):
    """Create a demo case, ingest the generated evidence and analyse it. Returns case_id."""
    if name not in SCENARIOS:
        raise KeyError(name)
    with store.session() as conn:
        case_id = db.create_case(conn, SCENARIOS[name]["case_name"], "Demo investigator",
                                 SCENARIOS[name]["blurb"], is_demo=True)
    with tempfile.TemporaryDirectory() as tmp:
        for item in generate(name, tmp):
            evidence.add_evidence(store, case_id, os.path.join(tmp, item["file"]), item["file"],
                                  kind=item["kind"], origin="demo", default_user=item["user"],
                                  actor="demo loader")
    with store.session() as conn:
        detector.analyze_case(conn, case_id, db.get_settings(conn))
        db.log_custody(conn, case_id, "Analysis run", "Timeline rebuilt and detection rules applied", "system")
    return case_id


def write_samples(base_dir):
    """Write both scenarios into sample_evidence/ so the Upload flow can be demonstrated too."""
    for name in SCENARIOS:
        generate(name, os.path.join(base_dir, f"scenario_{name}"))
