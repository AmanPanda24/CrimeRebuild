# Created by: Aman Kumar Panda
"""End-to-end tests: parsers -> timeline -> detectors -> web app -> PDF."""
import os
import struct
import tempfile

import pandas as pd
import pytest

from crimerebuild import analysis, collector, create_app, db, demo, detector, evidence, parsers, timeline
from crimerebuild.evidence import DuplicateEvidence


@pytest.fixture()
def store(tmp_path):
    return db.Store(str(tmp_path))


def _alerts(store, case_id):
    with store.session() as conn:
        return detector.load_alerts(conn, case_id)


def _case(store, case_id):
    with store.session() as conn:
        return db.get_case(conn, case_id)


# ---------------------------------------------------------------- parsers
def test_chrome_history_parser_reads_real_sqlite(tmp_path):
    path = str(tmp_path / "History")
    from datetime import datetime
    demo.make_chrome_history(path, [(datetime(2026, 9, 14, 10, 7, 20), "https://mail.google.com/mail/u/0/", "Inbox")],
                             [(datetime(2026, 9, 14, 9, 14), r"C:\Users\a\Downloads\x.xlsx", "https://intranet/x", 10)])
    res = parsers.parse_file(path, "auto", "aman")
    assert res.kind == "browser"
    actions = {r["action"] for r in res.rows}
    assert actions == {"Webmail Opened", "File Downloaded"}
    assert res.rows[0]["ts"].startswith("2026-09-14")
    assert all(r["user"] == "aman" for r in res.rows)


def test_kind_detection_from_columns(tmp_path):
    cases = {"usb": "Timestamp,Event,DeviceName,Serial\n2026-01-01 10:00:00,Connected,Stick,123\n",
             "login": "Timestamp,User,Result,SourceIP\n2026-01-01 10:00:00,bob,Failed,10.0.0.1\n",
             "file": "Timestamp,Action,Path,User\n2026-01-01 10:00:00,Deleted,C:\\a.txt,bob\n",
             "eventlog": "TimeCreated,EventID,Message\n2026-01-01 10:00:00,1102,cleared\n",
             "browser": "timestamp,url,title\n2026-01-01 10:00:00,https://x.com,X\n"}
    for kind, text in cases.items():
        p = tmp_path / f"{kind}.csv"
        p.write_text(text)
        assert parsers.sniff_kind(str(p)) == kind


def test_eventlog_access_mask_and_logon(tmp_path):
    p = tmp_path / "ev.csv"
    p.write_text("TimeCreated,EventID,Account,ObjectName,AccessMask,LogonType,IpAddress\n"
                 "2026-01-01 10:00:00,4663,bob,C:\\x.doc,0x10000,,\n"
                 "2026-01-01 10:00:01,4663,bob,C:\\y.doc,0x2,,\n"
                 "2026-01-01 10:00:02,4625,CORP\\eve,,,3,10.1.1.1\n")
    rows = parsers.parse_file(str(p), "eventlog").rows
    assert [r["action"] for r in rows] == ["File Deleted", "File Modified", "Login Failed"]
    assert rows[2]["user"] == "eve" and rows[2]["dest"] == "10.1.1.1"      # domain stripped, IP kept


def test_bad_rows_are_skipped_not_fatal(tmp_path):
    p = tmp_path / "u.csv"
    p.write_text("Timestamp,Event,DeviceName\nnot-a-date,Connected,A\n2026-01-01 10:00:00,Connected,B\n")
    res = parsers.parse_file(str(p), "usb")
    assert len(res.rows) == 1 and res.skipped == 1


def test_unknown_file_gives_clear_error(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("foo,bar\n1,2\n")
    with pytest.raises(parsers.ParseError):
        parsers.parse_file(str(p), "auto")


# ---------------------------------------------------------------- timeline + detection
def test_insider_scenario_matches_slide_story(store):
    cid = demo.load_demo(store, "insider")
    with store.session() as conn:
        tl = timeline.build_timeline(conn, cid)
    df = tl.df
    assert list(df["ts"]) == sorted(df["ts"])                       # strictly chronological
    assert set(df["source"]) == {"Event Log", "Browser", "USB", "File Log", "Login Log"}
    story = df[df["id"].isin({i for a in _alerts(store, cid) for i in a["event_ids"]})]
    assert list(story["action"]) == ["USB Connected", "File Accessed", "File Copied", "Webmail Opened",
                                     "Webmail Opened", "File Deleted", "USB Disconnected"]
    rules = {a["rule"] for a in _alerts(store, cid)}
    assert rules == {"usb_exfiltration", "file_tampering"}
    case = _case(store, cid)
    assert case["risk_level"] == "Critical" and case["risk_score"] == 85


def test_temp_file_housekeeping_is_not_flagged(store):
    cid = demo.load_demo(store, "insider")
    assert not any(a["rule"] == "mass_deletion" for a in _alerts(store, cid))


def test_intrusion_triggers_all_five_rules(store):
    cid = demo.load_demo(store, "intrusion")
    rules = {a["rule"] for a in _alerts(store, cid)}
    assert rules == {"mass_deletion", "usb_exfiltration", "off_hours_login", "brute_force", "file_tampering"}
    titles = {a["title"] for a in _alerts(store, cid)}
    assert "Repeated failed logins followed by success" in titles
    assert "Audit log cleared (anti-forensics)" in titles
    assert _case(store, cid)["risk_score"] == 100                       # capped


def test_burst_groups_sliding_window():
    assert detector.burst_groups([0, 10, 20, 30, 40], 60, 5) == [[0, 1, 2, 3, 4]]
    assert detector.burst_groups([0, 100, 200, 300, 400], 60, 3) == []   # spread out: no burst
    assert detector.burst_groups([0, 1, 2, 500, 501, 502], 10, 3) == [[0, 1, 2], [3, 4, 5]]


def test_thresholds_change_results(store):
    cid = demo.load_demo(store, "insider")
    with store.session() as conn:
        cfg = db.get_settings(conn)
        cfg["sensitive_keywords"] = ["no-such-keyword"]
        alerts, score, _ = detector.analyze_case(conn, cid, cfg)
    assert [a["severity"] for a in alerts] == ["medium"] and score == 20    # copy still seen, no longer 'sensitive'


def test_duplicate_events_are_merged(store, tmp_path):
    with store.session() as conn:
        cid = db.create_case(conn, "dup")
    a = tmp_path / "a.csv"
    b = tmp_path / "b.csv"
    a.write_text("Timestamp,User,Result\n2026-01-01 10:00:00,bob,Failed\n")
    b.write_text("Timestamp,User,Result\n2026-01-01 10:00:00,bob,Failed\n2026-01-01 10:05:00,bob,Success\n")
    evidence.add_evidence(store, cid, str(a), "a.csv", kind="login")
    evidence.add_evidence(store, cid, str(b), "b.csv", kind="login")
    with store.session() as conn:
        tl = timeline.build_timeline(conn, cid)
    assert len(tl.df) == 2 and tl.duplicates == 1


def test_multi_user_timezones_are_normalised(tmp_path):
    p = tmp_path / "l.csv"
    p.write_text("Timestamp,User,Result\n2026-01-01T10:00:00+05:30,bob,Success\n")
    assert parsers.parse_file(str(p), "login").rows[0]["ts"] == "2026-01-01 04:30:00"


# ---------------------------------------------------------------- evidence integrity
def test_integrity_check_detects_tampering(store, tmp_path):
    cid = demo.load_demo(store, "insider")
    assert all(r["status"] == "OK" for r in evidence.verify_case(store, cid))
    with store.session() as conn:
        victim = conn.execute("SELECT stored_path FROM evidence WHERE case_id=? AND kind='usb'", (cid,)).fetchone()[0]
    os.chmod(victim, 0o644)
    with open(victim, "a") as fh:
        fh.write("tampered\n")
    status = {r["filename"]: r["status"] for r in evidence.verify_case(store, cid)}
    assert status["usb_activity.csv"] == "MODIFIED"


def test_same_file_cannot_be_added_twice(store, tmp_path):
    with store.session() as conn:
        cid = db.create_case(conn, "x")
    p = tmp_path / "l.csv"
    p.write_text("Timestamp,User,Result\n2026-01-01 10:00:00,bob,Failed\n")
    evidence.add_evidence(store, cid, str(p), "l.csv", kind="login")
    with pytest.raises(DuplicateEvidence):
        evidence.add_evidence(store, cid, str(p), "copy.csv", kind="login")


def test_evidence_copy_is_read_only_and_original_untouched(store, tmp_path):
    with store.session() as conn:
        cid = db.create_case(conn, "x")
    p = tmp_path / "l.csv"
    p.write_text("Timestamp,User,Result\n2026-01-01 10:00:00,bob,Failed\n")
    before = evidence.sha256_file(str(p))
    evidence.add_evidence(store, cid, str(p), "l.csv", kind="login")
    assert evidence.sha256_file(str(p)) == before
    with store.session() as conn:
        stored = conn.execute("SELECT stored_path FROM evidence").fetchone()[0]
    assert not os.access(stored, os.W_OK) or os.geteuid() == 0   # root can always write; others cannot


# ---------------------------------------------------------------- collector helpers (pure parsing)
def test_recycle_bin_i_record_v2():
    path = "C:\\Finance\\Confidential.pdf"
    raw = path.encode("utf-16le") + b"\x00\x00"
    ft = int((collector.datetime(2026, 9, 14, 10, 9, 30) - collector.datetime(1601, 1, 1)).total_seconds() * 10_000_000)
    blob = struct.pack("<qqqi", 2, 2480 * 1024, ft, len(path) + 1) + raw
    when, size, parsed = collector.parse_recycle_i(blob)
    assert parsed == path and size == 2480 * 1024 and str(when) == "2026-09-14 10:09:30"


def test_setupapi_usb_install_parsing():
    text = (">>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00\\4C53&0]\n"
            ">>>  Section start 2026/09/14 10:01:12.345\n")
    ((when, instance),) = list(collector.parse_setupapi(text))
    assert str(when) == "2026-09-14 10:01:12" and "SanDisk" in instance


def test_event_xml_conversion():
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID>'
           '<TimeCreated SystemTime="2026-09-14T23:50:10.123Z"/><Channel>Security</Channel><Computer>PC</Computer></System>'
           '<EventData><Data Name="TargetUserName">rohan</Data><Data Name="LogonType">10</Data>'
           '<Data Name="IpAddress">192.168.1.77</Data></EventData></Event>')
    row = collector.event_xml_to_row(xml)
    assert row[:2] == ["2026-09-14 23:50:10", 4625] and row[4] == "rohan" and row[6] == "192.168.1.77"


def test_live_collection_refuses_politely_off_windows(store):
    if collector.IS_WINDOWS:
        pytest.skip("Windows host")
    with pytest.raises(collector.CollectorUnavailable):
        collector.collect_all(tempfile.gettempdir())


# ---------------------------------------------------------------- web app + report
@pytest.fixture()
def client(tmp_path):
    app = create_app(str(tmp_path))
    app.testing = True
    return app.test_client()


def _demo_case(client, name):
    return demo.load_demo(client.application.extensions["store"], name)


def test_home_has_no_default_demo_and_empty_case_is_blank(client):
    home = client.get("/").data.lower()
    assert b"demo scenario" not in home and b"no cases yet" in home
    assert client.post("/cases/demo", data={"scenario": "insider"}).status_code in (404, 405)
    cid = int(client.post("/cases/new", data={"name": "Blank"}).headers["Location"].split("/")[2])
    page = client.get(f"/case/{cid}").data
    assert b"This case is empty" in page and b"Risk score" not in page


def test_every_page_renders_for_both_scenarios(client):
    for name in ("insider", "intrusion"):
        cid = _demo_case(client, name)
        for path in ("", "/timeline", "/alerts", "/evidence", "/timeline?alert=1", "/timeline?flagged=1&source=USB",
                     "/timeline?q=confidential", "/export.csv"):
            resp = client.get(f"/case/{cid}{path}")
            assert resp.status_code == 200, path
    for path in ("/", "/settings", "/about"):
        assert client.get(path).status_code == 200


def test_upload_flow_and_pdf(client, tmp_path):
    cid = int(client.post("/cases/new", data={"name": "Upload test"}).headers["Location"].split("/")[2])
    up = tmp_path / "usb.csv"
    up.write_text("Timestamp,Event,DeviceName,DriveLetter\n2026-01-01 10:00:00,Connected,Stick,E:\n")
    r = client.post(f"/case/{cid}/evidence", data={"kind": "auto", "files": (open(up, "rb"), "usb.csv")},
                    content_type="multipart/form-data", follow_redirects=True)
    assert r.status_code == 200 and b"events parsed as USB" in r.data
    pdf = client.get(f"/case/{cid}/report.pdf")
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF")


def test_pdf_for_demo_case(client):
    cid = _demo_case(client, "intrusion")
    pdf = client.get(f"/case/{cid}/report.pdf")
    assert pdf.data.startswith(b"%PDF") and len(pdf.data) > 10_000


def test_settings_save_reanalyses_cases(client):
    cid = _demo_case(client, "intrusion")
    client.post("/settings", data={"mass_delete_count": "50"}, follow_redirects=True)
    assert b"mass deletion" not in client.get(f"/case/{cid}/alerts").data.lower().replace(b"17 files", b"")
    client.post("/settings", data={"reset": "1"})
    assert b"17 files deleted" in client.get(f"/case/{cid}/alerts").data


def test_unknown_case_is_404(client):
    assert client.get("/case/999").status_code == 404
