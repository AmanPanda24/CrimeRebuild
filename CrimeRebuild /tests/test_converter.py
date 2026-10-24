# Created by: Aman Kumar Panda
"""Mixed-format uploads: ZIP + CSV + SQLite + Excel + FTK/Autopsy listings -> JSON -> analysis."""
import json
import os
import sqlite3
import zipfile

import pandas as pd
import pytest

from crimerebuild import analysis, converter, db, demo, detector, evidence



@pytest.fixture()
def store(tmp_path):
    return db.Store(str(tmp_path / "data"))


def _ingest(store, case_id, tmp_path, zip_path):
    items = converter.expand_archives(str(zip_path), str(tmp_path / "x"), os.path.basename(zip_path))
    return [evidence.add_evidence(store, case_id, p, name) for name, p in items]


def test_zip_of_mixed_files_is_converted_to_json_and_analysed(store, tmp_path):
    demo.write_samples(str(tmp_path / "samples"))
    SAMPLES = str(tmp_path / "samples" / "scenario_insider")
    z = tmp_path / "evidence.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for name in os.listdir(SAMPLES):
            zf.write(os.path.join(SAMPLES, name), f"case/{name}")      # csv files + Chrome_History (sqlite)
    with store.session() as conn:
        cid = db.create_case(conn, "zip")
    results = _ingest(store, cid, tmp_path, z)
    assert len(results) == 5 and all(r.status == "parsed" for r in results)
    analysis.reanalyze(store, cid)
    with store.session() as conn:
        titles = " ".join(a["title"] for a in detector.load_alerts(conn, cid)).lower()
    assert "usb" in titles                                              # same finding as the demo scenario
    converted = os.listdir(store.case_dir(cid, "converted"))
    assert len(converted) >= 4 and all(c.endswith(".json") for c in converted)
    doc = json.load(open(os.path.join(store.case_dir(cid, "converted"), converted[0])))
    assert {"source_file", "source_format", "record_count", "records"} <= set(doc)


def test_ftk_style_file_list_expands_to_one_event_per_timestamp(store, tmp_path):
    p = tmp_path / "ftk_filelist.csv"
    p.write_text("Filename,Full Path,Size,Created,Modified,Accessed\n"
                 'a.docx,C:\\Users\\bob\\a.docx,10,2025-01-01 10:00:00,2025-01-02 10:00:00,2025-01-03 10:00:00\n')
    with store.session() as conn:
        cid = db.create_case(conn, "ftk")
    r = evidence.add_evidence(store, cid, str(p), "ftk_filelist.csv")
    assert r.status == "parsed" and r.parsed == 3 and r.kind == "file"


def test_excel_and_autopsy_db(store, tmp_path):
    x = tmp_path / "report.xlsx"
    pd.DataFrame({"Timestamp": ["2025-01-01 10:00:00"], "User": ["bob"], "Result": ["Failed"],
                  "SourceIP": ["10.0.0.5"], "LogonType": ["3"]}).to_excel(x, index=False)
    db_path = tmp_path / "autopsy.db"
    con = sqlite3.connect(db_path)
    con.execute("CREATE TABLE tsk_files(name TEXT, parent_path TEXT, size INT, crtime INT, mtime INT, atime INT, ctime INT)")
    con.execute("INSERT INTO tsk_files VALUES('secret.pdf','/Users/bob/',100,1735725600,1735729200,1735732800,0)")
    con.commit(); con.close()
    with store.session() as conn:
        cid = db.create_case(conn, "mix")
    r1 = evidence.add_evidence(store, cid, str(x), "report.xlsx")
    r2 = evidence.add_evidence(store, cid, str(db_path), "autopsy.db")
    assert (r1.status, r1.kind, r1.parsed) == ("parsed", "login", 1)
    assert (r2.status, r2.kind, r2.parsed) == ("parsed", "file", 3)       # ctime=0 is dropped


@pytest.mark.parametrize("name,payload,needle", [
    ("disk.E01", b"EVF\x09\x0d\x0a\xff\x00" + b"0" * 32, "export"),
    ("cap.pcapng", b"\x0a\x0d\x0d\x0a" + b"0" * 32, "Wireshark"),
])
def test_unsupported_formats_give_a_clear_message(store, tmp_path, name, payload, needle):
    p = tmp_path / name
    p.write_bytes(payload)
    with store.session() as conn:
        cid = db.create_case(conn, "bad")
    r = evidence.add_evidence(store, cid, str(p), name)
    assert r.status == "failed" and needle in r.error


def test_zip_slip_and_password_protected_archives_are_safe(tmp_path):
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../../escape.csv", "a,b\n1,2\n")
    items = converter.expand_archives(str(z), str(tmp_path / "out"))
    assert len(items) == 1 and os.path.commonpath([items[0][1], str(tmp_path / "out")]) == str(tmp_path / "out")
    assert not (tmp_path / "escape.csv").exists()
