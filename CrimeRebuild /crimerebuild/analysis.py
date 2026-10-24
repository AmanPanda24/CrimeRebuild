# Created by: Aman Kumar Panda
"""Glue between storage, timeline engine, detector and summary.

`case_bundle` gathers everything the dashboard and the PDF report need, so both
show exactly the same facts.
"""
from . import constants as C
from . import db, detector
from .summary import build_summary
from .timeline import (activity_buckets, build_timeline, clusters, file_chains, source_counts, top_users)


def event_alert_map(alerts):
    """event_id -> {'severity': highest severity, 'alerts': [alert ids]}"""
    out = {}
    for a in alerts:
        for eid in a["event_ids"]:
            slot = out.setdefault(eid, {"severity": a["severity"], "alerts": []})
            if C.SEVERITY_RANK[a["severity"]] > C.SEVERITY_RANK[slot["severity"]]:
                slot["severity"] = a["severity"]
            slot["alerts"].append(a["id"])
    return out


def case_bundle(conn, case_id):
    case = db.get_case(conn, case_id)
    if case is None:
        return None
    cfg = db.get_settings(conn)
    tl = build_timeline(conn, case_id)
    alerts = detector.load_alerts(conn, case_id)
    chains = file_chains(tl.df, cfg["sensitive_keywords"])
    bursts = clusters(tl.df)
    summary = build_summary(case, tl, alerts, chains, bursts)
    evidence = [dict(r) for r in conn.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY id", (case_id,))]
    return {
        "case": case, "cfg": cfg, "tl": tl, "df": tl.df, "alerts": alerts, "chains": chains,
        "clusters": bursts, "summary": summary, "evidence": evidence,
        "flags": event_alert_map(alerts),
        "activity": activity_buckets(tl.df),
        "sources": source_counts(tl.df),
        "users": top_users(tl.df),
    }


def reanalyze(store, case_id):
    """Re-run detection with the current settings."""
    with store.session() as conn:
        cfg = db.get_settings(conn)
        alerts, score, level = detector.analyze_case(conn, case_id, cfg)
        db.log_custody(conn, case_id, "Analysis run",
                       f"Timeline rebuilt; {len(alerts)} alert(s); risk score {score} ({level})", "system")
    return alerts, score, level
