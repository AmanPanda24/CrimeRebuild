# Created by: Aman Kumar Panda
"""Web routes - Module 5 (visualisation dashboard) and the investigator workflow."""
import csv
import io
import os
import shutil
import tempfile

import pandas as pd
from flask import (Blueprint, Response, abort, current_app, flash, redirect, render_template, request, send_file,
                   url_for)
from werkzeug.utils import secure_filename

from . import analysis, collector, constants as C, converter, db, evidence
from .report import build_pdf

bp = Blueprint("main", __name__)
PER_PAGE = 100


def store():
    return current_app.extensions["store"]


def _bundle_or_404(conn, case_id):
    b = analysis.case_bundle(conn, case_id)
    if b is None:
        abort(404)
    return b


# ----------------------------------------------------------------------------
# cases
# ----------------------------------------------------------------------------
@bp.route("/")
def index():
    with store().session() as conn:
        cases = conn.execute(
            "SELECT c.*, (SELECT COUNT(*) FROM events e WHERE e.case_id=c.id) AS n_events, "
            "(SELECT COUNT(*) FROM alerts a WHERE a.case_id=c.id) AS n_alerts, "
            "(SELECT COUNT(*) FROM evidence v WHERE v.case_id=c.id) AS n_evidence "
            "FROM cases c ORDER BY c.id DESC").fetchall()
    return render_template("cases.html", cases=cases, active="cases")


@bp.post("/cases/new")
def new_case():
    with store().session() as conn:
        case_id = db.create_case(conn, request.form.get("name", ""), request.form.get("investigator", ""),
                                 request.form.get("description", ""))
    flash("Case created. Add evidence to begin the reconstruction.", "success")
    return redirect(url_for("main.evidence_page", case_id=case_id))


@bp.post("/case/<int:case_id>/delete")
def delete_case(case_id):
    with store().session() as conn:
        _bundle_or_404(conn, case_id)
        conn.execute("DELETE FROM cases WHERE id=?", (case_id,))
    shutil.rmtree(os.path.join(store().data_dir, "cases", str(case_id)), ignore_errors=True)
    flash("Case deleted.", "info")
    return redirect(url_for("main.index"))


# ----------------------------------------------------------------------------
# dashboard
# ----------------------------------------------------------------------------
@bp.route("/case/<int:case_id>")
def dashboard(case_id):
    with store().session() as conn:
        b = _bundle_or_404(conn, case_id)
    chart = {"risk": b["case"]["risk_score"], "level": b["case"]["risk_level"], "activity": b["activity"],
             "sources": b["sources"], "users": b["users"], "severity": b["summary"]["severity_counts"]}
    return render_template("dashboard.html", b=b, case=b["case"], chart=chart, active="dashboard")


# ----------------------------------------------------------------------------
# timeline
# ----------------------------------------------------------------------------
def _parse_dt(text):
    try:
        return pd.Timestamp(text) if text else None
    except (ValueError, TypeError):
        return None


@bp.route("/case/<int:case_id>/timeline")
def timeline_page(case_id):
    with store().session() as conn:
        b = _bundle_or_404(conn, case_id)
    df, flags = b["df"], b["flags"]
    args = request.args
    f = {k: args.get(k, "").strip() for k in ("q", "source", "action", "user", "start", "end")}
    f["flagged"] = args.get("flagged") == "1"

    focus_alert = None
    focus_ids = set()
    if args.get("alert", "").isdigit():
        focus_alert = next((a for a in b["alerts"] if a["id"] == int(args["alert"])), None)
    ctx = args.get("ctx", "")
    if focus_alert:
        focus_ids = set(focus_alert["event_ids"])
        ctx_min = int(ctx) if ctx.isdigit() else 10
        if ctx_min > 0:
            lo = pd.Timestamp(focus_alert["first_ts"]) - pd.Timedelta(minutes=ctx_min)
            hi = pd.Timestamp(focus_alert["last_ts"]) + pd.Timedelta(minutes=ctx_min)
            df = df[(df["ts"] >= lo) & (df["ts"] <= hi)]
        else:
            df = df[df["id"].isin(focus_ids)]
        ctx = str(ctx_min)

    if not df.empty:
        if f["source"]:
            df = df[df["source"] == f["source"]]
        if f["action"]:
            df = df[df["action"] == f["action"]]
        if f["user"]:
            df = df[df["user"] == f["user"]]
        if f["flagged"]:
            df = df[df["id"].isin(flags.keys())]
        if f["q"]:
            needle = f["q"].lower()
            hay = (df["action"] + " " + df["user"] + " " + df["target"] + " " + df["dest"] + " " + df["details"]).str.lower()
            df = df[hay.str.contains(needle, regex=False)]
        lo, hi = _parse_dt(f["start"]), _parse_dt(f["end"])
        if lo is not None:
            df = df[df["ts"] >= lo]
        if hi is not None:
            df = df[df["ts"] <= hi]

    total = len(df)
    page = max(1, int(args.get("page", 1) if str(args.get("page", 1)).isdigit() else 1))
    if args.get("focus", "").isdigit() and not df.empty:        # jump to the page that holds this event
        fid = int(args["focus"])
        positions = (df["id"] == fid).to_numpy().nonzero()[0]
        if len(positions):
            page = int(positions[0]) // PER_PAGE + 1
            focus_ids.add(fid)
    pages = max(1, -(-total // PER_PAGE))
    page = min(page, pages)
    chunk = df.iloc[(page - 1) * PER_PAGE: page * PER_PAGE]

    items, prev_ts, prev_date = [], None, None
    for _, r in chunk.iterrows():
        gap = (r["ts"] - prev_ts).total_seconds() if prev_ts is not None else 0
        new_day = r["ts"].date() != prev_date
        flag = flags.get(int(r["id"]))
        items.append({"row": r.to_dict(), "gap": gap if gap >= 900 else 0, "new_day": new_day, "flag": flag,
                      "focus": int(r["id"]) in focus_ids})
        prev_ts, prev_date = r["ts"], r["ts"].date()

    full = b["df"]
    choices = {"sources": sorted(full["source"].unique()) if not full.empty else [],
               "actions": sorted(full["action"].unique()) if not full.empty else [],
               "users": sorted(u for u in full["user"].unique() if u) if not full.empty else []}
    query = {k: v for k, v in args.items() if k not in ("page", "focus") and v}
    return render_template("timeline.html", b=b, case=b["case"], items=items, f=f, choices=choices, total=total,
                           page=page, pages=pages, focus_alert=focus_alert, ctx=ctx, query=query,
                           active="timeline")


@bp.route("/case/<int:case_id>/export.csv")
def export_csv(case_id):
    with store().session() as conn:
        b = _bundle_or_404(conn, case_id)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["seq", "timestamp_utc", "source", "action", "user", "target", "destination", "details",
                "alert_severity", "alert_ids"])
    for _, r in b["df"].iterrows():
        fl = b["flags"].get(int(r["id"]))
        w.writerow([r["seq"], r["ts"].strftime("%Y-%m-%d %H:%M:%S"), r["source"], r["action"], r["user"],
                    r["target"], r["dest"], r["details"], fl["severity"] if fl else "",
                    ";".join(str(i) for i in fl["alerts"]) if fl else ""])
    name = f"crimerebuild_case{case_id}_timeline.csv"
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


# ----------------------------------------------------------------------------
# alerts
# ----------------------------------------------------------------------------
@bp.route("/case/<int:case_id>/alerts")
def alerts_page(case_id):
    with store().session() as conn:
        b = _bundle_or_404(conn, case_id)
    by_id = b["df"].set_index("id") if not b["df"].empty else None
    rows = []
    for a in b["alerts"]:
        evs = []
        if by_id is not None:
            for eid in a["event_ids"][:8]:
                if eid in by_id.index:
                    evs.append(by_id.loc[eid].to_dict() | {"id": eid})
        rows.append({"alert": a, "events": evs, "more": max(0, len(a["event_ids"]) - len(evs))})
    return render_template("alerts.html", b=b, case=b["case"], rows=rows, active="alerts")


# ----------------------------------------------------------------------------
# evidence
# ----------------------------------------------------------------------------
@bp.route("/case/<int:case_id>/evidence")
def evidence_page(case_id, verification=None):
    with store().session() as conn:
        b = _bundle_or_404(conn, case_id)
        custody = conn.execute("SELECT * FROM custody WHERE case_id=? ORDER BY id DESC", (case_id,)).fetchall()
    return render_template("evidence.html", b=b, case=b["case"], custody=custody, verification=verification,
                           can_collect=collector.IS_WINDOWS, active="evidence")


@bp.post("/case/<int:case_id>/evidence")
def upload_evidence(case_id):
    files = [f for f in request.files.getlist("files") if f and f.filename]
    if not files:
        flash("Choose at least one evidence file.", "warning")
        return redirect(url_for("main.evidence_page", case_id=case_id))
    kind = request.form.get("kind", "auto")
    user = request.form.get("default_user", "").strip()
    since = request.form.get("since_days", "").strip()
    since = int(since) if since.isdigit() and int(since) > 0 else None
    added = 0
    with tempfile.TemporaryDirectory() as tmp:
        for idx, f in enumerate(files):
            name = secure_filename(f.filename) or "evidence.dat"
            path = os.path.join(tmp, f"{idx}_{name}")
            f.save(path)
            try:                                  # a ZIP (PK) is unpacked into its member files
                items = converter.expand_archives(path, os.path.join(tmp, f"x{idx}"), f.filename)
            except converter.ConvertError as exc:
                flash(str(exc), "danger")
                continue
            if len(items) != 1 or items[0][1] != path:
                with store().session() as conn:
                    db.log_custody(conn, case_id, "Archive received",
                                   f"{f.filename} | SHA-256 {evidence.sha256_file(path)} | "
                                   f"{len(items)} file(s) extracted", "investigator")
                flash(f"{f.filename}: unpacked {len(items)} file(s).", "info")
            for disp, p in items:
                try:
                    res = evidence.add_evidence(store(), case_id, p, disp, kind=kind, origin="upload",
                                                default_user=user, since_days=since)
                except evidence.DuplicateEvidence as exc:
                    flash(str(exc), "warning")
                    continue
                if res.status == "failed":
                    flash(f"{disp}: {res.error}", "danger")
                else:
                    added += 1
                    msg = (f"{disp}: {res.parsed:,} events parsed as {C.SOURCES.get(res.kind, res.kind)}"
                           + (f" ({res.skipped} rows skipped)" if res.skipped else "") + ".")
                    flash(msg, "success")
                    for w in res.warnings:
                        flash(w, "info")
    if added:
        analysis.reanalyze(store(), case_id)
    return redirect(url_for("main.dashboard" if added else "main.evidence_page", case_id=case_id))


@bp.post("/case/<int:case_id>/collect")
def collect_live(case_id):
    days = request.form.get("days", "14")
    days = int(days) if days.isdigit() and 0 < int(days) <= 365 else 14
    try:
        summary = collector.collect_into_case(store(), case_id, days)
    except collector.CollectorUnavailable as exc:
        flash(str(exc), "danger")
        return redirect(url_for("main.evidence_page", case_id=case_id))
    for w in summary["warnings"]:
        flash(w, "warning")
    for r in summary["ingested"]:
        flash(f"{r.filename}: {r.parsed:,} events ({C.SOURCES.get(r.kind, r.kind)}).", "success")
    if summary["ingested"]:
        analysis.reanalyze(store(), case_id)
        return redirect(url_for("main.dashboard", case_id=case_id))
    flash("Nothing new was collected.", "info")
    return redirect(url_for("main.evidence_page", case_id=case_id))


@bp.post("/case/<int:case_id>/verify")
def verify(case_id):
    results = evidence.verify_case(store(), case_id)
    bad = [r for r in results if r["status"] != "OK"]
    flash("Integrity problem found - see the table below." if bad else
          f"All {len(results)} evidence file(s) match their recorded SHA-256 hash.", "danger" if bad else "success")
    return evidence_page(case_id, verification={r["id"]: r for r in results})


@bp.post("/case/<int:case_id>/reanalyze")
def reanalyze(case_id):
    alerts, score, level = analysis.reanalyze(store(), case_id)
    flash(f"Analysis re-run: {len(alerts)} alert(s), risk {score}/100 ({level}).", "success")
    return redirect(request.referrer or url_for("main.dashboard", case_id=case_id))


# ----------------------------------------------------------------------------
# report
# ----------------------------------------------------------------------------
@bp.route("/case/<int:case_id>/report.pdf")
def report_pdf(case_id):
    results = evidence.verify_case(store(), case_id, actor="report generator")
    with store().session() as conn:
        b = _bundle_or_404(conn, case_id)
        custody = conn.execute("SELECT * FROM custody WHERE case_id=? ORDER BY id", (case_id,)).fetchall()
        db.log_custody(conn, case_id, "Report exported", "PDF forensic report generated", "report generator")
    pdf = build_pdf(b, results, custody)
    return send_file(io.BytesIO(pdf), mimetype="application/pdf", as_attachment=True,
                     download_name=f"CrimeRebuild_Case{case_id}_Report.pdf")


# ----------------------------------------------------------------------------
# settings & about
# ----------------------------------------------------------------------------
@bp.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        with store().session() as conn:
            if request.form.get("reset"):
                db.reset_settings(conn)
                flash("Detection settings reset to defaults.", "info")
            else:
                db.save_settings(conn, request.form)
                flash("Detection settings saved.", "success")
            ids = [r["id"] for r in conn.execute("SELECT id FROM cases")]
        for cid in ids:
            analysis.reanalyze(store(), cid)
        if ids:
            flash(f"{len(ids)} case(s) were re-analysed with the new thresholds.", "info")
        return redirect(url_for("main.settings"))
    with store().session() as conn:
        raw = db.get_raw_settings(conn)
    return render_template("settings.html", defs=db.SETTING_DEFS, raw=raw, active="settings")


@bp.route("/about")
def about():
    return render_template("about.html", active="about")
