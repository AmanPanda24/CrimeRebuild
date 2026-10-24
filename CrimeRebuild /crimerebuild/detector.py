# Created by: Aman Kumar Panda
"""Module 4 - Suspicious Activity Detection.

Five transparent, rule-based detectors (no ML) - each one is a short function
you can explain in a viva:

    1. mass_deletion      many files deleted by one user inside a short window
    2. usb_exfiltration   files copied to a removable drive during a USB session
    3. off_hours_login    successful login during unusual hours
    4. brute_force        repeated failed logins (then maybe a success)
    5. file_tampering     protected files changed, audit log cleared, or a
                          sensitive file deleted right after it was copied

Every alert stores the ids of the exact events that triggered it, so the
dashboard can jump from an alert to the right point on the timeline.

Risk score = sum of severity points of all alerts, capped at 100.
"""
import re
from urllib.parse import urlparse

import pandas as pd

from . import constants as C
from .timeline import EPOCH, basename, is_sensitive, norm_path, seconds, build_timeline

MIN = pd.Timedelta(minutes=1)


# ----------------------------------------------------------------------------
# generic helpers
# ----------------------------------------------------------------------------
def burst_groups(times, window_s, min_count):
    """Indices of events that sit inside ANY sliding window holding >= min_count events.

    `times` must be sorted. Overlapping windows are merged into one group, so a
    single attack burst becomes a single alert.
    """
    n = len(times)
    flagged = [False] * n
    j = 0
    for i in range(n):
        while j < n and times[j] - times[i] <= window_s:
            j += 1
        if j - i >= min_count:
            for k in range(i, j):
                flagged[k] = True
    groups, cur = [], []
    for k in range(n):
        if flagged[k]:
            if cur and times[k] - times[cur[-1]] > window_s:     # a quiet gap separates two bursts
                groups.append(cur)
                cur = []
            cur.append(k)
        elif cur:
            groups.append(cur)
            cur = []
    if cur:
        groups.append(cur)
    return groups


def chain_groups(times, max_gap_s):
    """Split sorted times into runs where consecutive events are at most max_gap_s apart."""
    groups, cur = [], []
    for k, t in enumerate(times):
        if cur and t - times[cur[-1]] > max_gap_s:
            groups.append(cur)
            cur = []
        cur.append(k)
    if cur:
        groups.append(cur)
    return groups


def drive_of(path):
    m = re.match(r"^\s*([A-Za-z]):", path or "")
    return f"{m.group(1).upper()}:" if m else ""


def _t(ts):
    return pd.Timestamp(ts).strftime("%H:%M:%S")


def _names(rows, limit=4):
    names, seen = [], set()
    for n in rows:
        if n and n.lower() not in seen:
            seen.add(n.lower())
            names.append(n)
    shown = ", ".join(names[:limit])
    return shown + (f" and {len(names) - limit} more" if len(names) > limit else "")


def make_alert(rule, severity, title, description, events, user=""):
    """events: DataFrame (or list of ids) of the evidence events behind the alert."""
    info = C.RULE_INFO[rule]
    if isinstance(events, pd.DataFrame):
        ids = [int(i) for i in events["id"].tolist()]
        first, last = events["ts"].min(), events["ts"].max()
    else:
        raise TypeError("events must be a DataFrame")
    return {
        "rule": rule, "severity": severity, "points": C.SEVERITY_POINTS[severity],
        "title": title, "description": description, "user": user,
        "event_ids": list(dict.fromkeys(ids)),
        "first_ts": first.strftime("%Y-%m-%d %H:%M:%S"), "last_ts": last.strftime("%Y-%m-%d %H:%M:%S"),
        "mitre": info[1],
    }


def _mask(series, fn):
    """Boolean mask from a per-value test; safe on empty Series."""
    return series.map(fn).astype(bool)


def _concat(*frames):
    frames = [f for f in frames if f is not None and len(f)]
    if not frames:
        return pd.DataFrame()
    out = pd.concat(frames)
    return out[~out.index.duplicated()].sort_values(["ts", "id"])


# ----------------------------------------------------------------------------
# rule 1 - mass file deletion
# ----------------------------------------------------------------------------
def rule_mass_deletion(df, cfg):
    alerts = []
    dels = df[df["action"] == "File Deleted"]
    ignore = cfg["deletion_ignore_paths"]
    if ignore and len(dels):
        dels = dels[_mask(dels["target"], lambda p: not any(x in norm_path(p) for x in ignore))]
    need, window = cfg["mass_delete_count"], cfg["mass_delete_window_min"] * 60
    for ukey, g in dels.groupby("ukey"):
        for grp in burst_groups(seconds(g["ts"]), window, need):
            ev = g.iloc[grp]
            n = len(ev)
            sev = "critical" if n >= 3 * need else "high"
            who = ev["user"].iloc[0] or "an unknown user"
            span = int((ev["ts"].max() - ev["ts"].min()).total_seconds())
            alerts.append(make_alert(
                "mass_deletion", sev, f"{n} files deleted in a short burst",
                f"{who} deleted {n} files within {span // 60}m {span % 60:02d}s "
                f"(threshold: {need} files in {cfg['mass_delete_window_min']} min). "
                f"Examples: {_names([basename(t) for t in ev['target']])}.",
                ev, ev["user"].iloc[0]))
    return alerts


# ----------------------------------------------------------------------------
# rule 2 - USB data exfiltration
# ----------------------------------------------------------------------------
def usb_sessions(df, max_hours):
    """Pair each USB Connected event with the next matching disconnect."""
    usb = df[df["category"] == "usb"]
    discs = usb[usb["action"] == "USB Disconnected"]
    sessions = []
    for _, c in usb[usb["action"] == "USB Connected"].iterrows():
        drive = c["dest"].upper()
        end_row = None
        for _, d in discs[discs["ts"] >= c["ts"]].iterrows():
            if (drive and d["dest"].upper() == drive) or (c["target"] and d["target"] == c["target"]):
                end_row = d
                break
        end = end_row["ts"] if end_row is not None else c["ts"] + pd.Timedelta(hours=max_hours)
        sessions.append({"start": c["ts"], "end": end, "drive": drive, "device": c["target"],
                         "conn": c, "disc": end_row})
    return sessions


def rule_usb_exfiltration(df, cfg):
    alerts = []
    writes = df[df["action"].isin(["File Copied", "File Created", "File Modified"])].copy()
    if writes.empty:
        return alerts
    writes["drv"] = [drive_of(d) if a == "File Copied" else drive_of(t)
                     for a, d, t in zip(writes["action"], writes["dest"], writes["target"])]
    # file name that ended up on the drive
    writes["fname"] = [(db_ or b) if a == "File Copied" else b
                       for a, db_, b in zip(writes["action"], writes["dbase"], writes["base"])]
    web = df[df["action"].isin(["Webmail Opened", "Cloud Storage Visited"])]

    for s in usb_sessions(df, cfg["usb_session_max_hours"]):
        in_win = (writes["ts"] >= s["start"]) & (writes["ts"] <= s["end"])
        if s["drive"]:
            on_drive = writes["drv"] == s["drive"]
        else:                      # drive letter unknown: any non-system drive during the session
            on_drive = ~writes["drv"].isin(["", "C:"])
        sel = writes[in_win & on_drive]
        copies = sel[sel["action"] == "File Copied"]
        if sel.empty:
            continue
        names = [n for n in sel["fname"].tolist() if n]
        distinct = list(dict.fromkeys(n.lower() for n in names))
        sensitive = [n for n in distinct if is_sensitive(n, cfg["sensitive_keywords"])]
        if sensitive:
            sev = "critical"
        elif len(distinct) >= cfg["usb_bulk_files"]:
            sev = "high"
        elif len(copies):
            sev = "medium"
        else:
            sev = "low"

        # context: webmail / cloud sites opened around the session, and the file opens just before each copy
        near_web = web[(web["ts"] >= s["start"] - 10 * MIN) & (web["ts"] <= s["end"] + 10 * MIN)]
        pre_access = []
        for _, c in copies.iterrows():
            prior = df[(df["action"] == "File Accessed") & (df["base"] == c["base"]) &
                       (df["ts"] <= c["ts"]) & (df["ts"] >= c["ts"] - 30 * MIN)]
            if len(prior):
                pre_access.append(prior.iloc[[-1]])
        conn_df = df[df["id"] == s["conn"]["id"]]
        disc_df = df[df["id"] == s["disc"]["id"]] if s["disc"] is not None else None
        ev = _concat(conn_df, sel, near_web, disc_df, *pre_access)
        user = (copies["user"].iloc[0] if len(copies) else sel["user"].iloc[0]) or s["conn"]["user"]

        desc = (f"{len(distinct)} file(s) were written to removable device '{s['device']}'"
                f"{' (' + s['drive'] + ')' if s['drive'] else ''} between {_t(sel['ts'].min())} and {_t(sel['ts'].max())}: "
                f"{_names(names)}.")
        if sensitive:
            desc += f" Sensitive file(s) involved: {_names(sensitive)}."
        if len(near_web):
            desc += (f" {len(near_web)} webmail/cloud-storage visit(s) happened around the same time "
                     f"({_names([urlparse(u).hostname or u for u in near_web['target']], 2)}), a possible second exfiltration channel.")
        alerts.append(make_alert("usb_exfiltration", sev, "Files copied to a USB device", desc, ev, user))
    return alerts


# ----------------------------------------------------------------------------
# rule 3 - off-hours login
# ----------------------------------------------------------------------------
def _is_night(hour, start, end):
    if start == end:
        return False
    return start <= hour < end if start < end else (hour >= start or hour < end)


FOLLOW_ACTIONS = {"File Accessed", "File Copied", "File Deleted", "File Modified", "File Created",
                  "USB Connected", "Process Started", "Account Created", "Service Installed",
                  "Scheduled Task Created", "Audit Log Cleared"}


def rule_off_hours_login(df, cfg):
    alerts = []
    s, e = cfg["night_start_hour"], cfg["night_end_hour"]
    logins = df[df["action"] == "Login Success"]
    if logins.empty or s == e:
        return alerts
    night = logins[_mask(logins["ts"].dt.hour, lambda h: _is_night(h, s, e))]
    for ukey, g in night.groupby("ukey"):
        for grp in chain_groups(seconds(g["ts"]), 3600):
            ev = g.iloc[grp]
            first = ev["ts"].min()
            same_user = df["ukey"] == ukey if ukey else pd.Series(True, index=df.index)
            follow = df[same_user & df["action"].isin(FOLLOW_ACTIONS) &
                        (df["ts"] > first) & (df["ts"] <= first + 60 * MIN)]
            who = ev["user"].iloc[0] or "An unknown user"
            sev = "high" if len(follow) >= 3 else "medium"
            desc = (f"{who} logged in at {_t(first)}, outside normal hours "
                    f"({s:02d}:00-{e:02d}:00 is treated as off-hours).")
            if len(follow):
                desc += f" {len(follow)} file, USB or system action(s) by the same account followed within the next hour."
            alerts.append(make_alert("off_hours_login", sev, "Login during off-hours", desc,
                                     _concat(ev, follow.head(8)), ev["user"].iloc[0]))
    return alerts


# ----------------------------------------------------------------------------
# rule 4 - repeated failed logins
# ----------------------------------------------------------------------------
def rule_brute_force(df, cfg):
    alerts = []
    fails = df[df["action"] == "Login Failed"]
    need, window = cfg["brute_force_count"], cfg["brute_force_window_min"] * 60
    covered = set()
    for ukey, g in fails.groupby("ukey"):
        for grp in burst_groups(seconds(g["ts"]), window, need):
            ev = g.iloc[grp]
            last = ev["ts"].max()
            succ = df[(df["action"] == "Login Success") & (df["ukey"] == ukey) &
                      (df["ts"] > last) & (df["ts"] <= last + 10 * MIN)]
            n = len(ev)
            sev = "critical" if len(succ) else ("high" if n >= 3 * need else "medium")
            who = ev["user"].iloc[0] or "unknown account"
            ips = sorted({d for d in ev["dest"] if d})
            desc = (f"{n} failed logins for '{who}' in {int((ev['ts'].max() - ev['ts'].min()).total_seconds() // 60)} min"
                    f"{' from ' + ', '.join(ips) if ips else ''} (threshold: {need} in {cfg['brute_force_window_min']} min).")
            if len(succ):
                desc += f" A successful login followed at {_t(succ['ts'].iloc[0])}: the account may be compromised."
            all_ev = _concat(ev, succ.head(1))
            covered.update(int(i) for i in ev["id"])
            alerts.append(make_alert("brute_force", sev, "Repeated failed logins" +
                                     (" followed by success" if len(succ) else ""), desc, all_ev, ev["user"].iloc[0]))
    # password spraying: one source address, many different accounts
    with_ip = fails[fails["dest"] != ""]
    for ip, g in with_ip.groupby("dest"):
        if g["ukey"].nunique() < 3:
            continue
        for grp in burst_groups(seconds(g["ts"]), window, need):
            ev = g.iloc[grp]
            ev = ev[~ev["id"].isin(covered)]
            if len(ev) < need:
                continue
            alerts.append(make_alert(
                "brute_force", "high", "Password spraying from one address",
                f"{len(ev)} failed logins across {ev['ukey'].nunique()} different accounts came from {ip}.", ev, ""))
    return alerts


# ----------------------------------------------------------------------------
# rule 5 - file tampering / anti-forensics
# ----------------------------------------------------------------------------
def rule_file_tampering(df, cfg):
    alerts = []
    changes = df[df["action"].isin(["File Modified", "File Created", "File Deleted", "File Renamed"])]

    # (a) protected locations changed
    used = set()
    for pattern in sorted(cfg["protected_paths"], key=len, reverse=True):   # most specific pattern first
        if changes.empty:
            break
        hit = changes[_mask(changes["target"], lambda p, pat=pattern: pat in norm_path(p))]
        hit = hit[~hit["id"].isin(used)]
        used.update(int(i) for i in hit["id"])
        for ukey, g in hit.groupby("ukey"):
            who = g["user"].iloc[0] or "An unknown user"
            alerts.append(make_alert(
                "file_tampering", "high", "Protected file modified",
                f"{who} changed {len(g)} file(s) in a protected location ('{pattern}'): "
                f"{_names([basename(t) for t in g['target']])}.", g.head(25), g["user"].iloc[0]))

    # (b) audit log cleared (anti-forensics)
    for _, r in df[df["action"] == "Audit Log Cleared"].iterrows():
        recent = df[(df["action"] == "Process Started") & (df["ts"] <= r["ts"]) & (df["ts"] >= r["ts"] - 2 * MIN) &
                    df["details"].str.contains("wevtutil|Clear-EventLog", case=False, regex=True)]
        who = r["user"] or "An unknown user"
        alerts.append(make_alert(
            "file_tampering", "critical", "Audit log cleared (anti-forensics)",
            f"{who} cleared the event log at {_t(r['ts'])}. Attackers do this to hide earlier activity, "
            f"so events before this moment may be missing.", _concat(df[df["id"] == r["id"]], recent), r["user"]))

    # (c) sensitive file deleted soon after being copied
    window = cfg["cover_window_min"] * MIN
    dels = df[(df["action"] == "File Deleted")]
    dels = dels[_mask(dels["base"], lambda n: is_sensitive(n, cfg["sensitive_keywords"]))]
    pairs = []
    for _, d in dels.iterrows():
        cp = df[(df["action"] == "File Copied") & (df["base"] == d["base"]) &
                (df["ts"] <= d["ts"]) & (df["ts"] >= d["ts"] - window)]
        if len(cp):
            pairs.append((d, cp.iloc[[-1]]))
    if pairs:
        pair_df = pd.DataFrame([{"ts": d["ts"], "ukey": d["ukey"]} for d, _ in pairs])
        for grp in chain_groups(seconds(pair_df["ts"]), 30 * 60):
            members = [pairs[k] for k in grp]
            ev = _concat(*[df.loc[[d.name]] for d, _ in members], *[c for _, c in members])
            names = [d["base"] for d, _ in members]
            who = members[0][0]["user"] or "An unknown user"
            alerts.append(make_alert(
                "file_tampering", "high", "Sensitive file deleted after being copied",
                f"{who} deleted {len(members)} sensitive file(s) shortly after copying them: {_names(names)}. "
                f"Removing the original after a copy can destroy evidence of what was taken.",
                ev, members[0][0]["user"]))
    return alerts


RULES = (rule_mass_deletion, rule_usb_exfiltration, rule_off_hours_login, rule_brute_force, rule_file_tampering)


def run_rules(df, cfg):
    if df.empty:
        return []
    alerts = []
    for rule in RULES:
        alerts.extend(rule(df, cfg))
    alerts.sort(key=lambda a: (a["first_ts"], -a["points"], a["rule"]))
    return alerts


def risk_from_alerts(alerts):
    score = min(100, sum(a["points"] for a in alerts))
    return score, C.risk_level(score)


# ----------------------------------------------------------------------------
# persistence
# ----------------------------------------------------------------------------
def analyze_case(conn, case_id, cfg):
    """Re-run detection for the case and store alerts + the case risk score."""
    tl = build_timeline(conn, case_id)
    alerts = run_rules(tl.df, cfg)
    conn.execute("DELETE FROM alerts WHERE case_id=?", (case_id,))
    for a in alerts:
        cur = conn.execute(
            "INSERT INTO alerts(case_id, rule, title, severity, points, description, user, first_ts, last_ts, mitre) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (case_id, a["rule"], a["title"], a["severity"], a["points"], a["description"], a["user"],
             a["first_ts"], a["last_ts"], a["mitre"]))
        conn.executemany("INSERT OR IGNORE INTO alert_events(alert_id, event_id) VALUES(?,?)",
                         [(cur.lastrowid, i) for i in a["event_ids"]])
    score, level = risk_from_alerts(alerts)
    conn.execute("UPDATE cases SET risk_score=?, risk_level=? WHERE id=?", (score, level, case_id))
    return alerts, score, level


def load_alerts(conn, case_id):
    """Stored alerts as dicts with their linked event ids."""
    out = []
    links = {}
    for r in conn.execute("SELECT ae.alert_id, ae.event_id FROM alert_events ae "
                          "JOIN alerts a ON a.id = ae.alert_id WHERE a.case_id=?", (case_id,)):
        links.setdefault(r["alert_id"], []).append(r["event_id"])
    rows = conn.execute("SELECT * FROM alerts WHERE case_id=? ORDER BY first_ts, id", (case_id,)).fetchall()
    for r in rows:
        d = dict(r)
        d["event_ids"] = sorted(links.get(r["id"], []))
        d["rule_title"] = C.RULE_INFO.get(r["rule"], (r["rule"], ""))[0]
        out.append(d)
    return out
