# Created by: Aman Kumar Panda
"""Plain-language incident summary (template-based - no AI/LLM involved).

Turns the structured timeline + alerts into sentences an investigator can read
or paste into a report.
"""
from urllib.parse import urlparse

from . import constants as C
from .timeline import basename, event_dict, human_duration, story_steps


def describe_event(e):
    """One readable sentence for a single event dict."""
    a = e["action"]
    who = e["user"] or "A user"
    name = basename(e["target"]) or e["target"]
    host = urlparse(e["target"]).hostname or e["target"]
    if a == "Login Success":
        return f"{who} logged in" + (f" from {e['dest']}" if e["dest"] else "")
    if a == "Login Failed":
        return f"A failed login was recorded for {who}" + (f" from {e['dest']}" if e["dest"] else "")
    if a == "Logoff":
        return f"{who} logged off"
    if a == "USB Connected":
        return f"{who} connected USB device '{e['target']}'" + (f" as drive {e['dest']}" if e["dest"] else "")
    if a == "USB Disconnected":
        return f"USB device '{e['target']}' was removed"
    if a == "File Accessed":
        return f"{who} opened {name}"
    if a == "File Copied":
        return f"{who} copied {name}" + (f" to {e['dest']}" if e["dest"] else "")
    if a == "File Deleted":
        return f"{who} deleted {name}"
    if a == "File Modified":
        return f"{who} modified {name}"
    if a == "File Created":
        return f"{who} created {name}"
    if a == "File Renamed":
        return f"{who} renamed or moved {name}"
    if a == "File Downloaded":
        return f"{name} was downloaded from the browser"
    if a == "Webmail Opened":
        return f"Webmail was opened ({host})"
    if a == "Cloud Storage Visited":
        return f"A cloud-storage site was visited ({host})"
    if a == "URL Visited":
        return f"A web page was visited ({host})"
    if a == "Process Started":
        return f"{name or 'A program'} was started" + (f" by {e['user']}" if e["user"] else "")
    if a == "Audit Log Cleared":
        return f"{who} cleared the audit log"
    if a == "Account Created":
        return f"{who} created the account '{e['target']}'"
    if a == "Service Installed":
        return f"A service '{e['target']}' was installed"
    return f"{a}" + (f": {e['target']}" if e["target"] else "")


def _lower_first(text):
    if text.startswith(('A ', 'An ', 'The ')) or (len(text) > 1 and text[1].islower()):
        return text[0].lower() + text[1:]
    return text


def step_text(step):
    base = describe_event(step)
    if step["count"] > 1:
        return f"{base} ({step['count']} times)"
    return base


def key_sequence(df, alerts, n_alerts=3):
    """The events behind the most serious alerts, compressed into at most ~10 story steps."""
    if not alerts or df.empty:
        return [], 0
    top = sorted(alerts, key=lambda a: (-a["points"], a["first_ts"]))[:n_alerts]
    ids = {i for a in top for i in a["event_ids"]}
    sub = df[df["id"].isin(ids)]
    return story_steps([event_dict(r) for _, r in sub.iterrows()])


RECOMMENDATIONS = {
    "usb_exfiltration": "Seize the USB device and image it before it is reused; record its serial number and check what the user's webmail and cloud sessions sent.",
    "mass_deletion": "Check the Recycle Bin and available backups or shadow copies to recover the deleted files, and note the exact time window for the report.",
    "off_hours_login": "Confirm with the account owner whether the night-time login was authorised; review the source address and the activity that followed.",
    "brute_force": "Reset the affected credentials, review the source address in firewall or router logs, and enable account lock-out.",
    "file_tampering": "Treat the host as untrusted: compare protected files with known-good copies and collect evidence from other sources, since logs may have been altered.",
}


def build_summary(case, tl, alerts, chains, clusters):
    df = tl.df
    if df.empty:
        return {"headline": "No evidence loaded yet",
                "overview": "Upload evidence files to reconstruct a timeline.",
                "sequence": [], "sequence_extra": 0, "sequence_text": "", "findings": [],
                "facts": [], "recommendations": [], "severity_counts": {s: 0 for s in C.SEVERITIES}}

    n_src = df["source"].nunique()
    span = (tl.end - tl.start).total_seconds()
    sev_counts = {s: 0 for s in C.SEVERITIES}
    for a in alerts:
        sev_counts[a["severity"]] += 1

    level = case["risk_level"]
    if alerts:
        headline = (f"{level} risk: {len(alerts)} suspicious pattern{'s' if len(alerts) != 1 else ''} "
                    f"across {n_src} evidence source{'s' if n_src != 1 else ''}")
    else:
        headline = "No suspicious patterns were detected"

    overview = (f"CrimeRebuild merged {len(df):,} events from {n_src} source{'s' if n_src != 1 else ''} into one "
                f"timeline covering {tl.start:%d %b %Y %H:%M} to {tl.end:%d %b %Y %H:%M} ({human_duration(span)}).")
    if tl.duplicates:
        overview += f" {tl.duplicates} duplicate record{'s' if tl.duplicates != 1 else ''} were merged."

    steps, extra = key_sequence(df, alerts)
    seq_text = " ".join(f"At {s['ts']:%H:%M:%S}, {_lower_first(step_text(s))}." for s in steps)

    findings = [{"time": a["first_ts"], "severity": a["severity"], "title": a["title"],
                 "text": a["description"], "rule": a["rule"], "id": a["id"]} for a in alerts]

    users = sorted({u for u in df["user"] if u})
    devices = sorted({t for t in df.loc[df["action"] == "USB Connected", "target"] if t})
    facts = [("Time window", f"{tl.start:%d %b %Y %H:%M:%S} to {tl.end:%d %b %Y %H:%M:%S}"),
             ("Accounts seen", ", ".join(users) or "none recorded")]
    if devices:
        facts.append(("USB devices", ", ".join(devices)))
    if chains:
        facts.append(("Files of interest", ", ".join(c["name"] for c in chains[:3])))

    recs, seen = [], set()
    for a in sorted(alerts, key=lambda a: -a["points"]):
        if a["rule"] not in seen:
            seen.add(a["rule"])
            recs.append(RECOMMENDATIONS[a["rule"]])
    return {"headline": headline, "overview": overview, "sequence": steps, "sequence_extra": extra,
            "sequence_text": seq_text, "findings": findings, "facts": facts, "recommendations": recs,
            "severity_counts": sev_counts}
