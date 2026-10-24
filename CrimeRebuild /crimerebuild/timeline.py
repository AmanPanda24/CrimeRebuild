# Created by: Aman Kumar Panda
"""Module 3 - Timeline Reconstruction Engine (the core innovation).

All events from every evidence source are merged into one list, sorted by
timestamp, de-duplicated, then enriched so that investigators (and the
detection rules) can reason about a single ordered story:

* build_timeline  - merge + sort + de-duplicate, adds gap and helper columns
* activity_buckets - events-per-interval series for the activity graph
* clusters        - bursts of activity separated by quiet gaps
* file_chains     - per-file life stories that cross evidence sources
"""
import re
from dataclasses import dataclass

import pandas as pd

from . import constants as C

EPOCH = pd.Timestamp("1970-01-01")
TEXT_COLS = ["source", "category", "action", "user", "target", "dest", "details"]
DEDUPE_COLS = ["ts", "source", "action", "user", "target", "dest", "details"]


def basename(path):
    parts = [p for p in re.split(r"[\\/]", (path or "").strip()) if p]
    return parts[-1] if parts else ""


def norm_path(path):
    return (path or "").replace("\\", "/").lower()


def is_sensitive(name, keywords):
    n = (name or "").lower()
    return any(k and k in n for k in keywords)


def seconds(series):
    """Datetime Series -> list of float seconds since epoch (independent of pandas time unit)."""
    return ((series - EPOCH).dt.total_seconds()).tolist()


@dataclass
class Timeline:
    df: pd.DataFrame
    duplicates: int = 0

    @property
    def empty(self):
        return self.df.empty

    @property
    def start(self):
        return None if self.empty else self.df["ts"].min()

    @property
    def end(self):
        return None if self.empty else self.df["ts"].max()


def build_timeline(conn, case_id):
    """Load every stored event for the case and return the unified, ordered timeline."""
    df = pd.read_sql_query("SELECT * FROM events WHERE case_id = ?", conn, params=(case_id,))
    if df.empty:
        cols = ["id", "case_id", "evidence_id", "ts"] + TEXT_COLS + ["ukey", "base", "dbase", "seq", "gap_s"]
        return Timeline(pd.DataFrame(columns=cols), 0)
    for col in TEXT_COLS:
        df[col] = df[col].fillna("").astype(str)
    df["ts"] = pd.to_datetime(df["ts"])
    df = df.sort_values(["ts", "id"], kind="mergesort").reset_index(drop=True)
    before = len(df)
    df = df.drop_duplicates(subset=DEDUPE_COLS, keep="first").reset_index(drop=True)
    df["ukey"] = df["user"].str.lower()
    df["base"] = df["target"].map(basename).str.lower()
    df["dbase"] = df["dest"].map(basename).str.lower()
    df["seq"] = df.index + 1
    df["gap_s"] = df["ts"].diff().dt.total_seconds().fillna(0.0)
    return Timeline(df, before - len(df))


# ----------------------------------------------------------------------------
# activity graph
# ----------------------------------------------------------------------------
_BUCKETS = [(1, "1min"), (5, "5min"), (15, "15min"), (60, "1h"), (360, "6h"), (1440, "1D"), (10080, "7D")]


def activity_buckets(df, max_bars=48):
    """Events per time bucket, stacked by source. Returns chart-ready dict."""
    if df.empty:
        return {"labels": [], "datasets": [], "bucket": ""}
    span_min = max((df["ts"].max() - df["ts"].min()).total_seconds() / 60.0, 1.0)
    minutes, freq = _BUCKETS[-1]
    for m, f in _BUCKETS:
        if span_min / m <= max_bars:
            minutes, freq = m, f
            break
    counts = (df.assign(_n=1).set_index("ts")
                .groupby([pd.Grouper(freq=freq), "source"])["_n"].sum().unstack(fill_value=0))
    full = pd.date_range(counts.index.min(), counts.index.max(), freq=freq)
    counts = counts.reindex(full, fill_value=0)
    multi_day = span_min > 1440
    fmt = "%d %b" if minutes >= 1440 else ("%d %b %H:%M" if multi_day else "%H:%M")
    return {
        "labels": [t.strftime(fmt) for t in counts.index],
        "datasets": [{"source": s, "data": [int(v) for v in counts[s].tolist()]} for s in counts.columns],
        "bucket": {1: "1 minute", 5: "5 minutes", 15: "15 minutes", 60: "1 hour", 360: "6 hours",
                   1440: "1 day", 10080: "1 week"}[minutes],
    }


def clusters(df, gap_minutes=30):
    """Split the timeline into bursts separated by gaps longer than gap_minutes."""
    if df.empty:
        return []
    gid = (df["gap_s"] > gap_minutes * 60).cumsum()
    out = []
    for _, g in df.groupby(gid, sort=True):
        out.append({"start": g["ts"].min(), "end": g["ts"].max(), "count": int(len(g)),
                    "users": sorted({u for u in g["user"] if u}),
                    "sources": sorted(set(g["source"]))})
    return out


# ----------------------------------------------------------------------------
# cross-source file stories
# ----------------------------------------------------------------------------
def event_dict(row):
    return {"id": int(row["id"]), "ts": row["ts"], "source": row["source"], "action": row["action"],
            "user": row["user"], "target": row["target"], "dest": row["dest"], "details": row["details"]}


def file_chains(df, keywords, limit=5):
    """Group file events by file name across every source to reveal what happened to each file."""
    if df.empty:
        return []
    sub = df[df["category"].eq("file") | df["action"].eq("File Downloaded")]
    groups = {}
    for _, r in sub.iterrows():
        names = {r["base"]}
        if r["action"] == "File Copied" and r["dbase"]:
            names.add(r["dbase"])
        for n in names:
            if n:
                groups.setdefault(n, []).append(r)
    chains = []
    for name, rows in groups.items():
        actions = []
        for r in rows:
            if r["action"] not in actions:
                actions.append(r["action"])
        if len(actions) < 2:
            continue
        sensitive = is_sensitive(name, keywords)
        copied_and_deleted = "File Copied" in actions and "File Deleted" in actions
        score = (100 if sensitive else 0) + 10 * len(actions) + (30 if copied_and_deleted else 0)
        evs = [event_dict(r) for r in rows]
        chains.append({"name": basename(rows[0]["target"]) if rows[0]["base"] == name else name, "sensitive": sensitive, "actions": actions, "events": evs,
                       "start": evs[0]["ts"], "end": evs[-1]["ts"],
                       "duration_s": (evs[-1]["ts"] - evs[0]["ts"]).total_seconds(), "score": score})
    chains.sort(key=lambda c: (-c["score"], c["start"]))
    return chains[:limit]


def story_steps(events, max_steps=10):
    """Compress consecutive identical actions ('Login Failed' x14) into single steps."""
    steps = []
    for e in events:
        if steps and steps[-1]["action"] == e["action"] and steps[-1]["user"] == e["user"]:
            steps[-1]["count"] += 1
            steps[-1]["end"] = e["ts"]
            continue
        steps.append({"action": e["action"], "user": e["user"], "ts": e["ts"], "end": e["ts"], "count": 1,
                      "target": e["target"], "dest": e["dest"], "source": e["source"], "id": e["id"],
                      "category": C.category_of(e["action"]),
                      "details": e["details"]})
    return steps[:max_steps], max(0, len(steps) - max_steps)


def top_users(df, n=6):
    if df.empty:
        return []
    c = df[df["user"].ne("")].groupby("user").size().sort_values(ascending=False).head(n)
    return [{"user": u, "count": int(v)} for u, v in c.items()]


def source_counts(df):
    if df.empty:
        return []
    c = df.groupby("source").size().sort_values(ascending=False)
    return [{"source": s, "count": int(v)} for s, v in c.items()]


def human_duration(seconds_value):
    s = int(round(seconds_value))
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}m {s:02d}s" if s else f"{m}m"
    h, m = divmod(m, 60)
    if h < 48:
        return f"{h}h {m:02d}m" if m else f"{h}h"
    d, h = divmod(h, 24)
    return f"{d}d {h}h"
