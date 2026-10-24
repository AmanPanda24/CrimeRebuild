# Created by: Aman Kumar Panda
"""Module 6 - Forensic report export (PDF, ReportLab)."""
import io
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

import config
from . import constants as C
from .summary import describe_event

NAVY = colors.HexColor("#1c1d20")
CYAN = colors.HexColor("#059669")
INK = colors.HexColor("#1f2023")
MUTED = colors.HexColor("#6b6b73")
LINE = colors.HexColor("#dcdcdf")
PANEL = colors.HexColor("#f5f5f6")
SEV_COLOR = {"low": colors.HexColor("#6b7280"), "medium": colors.HexColor("#d99a0b"),
             "high": colors.HexColor("#ea6a1f"), "critical": colors.HexColor("#d6224a")}
SEV_TINT = {"low": colors.HexColor("#ececee"), "medium": colors.HexColor("#fff4d6"),
            "high": colors.HexColor("#ffe6d6"), "critical": colors.HexColor("#ffdce4")}
LEVEL_COLOR = {"None": colors.HexColor("#16a34a"), "Low": colors.HexColor("#6b7280"),
               "Medium": colors.HexColor("#d99a0b"), "High": colors.HexColor("#ea6a1f"),
               "Critical": colors.HexColor("#d6224a")}
MAX_TIMELINE_ROWS = 600


def _s(text):
    """Make arbitrary text safe for ReportLab's built-in fonts + XML markup."""
    text = str(text if text is not None else "")
    text = text.encode("cp1252", errors="replace").decode("cp1252")
    return escape(text)


def _styles():
    base = getSampleStyleSheet()
    mk = lambda name, **kw: ParagraphStyle(name, parent=base["Normal"], **kw)
    return {
        "title": mk("t", fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=INK, spaceAfter=2),
        "sub": mk("sub", fontSize=10, leading=13, textColor=MUTED),
        "h1": mk("h1", fontName="Helvetica-Bold", fontSize=13, leading=16, textColor=INK, spaceBefore=14, spaceAfter=6),
        "body": mk("b", fontSize=9, leading=12.5, textColor=INK, alignment=TA_LEFT),
        "small": mk("s", fontSize=7.6, leading=9.6, textColor=INK),
        "tiny": mk("tiny", fontSize=6.6, leading=8.2, textColor=INK),
        "mono": mk("m", fontName="Courier", fontSize=6.2, leading=7.6, textColor=INK),
        "muted": mk("mu", fontSize=8, leading=10.5, textColor=MUTED),
        "cell_b": mk("cb", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=INK),
        "white_b": mk("wb", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=colors.white),
    }


class _NumberedCanvas(rl_canvas.Canvas):
    """Canvas that can print 'Page X of Y' (needs the total, so pages are saved first)."""

    footer_text = ""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._saved = []

    def showPage(self):
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved)
        for state in self._saved:
            self.__dict__.update(state)
            self._footer(total)
            super().showPage()
        super().save()

    def _footer(self, total):
        w, _h = A4
        self.setStrokeColor(LINE)
        self.line(18 * mm, 14 * mm, w - 18 * mm, 14 * mm)
        self.setFont("Helvetica", 7.5)
        self.setFillColor(MUTED)
        self.drawString(18 * mm, 10 * mm, self.footer_text)
        self.drawRightString(w - 18 * mm, 10 * mm, f"Page {self._pageNumber} of {total}")


def _chart(activity, width=500, height=120):
    labels = activity["labels"]
    if not labels:
        return None
    totals = [sum(ds["data"][i] for ds in activity["datasets"]) for i in range(len(labels))]
    d = Drawing(width, height)
    bc = VerticalBarChart()
    bc.x, bc.y, bc.width, bc.height = 28, 24, width - 36, height - 34
    bc.data = [totals]
    bc.bars[0].fillColor = CYAN
    bc.bars[0].strokeColor = None
    bc.categoryAxis.categoryNames = labels
    bc.categoryAxis.labels.fontSize = 5.5
    bc.categoryAxis.labels.angle = 60 if len(labels) > 14 else 0
    bc.categoryAxis.labels.dy = -8 if len(labels) > 14 else -2
    bc.categoryAxis.labels.boxAnchor = "e" if len(labels) > 14 else "n"
    bc.categoryAxis.strokeColor = LINE
    bc.valueAxis.valueMin = 0
    bc.valueAxis.labels.fontSize = 6
    bc.valueAxis.strokeColor = LINE
    bc.valueAxis.gridStrokeColor = LINE
    bc.valueAxis.visibleGrid = True
    bc.groupSpacing = 2
    d.add(bc)
    return d


def _table(data, widths, style_extra=(), header=True, repeat=1):
    t = Table(data, colWidths=widths, repeatRows=repeat if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("LINEBELOW", (0, 0), (-1, 0), 0, NAVY)]
    t.setStyle(TableStyle(style + list(style_extra)))
    return t


def build_pdf(bundle, verification, custody):
    """Return the PDF as bytes. `verification` is evidence.verify_case() output."""
    case, df, alerts, summary = bundle["case"], bundle["df"], bundle["alerts"], bundle["summary"]
    st = _styles()
    buf = io.BytesIO()
    meta = config.PROJECT_META
    footer = f"{meta['title']} forensic report  |  Case #{case['id']}"

    class Canvas(_NumberedCanvas):
        footer_text = footer

    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm,
                            bottomMargin=20 * mm, title=f"CrimeRebuild report - {case['name']}",
                            author=meta["author"], subject="Digital forensic incident report")
    W = A4[0] - 36 * mm
    story = []

    # --- title block --------------------------------------------------------------------------
    story += [Paragraph("Digital Forensic Incident Report", st["title"]),
              Paragraph(f"Generated by {meta['title']} on {datetime.now():%d %b %Y %H:%M}  |  Created by: {meta['author']}", st["sub"]),
              Spacer(1, 8)]
    info = [[Paragraph("Case", st["cell_b"]), Paragraph(_s(f"#{case['id']}  {case['name']}"), st["body"]),
             Paragraph("Investigator", st["cell_b"]), Paragraph(_s(case["investigator"] or "not recorded"), st["body"])],
            [Paragraph("Opened", st["cell_b"]), Paragraph(_s(case["created_at"]), st["body"]),
             Paragraph("Evidence files", st["cell_b"]), Paragraph(str(len(bundle["evidence"])), st["body"])]]
    story.append(_table(info, [60, W / 2 - 60, 70, W / 2 - 70], header=False))
    story.append(Spacer(1, 10))

    # --- risk block ----------------------------------------------------------------------------
    lvl = case["risk_level"]
    sev = summary["severity_counts"]
    big = ParagraphStyle("big", parent=st["body"], fontSize=30, leading=34, textColor=colors.white,
                         fontName="Helvetica-Bold")
    risk_cell = Table([[Paragraph(f'{case["risk_score"]}<font size="9" name="Helvetica"> / 100</font>', big)],
                       [Paragraph(f'<font color="white"><b>{_s(lvl)} risk</b></font>', st["body"])]],
                      colWidths=[110])
    risk_cell.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), LEVEL_COLOR.get(lvl, MUTED)),
                                   ("LEFTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (0, 0), 8),
                                   ("BOTTOMPADDING", (0, -1), (-1, -1), 8)]))
    counts = " &nbsp;&nbsp; ".join(
        f'<font color="{SEV_COLOR[s].hexval().replace("0x", "#")}"><b>{sev[s]}</b></font> {s}'
        for s in reversed(C.SEVERITIES))
    right = [Paragraph(_s(summary["headline"]), st["cell_b"]), Spacer(1, 3),
             Paragraph(_s(summary["overview"]), st["body"]), Spacer(1, 3),
             Paragraph(f"Alerts by severity: {counts}", st["body"])]
    block = Table([[risk_cell, right]], colWidths=[120, W - 120])
    block.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    story.append(block)

    # --- executive summary --------------------------------------------------------------------
    story.append(Paragraph("1. What happened", st["h1"]))
    if summary["sequence_text"]:
        story.append(Paragraph(_s(summary["sequence_text"]), st["body"]))
        if summary["sequence_extra"]:
            story.append(Paragraph(f"(+{summary['sequence_extra']} further step(s) - see the complete timeline.)", st["muted"]))
    else:
        story.append(Paragraph("No suspicious sequence of events was reconstructed from the available evidence.", st["body"]))
    if summary["facts"]:
        story.append(Spacer(1, 6))
        story.append(_table([[Paragraph(_s(k), st["cell_b"]), Paragraph(_s(v), st["body"])] for k, v in summary["facts"]],
                            [90, W - 90], header=False))

    # --- findings ------------------------------------------------------------------------------
    story.append(Paragraph("2. Findings", st["h1"]))
    if not alerts:
        story.append(Paragraph("None of the five detection rules fired.", st["body"]))
    else:
        rows = [[Paragraph("Severity", st["white_b"]), Paragraph("Time", st["white_b"]),
                 Paragraph("Finding", st["white_b"])]]
        extra = []
        for i, a in enumerate(alerts, start=1):
            rows.append([Paragraph(f'<b>{a["severity"].upper()}</b><br/>{a["points"]} pts', st["small"]),
                         Paragraph(_s(a["first_ts"][:10]) + "<br/>" + _s(a["first_ts"][11:]), st["small"]),
                         Paragraph(f'<b>{_s(a["title"])}</b><br/>{_s(a["description"])}'
                                   f'<br/><font color="#6b6b73">{_s(a["mitre"])} - {len(a["event_ids"])} linked event(s)</font>',
                                   st["small"])])
            extra.append(("BACKGROUND", (0, i), (0, i), SEV_TINT[a["severity"]]))
            extra.append(("LINEBEFORE", (0, i), (0, i), 3, SEV_COLOR[a["severity"]]))
        story.append(_table(rows, [58, 62, W - 120], extra))

    # --- activity chart -----------------------------------------------------------------------
    chart = _chart(bundle["activity"])
    if chart:
        story.append(Paragraph("3. Activity over time", st["h1"]))
        story.append(Paragraph(f"Events per {bundle['activity']['bucket']} across all evidence sources.", st["muted"]))
        story.append(chart)

    if summary["recommendations"]:
        story.append(Paragraph("4. Suggested next steps", st["h1"]))
        for r in summary["recommendations"]:
            story.append(Paragraph("- " + _s(r), st["body"]))
            story.append(Spacer(1, 2))

    # --- key chains ---------------------------------------------------------------------------
    if bundle["chains"]:
        story.append(Paragraph("5. File life stories across sources", st["h1"]))
        story.append(Paragraph("Events about the same file name, merged from every evidence source.", st["muted"]))
        for ch in bundle["chains"][:3]:
            rows = [[Paragraph(f'<b>{_s(ch["name"])}</b>' + ("  (sensitive name)" if ch["sensitive"] else ""), st["white_b"]), "", ""]]
            for e in ch["events"]:
                rows.append([Paragraph(f"{e['ts']:%H:%M:%S}", st["small"]), Paragraph(_s(e["source"]), st["small"]),
                             Paragraph(_s(describe_event(e)), st["small"])])
            t = _table(rows, [52, 62, W - 114], [("SPAN", (0, 0), (-1, 0))])
            story.append(KeepTogether([t, Spacer(1, 6)]))

    # --- complete timeline --------------------------------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("6. Complete reconstructed timeline", st["h1"]))
    shown = df.head(MAX_TIMELINE_ROWS)
    note = (f"All {len(df):,} events from every source, sorted by timestamp. Rows tinted by alert severity are "
            f"linked to a finding.")
    if len(df) > len(shown):
        note += f" The first {len(shown)} are listed here; export the CSV from the dashboard for the rest."
    story.append(Paragraph(note, st["muted"]))
    story.append(Spacer(1, 4))
    rows = [[Paragraph(h, st["white_b"]) for h in ("#", "Time (UTC)", "Source", "Event", "Account", "Target / details")]]
    extra = []
    for i, (_, r) in enumerate(shown.iterrows(), start=1):
        detail = _s((r["target"] or "")[:90])
        if r["dest"] and r["action"] == "File Copied":
            detail += f" -> {_s(r['dest'])}"
        if r["details"]:
            detail += ("<br/>" if detail else "") + f'<font color="#6b6b73">{_s(r["details"][:110])}</font>'
        rows.append([Paragraph(str(r["seq"]), st["tiny"]), Paragraph(f"{r['ts']:%d %b<br/>%H:%M:%S}", st["tiny"]),
                     Paragraph(_s(r["source"]), st["tiny"]), Paragraph(f"<b>{_s(r['action'])}</b>", st["tiny"]),
                     Paragraph(_s(r["user"]), st["tiny"]), Paragraph(detail, st["tiny"])])
        flag = bundle["flags"].get(int(r["id"]))
        if flag:
            extra.append(("BACKGROUND", (0, i), (-1, i), SEV_TINT[flag["severity"]]))
            extra.append(("LINEBEFORE", (0, i), (0, i), 2.5, SEV_COLOR[flag["severity"]]))
    story.append(_table(rows, [22, 40, 44, 74, 58, W - 238], extra))

    # --- evidence and integrity ---------------------------------------------------------------
    story.append(Paragraph("7. Evidence and integrity", st["h1"]))
    status = {v["id"]: v["status"] for v in verification}
    rows = [[Paragraph(h, st["white_b"]) for h in ("File", "Type", "Events", "SHA-256 recorded at intake", "Integrity now")]]
    extra = []
    for i, ev in enumerate(bundle["evidence"], start=1):
        ok = status.get(ev["id"], "?")
        rows.append([Paragraph(_s(ev["filename"]), st["small"]), Paragraph(_s(C.SOURCES.get(ev["kind"], ev["kind"] or "unknown")), st["small"]),
                     Paragraph(str(ev["rows_parsed"]), st["small"]), Paragraph(_s(ev["sha256"]), st["mono"]),
                     Paragraph(f"<b>{_s(ok)}</b>", st["small"])])
        extra.append(("TEXTCOLOR", (4, i), (4, i), colors.HexColor("#16a34a") if ok == "OK" else SEV_COLOR["critical"]))
    story.append(_table(rows, [100, 62, 36, W - 100 - 62 - 36 - 58, 58], extra))
    story.append(Paragraph("Hashes were recomputed when this report was generated. All analysis ran on read-only copies "
                           "of the evidence; the originals were never modified.", st["muted"]))

    story.append(Paragraph("8. Chain of custody log", st["h1"]))
    rows = [[Paragraph(h, st["white_b"]) for h in ("Time", "Actor", "Action", "Detail")]]
    for c in custody:
        rows.append([Paragraph(_s(c["ts"]), st["tiny"]), Paragraph(_s(c["actor"]), st["tiny"]),
                     Paragraph(_s(c["action"]), st["tiny"]), Paragraph(_s(c["detail"]), st["tiny"])])
    story.append(_table(rows, [76, 62, 70, W - 208]))

    story.append(Paragraph("9. Method and limitations", st["h1"]))
    story.append(Paragraph(
        "Evidence from each source is parsed into one common event schema, merged and sorted by timestamp, then "
        "checked by five rule-based detectors (mass deletion, USB exfiltration, off-hours login, repeated failed logins, "
        "file tampering). The risk score is the sum of alert severity points (low 10, medium 20, high 35, critical 50), "
        "capped at 100. Rules and thresholds are transparent and can be tuned in the settings page. "
        "Timestamps without a time zone are assumed to be UTC. This report is an academic investigation aid; it is not "
        "intended as court-admissible evidence, and findings should be verified against the original sources.", st["body"]))

    doc.build(story, canvasmaker=Canvas)
    return buf.getvalue()
