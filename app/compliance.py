"""
compliance.py — generowanie raportu PDF "dowodu monitorowania" dla klienta.

To jest sedno propozycji wartości dla segmentu MŚP objętego NIS2/KSC:
klient nie kupuje "AI do wykrywania anomalii", kupuje comiesięczny
dokument, który może pokazać audytorowi jako dowód, że spełnia
obowiązek ciągłego monitorowania z art. 8 ustawy o KSC.

Raport jest wygenerowany automatycznie i NIE zastępuje oceny osoby
odpowiedzialnej za cyberbezpieczeństwo — to jest jawnie zaznaczone
w dokumencie (kwestia odpowiedzialności prawnej).
"""

import io
import datetime
from collections import Counter

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def _styles():
    base = getSampleStyleSheet()
    base.add(ParagraphStyle(
        name="ReportTitle", parent=base["Title"], fontSize=18, spaceAfter=4
    ))
    base.add(ParagraphStyle(
        name="Small", parent=base["Normal"], fontSize=8, textColor=colors.grey
    ))
    return base


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#f43f5e"),
    "HIGH": colors.HexColor("#fb7a3c"),
    "MEDIUM": colors.HexColor("#d97706"),
    "LOW": colors.HexColor("#059669"),
}


def build_compliance_pdf(tenant, alerts, period_start, period_end, generated_by="system"):
    """
    tenant: dict z tabeli tenants (id, name, sector)
    alerts: lista dictów (jak z db.fetch_alerts_between)
    period_start/period_end: stringi 'YYYY-MM-DD'
    Zwraca: bytes gotowego PDF-a.
    """
    styles = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=20 * mm, bottomMargin=18 * mm,
        leftMargin=18 * mm, rightMargin=18 * mm,
    )

    story = []

    story.append(Paragraph("Raport monitorowania bezpieczeństwa", styles["ReportTitle"]))
    story.append(Paragraph(
        "Dowód realizacji obowiązku ciągłego monitorowania systemów "
        "(art. 8 ustawy o krajowym systemie cyberbezpieczeństwa, "
        "implementacja dyrektywy NIS2).",
        styles["Normal"],
    ))
    story.append(Spacer(1, 10 * mm))

    meta_rows = [
        ["Podmiot", tenant.get("name", "—")],
        ["Sektor", tenant.get("sector") or "—"],
        ["Okres raportu", f"{period_start} — {period_end}"],
        ["Data wygenerowania", datetime.datetime.now().strftime("%Y-%m-%d %H:%M")],
        ["Wygenerowano przez", generated_by],
    ]
    meta_table = Table(meta_rows, colWidths=[45 * mm, 120 * mm])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.grey),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e5e5")),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8 * mm))

    counts = Counter(a["severity"].upper() for a in alerts)
    total = len(alerts)

    story.append(Paragraph("Podsumowanie okresu", styles["Heading2"]))
    summary_rows = [["Poziom ryzyka", "Liczba alertów"]]
    for sev in SEVERITY_ORDER:
        summary_rows.append([sev, str(counts.get(sev, 0))])
    summary_rows.append(["RAZEM", str(total)])

    summary_table = Table(summary_rows, colWidths=[60 * mm, 40 * mm])
    style_cmds = [
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111a30")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
    ]
    for i, sev in enumerate(SEVERITY_ORDER, start=1):
        style_cmds.append(("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLORS[sev]))
    summary_table.setStyle(TableStyle(style_cmds))
    story.append(summary_table)
    story.append(Spacer(1, 8 * mm))

    story.append(Paragraph(
        "Alerty poziomu CRITICAL i HIGH w okresie", styles["Heading2"]
    ))
    priority = [a for a in alerts if a["severity"].upper() in ("CRITICAL", "HIGH")]
    priority.sort(key=lambda a: a["timestamp"])

    if not priority:
        story.append(Paragraph(
            "Brak alertów wysokiego priorytetu w tym okresie.", styles["Normal"]
        ))
    else:
        rows = [["Czas", "Konto", "Akcja", "Scenariusz", "Poziom"]]
        for a in priority[:200]:
            rows.append([
                a["timestamp"], a["actor"], a["action"],
                (a.get("attack_type") or "—")[:60], a["severity"].upper(),
            ])
        t = Table(rows, colWidths=[28 * mm, 25 * mm, 28 * mm, 65 * mm, 20 * mm], repeatRows=1)
        t.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111a30")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)

    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph(
        "Niniejszy dokument został wygenerowany automatycznie na podstawie "
        "logów systemowych i reguł detekcji. Nie stanowi samodzielnie "
        "pełnej oceny ryzyka wymaganej przepisami — powinien zostać "
        "zweryfikowany przez osobę odpowiedzialną za cyberbezpieczeństwo "
        "w organizacji przed przedłożeniem audytorowi lub CSIRT.",
        styles["Small"],
    ))

    doc.build(story)
    return buf.getvalue()
