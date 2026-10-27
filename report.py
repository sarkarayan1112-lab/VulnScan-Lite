from datetime import datetime
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

SECTION_NAMES = {
    "headers": "Security Headers",
    "ssl": "SSL / TLS",
    "cms": "CMS & Server Information",
}


def build_pdf(result):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, title="VulnScan Lite Report")
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("VulnScan Lite - Security Report", styles["Title"]))
    story.append(Paragraph("Target: " + escape(result["target"]), styles["Normal"]))
    story.append(Paragraph("Generated: " + datetime.now().strftime("%d %b %Y, %H:%M"), styles["Normal"]))
    story.append(Spacer(1, 14))
    story.append(Paragraph(
        "Grade: " + result["grade"] + " | Score: " + str(result["score"]) + "/100 | "
        + str(result["passed_checks"]) + " of " + str(result["total_checks"]) + " checks passed",
        styles["Heading2"],
    ))
    story.append(Spacer(1, 10))

    for key, data in result["details"].items():
        story.append(Paragraph(SECTION_NAMES.get(key, key), styles["Heading3"]))
        rows = [["Check", "Result"]]
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
        for i, item in enumerate(data["results"], start=1):
            text = escape(item["check"])
            if not item["passed"] and item["fix"]:
                text += "<br/><font color='#b45309'>How to fix: " + escape(item["fix"]) + "</font>"
            rows.append([
                Paragraph(text, styles["BodyText"]),
                "PASSED" if item["passed"] else "FAILED",
            ])
            color = colors.HexColor("#15803d") if item["passed"] else colors.HexColor("#b91c1c")
            style_cmds.append(("TEXTCOLOR", (1, i), (1, i), color))

        table = Table(rows, colWidths=[390, 70])
        table.setStyle(TableStyle(style_cmds))
        story.append(table)
        story.append(Spacer(1, 12))

    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Disclaimer: This report is based on passive analysis only. Only scan websites you own.",
        styles["Italic"],
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer