"""Generate professional PDF vulnerability assessment reports."""

from collections import Counter
import os
import textwrap

from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

import config
from .html_generator import OWASP_TOP_10, report_filename


PALETTE = {
    "CRITICAL": HexColor("#D92D20"),
    "HIGH": HexColor("#E35D12"),
    "MEDIUM": HexColor("#B7791F"),
    "LOW": HexColor("#0077B6"),
    "INFO": HexColor("#6956C7"),
}
DARK = HexColor("#1E293B")
CARD = colors.white
BORDER = HexColor("#D8E1EC")
BODY = HexColor("#1E293B")
MUTED = HexColor("#64748B")
CYAN = HexColor("#0F766E")


def _safe(value):
    return (
        str(value or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br/>")
    )


def _footer(canvas, document):
    canvas.saveState()
    canvas.setStrokeColor(BORDER)
    canvas.line(20 * mm, 14 * mm, 190 * mm, 14 * mm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawString(20 * mm, 9 * mm, f"Bug Hunter Pro {config.APP_VERSION} | Confidential")
    canvas.drawRightString(190 * mm, 9 * mm, f"Page {document.page}")
    canvas.restoreState()


def _risk_gauge(canvas, x, y, score):
    canvas.saveState()
    canvas.setFillColor(BORDER)
    canvas.circle(x, y, 28 * mm, fill=1, stroke=0)
    canvas.setFillColor(CYAN if score < 7 else PALETTE["CRITICAL"])
    canvas.wedge(
        x - 28 * mm,
        y - 28 * mm,
        x + 28 * mm,
        y + 28 * mm,
        90,
        -360 * min(float(score), 10) / 10,
        fill=1,
        stroke=0,
    )
    canvas.setFillColor(colors.white)
    canvas.circle(x, y, 21 * mm, fill=1, stroke=0)
    canvas.setFillColor(BODY)
    canvas.setFont("Helvetica-Bold", 25)
    canvas.drawCentredString(x, y + 2 * mm, f"{float(score):.1f}")
    canvas.setFont("Helvetica", 8)
    canvas.drawCentredString(x, y - 6 * mm, "RISK / 10")
    canvas.restoreState()


def generate_pdf_report(scan, findings, output_path=None, configuration=None):
    configuration = configuration or {}
    if not output_path:
        os.makedirs(config.REPORT_OUTPUT_DIR, exist_ok=True)
        output_path = os.path.join(config.REPORT_OUTPUT_DIR, report_filename(scan, "pdf"))
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    document = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        title=f"Bug Hunter Pro Report - {scan.get('target', '')}",
        author="Bug Hunter Pro",
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            "CyberTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=31,
            leading=35,
            textColor=CYAN,
            alignment=TA_CENTER,
            spaceAfter=10,
        )
    )
    styles.add(
        ParagraphStyle(
            "Section",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=18,
            textColor=DARK,
            spaceBefore=10,
            spaceAfter=10,
        )
    )
    styles.add(
        ParagraphStyle(
            "FindingTitle",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            textColor=BODY,
            leading=16,
        )
    )
    styles.add(
        ParagraphStyle(
            "Evidence",
            parent=styles["Code"],
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=BODY,
            backColor=HexColor("#F1F4F8"),
            borderColor=HexColor("#D5DFEA"),
            borderWidth=0.5,
            borderPadding=7,
            spaceBefore=4,
            spaceAfter=8,
        )
    )
    story = [
        Spacer(1, 38 * mm),
        Paragraph("BUG HUNTER PRO", styles["CyberTitle"]),
        Paragraph(
            "Vulnerability Assessment Report",
            ParagraphStyle(
                "Subtitle",
                parent=styles["Heading2"],
                alignment=TA_CENTER,
                textColor=DARK,
                fontSize=17,
            ),
        ),
        Spacer(1, 15 * mm),
        Table(
            [
                ["Target", scan.get("target", "")],
                ["Scan date", scan.get("started_at", "")],
                ["Scan type", scan.get("scan_type", "all")],
                ["Scan ID", scan.get("id", "")],
            ],
            colWidths=[35 * mm, 115 * mm],
            style=TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), DARK),
                    ("TEXTCOLOR", (0, 0), (0, -1), CYAN),
                    ("TEXTCOLOR", (1, 0), (1, -1), BODY),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 8),
                ]
            ),
        ),
        Spacer(1, 72 * mm),
        Paragraph(
            "<b>CONFIDENTIALITY NOTICE</b><br/>This report is intended only for the "
            "organization that authorized the assessment. Test only systems you own or "
            "have explicit permission to assess.",
            ParagraphStyle(
                "Notice",
                parent=styles["BodyText"],
                textColor=PALETTE["HIGH"],
                borderColor=PALETTE["HIGH"],
                borderWidth=1,
                borderPadding=8,
                alignment=TA_CENTER,
            ),
        ),
        PageBreak(),
        Paragraph("Executive Summary", styles["Section"]),
    ]
    counts = Counter(item.get("severity", "INFO") for item in findings)
    severity_table = [["Severity", "Count"]]
    for severity in PALETTE:
        severity_table.append([severity, counts[severity]])
    table = Table(severity_table, colWidths=[70 * mm, 35 * mm])
    table_style = [
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), CYAN),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("ALIGN", (1, 1), (1, -1), "CENTER"),
        ("PADDING", (0, 0), (-1, -1), 7),
    ]
    for index, severity in enumerate(PALETTE, start=1):
        table_style.extend(
            [
                ("TEXTCOLOR", (0, index), (0, index), PALETTE[severity]),
                ("FONTNAME", (0, index), (0, index), "Helvetica-Bold"),
            ]
        )
    table.setStyle(TableStyle(table_style))
    story.extend(
        [
            table,
            Spacer(1, 10 * mm),
            Paragraph(
                f"<b>Overall risk score: {float(scan.get('risk_score', 0)):.1f}/10</b>",
                styles["Heading2"],
            ),
            Paragraph(
                "The risk score weights critical, high, medium, and low findings against "
                "the number of completed checks. Individual critical findings should be "
                "reviewed immediately regardless of the aggregate score.",
                styles["BodyText"],
            ),
            Spacer(1, 6 * mm),
            Paragraph("Top three findings", styles["Heading2"]),
        ]
    )
    if findings:
        for item in findings[:3]:
            story.append(
                Paragraph(
                    f"<font color='{PALETTE.get(item.get('severity','INFO')).hexval()}'>"
                    f"<b>{_safe(item.get('severity'))}</b></font> - {_safe(item.get('title'))}",
                    styles["BodyText"],
                )
            )
    else:
        story.append(Paragraph("No findings were recorded.", styles["BodyText"]))
    story.extend(
        [
            Spacer(1, 6 * mm),
            Paragraph(
                f"<b>Scope:</b> {_safe(scan.get('target'))}<br/>"
                f"<b>Duration:</b> {_safe(scan.get('started_at'))} to {_safe(scan.get('completed_at'))}",
                styles["BodyText"],
            ),
            PageBreak(),
            Paragraph("Detailed Findings", styles["Section"]),
        ]
    )
    for finding in findings:
        severity = finding.get("severity", "INFO")
        badge = Table(
            [[severity, f"CVSS {float(finding.get('cvss_score', 0)):.1f}"]],
            colWidths=[30 * mm, 28 * mm],
            style=TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), PALETTE.get(severity, PALETTE["INFO"])),
                    ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]
            ),
        )
        evidence = "\n".join(
            textwrap.wrap(str(finding.get("evidence", "")), width=105, replace_whitespace=False)
        )
        block = [
            badge,
            Spacer(1, 3 * mm),
            Paragraph(_safe(finding.get("title")), styles["FindingTitle"]),
            Paragraph(f"<b>Description</b><br/>{_safe(finding.get('description'))}", styles["BodyText"]),
            Spacer(1, 2 * mm),
            Paragraph("<b>Evidence</b>", styles["BodyText"]),
            Paragraph(_safe(evidence), styles["Evidence"]),
            Paragraph(f"<b>Remediation</b><br/>{_safe(finding.get('remediation'))}", styles["BodyText"]),
            Spacer(1, 2 * mm),
            Paragraph(
                f"<b>OWASP:</b> {_safe(finding.get('owasp') or 'Unmapped')}<br/>"
                f"<b>MITRE ATT&amp;CK:</b> {_safe(finding.get('mitre') or 'Not mapped')}<br/>"
                f"<b>Location:</b> {_safe(finding.get('url'))}",
                styles["BodyText"],
            ),
            Spacer(1, 8 * mm),
        ]
        story.append(KeepTogether(block))
    story.extend([PageBreak(), Paragraph("OWASP Top 10 Mapping", styles["Section"])])
    mapping = [["OWASP category", "Findings", "Status"]]
    for category in OWASP_TOP_10:
        count = sum(1 for item in findings if category in item.get("owasp", ""))
        mapping.append([category, count, "Findings present" if count else "No findings"])
    mapping_table = Table(mapping, colWidths=[105 * mm, 23 * mm, 42 * mm], repeatRows=1)
    mapping_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), CYAN),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.extend(
        [
            mapping_table,
            PageBreak(),
            Paragraph("Appendix", styles["Section"]),
            Paragraph("URLs and endpoints recorded", styles["Heading2"]),
        ]
    )
    urls = sorted({item.get("url", "") for item in findings if item.get("url")})
    for url in urls:
        story.append(Paragraph(_safe(url), styles["Code"]))
    story.extend(
        [
            Spacer(1, 5 * mm),
            Paragraph("Scan configuration", styles["Heading2"]),
            Paragraph(_safe(configuration), styles["Evidence"]),
            Paragraph(
                f"Bug Hunter Pro version {config.APP_VERSION}. Automated findings require "
                "human validation and may include false positives.",
                styles["BodyText"],
            ),
        ]
    )

    def first_page(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(colors.white)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        _risk_gauge(canvas, A4[0] / 2, 92 * mm, float(scan.get("risk_score", 0)))
        canvas.restoreState()

    document.build(story, onFirstPage=first_page, onLaterPages=_footer)
    return output_path
