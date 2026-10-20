"""Professional PDF renderer for audit reports.

The report generator exposes a small block-based API. This module turns those
blocks into a readable A4 document with Unicode-safe typography, styled tables,
consistent spacing and page numbering.
"""
from __future__ import annotations

from html import escape
from io import BytesIO
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    LongTable,
    PageTemplate,
    Paragraph,
    Spacer,
    TableStyle,
)


PAGE_W, PAGE_H = A4
NAVY = colors.HexColor("#12304A")
BLUE = colors.HexColor("#1769AA")
PALE_BLUE = colors.HexColor("#F5F9FD")
TEXT = colors.HexColor("#263746")
MUTED = colors.HexColor("#687887")
LINE = colors.HexColor("#D8E1E8")


def _register_fonts() -> tuple[str, str]:
    """Use a Unicode Windows font when available; keep a safe PDF fallback."""
    candidates = (
        ("AuditSans", "AuditSans-Bold", Path(r"C:\Windows\Fonts\segoeui.ttf"), Path(r"C:\Windows\Fonts\segoeuib.ttf")),
        ("AuditSans", "AuditSans-Bold", Path(r"C:\Windows\Fonts\arial.ttf"), Path(r"C:\Windows\Fonts\arialbd.ttf")),
    )
    for regular, bold, regular_path, bold_path in candidates:
        if regular_path.exists() and bold_path.exists():
            try:
                pdfmetrics.registerFont(TTFont(regular, str(regular_path)))
                pdfmetrics.registerFont(TTFont(bold, str(bold_path)))
                return regular, bold
            except Exception:
                pass
    return "Helvetica", "Helvetica-Bold"


def _clean(value: object) -> str:
    """Normalize line-breaking punctuation without damaging French accents."""
    return (str(value or "")
            .replace("\u00a0", " ")
            .replace("\u2011", "-")
            .replace("\u2013", "-")
            .replace("\u2014", "-")
            .replace("\u2192", "->")
            .replace("\u2022", "-"))


def _paragraph(text: object, style: ParagraphStyle) -> Paragraph:
    value = escape(_clean(text)).replace("\n", "<br/>")
    return Paragraph(value or "&nbsp;", style)


def _offsets(style: str) -> list[float]:
    try:
        return [float(part) for part in style.split(":", 1)[1].split(",") if part.strip()]
    except (IndexError, ValueError):
        return [0.0]


def _row_cells(text: str, count: int) -> list[str]:
    cells = text.split("|")
    cells += [""] * max(0, count - len(cells))
    return cells[:count]


def _table(blocks: list[tuple[str, str]], start: int, content_width: float, styles: dict[str, ParagraphStyle]):
    header_style, header_text = blocks[start]
    offsets = _offsets(header_style)
    column_count = len(offsets)
    widths = [offsets[i + 1] - offsets[i] for i in range(column_count - 1)]
    widths.append(max(60, content_width - (offsets[-1] if offsets else 0)))
    # The legacy block definitions use page-coordinate offsets.  Some of them
    # were authored for a wider page than A4, so normalize them before handing
    # them to ReportLab.  This keeps every table inside the printable frame.
    total_width = sum(widths)
    if total_width > content_width and total_width:
        scale = content_width / total_width
        widths = [width * scale for width in widths]
    rows = [[_paragraph(cell, styles["table_header"]) for cell in _row_cells(header_text, column_count)]]
    index = start + 1
    while index < len(blocks) and blocks[index][0].startswith("t:"):
        rows.append([_paragraph(cell, styles["table_cell"]) for cell in _row_cells(blocks[index][1], column_count)])
        index += 1

    table = LongTable(rows, colWidths=widths, repeatRows=1, hAlign="LEFT", splitByRow=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.35, LINE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE_BLUE]),
    ]))
    return table, index


def _page_chrome(canvas, document, title: str, regular: str, bold: str) -> None:
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, PAGE_H - 15 * mm, PAGE_W, 15 * mm, stroke=0, fill=1)
    canvas.setFillColor(colors.white)
    canvas.setFont(bold, 8.5)
    canvas.drawString(18 * mm, PAGE_H - 9.5 * mm, "SECURITY AUDITOR")
    canvas.setFont(regular, 8)
    canvas.drawRightString(PAGE_W - 18 * mm, PAGE_H - 9.5 * mm, title[:72])
    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(0.5)
    canvas.line(18 * mm, 14 * mm, PAGE_W - 18 * mm, 14 * mm)
    canvas.setFillColor(MUTED)
    canvas.setFont(regular, 7.5)
    canvas.drawString(18 * mm, 8.5 * mm, "Document confidentiel - Rapport de sécurité")
    canvas.drawRightString(PAGE_W - 18 * mm, 8.5 * mm, f"Page {document.page}")
    canvas.restoreState()


def render_pdf(blocks: list[tuple[str, str]], title: str) -> bytes:
    """Render report blocks into a styled, Unicode-safe A4 PDF."""
    regular, bold = _register_fonts()
    buffer = BytesIO()
    margin_x = 18 * mm
    doc = BaseDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=margin_x,
        rightMargin=margin_x,
        topMargin=25 * mm,
        bottomMargin=21 * mm,
        title=title,
        author="Security Auditor",
        subject="Rapport d'audit de sécurité",
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="audit")
    doc.addPageTemplates([PageTemplate(id="audit", frames=[frame], onPage=lambda c, d: _page_chrome(c, d, title, regular, bold))])

    sample = getSampleStyleSheet()
    styles = {
        "h1": ParagraphStyle("AuditH1", parent=sample["Title"], fontName=bold, fontSize=23, leading=28, textColor=NAVY, spaceAfter=5, alignment=TA_LEFT),
        "h2": ParagraphStyle("AuditH2", parent=sample["Heading2"], fontName=bold, fontSize=15, leading=19, textColor=NAVY, spaceBefore=15, spaceAfter=7, keepWithNext=True),
        "h3": ParagraphStyle("AuditH3", parent=sample["Heading3"], fontName=bold, fontSize=11.5, leading=15, textColor=BLUE, spaceBefore=10, spaceAfter=4, keepWithNext=True),
        "body": ParagraphStyle("AuditBody", parent=sample["BodyText"], fontName=regular, fontSize=9.5, leading=13.5, textColor=TEXT, spaceAfter=5),
        "kv": ParagraphStyle("AuditKV", parent=sample["BodyText"], fontName=regular, fontSize=9, leading=12, textColor=MUTED, leftIndent=7, spaceAfter=3),
        "bullet": ParagraphStyle("AuditBullet", parent=sample["BodyText"], fontName=regular, fontSize=9.2, leading=13, textColor=TEXT, leftIndent=14, firstLineIndent=-8, spaceAfter=3),
        "table_header": ParagraphStyle("AuditTableHeader", parent=sample["BodyText"], fontName=bold, fontSize=8, leading=10, textColor=colors.white, spaceAfter=0),
        "table_cell": ParagraphStyle("AuditTableCell", parent=sample["BodyText"], fontName=regular, fontSize=8.2, leading=10.5, textColor=TEXT, spaceAfter=0),
    }

    story = []
    index = 0
    while index < len(blocks):
        style, text = blocks[index]
        if style.startswith("th:"):
            table, index = _table(blocks, index, doc.width, styles)
            story.extend([Spacer(1, 4), table, Spacer(1, 7)])
            continue
        if style == "hr":
            story.extend([Spacer(1, 3), HRFlowable(width="100%", thickness=0.8, color=LINE, spaceBefore=2, spaceAfter=8)])
        elif style == "h1":
            story.extend([_paragraph(text, styles["h1"]), HRFlowable(width="100%", thickness=2, color=BLUE, spaceBefore=1, spaceAfter=10)])
        elif style == "h2":
            story.extend([_paragraph(text, styles["h2"]), HRFlowable(width="100%", thickness=0.8, color=LINE, spaceBefore=0, spaceAfter=6)])
        elif style == "h3":
            story.append(_paragraph(text, styles["h3"]))
        elif style == "bullet":
            story.append(_paragraph(f"- {_clean(text)}", styles["bullet"]))
        elif style == "kv":
            story.append(_paragraph(text, styles["kv"]))
        else:
            story.append(_paragraph(text, styles["body"]))
        index += 1

    doc.build(story)
    return buffer.getvalue()
