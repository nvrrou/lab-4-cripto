#!/usr/bin/env python3
"""Exporta el Markdown del informe a DOCX editable y PDF (sin capturas simuladas)."""
from pathlib import Path
import re
import textwrap
from xml.sax.saxutils import escape

from docx import Document
from docx.shared import Cm, Pt, RGBColor
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'informe' / 'Informe_Laboratorio_4'


def blocks(markdown):
    lines = markdown.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        if line.startswith('```'):
            code = []
            index += 1
            while index < len(lines) and not lines[index].startswith('```'):
                code.append(lines[index])
                index += 1
            yield 'code', '\n'.join(code)
        elif line.startswith('|'):
            rows = []
            while index < len(lines) and lines[index].startswith('|'):
                cells = [c.strip() for c in lines[index].strip('|').split('|')]
                if not all(re.fullmatch(r':?-+:?', c) for c in cells):
                    rows.append(cells)
                index += 1
            yield 'table', rows
            continue
        elif line.startswith('#'):
            depth = len(line) - len(line.lstrip('#'))
            yield 'heading', (depth, line[depth:].strip())
        else:
            yield 'paragraph', line
        index += 1


def export():
    doc = Document()
    section = doc.sections[0]
    section.top_margin = section.bottom_margin = Cm(2)
    section.left_margin = section.right_margin = Cm(2)
    doc.styles['Normal'].font.name = 'Arial'
    doc.styles['Normal'].font.size = Pt(10)
    fonts = Path('/System/Library/Fonts/Supplemental')
    regular, bold, mono = 'Helvetica', 'Helvetica-Bold', 'Courier'
    if (fonts / 'Arial.ttf').exists():
        for alias, filename in [('LabArial', 'Arial.ttf'), ('LabArialBold', 'Arial Bold.ttf'), ('LabMono', 'Courier New.ttf')]:
            pdfmetrics.registerFont(TTFont(alias, str(fonts / filename)))
        regular, bold, mono = 'LabArial', 'LabArialBold', 'LabMono'
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='BodyLab', fontName=regular, fontSize=9, leading=13,
                              spaceAfter=8, splitLongWords=True, alignment=TA_LEFT))
    styles.add(ParagraphStyle(name='CellLab', fontName=regular, fontSize=8, leading=10))
    styles.add(ParagraphStyle(name='CodeLab', fontName=mono, fontSize=8, leading=10,
                              backColor=colors.HexColor('#f3f5f7'), spaceAfter=10))
    for name in ['Title', 'Heading1', 'Heading2', 'Heading3']:
        styles[name].fontName = bold
        styles[name].textColor = colors.HexColor('#16324f')
        styles[name].keepWithNext = True
    story = []
    for kind, value in blocks(BASE.with_suffix('.md').read_text()):
        if kind == 'heading':
            depth, title = value
            doc.add_heading(title, level=min(depth - 1, 3))
            style = styles['Title' if depth == 1 else f'Heading{min(depth-1, 3)}']
            story.append(Paragraph(escape(title), style))
        elif kind == 'paragraph':
            paragraph = doc.add_paragraph(value)
            if value.startswith('[EVIDENCIA'):
                for run in paragraph.runs:
                    run.font.color.rgb = RGBColor.from_string('9C4100')
            story.append(Paragraph(escape(value), styles['BodyLab']))
        elif kind == 'code':
            # El contenido sigue exacto en el Markdown/TXT; solo se envuelve visualmente.
            wrapped = '\n'.join(textwrap.fill(line, width=100, replace_whitespace=False,
                                  drop_whitespace=False) if line else '' for line in value.splitlines())
            p = doc.add_paragraph()
            run = p.add_run(wrapped)
            run.font.name = 'Courier New'
            run.font.size = Pt(8)
            story.append(Preformatted(wrapped, styles['CodeLab']))
        else:
            table = doc.add_table(rows=1, cols=len(value[0]))
            table.style = 'Light Shading Accent 1'
            for cell, text in zip(table.rows[0].cells, value[0]):
                cell.text = text
            for row in value[1:]:
                for cell, text in zip(table.add_row().cells, row):
                    cell.text = text
            for row in table.rows:
                for cell in row.cells:
                    for paragraph in cell.paragraphs:
                        for run in paragraph.runs:
                            run.font.size = Pt(8)
            rows = [[Paragraph(escape(cell), styles['CellLab']) for cell in row] for row in value]
            count = len(value[0])
            widths = ([42, 85, 125, 125, 50] if count == 5 else
                      [110, 372] if count == 2 else [110, 125, 247])
            pdf_table = Table(rows, colWidths=widths, repeatRows=1, hAlign='LEFT')
            pdf_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dce7f1')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f6f8fa')]),
                ('GRID', (0, 0), (-1, -1), .3, colors.HexColor('#bec9d4')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            story += [pdf_table, Spacer(1, 10)]
    doc.save(BASE.with_suffix('.docx'))

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFillColor(colors.white)
        canvas.rect(0, 0, A4[0], A4[1], stroke=0, fill=1)
        canvas.setFont(regular, 8)
        canvas.setFillColor(colors.HexColor('#667788'))
        canvas.drawString(56, 26, 'Laboratorio 4 — desarrollo técnico / capturas visuales pendientes')
        canvas.drawRightString(A4[0] - 56, 26, str(document.page))
        canvas.restoreState()

    pdf = SimpleDocTemplate(str(BASE.with_suffix('.pdf')), pagesize=A4,
                            rightMargin=56, leftMargin=56, topMargin=48, bottomMargin=48,
                            title='Informe Laboratorio 4 — Criptografía')
    pdf.build(story, onFirstPage=footer, onLaterPages=footer)
    print(BASE.with_suffix('.docx'))
    print(BASE.with_suffix('.pdf'))


if __name__ == '__main__':
    export()
