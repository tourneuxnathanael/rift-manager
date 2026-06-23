"""Génération du rapport PDF d'un scan, dans l'esprit "relevé d'inspection structurelle".
Utilise uniquement les polices PDF standard (Helvetica/Courier) pour ne dépendre
d'aucune ressource externe."""

from io import BytesIO
from datetime import datetime, timezone

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.graphics.shapes import Drawing, Rect, Line, Polygon, String
from reportlab.pdfgen.canvas import Canvas

# ---------- Palette (déclinaison print de l'identité web) ----------

INK = colors.HexColor("#0a0d12")
PAPER = colors.HexColor("#ece6d6")
PAPER_INK = colors.HexColor("#14181f")
HAZARD = colors.HexColor("#b35e00")     # variante foncée pour lisibilité sur papier
SIGNAL = colors.HexColor("#1e7d6f")
FAULT = colors.HexColor("#c1372d")
MUTED = colors.HexColor("#5b6472")
HAIRLINE = colors.HexColor("#d8d2c0")

SEVERITY_COLOR = {"critical": FAULT, "high": HAZARD, "medium": colors.HexColor("#9a7b1f"), "low": MUTED}
SEVERITY_LABEL_FR = {"critical": "CRITIQUE", "high": "ÉLEVÉE", "medium": "MOYENNE", "low": "FAIBLE"}

CHECK_LABELS = [
    ("https_redirect", "Redirection HTTPS"),
    ("ssl_certificate", "Certificat SSL"),
    ("exposed_files", "Fichiers sensibles"),
    ("security_headers", "Headers de sécurité"),
    ("spf_dmarc", "SPF / DMARC"),
    ("cookies", "Cookies"),
    ("cors", "Configuration CORS"),
    ("tls_version", "Versions TLS"),
    ("server_info_disclosure", "Fuite d'info serveur"),
    ("dangerous_http_methods", "Méthodes HTTP dangereuses"),
]


def _zone_color(score: int):
    if score >= 75:
        return SIGNAL
    if score >= 40:
        return HAZARD
    return FAULT


def _hex(c) -> str:
    """Convertit une couleur reportlab en chaîne '#rrggbb' utilisable dans le markup <font color=...>."""
    return "#" + c.hexval()[2:]


def _score_gauge_drawing(score: int, grade: str) -> Drawing:
    """Cadran simplifié pour le PDF : barre à 3 zones (proportionnelles aux seuils
    réels 40/75) + marqueur de score."""
    width, height = 460, 46
    d = Drawing(width, height)

    fault_w = width * 0.40
    hazard_w = width * 0.35
    signal_w = width * 0.25

    d.add(Rect(0, 14, fault_w, 16, fillColor=FAULT, strokeColor=None))
    d.add(Rect(fault_w, 14, hazard_w, 16, fillColor=HAZARD, strokeColor=None))
    d.add(Rect(fault_w + hazard_w, 14, signal_w, 16, fillColor=SIGNAL, strokeColor=None))

    marker_x = max(2, min(width - 2, (score / 100) * width))
    d.add(Polygon(
        points=[marker_x - 7, 36, marker_x + 7, 36, marker_x, 14],
        fillColor=PAPER_INK, strokeColor=None,
    ))
    d.add(Line(marker_x, 14, marker_x, 30, strokeColor=PAPER_INK, strokeWidth=1.5))

    d.add(String(0, 0, "0", fontName="Courier", fontSize=8, fillColor=MUTED))
    d.add(String(width - 18, 0, "100", fontName="Courier", fontSize=8, fillColor=MUTED))

    return d


def _styles():
    base = getSampleStyleSheet()
    return {
        "eyebrow": ParagraphStyle(
            "eyebrow", parent=base["Normal"], fontName="Courier-Bold", fontSize=8.5,
            textColor=HAZARD, leading=11, spaceAfter=4, tracking=1,
        ),
        "title": ParagraphStyle(
            "title", parent=base["Normal"], fontName="Courier-Bold", fontSize=20,
            textColor=INK, leading=24, spaceAfter=2,
        ),
        "meta": ParagraphStyle(
            "meta", parent=base["Normal"], fontName="Courier", fontSize=9,
            textColor=MUTED, leading=13,
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Normal"], fontName="Courier-Bold", fontSize=12.5,
            textColor=INK, leading=16, spaceBefore=18, spaceAfter=8,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"], fontName="Helvetica", fontSize=9.3,
            textColor=colors.HexColor("#2a2f38"), leading=13.5,
        ),
        "label": ParagraphStyle(
            "label", parent=base["Normal"], fontName="Courier-Bold", fontSize=8,
            textColor=MUTED, leading=11,
        ),
        "evidence": ParagraphStyle(
            "evidence", parent=base["Normal"], fontName="Courier", fontSize=8.2,
            textColor=colors.HexColor("#7a4a17"), leading=12,
            backColor=colors.HexColor("#f7f2e8"), borderColor=HAIRLINE,
            borderWidth=0.5, borderPadding=6,
        ),
        "score_number": ParagraphStyle(
            "score_number", parent=base["Normal"], fontName="Courier-Bold", fontSize=34,
            textColor=INK, leading=36,
        ),
        "score_sub": ParagraphStyle(
            "score_sub", parent=base["Normal"], fontName="Courier", fontSize=10,
            textColor=MUTED, leading=13,
        ),
        "vuln_title": ParagraphStyle(
            "vuln_title", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=10,
            textColor=INK, leading=13,
        ),
        "footer": ParagraphStyle(
            "footer", parent=base["Normal"], fontName="Courier", fontSize=7.5,
            textColor=MUTED, leading=10,
        ),
    }


def _footer_canvas(canvas: Canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(HAIRLINE)
    canvas.setLineWidth(0.5)
    canvas.line(20 * mm, 16 * mm, doc.pagesize[0] - 20 * mm, 16 * mm)
    canvas.setFont("Courier", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(20 * mm, 12 * mm, "RIFT MANAGER // RELEVÉ D'INTÉGRITÉ — rift-manager.pro")
    canvas.drawRightString(doc.pagesize[0] - 20 * mm, 12 * mm, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()


def build_scan_pdf(result: dict) -> bytes:
    """Construit le rapport PDF complet à partir d'un dict de résultat de scan
    (même structure que la réponse de l'API /scan ou /scans/history/{id})."""
    styles = _styles()
    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=20 * mm, bottomMargin=24 * mm, leftMargin=20 * mm, rightMargin=20 * mm,
        title=f"Rapport Rift Manager — {result.get('target', '')}",
    )

    story = []

    # ---------- En-tête ----------
    story.append(Paragraph("RIFT_MANAGER // RELEVÉ D'INTÉGRITÉ STRUCTURELLE", styles["eyebrow"]))
    story.append(Paragraph(result.get("target", "—"), styles["title"]))

    scanned_at = result.get("scanned_at", "")
    try:
        scan_dt = datetime.fromisoformat(scanned_at.replace("Z", "+00:00"))
        scan_date_label = scan_dt.strftime("%d/%m/%Y à %H:%M UTC")
    except Exception:
        scan_date_label = scanned_at

    generated_label = datetime.now(timezone.utc).strftime("%d/%m/%Y à %H:%M UTC")
    story.append(Paragraph(f"Scanné le {scan_date_label}  ·  Rapport généré le {generated_label}", styles["meta"]))
    story.append(Spacer(1, 16))

    # ---------- Score ----------
    score = int(result.get("score", 0))
    grade = result.get("grade", "—")
    score_row = Table(
        [[
            Paragraph(f"{score}<font size=12>/100</font>", styles["score_number"]),
            Paragraph(f"NOTE&nbsp;&nbsp;<font size=16 color='{_hex(_zone_color(score))}'>{grade}</font>", styles["score_sub"]),
        ]],
        colWidths=[140, 320],
    )
    score_row.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))

    score_card = Table(
        [[score_row], [Spacer(1, 14)], [_score_gauge_drawing(score, grade)]],
        colWidths=[460],
    )
    score_card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PAPER),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (0, 0), 16),
        ("BOTTOMPADDING", (0, -1), (0, -1), 16),
    ]))
    story.append(score_card)
    story.append(Spacer(1, 18))

    # ---------- Résumé des contrôles ----------
    story.append(Paragraph("RÉSUMÉ DES CONTRÔLES", styles["h2"]))

    checks = result.get("checks", {})
    rows = [[
        Paragraph("Contrôle", styles["label"]),
        Paragraph("Statut", styles["label"]),
        Paragraph("Détail", styles["label"]),
    ]]
    for key, label in CHECK_LABELS:
        c = checks.get(key, {})
        if key == "security_headers":
            passed = c.get("points") == c.get("max_points")
            detail = f"{c.get('points', 0)}/{c.get('max_points', 0)} points"
        else:
            passed = c.get("passed", False)
            detail = c.get("detail", "")
        status_text = "PASS" if passed else "ATTENTION"
        status_color = SIGNAL if passed else HAZARD
        rows.append([
            Paragraph(label, styles["body"]),
            Paragraph(f"<font color='{_hex(status_color)}'><b>{status_text}</b></font>", styles["body"]),
            Paragraph(detail, styles["body"]),
        ])

    checks_table = Table(rows, colWidths=[150, 70, 240], repeatRows=1)
    checks_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1ede2")),
        ("LINEBELOW", (0, 0), (-1, 0), 0.75, HAIRLINE),
        ("LINEBELOW", (0, 1), (-1, -1), 0.4, HAIRLINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(checks_table)

    # ---------- Vulnérabilités ----------
    vulns = result.get("vulnerabilities", []) or []
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    vulns_sorted = sorted(vulns, key=lambda v: severity_order.get(v.get("severity"), 4))

    story.append(Spacer(1, 6))
    if not vulns_sorted:
        story.append(Paragraph("VULNÉRABILITÉS", styles["h2"]))
        story.append(Paragraph(
            "<font color='#1e7d6f'><b>Aucune vulnérabilité détectée par ce scan.</b></font>", styles["body"]
        ))
    else:
        story.append(Paragraph(f"VULNÉRABILITÉS — {len(vulns_sorted)} DÉTECTÉE(S)", styles["h2"]))

        for v in vulns_sorted:
            sev = v.get("severity", "low")
            sev_color = SEVERITY_COLOR.get(sev, MUTED)
            sev_label = v.get("severity_label") or SEVERITY_LABEL_FR.get(sev, sev.upper())

            block = []
            header_table = Table(
                [[
                    Paragraph(v.get("title", ""), styles["vuln_title"]),
                    Paragraph(
                        f"<font color='{_hex(sev_color)}'><b>{sev_label}</b></font>",
                        ParagraphStyle("sev", parent=styles["label"], alignment=TA_CENTER),
                    ),
                ]],
                colWidths=[370, 90],
            )
            header_table.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LINEBELOW", (0, 0), (-1, 0), 1.5, sev_color),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            block.append(header_table)
            block.append(Spacer(1, 4))
            block.append(Paragraph(f"<b>Risque —</b> {v.get('risk', '')}", styles["body"]))
            block.append(Spacer(1, 3))
            block.append(Paragraph(f"<b>Recommandation —</b> {v.get('recommendation', '')}", styles["body"]))
            evidence = v.get("evidence")
            if evidence:
                block.append(Spacer(1, 5))
                block.append(Paragraph(evidence, styles["evidence"]))
            block.append(Spacer(1, 14))

            story.append(KeepTogether(block))

    # ---------- Note de bas de rapport ----------
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Ce relevé est généré automatiquement par un scan passif et externe. Les résultats sont "
        "indicatifs : un score élevé ne garantit pas l'absence de vulnérabilités, et ce rapport ne "
        "remplace pas un audit de sécurité approfondi (pentest).",
        styles["footer"],
    ))

    doc.build(story, onFirstPage=_footer_canvas, onLaterPages=_footer_canvas)
    return buffer.getvalue()
