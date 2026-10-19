"""
=============================================================================
KAVACH — PDF Incident Report Generator Service
=============================================================================
Generates a professional PDF document titled:
"Cyber Security Incident Report / Complaint Draft"

Important Legal Disclaimer:
This document is an automatically generated incident report / complaint draft
and is NOT an official complaint filing with a law-enforcement or cybercrime authority.
=============================================================================
"""

import io
from datetime import datetime, timezone
from typing import Any, Dict

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

REPORT_DISCLAIMER_TEXT = (
    "DISCLAIMER: This document is an automatically generated Cyber Security Incident Report / Complaint Draft "
    "produced by KAVACH AI Digital Guardian. It is intended solely as an evidence compilation and reference draft "
    "to assist users when filing reports. This document DOES NOT constitute an official legal complaint filing "
    "with any police department, Cyber Crime Cell, or government law-enforcement authority."
)


def generate_incident_report_pdf(report_data: Dict[str, Any], is_guardian_view: bool = False) -> bytes:
    """
    Generates a PDF document for an IncidentReport record.

    :param report_data: Dictionary containing report fields and evidence.
    :param is_guardian_view: If True, renders sanitized evidence with private details masked.
    :return: PDF document bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom Color Palette
    primary_color = colors.HexColor("#1e293b")  # Dark Slate Header
    accent_color = colors.HexColor("#0f172a")
    risk_level = report_data.get("risk_level", "SAFE").upper()
    
    if "HIGH" in risk_level:
        badge_bg = colors.HexColor("#ef4444")
        badge_fg = colors.white
    elif "SUSPICIOUS" in risk_level:
        badge_bg = colors.HexColor("#f59e0b")
        badge_fg = colors.black
    else:
        badge_bg = colors.HexColor("#3b82f6")
        badge_fg = colors.white

    # Custom Paragraph Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        alignment=0
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#64748b"),
        alignment=0
    )

    section_heading_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=4
    )

    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#334155")
    )

    disclaimer_style = ParagraphStyle(
        'DisclaimerText',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#475569")
    )

    elements = []

    # 1. Header Banner
    elements.append(Paragraph("KAVACH AI DIGITAL GUARDIAN", subtitle_style))
    elements.append(Paragraph("CYBER SECURITY INCIDENT REPORT / COMPLAINT DRAFT", title_style))
    elements.append(Spacer(1, 6))
    elements.append(HRFlowable(width="100%", thickness=2, color=primary_color, spaceAfter=12))

    # 2. Metadata Table
    report_id = report_data.get("report_id", "KAV-2026-000000")
    incident_type = report_data.get("incident_type", "MULTI_SIGNAL_SCAM")
    risk_score = report_data.get("risk_score", 0)
    detected_at = report_data.get("detected_at", datetime.now(timezone.utc).isoformat())
    scan_id = report_data.get("security_scan_id", "N/A")

    meta_table_data = [
        [
            Paragraph("<b>Report ID:</b>", body_style),
            Paragraph(str(report_id), body_style),
            Paragraph("<b>Risk Verdict:</b>", body_style),
            Paragraph(f"<font color='{badge_bg.hexval()}'><b>{risk_level} ({risk_score}/100)</b></font>", body_style)
        ],
        [
            Paragraph("<b>Incident Type:</b>", body_style),
            Paragraph(str(incident_type), body_style),
            Paragraph("<b>Detection Time:</b>", body_style),
            Paragraph(str(detected_at), body_style)
        ],
        [
            Paragraph("<b>Scan Reference:</b>", body_style),
            Paragraph(f"Security Scan #{scan_id}", body_style),
            Paragraph("<b>Status:</b>", body_style),
            Paragraph("Draft Complaint Record", body_style)
        ]
    ]

    meta_table = Table(meta_table_data, colWidths=[1.3*inch, 2.2*inch, 1.3*inch, 2.2*inch])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 12))

    # 3. Incident Summary Section
    elements.append(Paragraph("1. INCIDENT SUMMARY", section_heading_style))
    summary_text = report_data.get("summary", "No summary provided.")
    elements.append(Paragraph(summary_text, body_style))
    elements.append(Spacer(1, 10))

    # 4. Threat Analysis Section
    elements.append(Paragraph("2. THREAT ANALYSIS", section_heading_style))
    meta = report_data.get("report_metadata", {})
    ml_model = meta.get("model", "Rule Heuristics / ML Classifier")
    ml_verdict = meta.get("ml_prediction") or meta.get("verdict", risk_level)
    confidence = meta.get("confidence") or meta.get("scam_probability", "N/A")

    analysis_text = (
        f"The KAVACH Multi-Engine Scanner evaluated this incident using <b>{ml_model}</b>. "
        f"The primary classification model evaluated the threat level as <b>{ml_verdict}</b> "
        f"(Confidence/Scam Score: {confidence}%)."
    )
    elements.append(Paragraph(analysis_text, body_style))
    elements.append(Spacer(1, 10))

    # 5. Evidence Summary (Sanitized / Privacy Preserved)
    elements.append(Paragraph("3. EVIDENCE SUMMARY", section_heading_style))
    evidence = report_data.get("sanitized_evidence", {})
    
    evidence_rows = []
    if is_guardian_view:
        evidence_rows.append([Paragraph("<i>Note: Viewing sanitized evidence format. Sensitive private details are masked.</i>", disclaimer_style)])

    input_ref = evidence.get("input_reference") or evidence.get("filename") or "Submitted Digital Content"
    evidence_rows.append([Paragraph(f"<b>Content Reference:</b> {input_ref}", body_style)])

    extracted_preview = evidence.get("text_preview") or evidence.get("preview")
    if extracted_preview:
        evidence_rows.append([Paragraph(f"<b>Content Snippet:</b> {extracted_preview[:300]}", body_style)])

    ev_table = Table(evidence_rows, colWidths=[7.0*inch])
    ev_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(ev_table)
    elements.append(Spacer(1, 10))

    # 6. Detected Indicators
    indicators = report_data.get("detected_indicators") or meta.get("detected_indicators") or []
    if indicators:
        elements.append(Paragraph("4. DETECTED THREAT INDICATORS", section_heading_style))
        ind_items = [Paragraph(f"• {ind}", body_style) for ind in indicators]
        for item in ind_items:
            elements.append(item)
        elements.append(Spacer(1, 10))

    # 7. Suspicious URLs / QR Code Information
    urls = meta.get("urls") or meta.get("analyzed_urls") or []
    qr_codes = meta.get("qr_codes") or []
    if urls or qr_codes:
        elements.append(Paragraph("5. SUSPICIOUS LINKS & QR PAYLOADS", section_heading_style))
        for u in urls:
            u_str = u if isinstance(u, str) else u.get("url", "")
            elements.append(Paragraph(f"• Deceptive Link: <code>{u_str}</code>", body_style))
        for q in qr_codes:
            q_payload = q.get("payload", "QR Code") if isinstance(q, dict) else str(q)
            elements.append(Paragraph(f"• Embedded QR Payload: <code>{q_payload}</code>", body_style))
        elements.append(Spacer(1, 10))

    # 8. Recommended Actions
    elements.append(Paragraph("6. RECOMMENDED SAFETY ACTIONS", section_heading_style))
    rec_action = report_data.get("recommended_action") or (
        "1. Do NOT click on links or QR codes embedded in this document/message.<br/>"
        "2. Do NOT transfer money or share OTPs.<br/>"
        "3. File an official complaint with your local law-enforcement agency or national cybercrime portal if financial loss occurred."
    )
    elements.append(Paragraph(rec_action, body_style))
    elements.append(Spacer(1, 14))

    # 9. Legal Disclaimer Box
    disclaimer_box_data = [[Paragraph(REPORT_DISCLAIMER_TEXT, disclaimer_style)]]
    disclaimer_table = Table(disclaimer_box_data, colWidths=[7.0*inch])
    disclaimer_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#fef2f2")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#fca5a5")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(disclaimer_table)

    # Build document
    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()
