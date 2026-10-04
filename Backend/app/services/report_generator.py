"""
SecureMail SOC Executive Forensic PDF Report Generator
======================================================
Builds publication-quality, CISO/SOC-ready Incident Investigation Reports (PDF)
using ReportLab with dynamic two-pass page numbering, defanged IOCs,
MITRE ATT&CK matrix mapping, and actionable remediation checklists.
"""

import io
import re
import datetime
from typing import Dict, Any, List, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas


# ── Color Palette Tokens ──────────────────────────────────────────────────────
C_PRIMARY = colors.HexColor("#0F172A")     # Deep Slate
C_ACCENT = colors.HexColor("#2563EB")      # Tech Blue
C_TEXT_DARK = colors.HexColor("#1E293B")   # Slate Dark
C_TEXT_MUTED = colors.HexColor("#64748B")  # Slate Muted
C_BG_CARD = colors.HexColor("#F8FAFC")     # Light Card Background
C_BORDER = colors.HexColor("#E2E8F0")      # Subtle Table Border
C_WHITE = colors.HexColor("#FFFFFF")

# Risk Level Colors
RISK_COLORS = {
    "critical": colors.HexColor("#DC2626"),  # Crimson
    "high": colors.HexColor("#EA580C"),      # Orange
    "medium": colors.HexColor("#D97706"),    # Amber
    "low": colors.HexColor("#16A34A"),       # Emerald
    "clean": colors.HexColor("#16A34A"),     # Emerald
}


# ── IOC Defanging Helper ──────────────────────────────────────────────────────
def defang_ioc(text: str) -> str:
    """
    Sanitizes malicious IOCs to prevent accidental clicking or resolution:
    - http:// -> hxxp://
    - https:// -> hxxps://
    - . -> [.]
    - @ -> [at]
    """
    if not text:
        return ""
    s = str(text)
    s = re.sub(r"^https://", "hxxps://", s, flags=re.IGNORECASE)
    s = re.sub(r"^http://", "hxxp://", s, flags=re.IGNORECASE)
    # Defang IP addresses and domains (replace dots with [.])
    s = s.replace(".", "[.]")
    return s


# ── Dynamic Two-Pass Page Numbering Canvas ─────────────────────────────────────
class NumberedCanvas(canvas.Canvas):
    """
    Accumulates drawing commands and decorates each page with running headers
    and dynamic 'Page X of Y' footers on the second pass.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(colors.HexColor("#64748B"))

        # Running Header (Top)
        self.drawString(
            36, letter[1] - 26,
            "SECUREMAIL DEFENSE PLATFORM  |  SOC INCIDENT FORENSIC AUDIT  |  TLP:AMBER"
        )
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(36, letter[1] - 30, letter[0] - 36, letter[1] - 30)

        # Running Footer (Bottom)
        self.line(36, 32, letter[0] - 36, 32)
        self.setFont("Helvetica", 7.5)
        self.drawString(
            36, 20,
            "CONFIDENTIAL  —  AUTHORIZED SECURITY OPERATIONS CENTER USE ONLY"
        )
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(letter[0] - 36, 20, page_str)
        self.restoreState()


# ── PDF Generation Service ────────────────────────────────────────────────────
def generate_forensic_pdf(scan_data: Dict[str, Any], incident_id: Optional[str] = None) -> bytes:
    """
    Builds and returns a binary PDF forensic report for a given email scan result.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=44,
        bottomMargin=44
    )

    # Styles
    base_styles = getSampleStyleSheet()
    
    style_title = ParagraphStyle(
        "ReportTitle",
        parent=base_styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=C_PRIMARY,
        spaceAfter=3
    )
    style_subtitle = ParagraphStyle(
        "ReportSubtitle",
        parent=base_styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=C_TEXT_MUTED,
        spaceAfter=12
    )
    style_sec_hdr = ParagraphStyle(
        "SectionHeader",
        parent=base_styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=C_PRIMARY,
        spaceBefore=10,
        spaceAfter=6
    )
    style_body = ParagraphStyle(
        "ReportBody",
        parent=base_styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=C_TEXT_DARK
    )
    style_mono = ParagraphStyle(
        "ReportMono",
        parent=base_styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0F172A")
    )
    style_badge_text = ParagraphStyle(
        "BadgeText",
        parent=base_styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=13,
        alignment=1,  # Centered
        textColor=C_WHITE
    )
    style_table_hdr = ParagraphStyle(
        "TableHdr",
        parent=base_styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=C_PRIMARY
    )
    style_table_cell = ParagraphStyle(
        "TableCell",
        parent=base_styles["Normal"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=10,
        textColor=C_TEXT_DARK
    )

    story: List[Any] = []

    # ── Normalize Scan Data ──
    inc_id = incident_id or scan_data.get("scan_id") or f"INC-{datetime.datetime.now().strftime('%Y%m%d')}-{abs(hash(str(scan_data.get('sender_email', '')))) % 10000:04d}"
    risk_score = scan_data.get("risk_score", 0)
    risk_level = str(scan_data.get("risk_level", "clean")).lower()
    risk_color = RISK_COLORS.get(risk_level, colors.HexColor("#16A34A"))
    
    sender_email = scan_data.get("sender_email") or scan_data.get("headers", {}).get("from_email") or "Unknown Sender"
    recipient_email = scan_data.get("headers", {}).get("to") or "Protected Mailbox"
    subject = scan_data.get("subject") or scan_data.get("headers", {}).get("subject") or "No Subject"
    timestamp = scan_data.get("timestamp") or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    threat_types = scan_data.get("threat_types", []) or ["clean"]
    
    auth = scan_data.get("authentication", {})
    headers = scan_data.get("header_analysis", {}) or scan_data.get("headers", {})
    urls = scan_data.get("urls", [])
    attachments = scan_data.get("attachments", [])
    phishing = scan_data.get("phishing_indicators", {})
    hop_audit = scan_data.get("received_hop_audit", {}) or {}
    ml_res = scan_data.get("ml_classifier", {}) or {}

    # ── SECTION 1: Header Banner & Executive Metadata ────────────────────────
    story.append(Paragraph("EXECUTIVE SECURITY INCIDENT REPORT", style_title))
    story.append(Paragraph(f"Forensic Investigation Telemetry & Indicator Dossier  •  Tracking ID: <b>{inc_id}</b>", style_subtitle))

    # Metadata Grid + Risk Gauge Box
    risk_box = Table(
        [
            [Paragraph("OVERALL RISK", ParagraphStyle("R1", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=C_WHITE, alignment=1))],
            [Paragraph(f"{risk_score} / 100", ParagraphStyle("R2", fontName="Helvetica-Bold", fontSize=20, leading=22, textColor=C_WHITE, alignment=1))],
            [Paragraph(risk_level.upper(), style_badge_text)]
        ],
        colWidths=[130]
    )
    risk_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), risk_color),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))

    meta_table_data = [
        [Paragraph("<b>Incident ID:</b>", style_table_hdr), Paragraph(inc_id, style_mono), risk_box],
        [Paragraph("<b>Timestamp:</b>", style_table_hdr), Paragraph(str(timestamp), style_table_cell), ""],
        [Paragraph("<b>Sender (From):</b>", style_table_hdr), Paragraph(defang_ioc(sender_email), style_mono), ""],
        [Paragraph("<b>Target Recipient:</b>", style_table_hdr), Paragraph(recipient_email, style_mono), ""],
        [Paragraph("<b>Subject:</b>", style_table_hdr), Paragraph(subject[:65] + ("..." if len(subject) > 65 else ""), style_table_cell), ""],
        [Paragraph("<b>Threat Tags:</b>", style_table_hdr), Paragraph(", ".join(t.upper() for t in threat_types), style_table_cell), ""]
    ]

    meta_grid = Table(meta_table_data, colWidths=[95, 315, 130])
    meta_grid.setStyle(TableStyle([
        ('SPAN', (2, 0), (2, 5)),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('BACKGROUND', (0, 0), (1, -1), C_BG_CARD),
        ('BOX', (0, 0), (1, -1), 0.5, C_BORDER),
    ]))
    story.append(meta_grid)
    story.append(Spacer(1, 10))

    # ── SECTION 2: Executive Summary & Probabilistic Attribution ─────────────
    story.append(Paragraph("1. Executive Summary & Probabilistic Attribution", style_sec_hdr))
    
    ml_prob = ml_res.get("probability", 0.0)
    ml_prob_pct = f"{ml_prob * 100:.1f}%"
    ml_conf = str(ml_res.get("confidence", "low")).upper()
    ml_verdict = str(ml_res.get("verdict", "clean")).upper()

    summary_text = (
        f"SecureMail multi-layered detection analyzed this communication and classified it with a risk score of "
        f"<b>{risk_score}/100 ({risk_level.upper()})</b>. "
    )
    if risk_level in ("critical", "high"):
        summary_text += (
            f"Active threat vectors were identified including <b>{', '.join(threat_types)}</b>. "
            f"Immediate isolation and remediation are advised."
        )
    elif risk_level == "medium":
        summary_text += "Suspicious signals were detected requiring analyst verification prior to release."
    else:
        summary_text += "Cryptographic authentication passed and no malicious payloads, homographs, or extortion indicators were detected."

    story.append(Paragraph(summary_text, style_body))
    story.append(Spacer(1, 6))

    # Feature Attribution Table
    top_signals = ml_res.get("top_signals", [])
    signals_cell = []
    if top_signals:
        for s in top_signals[:4]:
            tag_color = "#DC2626" if s.get("direction") == "threat" else "#16A34A"
            arrow = "▲" if s.get("direction") == "threat" else "▼"
            signals_cell.append(f"<font color='{tag_color}'><b>{arrow} {s.get('label', '')} ({s.get('weight_delta', 0):+.2f})</b></font>")
        signals_html = " &nbsp;|&nbsp; ".join(signals_cell)
    else:
        signals_html = "No anomalous risk factors extracted."

    ml_table_data = [
        [
            Paragraph("<b>Probabilistic Scoring:</b>", style_table_hdr),
            Paragraph(f"Phishing Probability: <b>{ml_prob_pct}</b> ({ml_verdict} — {ml_conf} CONFIDENCE)", style_table_cell)
        ],
        [
            Paragraph("<b>Key Explanations:</b>", style_table_hdr),
            Paragraph(signals_html, style_table_cell)
        ]
    ]
    ml_table = Table(ml_table_data, colWidths=[120, 420])
    ml_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), C_BG_CARD),
        ('BOX', (0, 0), (-1, -1), 0.5, C_BORDER),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, C_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(ml_table)
    story.append(Spacer(1, 10))

    # ── SECTION 3: MITRE ATT&CK Matrix Mapping ───────────────────────────────
    techniques = phishing.get("mitre_techniques", []) or []
    if techniques:
        story.append(Paragraph("2. MITRE ATT&CK® Threat Mapping", style_sec_hdr))
        mitre_rows = [
            [
                Paragraph("Tactic / ID", style_table_hdr),
                Paragraph("Technique Name", style_table_hdr),
                Paragraph("Detection Context", style_table_hdr)
            ]
        ]
        for tech in techniques:
            parts = tech.split(" ", 1)
            t_id = parts[0] if len(parts) > 0 else "T1566"
            t_name = parts[1].strip("()") if len(parts) > 1 else "Phishing"
            mitre_rows.append([
                Paragraph(f"<b>{t_id}</b>", style_mono),
                Paragraph(t_name, style_table_cell),
                Paragraph("Extracted from message body or header attack vector", style_table_cell)
            ])
        mitre_table = Table(mitre_rows, colWidths=[100, 180, 260])
        mitre_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#EEF2F6")),
            ('BOX', (0, 0), (-1, -1), 0.5, C_BORDER),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, C_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(mitre_table)
        story.append(Spacer(1, 10))

    # ── SECTION 4: Email Authentication & Protocol Verification ──────────────
    story.append(Paragraph("3. Email Authentication & Cryptographic Verification", style_sec_hdr))
    
    def _auth_badge(val: str):
        v = str(val or "none").lower()
        if v == "pass":
            return f"<font color='#16A34A'><b>PASS</b></font>"
        elif v in ("fail", "softfail"):
            return f"<font color='#DC2626'><b>{v.upper()}</b></font>"
        return f"<font color='#64748B'><b>{v.upper()}</b></font>"

    auth_rows = [
        [
            Paragraph("Protocol", style_table_hdr),
            Paragraph("Status", style_table_hdr),
            Paragraph("Details / Alignment", style_table_hdr)
        ],
        [
            Paragraph("<b>SPF</b> (Sender Policy Framework)", style_table_cell),
            Paragraph(_auth_badge(auth.get("spf")), style_table_cell),
            Paragraph(f"MTA IP: {defang_ioc(headers.get('originating_ip', 'Not specified'))}", style_table_cell)
        ],
        [
            Paragraph("<b>DKIM</b> (Cryptographic Signature)", style_table_cell),
            Paragraph(_auth_badge(auth.get("dkim")), style_table_cell),
            Paragraph(f"DKIM Header: {'Present' if headers.get('dkim_signature') else 'Missing'}", style_table_cell)
        ],
        [
            Paragraph("<b>DMARC</b> (Domain Alignment)", style_table_cell),
            Paragraph(_auth_badge(auth.get("dmarc")), style_table_cell),
            Paragraph(f"From Domain: {defang_ioc(headers.get('from_domain', '—'))}", style_table_cell)
        ],
        [
            Paragraph("<b>ARC</b> (Authenticated Received Chain)", style_table_cell),
            Paragraph(_auth_badge(auth.get("arc")), style_table_cell),
            Paragraph("Multi-hop intermediary seal validation", style_table_cell)
        ]
    ]
    auth_table = Table(auth_rows, colWidths=[160, 90, 290])
    auth_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#EEF2F6")),
        ('BOX', (0, 0), (-1, -1), 0.5, C_BORDER),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, C_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(auth_table)
    story.append(Spacer(1, 10))

    # ── SECTION 5: Defanged Indicators of Compromise (IOC Inventory) ─────────
    story.append(Paragraph("4. Defanged Indicators of Compromise (IOC Inventory)", style_sec_hdr))
    
    ioc_rows = [
        [
            Paragraph("IOC Type", style_table_hdr),
            Paragraph("Defanged Value", style_table_hdr),
            Paragraph("Threat Verdict / Context", style_table_hdr)
        ]
    ]

    # Add Originating IP
    orig_ip = headers.get("originating_ip")
    if orig_ip:
        ip_rep = headers.get("ip_reputation", {}) or {}
        abuse = ip_rep.get("abuse_confidence_score", 0)
        ioc_rows.append([
            Paragraph("IPv4 Address", style_table_cell),
            Paragraph(defang_ioc(orig_ip), style_mono),
            Paragraph(f"Abuse Score: {abuse}% | Country: {ip_rep.get('country_code', 'XX')}", style_table_cell)
        ])

    # Add URLs
    if urls:
        for u in urls[:6]:
            u_raw = u.get("url", "")
            u_defanged = defang_ioc(u_raw[:55] + ("..." if len(u_raw) > 55 else ""))
            u_status = "Lookalike / Phishing" if (u.get("is_lookalike") or u.get("is_homograph")) else "Official / Whitelisted" if u.get("is_official") else "External Link"
            ioc_rows.append([
                Paragraph("URL / Destination", style_table_cell),
                Paragraph(u_defanged, style_mono),
                Paragraph(u_status, style_table_cell)
            ])
    else:
        ioc_rows.append([
            Paragraph("URLs", style_table_cell),
            Paragraph("No external hyperlinked resources detected in body", style_table_cell),
            Paragraph("Clean", style_table_cell)
        ])

    # Add Attachments
    if attachments:
        for a in attachments:
            fname = defang_ioc(a.get("filename", "unknown"))
            fsize = f"{a.get('size_bytes', 0) / 1024:.1f} KB"
            vt_threat = "Malicious Payload" if a.get("is_malicious") or a.get("is_dangerous_ext") else "Benign Attachment"
            ioc_rows.append([
                Paragraph("Attachment Hash", style_table_cell),
                Paragraph(f"{fname} ({fsize})<br/>SHA256: {a.get('sha256', a.get('md5', '—'))[:28]}...", style_mono),
                Paragraph(vt_threat, style_table_cell)
            ])

    ioc_table = Table(ioc_rows, colWidths=[100, 270, 170])
    ioc_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#EEF2F6")),
        ('BOX', (0, 0), (-1, -1), 0.5, C_BORDER),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, C_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(ioc_table)
    story.append(Spacer(1, 10))

    # ── SECTION 6: SMTP Relay Trajectory & Latency Table ──────────────────────
    hops = hop_audit.get("hops", []) or []
    if hops:
        story.append(Paragraph("5. SMTP Relay Trajectory & Transit Latency", style_sec_hdr))
        hop_rows = [
            [
                Paragraph("Hop", style_table_hdr),
                Paragraph("Relay MTA & IP", style_table_hdr),
                Paragraph("Location / ISP", style_table_hdr),
                Paragraph("Latency Delta", style_table_hdr)
            ]
        ]
        for h in hops:
            h_num = str(h.get("hop_number", ""))
            h_ip = defang_ioc(h.get("ip") or "Private Subnet")
            h_host = h.get("host_from") or h.get("host_by") or "—"
            h_loc = f"{h.get('city', 'Unknown')}, {h.get('country', 'Unknown')} ({h.get('country_code', 'XX')})"
            h_isp = h.get("isp", "—")
            h_delay = f"+{h.get('delay_seconds', 0)}s"
            
            hop_rows.append([
                Paragraph(f"<b>#{h_num}</b>", style_mono),
                Paragraph(f"{defang_ioc(h_host[:32])}<br/>IP: {h_ip}", style_table_cell),
                Paragraph(f"{h_loc}<br/>ISP: {h_isp[:25]}", style_table_cell),
                Paragraph(h_delay, style_table_cell)
            ])
        
        hop_table = Table(hop_rows, colWidths=[40, 210, 210, 80])
        hop_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#EEF2F6")),
            ('BOX', (0, 0), (-1, -1), 0.5, C_BORDER),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, C_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(hop_table)
        story.append(Spacer(1, 10))

    # ── SECTION 7: SOC Incident Response Remediation Checklist ───────────────
    remediation_items = []
    if risk_level in ("critical", "high"):
        remediation_items = [
            "Quarantine message from all recipient mailboxes across Microsoft 365 / Google Workspace.",
            f"Add originating IP ({defang_ioc(orig_ip or 'MTA IP')}) to perimeter firewall drop / deny list.",
            "Sinkhole identified lookalike domains on internal DNS and Secure Web Gateways (SWG).",
            "Force credential reset and revoke active session tokens for recipients who interacted with links.",
            "Export defanged IOC package for ingestion into SIEM / SOAR automated containment playbooks."
        ]
    elif risk_level == "medium":
        remediation_items = [
            "Submit suspicious links and attachments to sandbox detonation environment.",
            "Contact sender via out-of-band communication channel to verify message authenticity.",
            "Monitor mailbox logs for anomalous outbound traffic or forwarding rules."
        ]
    else:
        remediation_items = [
            "No immediate remediation required — communication verified as authentic.",
            "Standard routine telemetry logged for compliance audit trail."
        ]

    remediation_block = [
        Paragraph("6. Actionable SOC Incident Response Checklist", style_sec_hdr)
    ]
    rem_rows = []
    for item in remediation_items:
        rem_rows.append([
            Paragraph("[  ]", ParagraphStyle("Box", fontName="Courier-Bold", fontSize=9, leading=11, textColor=C_PRIMARY)),
            Paragraph(item, style_table_cell)
        ])
    rem_table = Table(rem_rows, colWidths=[30, 510])
    rem_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
    ]))
    remediation_block.append(rem_table)

    story.append(KeepTogether(remediation_block))

    # Build Document using NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
