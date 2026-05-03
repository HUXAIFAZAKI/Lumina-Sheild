from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import os, hashlib, tempfile, io, textwrap, platform
from datetime import datetime


# ──────────────────────────────────────────────────────────────────────────
# Shareable PNG Verdict Card
# ──────────────────────────────────────────────────────────────────────────

def _hex_rgb(hx: str) -> tuple:
    hx = hx.lstrip("#")
    return tuple(int(hx[i:i + 2], 16) for i in (0, 2, 4))


def _load_font(size: int, bold: bool = False):
    """Try to load a TrueType font; fall back to PIL default."""
    from PIL import ImageFont
    candidates = []
    if platform.system() == "Windows":
        base = "C:/Windows/Fonts/"
        candidates = [
            base + ("arialbd.ttf" if bold else "arial.ttf"),
            base + ("calibrib.ttf" if bold else "calibri.ttf"),
            base + ("segoeui.ttf"),
        ]
    else:
        base = "/usr/share/fonts/truetype/"
        candidates = [
            base + ("dejavu/DejaVuSans-Bold.ttf" if bold else "dejavu/DejaVuSans.ttf"),
            base + ("liberation/LiberationSans-Bold.ttf" if bold else "liberation/LiberationSans-Regular.ttf"),
            base + ("ubuntu/Ubuntu-B.ttf" if bold else "ubuntu/Ubuntu-R.ttf"),
        ]
    for fp in candidates:
        if os.path.exists(fp):
            try:
                return ImageFont.truetype(fp, size)
            except Exception:
                pass
    return ImageFont.load_default()


def generate_verdict_card_png(
    verdict_label: str,
    confidence: int,
    claim_snippet: str,
    evidence_snippet: str,
    report_url: str = "https://luminashield.app",
) -> bytes:
    """
    Render a 900×500 px shareable verdict card as PNG bytes.
    Matches the Lumina Shield app color theme (warm parchment + golden accents).
    """
    from PIL import Image, ImageDraw

    W, H = 900, 500

    # ── App color constants ───────────────────────────────────────────────
    # Backgrounds
    BG         = (248, 246, 240)   # #f8f6f0 — app background parchment
    CARD_BG    = (255, 253, 245)   # #fffdf5 — card surface
    DIVIDER    = (229, 161,   0)   # #E5A100 — golden divider

    # Text hierarchy
    TEXT_MAIN  = ( 26,  23,  20)   # #1a1714 — near black
    TEXT_SUB   = (122, 114, 104)   # #7a7268 — warm gray
    TEXT_CAP   = (160, 149, 133)   # #a09585 — caption gray

    # Brand gradient: left→right  #c88b00 → #E5A100 → #FF8C42
    GRAD_L     = (200, 139,   0)   # #c88b00
    GRAD_M     = (229, 161,   0)   # #E5A100
    GRAD_R     = (255, 140,  66)   # #FF8C42

    # ── Verdict-specific accent (badge fill + bar) ────────────────────────
    _VERDICT_ACCENTS = {
        "TRUE":        {"fill": ( 46, 125,  50), "text": (255, 255, 255), "bar": ( 76, 175,  80)},
        "FALSE":       {"fill": (183,  28,  28), "text": (255, 255, 255), "bar": (229,  57,  53)},
        "FAKE":        {"fill": (183,  28,  28), "text": (255, 255, 255), "bar": (229,  57,  53)},
        "SCAM":        {"fill": (230,  81,   0), "text": (255, 255, 255), "bar": (255, 109,   0)},
        "MANIPULATED": {"fill": (245, 127,  23), "text": (255, 255, 255), "bar": (251, 192,  45)},
        "MIXTURE":     {"fill": (200, 139,   0), "text": (255, 255, 255), "bar": (229, 161,   0)},
    }
    acc = _VERDICT_ACCENTS.get(
        verdict_label,
        {"fill": ( 84, 110, 122), "text": (255, 255, 255), "bar": (144, 164, 174)},
    )

    # ── Canvas — warm parchment ───────────────────────────────────────────
    img = Image.new("RGB", (W, H), color=BG)
    draw = ImageDraw.Draw(img, "RGBA")

    # ── Top gradient bar (5 px, brand colors) ────────────────────────────
    for x in range(W):
        t = x / (W - 1)
        if t < 0.5:
            t2 = t * 2
            r = int(GRAD_L[0] * (1 - t2) + GRAD_M[0] * t2)
            g = int(GRAD_L[1] * (1 - t2) + GRAD_M[1] * t2)
            b = int(GRAD_L[2] * (1 - t2) + GRAD_M[2] * t2)
        else:
            t2 = (t - 0.5) * 2
            r = int(GRAD_M[0] * (1 - t2) + GRAD_R[0] * t2)
            g = int(GRAD_M[1] * (1 - t2) + GRAD_R[1] * t2)
            b = int(GRAD_M[2] * (1 - t2) + GRAD_R[2] * t2)
        draw.line([(x, 0), (x, 6)], fill=(r, g, b))

    # ── Fonts ─────────────────────────────────────────────────────────────
    fn_brand   = _load_font(22, bold=True)
    fn_sub     = _load_font(12)
    fn_label   = _load_font(11, bold=True)
    fn_verdict = _load_font(32, bold=True)
    fn_conf    = _load_font(30, bold=True)
    fn_body    = _load_font(15, bold=True)
    fn_evid    = _load_font(13)
    fn_foot    = _load_font(11)

    # ── Branding ─────────────────────────────────────────────────────────
    draw.text((34, 22), "LUMINA SHIELD", font=fn_brand, fill=GRAD_L)
    draw.text((34, 50), "AI-Powered Misinformation Verdict  ·  luminashield.app", font=fn_sub, fill=TEXT_SUB)

    # Golden divider line
    for x in range(W - 68):
        t = x / max(W - 69, 1)
        r = int(GRAD_L[0] * (1 - t) + GRAD_R[0] * t)
        g = int(GRAD_L[1] * (1 - t) + GRAD_R[1] * t)
        b = int(GRAD_L[2] * (1 - t) + GRAD_R[2] * t)
        draw.point((34 + x, 74), fill=(r, g, b, 140))

    # ── Verdict badge (rounded rect, verdict color) ───────────────────────
    icons = {
        "TRUE": "[OK]", "FALSE": "[X]", "FAKE": "[X]",
        "SCAM": "[!]", "MANIPULATED": "[!]", "MIXTURE": "[~]",
    }
    icon_ch = icons.get(verdict_label, "[?]")
    bx1, by1, bx2, by2 = 34, 92, 300, 158
    draw.rounded_rectangle([bx1, by1, bx2, by2], radius=14, fill=acc["fill"])
    # Subtle inner highlight (top strip)
    draw.rounded_rectangle([bx1 + 2, by1 + 2, bx2 - 2, by1 + 18], radius=10, fill=(*acc["bar"], 60))
    v_text = f"{icon_ch}  {verdict_label}"
    cx, cy = (bx1 + bx2) // 2, (by1 + by2) // 2
    draw.text((cx, cy), v_text, font=fn_verdict, fill=acc["text"], anchor="mm")

    # ── Confidence ────────────────────────────────────────────────────────
    draw.text((34, 172), "CONFIDENCE", font=fn_label, fill=TEXT_CAP)
    draw.text((34, 189), f"{confidence}%", font=fn_conf, fill=acc["fill"])

    # Bar track (warm gray trough)
    bx, by_bar, bw, bh = 34, 232, 480, 10
    draw.rounded_rectangle([bx, by_bar, bx + bw, by_bar + bh], radius=5, fill=(229, 221, 208))
    # Filled portion — gradient
    fw = max(1, int(bw * confidence / 100))
    for x in range(fw):
        t = x / max(fw - 1, 1)
        r = int(GRAD_L[0] * (1 - t) + GRAD_R[0] * t)
        g = int(GRAD_L[1] * (1 - t) + GRAD_R[1] * t)
        b = int(GRAD_L[2] * (1 - t) + GRAD_R[2] * t)
        draw.line([(bx + x, by_bar), (bx + x, by_bar + bh)], fill=(r, g, b))
    # Round the filled end
    if fw >= bh:
        draw.ellipse([bx + fw - bh, by_bar, bx + fw, by_bar + bh], fill=GRAD_R)

    # ── Claim ─────────────────────────────────────────────────────────────
    draw.text((34, 256), "CLAIM", font=fn_label, fill=TEXT_CAP)
    y_now = 273
    for line in textwrap.wrap(claim_snippet[:180], width=58)[:3]:
        draw.text((34, y_now), line, font=fn_body, fill=TEXT_MAIN)
        y_now += 22

    # ── Evidence ─────────────────────────────────────────────────────────
    draw.text((34, y_now + 6), "EVIDENCE", font=fn_label, fill=TEXT_CAP)
    y_now += 22
    for line in textwrap.wrap(evidence_snippet[:220], width=72)[:3]:
        draw.text((34, y_now), line, font=fn_evid, fill=TEXT_SUB)
        y_now += 18

    # ── Left accent stripe (brand gradient, matches top bar) ─────────────
    for y in range(H):
        t = y / (H - 1)
        if t < 0.5:
            t2 = t * 2
            r = int(GRAD_L[0] * (1 - t2) + GRAD_M[0] * t2)
            g = int(GRAD_L[1] * (1 - t2) + GRAD_M[1] * t2)
            b = int(GRAD_L[2] * (1 - t2) + GRAD_M[2] * t2)
        else:
            t2 = (t - 0.5) * 2
            r = int(GRAD_M[0] * (1 - t2) + GRAD_R[0] * t2)
            g = int(GRAD_M[1] * (1 - t2) + GRAD_R[1] * t2)
            b = int(GRAD_M[2] * (1 - t2) + GRAD_R[2] * t2)
        draw.line([(0, y), (4, y)], fill=(r, g, b))

    # ── Footer divider ────────────────────────────────────────────────────
    draw.line([(34, H - 42), (W - 34, H - 42)], fill=(229, 221, 208), width=1)
    draw.text(
        (34, H - 28),
        f"Fact-checked by Lumina Shield  ·  {datetime.now().strftime('%d %b %Y')}  ·  AI Misinformation Defense",
        font=fn_foot, fill=TEXT_CAP,
    )

    # ── QR Code (right side, warm-bordered) ──────────────────────────────
    try:
        import qrcode as _qr
        from PIL import Image as _PilImg
        qr = _qr.QRCode(
            version=2,
            error_correction=_qr.constants.ERROR_CORRECT_M,
            box_size=5, border=2,
        )
        qr.add_data(report_url)
        qr.make(fit=True)
        _qr_wrapper = qr.make_image(fill_color=(0, 0, 0), back_color=(255, 255, 255))
        if hasattr(_qr_wrapper, "get_image"):
            qr_pil_raw = _qr_wrapper.get_image()
        else:
            _buf2 = io.BytesIO()
            _qr_wrapper.save(_buf2)
            _buf2.seek(0)
            qr_pil_raw = _PilImg.open(_buf2)
        qr_pil = qr_pil_raw.convert("RGB").resize((134, 134))
        # Clean white border around QR
        border_img = _PilImg.new("RGB", (148, 148), color=(255, 255, 255))
        border_img.paste(qr_pil, (7, 7))
        paste_x, paste_y = W - 182, H - 196
        # Light warm shadow behind QR frame
        draw.rounded_rectangle(
            [paste_x - 4, paste_y - 4, paste_x + 152, paste_y + 152],
            radius=12,
            fill=(220, 215, 205),
        )
        img.paste(border_img, (paste_x, paste_y))
        draw.text(
            (paste_x + 10, paste_y + 152),
            "Scan for more info",
            font=fn_foot, fill=TEXT_CAP,
        )
    except Exception:
        pass  # qrcode unavailable — card renders without QR

    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    buf.seek(0)
    return buf.getvalue()

def generate_pdf(url: str, iocs: dict, summary_text: str = None, narrative_data: dict = None) -> str:
    # Use OS-appropriate temp directory
    tmp_dir = tempfile.gettempdir()
    filename = f"lumina_report_{hashlib.md5(url.encode()).hexdigest()}.pdf"
    path = os.path.join(tmp_dir, filename)

    doc = SimpleDocTemplate(path, pagesize=A4,
                            topMargin=40, bottomMargin=40,
                            leftMargin=40, rightMargin=40)
    styles = getSampleStyleSheet()

    # ── Custom styles ──────────────────────────────────────────────────────
    title_style = ParagraphStyle(
        'LuminaTitle', parent=styles['Title'],
        fontSize=22, textColor=colors.HexColor("#c88b00"),
        spaceAfter=4, leading=28,
    )
    subtitle_style = ParagraphStyle(
        'LuminaSubtitle', parent=styles['Normal'],
        fontSize=9, textColor=colors.HexColor("#7a7268"),
        spaceAfter=2,
    )
    heading_style = ParagraphStyle(
        'LuminaH2', parent=styles['Heading2'],
        fontSize=13, textColor=colors.HexColor("#1a1714"),
        spaceBefore=18, spaceAfter=6,
        borderPad=4,
    )
    subheading_style = ParagraphStyle(
        'LuminaH3', parent=styles['Heading3'],
        fontSize=11, textColor=colors.HexColor("#c88b00"),
        spaceBefore=10, spaceAfter=4,
    )
    normal_style = ParagraphStyle(
        'LuminaNormal', parent=styles['Normal'],
        fontSize=9, textColor=colors.HexColor("#1a1714"),
        leading=14,
    )
    caption_style = ParagraphStyle(
        'LuminaCaption', parent=styles['Normal'],
        fontSize=8, textColor=colors.HexColor("#7a7268"),
        leading=12,
    )
    footer_style = ParagraphStyle(
        'LuminaFooter', parent=styles['Normal'],
        fontSize=8, textColor=colors.HexColor("#a09585"),
        leading=11,
    )
    code_style = ParagraphStyle(
        'LuminaCode', parent=styles['Normal'],
        fontSize=8, textColor=colors.HexColor("#1a1714"),
        fontName='Courier', leading=12,
        leftIndent=10,
    )
    cell_style = ParagraphStyle(
        'LuminaCell', parent=styles['Normal'],
        fontSize=8, textColor=colors.HexColor("#1a1714"),
        leading=11,
    )

    import re as _re

    def _md_to_rl(text: str) -> str:
        """Convert markdown text to ReportLab XML-safe string with bold and bullets."""
        # Strip any existing HTML/XML tags
        text = _re.sub(r'<[^>]+>', '', str(text)).strip()
        # Escape XML special characters first
        text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        # Split on **bold** markers; insert <br/> before each bold section (except the first)
        parts = _re.split(r'\*\*(.+?)\*\*', text)
        result = parts[0]
        for i in range(1, len(parts), 2):
            bold_text = parts[i]
            after = parts[i + 1] if i + 1 < len(parts) else ''
            prefix = '<br/>' if result.strip() else ''
            result += f'{prefix}<b>{bold_text}</b>{after}'
        text = result
        # Bullet list items: '- item' → '• item' with leading line break
        text = _re.sub(r'(?m)^\s*-\s+', '<br/>\u2022\u00a0', text)
        # Real newlines → <br/>
        text = text.replace('\n', '<br/>')
        # Collapse multiple consecutive <br/>
        text = _re.sub(r'(<br/>){2,}', '<br/>', text)
        return text

    def _cp(text: str) -> Paragraph:
        """Wrap text in a Paragraph for table cells (enables word-wrap)."""
        return Paragraph(_md_to_rl(str(text)), cell_style)

    # ── Shared table style helper ──────────────────────────────────────────
    def _table_style(header_color="#E5A100", alt_row="#FFF8E7"):
        return TableStyle([
            ('BACKGROUND',    (0, 0), (-1,  0), colors.HexColor(header_color)),
            ('TEXTCOLOR',     (0, 0), (-1,  0), colors.white),
            ('FONTSIZE',      (0, 0), (-1,  0), 9),
            ('FONTNAME',      (0, 0), (-1,  0), 'Helvetica-Bold'),
            ('FONTSIZE',      (0, 1), (-1, -1), 8),
            ('ALIGN',         (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN',        (0, 0), (-1,  0), 'MIDDLE'),
            ('VALIGN',        (0, 1), (-1, -1), 'TOP'),
            ('GRID',          (0, 0), (-1, -1), 0.4, colors.HexColor("#ddd5c8")),
            ('ROWBACKGROUNDS',(0, 1), (-1, -1), [colors.white, colors.HexColor(alt_row)]),
            ('TOPPADDING',    (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        ])

    story = []

    # ===== HEADER =====
    story.append(Paragraph("Lumina Shield — Cyber Forensic Report", title_style))
    story.append(Paragraph(f"Target: {url}", subtitle_style))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%d %b %Y  %H:%M:%S UTC')}", subtitle_style))
    story.append(Spacer(1, 6))

    # Golden divider line
    from reportlab.platypus import HRFlowable
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#E5A100"), spaceAfter=10))

    # ===== RISK SCORE =====
    risk = iocs.get('risk_score', 0)
    severity = "LOW" if risk < 3 else "MEDIUM" if risk < 6 else "HIGH" if risk < 8 else "CRITICAL"
    sev_color = "#4CAF50" if risk < 3 else "#FF9800" if risk < 6 else "#f44336" if risk < 8 else "#b71c1c"
    risk_data = [
        ["Risk Score", "Severity", "Target"],
        [f"{risk} / 10", severity, url[:80]],
    ]
    risk_table = Table(risk_data, colWidths=[80, 100, 330])
    risk_table.setStyle(_table_style(header_color="#1a1714"))
    risk_table.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1,  0), colors.HexColor("#1a1714")),
        ('TEXTCOLOR',     (0, 0), (-1,  0), colors.white),
        ('FONTSIZE',      (0, 0), (-1,  0), 9),
        ('FONTNAME',      (0, 0), (-1,  0), 'Helvetica-Bold'),
        ('FONTSIZE',      (0, 1), (-1, -1), 10),
        ('FONTNAME',      (0, 1), (0,   1), 'Helvetica-Bold'),
        ('TEXTCOLOR',     (0, 1), (0,   1), colors.HexColor(sev_color)),
        ('TEXTCOLOR',     (1, 1), (1,   1), colors.HexColor(sev_color)),
        ('ALIGN',         (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID',          (0, 0), (-1, -1), 0.4, colors.HexColor("#ddd5c8")),
        ('TOPPADDING',    (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING',   (0, 0), (-1, -1), 8),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 14))

    # ===== AI EXECUTIVE SUMMARY =====
    if summary_text:
        story.append(Paragraph("AI Executive Summary", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))
        story.append(Paragraph(_md_to_rl(str(summary_text)), normal_style))
        story.append(Spacer(1, 10))

    # ===== NARRATIVE INTELLIGENCE =====
    if narrative_data and not narrative_data.get("error") and narrative_data.get("scenarios"):
        story.append(Paragraph("Narrative Intelligence Score", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))

        archetype      = narrative_data.get("campaign_archetype", "Unknown")
        target_profile = narrative_data.get("target_profile",     "Unknown")
        narrative_text = narrative_data.get("narrative",          "")
        ci_low         = narrative_data.get("risk_confidence_low",  "—")
        ci_high        = narrative_data.get("risk_confidence_high", "—")

        if narrative_text:
            story.append(Paragraph(_md_to_rl(str(narrative_text)), normal_style))
            story.append(Spacer(1, 6))

        meta_data = [["Campaign Archetype", "Target Profile", "Risk Confidence Range"]]
        meta_data.append([_cp(archetype), _cp(target_profile), _cp(f"{ci_low} – {ci_high} / 10")])
        meta_table = Table(meta_data, colWidths=[170, 170, 170])
        meta_table.setStyle(_table_style(header_color="#c88b00", alt_row="#fffdf5"))
        story.append(meta_table)
        story.append(Spacer(1, 8))

        scenarios = narrative_data.get("scenarios", [])
        if scenarios:
            story.append(Paragraph("Attack Scenario Probabilities", subheading_style))
            sc_data = [["Scenario", "Probability", "Description"]]
            for sc in scenarios:
                sc_data.append([
                    _cp(f"{sc.get('icon', '')} {sc.get('name', '')}"),
                    _cp(f"{sc.get('probability', 0)}%"),
                    _cp(sc.get("description", "")),
                ])
            sc_table = Table(sc_data, colWidths=[160, 60, 290])
            sc_table.setStyle(_table_style(header_color="#c88b00", alt_row="#fffdf5"))
            story.append(sc_table)
        story.append(Spacer(1, 10))

    # ===== VIRUSTOTAL DETECTION =====
    vt_stats = iocs.get("vt_stats", {})
    if vt_stats:
        story.append(Spacer(1, 8))
        story.append(Paragraph("VirusTotal Detection Summary", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))
        mal   = vt_stats.get("malicious",   0)
        sus   = vt_stats.get("suspicious",  0)
        harm  = vt_stats.get("harmless",    0)
        undet = vt_stats.get("undetected",  0)
        total = mal + sus + harm + undet
        vt_summary = [
            ["Malicious", "Suspicious", "Harmless", "Undetected", "Total"],
            [str(mal), str(sus), str(harm), str(undet), str(total)],
        ]
        vt_sum_tbl = Table(vt_summary, colWidths=[100, 100, 100, 100, 110])
        vt_sum_tbl.setStyle(_table_style(header_color="#c33"))
        story.append(vt_sum_tbl)
        story.append(Spacer(1, 8))

    # ===== VT HISTORY =====
    details = iocs.get("details", {})
    first_sub   = details.get("vt_first_submission")
    last_anal   = details.get("vt_last_analysis")
    times_sub   = details.get("vt_times_submitted")
    vt_rep      = iocs.get("vt_reputation")
    vt_votes    = details.get("vt_votes", {})
    if first_sub or last_anal or vt_rep is not None:
        story.append(Paragraph("VirusTotal History & Reputation", subheading_style))
        try:
            fs_str = datetime.fromtimestamp(first_sub).strftime("%Y-%m-%d") if first_sub else "N/A"
            la_str = datetime.fromtimestamp(last_anal).strftime("%Y-%m-%d") if last_anal else "N/A"
        except Exception:
            fs_str, la_str = str(first_sub), str(last_anal)
        vt_hist = [
            ["First Submitted", "Last Analysis", "Times Submitted", "Reputation", "Harmless Votes", "Malicious Votes"],
            [fs_str, la_str, str(times_sub or "N/A"), str(vt_rep or "N/A"),
             str(vt_votes.get("harmless", "N/A")), str(vt_votes.get("malicious", "N/A"))],
        ]
        vt_hist_tbl = Table(vt_hist, colWidths=[80, 80, 70, 65, 80, 80])
        vt_hist_tbl.setStyle(_table_style(header_color="#555"))
        story.append(vt_hist_tbl)
        story.append(Spacer(1, 8))

    # ===== VT PER-VENDOR TABLE (flagged only) =====
    vt_vendors = iocs.get("vt_vendors", {})
    flagged_vendors = {k: v for k, v in vt_vendors.items()
                       if v.get("category") in ("malicious", "suspicious", "phishing")}
    if flagged_vendors:
        story.append(Paragraph("Flagged Antivirus Engines", subheading_style))
        vt_data = [["Engine", "Category", "Result"]]
        for vendor, info in sorted(flagged_vendors.items()):
            vt_data.append([
                _cp(info.get("engine_name", vendor)),
                _cp(info.get("category", "").upper()),
                _cp(info.get("result", "N/A")),
            ])
        vt_table = Table(vt_data, colWidths=[180, 100, 230])
        vt_table.setStyle(_table_style(header_color="#E5A100"))
        story.append(vt_table)
        story.append(Spacer(1, 12))

    # ===== SITE CATEGORIES =====
    cats = iocs.get("vt_categories", {})
    if cats:
        story.append(Paragraph("Site Categories", subheading_style))
        for vendor, category in cats.items():
            story.append(Paragraph(f"• <b>{vendor}</b>: {category}", normal_style))
        story.append(Spacer(1, 8))

    # ===== HTTP RESPONSE =====
    http_info = iocs.get("vt_http_response", {})
    if http_info and http_info.get("status_code"):
        story.append(Paragraph("Last HTTP Response", subheading_style))
        http_rows = [["Status", "Server", "Content-Type", "Content-Length"]]
        http_rows.append([
            str(http_info.get("status_code", "N/A")),
            str(http_info.get("server", "N/A") or "N/A"),
            str(http_info.get("content_type", "N/A") or "N/A")[:50],
            str(http_info.get("content_length", "N/A")),
        ])
        http_tbl = Table(http_rows, colWidths=[55, 140, 200, 115])
        http_tbl.setStyle(_table_style(header_color="#555"))
        story.append(http_tbl)
        story.append(Spacer(1, 8))

    # ===== DOM HEURISTICS =====
    dom_heuristics = iocs.get("dom_heuristics")
    if dom_heuristics:
        story.append(Paragraph("Zero-Day DOM Heuristics", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))
        story.append(Paragraph(str(dom_heuristics), normal_style))
        story.append(Spacer(1, 10))

    # ===== REDIRECT CHAIN =====
    redirect_chain = iocs.get("redirect_chain", [])
    if redirect_chain:
        story.append(Paragraph("Redirect Chain", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))
        for idx, link in enumerate(redirect_chain):
            prefix = "   → " if idx > 0 else "[1] "
            prefix = f"[{idx+1}] " if idx == 0 else f"  ↓  [{idx+1}] "
            story.append(Paragraph(f"{prefix}{link}", code_style))
        story.append(Spacer(1, 10))

    # ===== EXTRACTED IOCs =====
    story.append(Paragraph("Extracted IOCs", heading_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))
    ioc_data = [["Type", "Value", "AbuseIPDB Score"]]
    abuse_score = str(details.get("abuseipdb", {}).get("abuseConfidenceScore", "N/A"))
    for ip in iocs.get("ips", []):
        ioc_data.append([_cp("IP"), _cp(ip), _cp(abuse_score)])
    for d in iocs.get("domains", []):
        ioc_data.append([_cp("Domain"), _cp(d), _cp("N/A")])
    for h in iocs.get("hashes", []):
        ioc_data.append([_cp("Hash"), _cp(h), _cp("N/A")])
    for e in iocs.get("emails", []):
        ioc_data.append([_cp("Email"), _cp(e), _cp("N/A")])

    if len(ioc_data) > 1:
        ioc_table = Table(ioc_data, colWidths=[70, 360, 80])
        ioc_table.setStyle(_table_style(header_color="#333333", alt_row="#f5f5f5"))
        story.append(ioc_table)
    else:
        story.append(Paragraph("No IOCs extracted.", caption_style))
    story.append(Spacer(1, 12))

    # ===== WHOIS =====
    whois_data = details.get("whois", {})
    if whois_data:
        story.append(Paragraph("WHOIS Information", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))
        whois_rows = [[_cp(str(k)), _cp(str(v))] for k, v in whois_data.items()]
        if whois_rows:
            whois_table = Table([["Field", "Value"]] + whois_rows, colWidths=[140, 370])
            whois_table.setStyle(_table_style(header_color="#1a1714", alt_row="#f9f7f3"))
            story.append(whois_table)
        story.append(Spacer(1, 8))

    # ===== SSL CERTIFICATE =====
    ssl_info = iocs.get("ssl_info", {})
    if ssl_info:
        story.append(Paragraph("SSL Certificate", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))
        ssl_fields = [
            ("Issuer",       ssl_info.get("issuer", "N/A")),
            ("Subject",      ssl_info.get("subject", "N/A")),
            ("Valid From",   ssl_info.get("validity_not_before", "N/A")),
            ("Valid To",     ssl_info.get("validity_not_after", "N/A")),
            ("Serial",       ssl_info.get("serial_number", "N/A")),
            ("Thumbprint",   ssl_info.get("thumbprint", "N/A")),
        ]
        san = ssl_info.get("san_domains", [])
        if san:
            ssl_fields.append(("SAN Domains", ", ".join(san[:10])))
        ssl_rows = [[_cp(f), _cp(str(v))] for f, v in ssl_fields if v and v != "N/A"]
        if ssl_rows:
            ssl_table = Table([["Field", "Value"]] + ssl_rows, colWidths=[100, 410])
            ssl_table.setStyle(_table_style(header_color="#1565C0", alt_row="#e8f4fd"))
            story.append(ssl_table)
        story.append(Spacer(1, 10))

    # ===== ABUSEIPDB =====
    abuse = details.get("abuseipdb", {})
    if abuse:
        story.append(Paragraph("AbuseIPDB Intelligence", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))
        abuse_rows = [["Abuse Score", "Country", "ISP", "Usage Type", "Total Reports", "Last Reported"]]
        abuse_rows.append([
            _cp(f"{abuse.get('abuseConfidenceScore', 'N/A')}%"),
            _cp(abuse.get("countryCode", "N/A")),
            _cp(str(abuse.get("isp", "N/A"))),
            _cp(str(abuse.get("usageType", "N/A"))),
            _cp(str(abuse.get("totalReports", "N/A"))),
            _cp(str(abuse.get("lastReportedAt", "N/A"))[:20]),
        ])
        abuse_tbl = Table(abuse_rows, colWidths=[70, 50, 130, 100, 70, 90])
        abuse_tbl.setStyle(_table_style(header_color="#c33", alt_row="#fff5f5"))
        story.append(abuse_tbl)
        story.append(Spacer(1, 10))

    # ===== THREATFOX IOCs =====
    threatfox = iocs.get("threatfox", [])
    if not threatfox:
        threatfox = details.get("threatfox", [])
    if threatfox:
        story.append(Paragraph("ThreatFox IOC Intelligence", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))
        tf_rows = [["IOC Value", "Threat Type", "Malware", "Confidence", "First Seen"]]
        for hit in threatfox[:20]:
            tf_rows.append([
                _cp(str(hit.get("ioc_value", "N/A"))),
                _cp(str(hit.get("threat_type", "N/A"))),
                _cp(str(hit.get("malware", "N/A"))),
                _cp(str(hit.get("confidence_level", "N/A"))),
                _cp(str(hit.get("first_seen", "N/A"))[:20]),
            ])
        tf_tbl = Table(tf_rows, colWidths=[155, 90, 110, 60, 95])
        tf_tbl.setStyle(_table_style(header_color="#b71c1c", alt_row="#fff5f5"))
        story.append(tf_tbl)
        story.append(Spacer(1, 10))

    # ===== OTX THREAT INTELLIGENCE =====
    otx = details.get("alienvault_otx", {})
    if otx:
        pulse_info  = otx.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0) or 0
        reputation  = otx.get("reputation", "N/A")
        pulses      = pulse_info.get("pulses", [])[:10]
        story.append(Paragraph("AlienVault OTX Threat Intelligence", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))
        story.append(Paragraph(
            f"<b>Pulse Count:</b> {pulse_count}  &nbsp;|&nbsp;  <b>Reputation:</b> {reputation}",
            normal_style,
        ))
        story.append(Spacer(1, 6))
        if pulses:
            pulse_rows = [["Pulse Name", "Tags", "Author", "TLP"]]
            for p in pulses:
                tags = ", ".join(p.get("tags", [])[:5]) or "—"
                pulse_rows.append([
                    _cp(p.get("name", "Unnamed")),
                    _cp(tags),
                    _cp(p.get("author_name", "N/A")),
                    _cp((p.get("tlp") or "white").upper()),
                ])
            pulse_tbl = Table(pulse_rows, colWidths=[200, 150, 110, 50])
            pulse_tbl.setStyle(_table_style(header_color="#1565C0", alt_row="#e8f4fd"))
            story.append(pulse_tbl)
        else:
            story.append(Paragraph("No OTX pulses reference this target.", caption_style))
        story.append(Spacer(1, 10))

    # ===== FOOTER =====
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#ddd5c8"), spaceAfter=8))
    story.append(Paragraph(
        f"Lumina Shield  \u00a9 2026  \u00b7  AI-Powered Cyber Forensic Report  \u00b7  "
        f"Generated {datetime.now().strftime('%d %b %Y %H:%M')} UTC  \u00b7  "
        "Verify all findings independently before taking action.",
        footer_style,
    ))

    doc.build(story)
    return path


# ──────────────────────────────────────────────────────────────────────────
# Deep Intelligence PDF (Cyber Analyst Deep Mode)
# Includes all basic forensics sections PLUS threat actor profile, MITRE
# ATT&CK mapping, kill-chain timeline, YARA/Snort rules, and annotations.
# ──────────────────────────────────────────────────────────────────────────

def generate_deep_pdf(
    target: str,
    iocs: dict = None,
    summary_text: str = None,
    narrative_data: dict = None,
    actor_profile: dict = None,
    kill_chain_data: dict = None,
    yara_rule: str = None,
    snort_rule: str = None,
    annotations: list = None,
) -> str:
    """Generate a comprehensive deep-mode forensic PDF report."""
    iocs = iocs or {}
    tmp_dir = tempfile.gettempdir()
    filename = f"lumina_deep_{hashlib.md5(target.encode()).hexdigest()}.pdf"
    path = os.path.join(tmp_dir, filename)

    doc = SimpleDocTemplate(path, pagesize=A4,
                            topMargin=40, bottomMargin=40,
                            leftMargin=40, rightMargin=40)
    styles = getSampleStyleSheet()

    # ── Shared styles (same palette as generate_pdf) ───────────────────────
    title_style = ParagraphStyle('DTitle', parent=styles['Title'],
        fontSize=22, textColor=colors.HexColor("#c88b00"), spaceAfter=4, leading=28)
    subtitle_style = ParagraphStyle('DSubtitle', parent=styles['Normal'],
        fontSize=9, textColor=colors.HexColor("#7a7268"), spaceAfter=2)
    heading_style = ParagraphStyle('DH2', parent=styles['Heading2'],
        fontSize=13, textColor=colors.HexColor("#1a1714"), spaceBefore=18, spaceAfter=6)
    subheading_style = ParagraphStyle('DH3', parent=styles['Heading3'],
        fontSize=11, textColor=colors.HexColor("#c88b00"), spaceBefore=10, spaceAfter=4)
    deep_heading_style = ParagraphStyle('DH2Deep', parent=styles['Heading2'],
        fontSize=13, textColor=colors.HexColor("#b71c1c"), spaceBefore=18, spaceAfter=6)
    normal_style = ParagraphStyle('DNormal', parent=styles['Normal'],
        fontSize=9, textColor=colors.HexColor("#1a1714"), leading=14)
    caption_style = ParagraphStyle('DCaption', parent=styles['Normal'],
        fontSize=8, textColor=colors.HexColor("#7a7268"), leading=12)
    code_style = ParagraphStyle('DCode', parent=styles['Normal'],
        fontSize=8, textColor=colors.HexColor("#1a1714"),
        fontName='Courier', leading=12, leftIndent=10)
    cell_style = ParagraphStyle('DCell', parent=styles['Normal'],
        fontSize=8, textColor=colors.HexColor("#1a1714"), leading=11)
    footer_style = ParagraphStyle('DFooter', parent=styles['Normal'],
        fontSize=8, textColor=colors.HexColor("#a09585"), leading=11)

    import re as _re

    def _md_to_rl(text: str) -> str:
        text = _re.sub(r'<[^>]+>', '', str(text)).strip()
        text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        parts = _re.split(r'\*\*(.+?)\*\*', text)
        result = parts[0]
        for i in range(1, len(parts), 2):
            bold_text = parts[i]
            after = parts[i + 1] if i + 1 < len(parts) else ''
            prefix = '<br/>' if result.strip() else ''
            result += f'{prefix}<b>{bold_text}</b>{after}'
        text = result
        text = _re.sub(r'(?m)^\s*-\s+', '<br/>\u2022\u00a0', text)
        text = text.replace('\n', '<br/>')
        text = _re.sub(r'(<br/>){2,}', '<br/>', text)
        return text

    def _cp(text: str) -> 'Paragraph':
        return Paragraph(_md_to_rl(str(text)), cell_style)

    def _table_style(header_color="#E5A100", alt_row="#FFF8E7"):
        return TableStyle([
            ('BACKGROUND',    (0, 0), (-1,  0), colors.HexColor(header_color)),
            ('TEXTCOLOR',     (0, 0), (-1,  0), colors.white),
            ('FONTSIZE',      (0, 0), (-1,  0), 9),
            ('FONTNAME',      (0, 0), (-1,  0), 'Helvetica-Bold'),
            ('FONTSIZE',      (0, 1), (-1, -1), 8),
            ('ALIGN',         (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN',        (0, 0), (-1,  0), 'MIDDLE'),
            ('VALIGN',        (0, 1), (-1, -1), 'TOP'),
            ('GRID',          (0, 0), (-1, -1), 0.4, colors.HexColor("#ddd5c8")),
            ('ROWBACKGROUNDS',(0, 1), (-1, -1), [colors.white, colors.HexColor(alt_row)]),
            ('TOPPADDING',    (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        ])

    from reportlab.platypus import HRFlowable
    story = []

    # ===== COVER =====
    story.append(Paragraph("Lumina Shield — Deep Intelligence Report", title_style))
    story.append(Paragraph(f"Target: {target}", subtitle_style))
    story.append(Paragraph("Mode: Cyber Analyst · Deep Mode", subtitle_style))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%d %b %Y  %H:%M:%S UTC')}", subtitle_style))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#E5A100"), spaceAfter=10))

    # ===== RISK SCORE (basic forensics) =====
    risk = iocs.get('risk_score', 0)
    severity = "LOW" if risk < 3 else "MEDIUM" if risk < 6 else "HIGH" if risk < 8 else "CRITICAL"
    sev_color = "#4CAF50" if risk < 3 else "#FF9800" if risk < 6 else "#f44336" if risk < 8 else "#b71c1c"
    risk_data = [["Risk Score", "Severity", "Target"],
                 [f"{risk} / 10", severity, target[:80]]]
    rt = Table(risk_data, colWidths=[80, 100, 330])
    rt.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0),  colors.HexColor("#1a1714")),
        ('TEXTCOLOR',     (0, 0), (-1, 0),  colors.white),
        ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, 0),  9),
        ('FONTSIZE',      (0, 1), (-1, -1), 10),
        ('FONTNAME',      (0, 1), (0,  1),  'Helvetica-Bold'),
        ('TEXTCOLOR',     (0, 1), (0,  1),  colors.HexColor(sev_color)),
        ('TEXTCOLOR',     (1, 1), (1,  1),  colors.HexColor(sev_color)),
        ('ALIGN',         (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID',          (0, 0), (-1, -1), 0.4, colors.HexColor("#ddd5c8")),
        ('TOPPADDING',    (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING',   (0, 0), (-1, -1), 8),
    ]))
    story.append(rt)
    story.append(Spacer(1, 14))

    # ===== AI EXECUTIVE SUMMARY =====
    if summary_text:
        story.append(Paragraph("AI Executive Summary", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))
        story.append(Paragraph(_md_to_rl(str(summary_text)), normal_style))
        story.append(Spacer(1, 10))

    # ===== NARRATIVE INTELLIGENCE =====
    if narrative_data and not narrative_data.get("error") and narrative_data.get("scenarios"):
        story.append(Paragraph("Narrative Intelligence", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))
        archetype      = narrative_data.get("campaign_archetype", "Unknown")
        target_profile = narrative_data.get("target_profile",     "Unknown")
        narrative_text = narrative_data.get("narrative", "")
        ci_low         = narrative_data.get("risk_confidence_low",  "—")
        ci_high        = narrative_data.get("risk_confidence_high", "—")
        if narrative_text:
            story.append(Paragraph(_md_to_rl(str(narrative_text)), normal_style))
            story.append(Spacer(1, 6))
        meta_data = [["Campaign Archetype", "Target Profile", "Risk Confidence Range"],
                     [_cp(archetype), _cp(target_profile), _cp(f"{ci_low} – {ci_high} / 10")]]
        mt = Table(meta_data, colWidths=[170, 170, 170])
        mt.setStyle(_table_style(header_color="#c88b00", alt_row="#fffdf5"))
        story.append(mt)
        story.append(Spacer(1, 8))
        scenarios = narrative_data.get("scenarios", [])
        if scenarios:
            story.append(Paragraph("Attack Scenario Probabilities", subheading_style))
            sc_data = [["Scenario", "Probability", "Description"]]
            for sc in scenarios:
                sc_data.append([_cp(f"{sc.get('icon','')} {sc.get('name','')}"),
                                 _cp(f"{sc.get('probability', 0)}%"),
                                 _cp(sc.get("description", ""))])
            sc_t = Table(sc_data, colWidths=[160, 60, 290])
            sc_t.setStyle(_table_style(header_color="#c88b00", alt_row="#fffdf5"))
            story.append(sc_t)
        story.append(Spacer(1, 10))

    # ===== VIRUSTOTAL =====
    vt_stats = iocs.get("vt_stats", {})
    if vt_stats:
        story.append(Paragraph("VirusTotal Detection Summary", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))
        mal   = vt_stats.get("malicious",  0)
        sus   = vt_stats.get("suspicious", 0)
        harm  = vt_stats.get("harmless",   0)
        undet = vt_stats.get("undetected", 0)
        total = mal + sus + harm + undet
        vt_sum = [["Malicious", "Suspicious", "Harmless", "Undetected", "Total"],
                  [str(mal), str(sus), str(harm), str(undet), str(total)]]
        vt_t = Table(vt_sum, colWidths=[100, 100, 100, 100, 110])
        vt_t.setStyle(_table_style(header_color="#c33"))
        story.append(vt_t)
        story.append(Spacer(1, 8))

    # ===== EXTRACTED IOCs =====
    story.append(Paragraph("Extracted IOCs", heading_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))
    details = iocs.get("details", {})
    abuse_score = str(details.get("abuseipdb", {}).get("abuseConfidenceScore", "N/A"))
    ioc_data = [["Type", "Value", "AbuseIPDB Score"]]
    for ip in iocs.get("ips",    []): ioc_data.append([_cp("IP"),     _cp(ip), _cp(abuse_score)])
    for d  in iocs.get("domains",[]): ioc_data.append([_cp("Domain"), _cp(d),  _cp("N/A")])
    for h  in iocs.get("hashes", []): ioc_data.append([_cp("Hash"),   _cp(h),  _cp("N/A")])
    for e  in iocs.get("emails", []): ioc_data.append([_cp("Email"),  _cp(e),  _cp("N/A")])
    if len(ioc_data) > 1:
        ioc_t = Table(ioc_data, colWidths=[70, 360, 80])
        ioc_t.setStyle(_table_style(header_color="#333333", alt_row="#f5f5f5"))
        story.append(ioc_t)
    else:
        story.append(Paragraph("No IOCs extracted.", caption_style))
    story.append(Spacer(1, 12))

    # ===== SSL =====
    ssl_info = iocs.get("ssl_info", {})
    if ssl_info:
        story.append(Paragraph("SSL Certificate", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))
        ssl_fields = [
            ("Issuer", ssl_info.get("issuer", "N/A")),
            ("Subject", ssl_info.get("subject", "N/A")),
            ("Valid From", ssl_info.get("validity_not_before", "N/A")),
            ("Valid To", ssl_info.get("validity_not_after", "N/A")),
            ("Serial", ssl_info.get("serial_number", "N/A")),
        ]
        san = ssl_info.get("san_domains", [])
        if san:
            ssl_fields.append(("SAN Domains", ", ".join(san[:10])))
        ssl_rows = [[_cp(f), _cp(str(v))] for f, v in ssl_fields if v and v != "N/A"]
        if ssl_rows:
            ssl_t = Table([["Field", "Value"]] + ssl_rows, colWidths=[100, 410])
            ssl_t.setStyle(_table_style(header_color="#1565C0", alt_row="#e8f4fd"))
            story.append(ssl_t)
        story.append(Spacer(1, 10))

    # ===== OTX =====
    otx = details.get("alienvault_otx", {})
    if otx:
        pulse_count = otx.get("pulse_info", {}).get("count", 0) or 0
        pulses = otx.get("pulse_info", {}).get("pulses", [])[:8]
        story.append(Paragraph("AlienVault OTX Threat Intelligence", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))
        story.append(Paragraph(f"<b>Pulse Count:</b> {pulse_count}", normal_style))
        if pulses:
            pulse_rows = [["Pulse Name", "Tags", "TLP"]]
            for p in pulses:
                tags = ", ".join(p.get("tags", [])[:5]) or "—"
                pulse_rows.append([_cp(p.get("name", "Unnamed")), _cp(tags),
                                    _cp((p.get("tlp") or "white").upper())])
            pt = Table(pulse_rows, colWidths=[230, 180, 100])
            pt.setStyle(_table_style(header_color="#1565C0", alt_row="#e8f4fd"))
            story.append(pt)
        story.append(Spacer(1, 10))

    # ══════════════════════════════════════════════════════════════════════
    # DEEP MODE SECTIONS
    # ══════════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#b71c1c"), spaceAfter=4))
    story.append(Paragraph("▌ Deep Intelligence Analysis", deep_heading_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#b71c1c"), spaceAfter=10))

    # ===== THREAT ACTOR PROFILE =====
    if actor_profile and not actor_profile.get("error"):
        story.append(Paragraph("Threat Actor Profile", deep_heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))

        threat_level = actor_profile.get("threat_level", "Unknown")
        motivation   = actor_profile.get("motivation",    "Unknown")
        narrative_ap = actor_profile.get("campaign_narrative", "")
        tl_data = [["Threat Level", "Motivation"],
                   [_cp(threat_level), _cp(motivation)]]
        tl_t = Table(tl_data, colWidths=[255, 255])
        tl_t.setStyle(_table_style(header_color="#b71c1c", alt_row="#fff5f5"))
        story.append(tl_t)
        story.append(Spacer(1, 6))

        if narrative_ap:
            story.append(Paragraph("Campaign Narrative", subheading_style))
            story.append(Paragraph(_md_to_rl(narrative_ap), normal_style))
            story.append(Spacer(1, 8))

        candidates = actor_profile.get("threat_actor_candidates", [])
        if candidates:
            story.append(Paragraph("Threat Actor Candidates", subheading_style))
            cand_data = [["Actor", "Confidence", "Reasoning"]]
            for c in candidates:
                cand_data.append([_cp(c.get("name", "?")),
                                   _cp(c.get("confidence", "?")),
                                   _cp(c.get("reasoning", ""))])
            cand_t = Table(cand_data, colWidths=[120, 70, 320])
            cand_t.setStyle(_table_style(header_color="#b71c1c", alt_row="#fff5f5"))
            story.append(cand_t)
            story.append(Spacer(1, 8))

        # MITRE ATT&CK Tactics
        tactics = actor_profile.get("mitre_tactics", [])
        if tactics:
            story.append(Paragraph("MITRE ATT&CK Tactics", subheading_style))
            story.append(Paragraph(", ".join(tactics), normal_style))
            story.append(Spacer(1, 6))

        # MITRE ATT&CK Techniques
        techniques = actor_profile.get("mitre_techniques", [])
        if techniques:
            story.append(Paragraph("MITRE ATT&CK Techniques", subheading_style))
            tech_data = [["ID", "Technique", "Relevance"]]
            for t in techniques:
                tech_data.append([_cp(t.get("id", "?")),
                                   _cp(t.get("name", "?")),
                                   _cp(t.get("relevance", ""))])
            tech_t = Table(tech_data, colWidths=[70, 160, 280])
            tech_t.setStyle(_table_style(header_color="#555", alt_row="#f9f7f3"))
            story.append(tech_t)
            story.append(Spacer(1, 8))

        # Recommended detections
        detections = actor_profile.get("recommended_detections", [])
        if detections:
            story.append(Paragraph("Recommended Detections", subheading_style))
            for d in detections:
                story.append(Paragraph(f"• {_md_to_rl(str(d))}", normal_style))
            story.append(Spacer(1, 8))

    # ===== KILL-CHAIN TIMELINE =====
    if kill_chain_data and not kill_chain_data.get("error"):
        story.append(Paragraph("Behavioral Kill-Chain Reconstruction", deep_heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))

        kc_narrative = kill_chain_data.get("narrative", "")
        kc_duration  = kill_chain_data.get("attack_duration_estimate", "Unknown")
        if kc_narrative:
            story.append(Paragraph(_md_to_rl(kc_narrative), normal_style))
        story.append(Paragraph(f"<b>Estimated Duration:</b> {kc_duration}", normal_style))
        story.append(Spacer(1, 6))

        phases = kill_chain_data.get("phases", [])
        if phases:
            phase_data = [["Phase", "Confidence", "Evidence"]]
            for ph in phases:
                phase_data.append([
                    _cp(f"{ph.get('icon','')} {ph.get('phase','?')}"),
                    _cp(ph.get("confidence", "?")),
                    _cp(ph.get("evidence", "")),
                ])
            ph_t = Table(phase_data, colWidths=[130, 70, 310])
            ph_t.setStyle(_table_style(header_color="#b71c1c", alt_row="#fff5f5"))
            story.append(ph_t)
        story.append(Spacer(1, 10))

    # ===== YARA RULE =====
    if yara_rule and yara_rule.strip():
        story.append(Paragraph("Generated YARA Rule", deep_heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))
        for line in yara_rule.splitlines():
            story.append(Paragraph(line.replace(' ', '\u00a0'), code_style))
        story.append(Spacer(1, 10))

    # ===== SNORT / SURICATA RULES =====
    if snort_rule and snort_rule.strip():
        story.append(Paragraph("Generated Snort / Suricata Rules", deep_heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))
        for line in snort_rule.splitlines():
            story.append(Paragraph(line.replace(' ', '\u00a0'), code_style))
        story.append(Spacer(1, 10))

    # ===== RESEARCH ANNOTATIONS =====
    if annotations:
        story.append(Paragraph("Research Annotations", deep_heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ddd5c8"), spaceAfter=6))
        ann_data = [["Timestamp", "Tags", "Note"]]
        for a in annotations:
            ann_data.append([_cp(str(a.get("timestamp", ""))[:19]),
                             _cp(str(a.get("tags", ""))),
                             _cp(str(a.get("note", "")))])
        ann_t = Table(ann_data, colWidths=[110, 100, 300])
        ann_t.setStyle(_table_style(header_color="#4a5568", alt_row="#f7fafc"))
        story.append(ann_t)
        story.append(Spacer(1, 10))

    # ===== FOOTER =====
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#ddd5c8"), spaceAfter=8))
    story.append(Paragraph(
        f"Lumina Shield \u00a9 2026  \u00b7  Deep Intelligence Report  \u00b7  "
        f"Generated {datetime.now().strftime('%d %b %Y %H:%M')} UTC  \u00b7  "
        "Verify all findings independently before taking action.",
        footer_style,
    ))

    doc.build(story)
    return path