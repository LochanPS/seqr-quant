import io
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = Path(__file__).parent / "templates"
env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))


def render_html(template_name: str, context: dict) -> str:
    return env.get_template(template_name).render(**context)


def html_to_pdf(html: str) -> bytes:
    try:
        import weasyprint
        return weasyprint.HTML(string=html).write_pdf()
    except Exception as e:
        raise RuntimeError(f"WeasyPrint unavailable: {e}")


# ── Shared style/color helpers ────────────────────────────────────────────────
# SeQr design system (matches landing + dashboard tokens):
#   amber #D7A352 accent · slate-900 ink · slate-50/200 surfaces ·
#   near-black #0A0A0A + cream #EDE7DC cover · emerald/rose/amber/violet status.

INK = "#0F172A"          # slate-900 — primary text / headers (was navy)
AMBER = "#D7A352"        # SeQr brand accent (was red)
SLATE_BG = "#F8FAFC"     # slate-50 — zebra rows
BORDER = "#E2E8F0"       # slate-200 — hairlines
MUTED = "#64748B"        # slate-500 — secondary text
NEAR_BLACK = "#0A0A0A"   # cover background
CREAM = "#EDE7DC"        # cover text

# Brand semantic colors (match dashboard).
SAFE = "#10B981"         # emerald
VULN = "#F43F5E"         # rose
URGENT_C = "#F59E0B"     # amber
PLANNED_C = "#8B5CF6"    # violet

# Deeper "print" shades for status TEXT in the report (restrained, audit-document feel).
P_GREEN = "#047857"      # emerald-700
P_RED = "#B91C1C"        # red-700
P_AMBER = "#B45309"      # amber-700
P_VIOLET = "#6D28D9"     # violet-700
P_SLATE = "#475569"      # slate-600

# Back-compat names (NAVY/RED/GREY_BG referenced elsewhere)
NAVY = INK
RED = AMBER
GREY_BG = SLATE_BG


def _rl_colors():
    """Returns (ink, amber, white) — kept as a 3-tuple for existing call sites."""
    from reportlab.lib import colors
    return (
        colors.HexColor(INK),
        colors.HexColor(AMBER),
        colors.white,
    )


_FW_DISPLAY = {
    "PCI_DSS_12_3_3": "PCI DSS 12.3.3",
    "PCI_DSS_4X": "PCI DSS 12.3.3",
    "SEBI_CSCRF": "SEBI CSCRF",
    "RBI_IT_FRAMEWORK": "RBI Q-SAFE",
    "NIST_FIPS": "NIST FIPS 203/204",
    "NIST_FIPS_203_204": "NIST FIPS 203/204",
    "DST_TASK_FORCE_2026": "DST Task Force",
    "DPDP_2023": "DPDP Act 2023 §8",
    "CERT_IN": "CERT-In",
}


def _fw_display(name: str) -> str:
    return _FW_DISPLAY.get(name, name.replace("_", " "))


# Make the framework display-name map available to the HTML (WeasyPrint) templates.
env.filters["fw_display"] = _fw_display


def _compliance_names(compliance: dict) -> str:
    names = [_fw_display(k) for k in compliance.keys()]
    if not names:
        return "PCI DSS 12.3.3, SEBI CSCRF and the DST Task Force roadmap"
    if len(names) <= 2:
        return " and ".join(names)
    return ", ".join(names[:-1]) + f" and {names[-1]}"


def _methodology_flowables(styles, generated_at):
    """Audit-grade provenance: how the assessment was measured. Shared by both reports."""
    from reportlab.platypus import Paragraph, Spacer, HRFlowable
    from reportlab.lib import colors
    out = [
        Paragraph("Methodology &amp; Provenance", styles["section_h"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor(AMBER), spaceAfter=8),
    ]
    lines = [
        "<b>Tool:</b> SeQr scanner — sslyze 6.0 for passive TLS analysis and an "
        "OpenSSL 3.5+ ML-KEM ClientHello for <b>active</b> post-quantum detection "
        "(passive scanning alone cannot confirm hybrid PQC support).",
        "<b>Method:</b> passive measurement plus an active key-exchange probe. No "
        "authentication, no exploitation, no data exfiltration — equivalent to a single "
        "ordinary client connection, rate-limited.",
        "<b>Coverage:</b> TLS (443), SSH key exchange + host keys (22), mail STARTTLS "
        "(SMTP / IMAP / POP3), and database TLS (PostgreSQL).",
        "<b>Scan confidence:</b> high = direct connection; medium = cloud-provider IP; "
        "low = CDN-terminated (origin configuration is not externally observable).",
        "<b>Not assessed:</b> origin servers behind CDNs, application-layer data handling, "
        "and internal / non-public services.",
        f"<b>Assessment date:</b> {generated_at}.",
    ]
    for ln in lines:
        out.append(Paragraph(ln, styles["small"]))
        out.append(Spacer(1, 3))
    return out


_RISK_BAND = {"low": P_GREEN, "medium": P_AMBER, "high": P_RED, "critical": P_RED}


def _styles():
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER

    navy, red, white = _rl_colors()
    ss = getSampleStyleSheet()

    def p(name, **kw):
        return ParagraphStyle(name, parent=ss["Normal"], **kw)

    return {
        "section_h": p("SectionH", textColor=navy, fontSize=13,
                        fontName="Helvetica-Bold", spaceBefore=16, spaceAfter=4),
        "h3": p("H3", textColor=navy, fontSize=10,
                fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4),
        "body": p("Body", fontSize=9, leading=13),
        "small": p("Small", fontSize=8, leading=11, textColor=colors.grey),
        "score": p("Score", fontSize=40, leading=44, textColor=colors.HexColor(INK),
                   alignment=TA_CENTER, fontName="Helvetica-Bold"),
        "label": p("Label", fontSize=9, textColor=colors.HexColor(MUTED), alignment=TA_CENTER),
        "confidential": p("Conf", fontSize=8, textColor=colors.HexColor(MUTED),
                           alignment=TA_CENTER, spaceBefore=20),
    }


def _tbl_style():
    from reportlab.platypus import TableStyle
    from reportlab.lib import colors
    ink, amber, white = _rl_colors()
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ink),
        ("TEXTCOLOR", (0, 0), (-1, 0), white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor(SLATE_BG)]),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor(BORDER)),
        ("LINEAFTER", (0, 0), (-2, -1), 0.4, colors.HexColor(BORDER)),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ])


# ── Cover page canvas draw ────────────────────────────────────────────────────

def _draw_cover(canvas_obj, doc_obj, org_name: str, subtitle: str,
                generated_at: str, meta_lines: list[str]):
    from reportlab.lib import colors
    W, H = doc_obj.pagesize
    amber = colors.HexColor(AMBER)
    cream = colors.HexColor(CREAM)
    cream_muted = colors.HexColor("#9A958B")  # cream at ~60% — secondary text

    canvas_obj.saveState()
    # Near-black background (matches the landing hero)
    canvas_obj.setFillColor(colors.HexColor(NEAR_BLACK))
    canvas_obj.rect(0, 0, W, H, fill=1, stroke=0)

    # Eyebrow — amber, restrained
    canvas_obj.setFillColor(amber)
    canvas_obj.setFont("Helvetica-Bold", 8.5)
    canvas_obj.drawString(50, H - 60, "SeQr Labs  ·  POST-QUANTUM ASSESSMENT  ·  CONFIDENTIAL")

    # Title block
    canvas_obj.setFillColor(cream)
    canvas_obj.setFont("Helvetica-Bold", 26)
    canvas_obj.drawString(50, H / 2 + 72, "Post-Quantum Cryptography")
    canvas_obj.setFillColor(amber)
    canvas_obj.setFont("Helvetica-Bold", 17)
    canvas_obj.drawString(50, H / 2 + 46, subtitle)
    canvas_obj.setFillColor(cream)
    canvas_obj.setFont("Helvetica", 13)
    canvas_obj.drawString(50, H / 2 + 16, org_name)

    # Single thin amber divider — the only "gold", deliberately understated
    canvas_obj.setStrokeColor(amber)
    canvas_obj.setLineWidth(1.2)
    canvas_obj.line(50, H / 2, 230, H / 2)

    # Meta block
    canvas_obj.setFillColor(cream_muted)
    canvas_obj.setFont("Helvetica", 9.5)
    y = H / 2 - 26
    for line in meta_lines:
        canvas_obj.drawString(50, y, line)
        y -= 16

    # Bottom confidential
    canvas_obj.setFillColor(colors.HexColor("#6B6760"))
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.drawString(50, 34, f"CONFIDENTIAL — SeQr Labs — {org_name}")
    canvas_obj.restoreState()


def _draw_footer(canvas_obj, doc_obj, org_name: str):
    from reportlab.lib import colors
    W, H = doc_obj.pagesize
    canvas_obj.saveState()
    canvas_obj.setStrokeColor(colors.HexColor(BORDER))
    canvas_obj.setLineWidth(0.5)
    canvas_obj.line(45, 42, W - 45, 42)
    canvas_obj.setFillColor(colors.HexColor(MUTED))
    canvas_obj.setFont("Helvetica", 7)
    canvas_obj.drawString(45, 30, f"SeQr Labs — Confidential — {org_name}")
    canvas_obj.drawRightString(W - 45, 30, f"Page {doc_obj.page}")
    canvas_obj.restoreState()


# ── ReportLab Platypus builders ───────────────────────────────────────────────

def _rl_executive_summary(ctx: dict) -> bytes:
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, PageBreak, HRFlowable,
    )
    from reportlab.platypus import TableStyle as TS
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors

    navy, red, white = _rl_colors()
    W, H = A4
    buf = io.BytesIO()
    styles = _styles()

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=45, rightMargin=45, topMargin=50, bottomMargin=55,
    )
    org = ctx["org_name"]

    def on_cover(c, d):
        _draw_cover(c, d, org, "Risk Assessment — Executive Summary",
                    ctx["generated_at"], [
                        f"Organisation: {org}",
                        f"Assets Scanned: {ctx['total_assets']}",
                        f"Generated: {ctx['generated_at']}",
                        f"Report ID: {ctx['report_id']}",
                    ])

    def on_later(c, d):
        _draw_footer(c, d, org)

    story = [PageBreak()]

    # ── Executive Summary ─────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", styles["section_h"]))
    story.append(HRFlowable(width="100%", thickness=2, color=red, spaceAfter=10))

    risk_label = ctx["risk_label"].upper()
    bc = _RISK_BAND.get(ctx["risk_label"].lower(), MUTED)

    score_cell = [
        Paragraph("Quantum Risk Score", styles["label"]),
        Paragraph(f'<font color="{bc}">{ctx["risk_score"]}</font>', styles["score"]),
        Paragraph("out of 100", styles["label"]),
        Spacer(1, 4),
        Paragraph(f'<font color="{bc}"><b>{risk_label}</b></font>', styles["label"]),
    ]
    findings_cell = [
        Paragraph("<b>Key Findings</b>", styles["h3"]),
        Spacer(1, 4),
        Paragraph(f'• {ctx["vulnerable_count"]} quantum-vulnerable cryptographic components identified', styles["body"]),
        Paragraph(f'• {ctx["hndl_count"]} component(s) at Harvest-Now Decrypt-Later risk', styles["body"]),
        Paragraph(f'• {ctx["immediate_count"]} finding(s) require immediate action', styles["body"]),
        Paragraph(f'• Mapped to {_compliance_names(ctx.get("compliance", {}))}', styles["body"]),
    ]

    kf_tbl = Table([[score_cell, findings_cell]], colWidths=[140, W - 275])
    kf_tbl.setStyle(TS([
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#f0f4fa")),
    ]))
    story.append(kf_tbl)
    story.append(Spacer(1, 14))

    # ── Compliance ────────────────────────────────────────────────────────────
    story.append(Paragraph("Compliance Status", styles["section_h"]))
    story.append(HRFlowable(width="100%", thickness=2, color=red, spaceAfter=8))

    status_colors = {
        "PASS": P_GREEN, "FAIL": P_RED, "PARTIAL": P_AMBER,
        "PLANNED": P_AMBER, "MONITOR": P_SLATE,
    }
    comp_rows = [["Framework", "Status", "Notes"]]
    for fw, data in ctx["compliance"].items():
        st = data["status"] if isinstance(data, dict) else data.status
        msg = data["message"] if isinstance(data, dict) else data.message
        sc = status_colors.get(st, MUTED)
        comp_rows.append([
            Paragraph(f'<b>{_fw_display(fw)}</b>', styles["small"]),
            Paragraph(f'<font color="{sc}"><b>{st}</b></font>', styles["body"]),
            Paragraph(msg or "", styles["small"]),
        ])

    comp_tbl = Table(comp_rows, colWidths=[108, 74, W - 272])
    comp_tbl.setStyle(_tbl_style())
    story.append(comp_tbl)
    story.append(Spacer(1, 14))

    # ── Top 5 actions ─────────────────────────────────────────────────────────
    story.append(Paragraph("Top 5 Priority Actions", styles["section_h"]))
    story.append(HRFlowable(width="100%", thickness=2, color=red, spaceAfter=8))

    tl_colors = {
        "IMMEDIATE": P_RED, "URGENT": P_AMBER,
        "PLANNED": P_VIOLET, "ROADMAP": P_SLATE,
    }
    act_rows = [["#", "Action", "Timeline", "Effort"]]
    for i, item in enumerate(ctx["top_actions"][:5], 1):
        tl = item.get("timeline", "PLANNED") if isinstance(item, dict) else getattr(item, "timeline", "PLANNED")
        ac = item.get("action", "") if isinstance(item, dict) else getattr(item, "action", "")
        ef = item.get("effort_hours", item.get("effort", "")) if isinstance(item, dict) else getattr(item, "effort_hours", "")
        tc = tl_colors.get(tl, "#888888")
        act_rows.append([
            str(i),
            Paragraph(str(ac), styles["body"]),
            Paragraph(f'<font color="{tc}"><b>{tl}</b></font>', styles["body"]),
            Paragraph(f"{ef} h" if isinstance(ef, (int, float)) else str(ef or ""), styles["small"]),
        ])

    if len(act_rows) > 1:
        act_tbl = Table(act_rows, colWidths=[18, W - 248, 78, 102])
        act_tbl.setStyle(_tbl_style())
        story.append(act_tbl)

    story.append(Spacer(1, 16))

    # ── About PQC ─────────────────────────────────────────────────────────────
    pqc_text = (
        "Quantum computers running Shor's algorithm will break RSA and elliptic-curve cryptography. "
        "While no cryptographically relevant quantum computer exists today, adversaries are collecting "
        "encrypted traffic now for future decryption (Harvest-Now Decrypt-Later). NIST finalised "
        "post-quantum standards in August 2024. India's DST Task Force published a migration roadmap "
        "in February 2026. Migration typically takes 42–54 months — organisations should begin now."
    )
    about_tbl = Table(
        [[Paragraph("<b>About Post-Quantum Cryptography</b>", styles["h3"])],
         [Paragraph(pqc_text, styles["body"])]],
        colWidths=[W - 90],
    )
    about_tbl.setStyle(TS([
        ("BOX", (0, 0), (-1, -1), 0.8, navy),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f8")),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(about_tbl)
    story.append(Spacer(1, 14))

    # ── Methodology & Provenance ──────────────────────────────────────────────
    for f in _methodology_flowables(styles, ctx["generated_at"]):
        story.append(f)

    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "<b>HNDL Disclaimer:</b> HNDL exposure scores are predictive cryptographic risk metrics "
        "based on data-type endurance, not indicators of active data interception or confirmed "
        "network breaches.",
        styles["small"],
    ))
    story.append(Paragraph(
        f"CONFIDENTIAL — SeQr Labs PQC Assessment — {org} — {ctx['generated_at']}",
        styles["confidential"],
    ))

    doc.build(story, onFirstPage=on_cover, onLaterPages=on_later)
    return buf.getvalue()


def _rl_technical_audit(ctx: dict) -> bytes:
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, PageBreak, HRFlowable,
    )
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors

    navy, red, white = _rl_colors()
    W, H = A4
    buf = io.BytesIO()
    styles = _styles()

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=45, rightMargin=45, topMargin=50, bottomMargin=55,
    )
    org = ctx["org_name"]

    def on_cover(c, d):
        _draw_cover(c, d, org, "Technical Audit Report",
                    ctx["generated_at"], [
                        f"Components: {ctx['total_components']}",
                        f"Assets: {ctx['total_assets']}",
                        f"Generated: {ctx['generated_at']}",
                        "Scanner version: SeQr 0.1.0",
                    ])

    def on_later(c, d):
        _draw_footer(c, d, org)

    story = [PageBreak()]

    # ── CBOM table ────────────────────────────────────────────────────────────
    story.append(Paragraph("Cryptographic Bill of Materials (CBOM)", styles["section_h"]))
    story.append(HRFlowable(width="100%", thickness=2, color=red, spaceAfter=8))
    story.append(Paragraph(
        f"Complete inventory of {ctx['total_components']} cryptographic components "
        f"across {ctx['total_assets']} scanned assets. Sorted by migration priority.",
        styles["body"],
    ))
    story.append(Spacer(1, 8))

    qs_colors = {"vulnerable": P_RED, "safe": P_GREEN, "deprecated": P_RED, "hybrid": P_VIOLET}
    cbom_rows = [["Location", "Algorithm", "Status", "HNDL", "Timeline", "Priority"]]
    for c in ctx["components"]:
        loc = (c.get("location_detail") or "")[:45] if isinstance(c, dict) else (c.location_detail or "")[:45]
        algo = c.get("algorithm", "") if isinstance(c, dict) else c.algorithm
        qs = c.get("quantum_status", "") if isinstance(c, dict) else c.quantum_status
        hndl = (c.get("estimated_hndl_exposure") if isinstance(c, dict) else c.estimated_hndl_exposure) or "N/A"
        tl = (c.get("threat_timeline") if isinstance(c, dict) else c.threat_timeline) or "N/A"
        pri = (c.get("pqc_migration_priority") if isinstance(c, dict) else c.pqc_migration_priority) or "N/A"
        sc = qs_colors.get(qs, "#888888")
        cbom_rows.append([
            Paragraph(loc, styles["small"]),
            Paragraph(algo, styles["small"]),
            Paragraph(f'<font color="{sc}"><b>{qs}</b></font>', styles["small"]),
            hndl, tl,
            str(pri) if pri != "N/A" else "N/A",
        ])

    cbom_tbl = Table(cbom_rows, colWidths=[140, 80, 62, 38, 60, 40], repeatRows=1)
    cbom_tbl.setStyle(_tbl_style())
    story.append(cbom_tbl)
    story.append(Spacer(1, 20))

    # ── Migration roadmap ─────────────────────────────────────────────────────
    story.append(Paragraph("Migration Roadmap", styles["section_h"]))
    story.append(HRFlowable(width="100%", thickness=2, color=red, spaceAfter=8))

    for tl in ["IMMEDIATE", "URGENT", "PLANNED", "ROADMAP"]:
        data = ctx["roadmap"].get(tl, {})
        comps = data.get("components", []) if isinstance(data, dict) else []
        if not comps:
            continue
        label = data.get("label", "") if isinstance(data, dict) else ""
        heading = f"{tl} — {label}" if label and label != tl else tl
        story.append(Paragraph(heading, styles["h3"]))
        rm_rows = [["Component", "Action", "Effort"]]
        for item in comps:
            loc = item.get("location", "") if isinstance(item, dict) else getattr(item, "location", "")
            ac = item.get("action", "") if isinstance(item, dict) else getattr(item, "action", "")
            ef = item.get("effort_hours", "") if isinstance(item, dict) else getattr(item, "effort_hours", "")
            rm_rows.append([
                Paragraph(str(loc), styles["small"]),
                Paragraph(str(ac), styles["small"]),
                Paragraph(f"{ef} h" if isinstance(ef, (int, float)) else str(ef or ""), styles["small"]),
            ])
        rm_tbl = Table(rm_rows, colWidths=[160, W - 340, 90])
        rm_tbl.setStyle(_tbl_style())
        story.append(rm_tbl)
        story.append(Spacer(1, 8))

    # ── Methodology & Provenance ──────────────────────────────────────────────
    story.append(Spacer(1, 8))
    for f in _methodology_flowables(styles, ctx["generated_at"]):
        story.append(f)

    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "<b>HNDL Disclaimer:</b> HNDL exposure scores are predictive cryptographic risk metrics "
        "based on data-type endurance, not indicators of active data interception or confirmed "
        "network breaches.",
        styles["small"],
    ))
    story.append(Paragraph(
        f"CONFIDENTIAL — SeQr Labs Technical Audit — {org} — {ctx['generated_at']}",
        styles["confidential"],
    ))

    doc.build(story, onFirstPage=on_cover, onLaterPages=on_later)
    return buf.getvalue()


# ── Public async builders ─────────────────────────────────────────────────────

async def build_executive_summary(
    org, components, risk_data, compliance_data, roadmap_data
) -> bytes:
    def _get(c, attr):
        return c.get(attr) if isinstance(c, dict) else getattr(c, attr, None)

    immediate = [c for c in components if _get(c, "threat_timeline") == "IMMEDIATE"]
    top_actions: list = []
    for tl in ["IMMEDIATE", "URGENT", "PLANNED", "ROADMAP"]:
        rd = roadmap_data.get(tl, {})
        bucket = rd.get("components", []) if isinstance(rd, dict) else []
        for item in bucket[:3]:
            entry = dict(item) if isinstance(item, dict) else item
            if isinstance(entry, dict):
                entry["timeline"] = tl
            top_actions.append(entry)
            if len(top_actions) >= 5:
                break

    context = {
        "org_name": org.name,
        "report_id": str(org.id)[:8].upper(),
        "generated_at": datetime.utcnow().strftime("%d %B %Y %H:%M UTC"),
        "total_assets": len(set(_get(c, "asset_id") for c in components)),
        "risk_score": risk_data.get("score", 0),
        "risk_label": risk_data.get("label", "low"),
        "vulnerable_count": sum(1 for c in components if _get(c, "quantum_status") == "vulnerable"),
        "hndl_count": sum(1 for c in components if _get(c, "estimated_hndl_exposure") == "high"),
        "immediate_count": len(immediate),
        "compliance": compliance_data,
        "compliance_names": _compliance_names(compliance_data),
        "top_actions": top_actions,
    }

    html = render_html("executive_summary.html", context)
    try:
        return html_to_pdf(html)
    except RuntimeError:
        return _rl_executive_summary(context)


async def build_technical_audit(org, components, roadmap_data) -> bytes:
    def _get(c, attr):
        return c.get(attr) if isinstance(c, dict) else getattr(c, attr, None)

    context = {
        "org_name": org.name,
        "generated_at": datetime.utcnow().strftime("%d %B %Y %H:%M UTC"),
        "total_components": len(components),
        "total_assets": len(set(_get(c, "asset_id") for c in components)),
        "components": [
            {
                "location_detail": c.location_detail,
                "algorithm": c.algorithm,
                "quantum_status": c.quantum_status,
                "estimated_hndl_exposure": c.estimated_hndl_exposure,
                "threat_timeline": c.threat_timeline,
                "pqc_migration_priority": c.pqc_migration_priority,
            }
            for c in sorted(components, key=lambda x: x.pqc_migration_priority or 0, reverse=True)
        ],
        "roadmap": roadmap_data,
    }

    html = render_html("technical_audit.html", context)
    try:
        return html_to_pdf(html)
    except RuntimeError:
        return _rl_technical_audit(context)
