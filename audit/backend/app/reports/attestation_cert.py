"""Attestation compliance certificate (PDF).

A one-page, auditor-facing rendering of a signed attestation. The signature + offline
verification are the source of truth (see app/spine/verify.py and `seqr verify-attestation`);
this PDF is the human-readable filing artifact that carries the same pinned facts and tells
the reader how to verify authenticity independently.

ReportLab only (always installed) — no WeasyPrint dependency, so certificate rendering never
depends on the optional GTK stack.
"""
import io
import textwrap
from datetime import datetime

from app.reports.generator import (
    AMBER, INK, MUTED, BORDER, NEAR_BLACK, CREAM, P_GREEN, _fw_display,
)


def _wrap_mono(value: str, width: int = 66) -> list[str]:
    return textwrap.wrap(value, width=width) or [""]


def build_attestation_certificate(att, org_name: str) -> bytes:
    """Render a signed attestation row into a one-page compliance certificate PDF."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak,
    )

    buf = io.BytesIO()
    W, H = A4
    ss = getSampleStyleSheet()

    def p(name, **kw):
        return ParagraphStyle(name, parent=ss["Normal"], **kw)

    st = {
        "h": p("H", textColor=colors.HexColor(INK), fontSize=13,
               fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=4),
        "body": p("Body", fontSize=9, leading=13),
        "small": p("Small", fontSize=8, leading=11, textColor=colors.HexColor(MUTED)),
        "mono": p("Mono", fontSize=8, leading=11, fontName="Courier"),
        "label": p("Label", fontSize=8, textColor=colors.HexColor(MUTED)),
    }

    covered = att.covered_asset_set or []
    created = att.created_at.strftime("%d %B %Y %H:%M UTC") if att.created_at else ""

    def on_cover(c, d):
        c.saveState()
        c.setFillColor(colors.HexColor(NEAR_BLACK))
        c.rect(0, H - 150, W, 150, fill=1, stroke=0)
        c.setFillColor(colors.HexColor(AMBER))
        c.setFont("Helvetica-Bold", 8.5)
        c.drawString(50, H - 40, "SeQr Labs  ·  POST-QUANTUM ASSESSMENT  ·  ATTESTATION CERTIFICATE")
        c.setFillColor(colors.HexColor(CREAM))
        c.setFont("Helvetica-Bold", 20)
        c.drawString(50, H - 78, "Cryptographic Posture Attestation")
        c.setFont("Helvetica", 12)
        c.drawString(50, H - 100, org_name)
        c.setFillColor(colors.HexColor("#9A958B"))
        c.setFont("Helvetica", 9)
        c.drawString(50, H - 122, f"Attested {created}")
        # footer
        c.setStrokeColor(colors.HexColor(BORDER)); c.setLineWidth(0.5)
        c.line(45, 42, W - 45, 42)
        c.setFillColor(colors.HexColor(MUTED)); c.setFont("Helvetica", 7)
        c.drawString(45, 30, f"CONFIDENTIAL — SeQr Labs — {org_name}")
        c.drawRightString(W - 45, 30, f"Attestation {str(att.id)[:8]}")
        c.restoreState()

    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=50, rightMargin=50,
                            topMargin=170, bottomMargin=55)
    story = []

    story.append(Paragraph(
        "This certificate attests to the post-quantum cryptographic posture of the organisation "
        "named above, measured against the stated policy at the time of attestation. The claim is "
        "Ed25519-signed and independently verifiable offline — no callback to SeQr is required.",
        st["body"],
    ))
    story.append(Spacer(1, 10))

    # Attested facts
    story.append(Paragraph("Attested facts", st["h"]))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor(AMBER), spaceAfter=8))
    rows = [
        ["Organisation", org_name],
        ["Policy version", att.policy_version or "—"],
        ["Policy content hash", att.policy_content_hash or "—"],
        ["Evaluation result hash", att.evaluation_result_hash or "—"],
        ["Assets covered", str(len(covered))],
        ["Scanner version", att.scanner_version or "n/a"],
        ["Graph schema version", str(att.graph_schema_version)],
        ["Attested at", created],
    ]
    body_rows = [[Paragraph(k, st["label"]), Paragraph(str(v), st["mono"])] for k, v in rows]
    t = Table(body_rows, colWidths=[150, W - 250])
    t.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor(BORDER)),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    # Signature block
    story.append(Paragraph("Signature", st["h"]))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor(AMBER), spaceAfter=8))
    story.append(Paragraph(f"Algorithm: Ed25519 &nbsp;·&nbsp; Signing key: {att.key_id}", st["small"]))
    story.append(Spacer(1, 4))
    for line in _wrap_mono(att.signature):
        story.append(Paragraph(line, st["mono"]))
    story.append(Spacer(1, 12))

    # How to verify
    story.append(Paragraph("Verify this certificate offline", st["h"]))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor(AMBER), spaceAfter=8))
    story.append(Paragraph(
        "Download the signed JSON artifact from the SeQr dashboard and run the SeQr CLI "
        "(air-gap friendly, no network):", st["body"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph("seqr verify-attestation seqr-attestation-&lt;id&gt;.json", st["mono"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "A <b>VALID</b> result proves the certificate is authentic and untampered. Establish trust "
        "by matching the signing key id above to SeQr's published attestation public key.",
        st["small"]))

    doc.build(story, onFirstPage=on_cover, onLaterPages=on_cover)
    return buf.getvalue()
