from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether
)


def generate_pdf_report(findings, target, output_file):
    """Generate a professional PDF vulnerability assessment report."""

    # ---------------------------------------------------------
    # PDF document
    # ---------------------------------------------------------

    document = SimpleDocTemplate(
        output_file,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    # ---------------------------------------------------------
    # Styles
    # ---------------------------------------------------------

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=24,
        leading=28,
        alignment=TA_CENTER,
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=11,
        alignment=TA_CENTER,
        textColor=colors.grey,
        spaceAfter=15
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=16,
        leading=20,
        spaceBefore=10,
        spaceAfter=8
    )

    finding_title_style = ParagraphStyle(
        "FindingTitle",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        spaceAfter=8
    )

    normal_style = ParagraphStyle(
        "NormalReport",
        parent=styles["Normal"],
        fontSize=9,
        leading=13
    )

    small_style = ParagraphStyle(
        "Small",
        parent=styles["Normal"],
        fontSize=8,
        leading=11
    )

    evidence_style = ParagraphStyle(
        "Evidence",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11
    )

    # ---------------------------------------------------------
    # Build report
    # ---------------------------------------------------------

    story = []

    generated_at = datetime.now().strftime(
        "%d %B %Y, %H:%M:%S"
    )

    # ---------------------------------------------------------
    # Header
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "AutoVulnScan",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Automated Vulnerability Assessment Report",
            subtitle_style
        )
    )

    metadata = [
        ["Target", str(target)],
        ["Generated", generated_at],
        ["Total Findings", str(len(findings))]
    ]

    metadata_table = Table(
        metadata,
        colWidths=[45 * mm, 125 * mm]
    )

    metadata_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#111827")),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
            ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#f3f4f6")),
            ("TEXTCOLOR", (1, 0), (1, -1), colors.black),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8)
        ])
    )

    story.append(metadata_table)
    story.append(Spacer(1, 12))

    # ---------------------------------------------------------
    # Severity summary
    # ---------------------------------------------------------

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Unknown": 0
    }

    for finding in findings:

        severity = finding.to_dict().get(
            "severity",
            "Unknown"
        )

        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts["Unknown"] += 1

    story.append(
        Paragraph(
            "Executive Summary",
            heading_style
        )
    )

    summary_data = [
        [
            "Critical",
            "High",
            "Medium",
            "Low",
            "Unknown"
        ],
        [
            str(severity_counts["Critical"]),
            str(severity_counts["High"]),
            str(severity_counts["Medium"]),
            str(severity_counts["Low"]),
            str(severity_counts["Unknown"])
        ]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[34 * mm] * 5
    )

    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8)
        ])
    )

    story.append(summary_table)
    story.append(Spacer(1, 15))

    # ---------------------------------------------------------
    # Findings
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "Vulnerability Findings",
            heading_style
        )
    )

    if not findings:

        story.append(
            Paragraph(
                "No confirmed vulnerabilities were identified.",
                normal_style
            )
        )

    # ---------------------------------------------------------
    # Individual findings
    # ---------------------------------------------------------

    for index, finding in enumerate(findings, start=1):

        data = finding.to_dict()

        vulnerability = (
            data.get("vulnerability")
            or "Unknown vulnerability"
        )

        story.append(
            Paragraph(
                f"Finding #{index}: {vulnerability}",
                finding_title_style
            )
        )

        details = [
            ["State", str(data.get("state") or "Unknown")],
            ["Severity", str(data.get("severity") or "Unknown")],
            ["Nmap Script", str(data.get("script") or "Unknown")],
            ["Port", str(data.get("port") or "Not identified")],
            ["Service", str(data.get("service") or "Not identified")],
            ["CVE", ", ".join(data.get("cves", [])) or "No CVE identified"],
            [
                "CVSS Score",
                str(data.get("cvss_score") or "Not available")
            ],
            [
                "CVSS Severity",
                str(data.get("cvss_severity") or "Not available")
            ]
        ]

        details_table = Table(
            details,
            colWidths=[45 * mm, 125 * mm]
        )

        details_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6)
            ])
        )

        story.append(details_table)
        story.append(Spacer(1, 10))

        # -----------------------------------------------------
        # Evidence
        # -----------------------------------------------------

        story.append(
            Paragraph(
                "Technical Evidence",
                heading_style
            )
        )

        evidence = data.get("evidence", [])

        if evidence:

            for item in evidence:

                story.append(
                    Paragraph(
                        f"• {item}",
                        evidence_style
                    )
                )

                story.append(
                    Spacer(1, 3)
                )

        else:

            story.append(
                Paragraph(
                    "No technical evidence extracted.",
                    normal_style
                )
            )

        # -----------------------------------------------------
        # Remediation
        # -----------------------------------------------------

        remediation = (
            data.get("remediation")
            or "No remediation guidance available."
        )

        remediation_table = Table(
            [
                [
                    Paragraph(
                        remediation,
                        normal_style
                    )
                ]
            ],
            colWidths=[170 * mm]
        )

        remediation_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    colors.HexColor("#f3f4f6")
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10)
            ])
        )

        # Keep the heading and remediation box together.
        remediation_section = KeepTogether([
            Paragraph(
                "Remediation",
                heading_style
            ),
            remediation_table
        ])

        story.append(remediation_section)
        story.append(Spacer(1, 15))

        if index < len(findings):

            story.append(PageBreak())

    # ---------------------------------------------------------
    # Footer
    # ---------------------------------------------------------

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "Generated by AutoVulnScan",
            subtitle_style
        )
    )

    # ---------------------------------------------------------
    # Generate PDF
    # ---------------------------------------------------------

    document.build(story)

    return output_file
