import html
from datetime import datetime


def generate_html_report(findings, target, output_file):
    """Generate a professional HTML vulnerability assessment report."""

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Unknown": 0
    }

    # Count vulnerabilities by severity
    for finding in findings:

        data = finding.to_dict()

        severity = data.get("severity", "Unknown")

        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts["Unknown"] += 1

    total_findings = len(findings)

    generated_at = datetime.now().strftime(
        "%d %B %Y, %H:%M:%S"
    )

    # ---------------------------------------------------------
    # Build finding sections
    # ---------------------------------------------------------

    findings_html = ""

    # Display a clear message when no vulnerabilities are found.
    if not findings:

        findings_html = """
        <div class="no-findings">

            <h2>No confirmed vulnerabilities were identified.</h2>

            <p>
                The vulnerability scan did not identify any
                confirmed findings for the target.
            </p>

        </div>
        """

    for index, finding in enumerate(findings, start=1):

        data = finding.to_dict()

        vulnerability = html.escape(
            str(data.get("vulnerability") or "Unknown")
        )

        script = html.escape(
            str(data.get("script") or "Unknown")
        )

        state = html.escape(
            str(data.get("state") or "Unknown")
        )

        severity = html.escape(
            str(data.get("severity") or "Unknown")
        )

        port = html.escape(
            str(data.get("port") or "Not identified")
        )

        service = html.escape(
            str(data.get("service") or "Not identified")
        )

        remediation = html.escape(
            str(
                data.get("remediation")
                or "No remediation available."
            )
        )

        cves = data.get("cves", [])

        if cves:

            cve_html = ", ".join(
                html.escape(str(cve))
                for cve in cves
            )

        else:

            cve_html = "No CVE identified"

        cvss_score = data.get("cvss_score")

        if cvss_score is None:
            cvss_score = "Not available"

        cvss_severity = data.get("cvss_severity")

        if cvss_severity is None:
            cvss_severity = "Not available"

        evidence_items = ""

        for evidence in data.get("evidence", []):

            evidence_items += (
                f"<li>{html.escape(str(evidence))}</li>"
            )

        if not evidence_items:

            evidence_items = (
                "<li>No technical evidence extracted.</li>"
            )

        findings_html += f"""
        <section class="finding">

            <div class="finding-header">

                <div>

                    <span class="finding-number">
                        Finding #{index}
                    </span>

                    <h2>{vulnerability}</h2>

                </div>

                <span class="severity severity-{severity.lower()}">
                    {severity}
                </span>

            </div>

            <div class="details-grid">

                <div class="detail">

                    <span class="label">State</span>

                    <span>{state}</span>

                </div>

                <div class="detail">

                    <span class="label">Nmap Script</span>

                    <span>{script}</span>

                </div>

                <div class="detail">

                    <span class="label">Port</span>

                    <span>{port}</span>

                </div>

                <div class="detail">

                    <span class="label">Service</span>

                    <span>{service}</span>

                </div>

                <div class="detail">

                    <span class="label">CVE</span>

                    <span>{cve_html}</span>

                </div>

                <div class="detail">

                    <span class="label">CVSS Score</span>

                    <span>{html.escape(str(cvss_score))}</span>

                </div>

                <div class="detail">

                    <span class="label">CVSS Severity</span>

                    <span>{html.escape(str(cvss_severity))}</span>

                </div>

            </div>

            <div class="section-block">

                <h3>Technical Evidence</h3>

                <ul>
                    {evidence_items}
                </ul>

            </div>

            <div class="section-block remediation">

                <h3>Remediation</h3>

                <p>{remediation}</p>

            </div>

        </section>
        """

    # ---------------------------------------------------------
    # Complete HTML document
    # ---------------------------------------------------------

    html_content = f"""
<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>AutoVulnScan Report</title>

    <style>

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            padding: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: #f4f6f8;
            color: #1f2937;
        }}

        .container {{
            max-width: 1100px;
            margin: 0 auto;
            padding: 40px 24px;
        }}

        .header {{
            background: #111827;
            color: white;
            padding: 35px;
            border-radius: 12px;
            margin-bottom: 25px;
        }}

        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 32px;
        }}

        .header p {{
            margin: 5px 0;
            color: #d1d5db;
        }}

        .summary {{
            display: grid;
            grid-template-columns:
                repeat(auto-fit, minmax(160px, 1fr));

            gap: 15px;

            margin-bottom: 30px;
        }}

        .summary-card {{
            background: white;
            border-radius: 10px;
            padding: 22px;
            box-shadow:
                0 2px 8px rgba(0, 0, 0, 0.08);
        }}

        .summary-card .number {{
            font-size: 28px;
            font-weight: bold;
            margin-bottom: 5px;
        }}

        .summary-card .label {{
            color: #6b7280;
            font-size: 14px;
        }}

        .finding {{
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 25px;

            box-shadow:
                0 2px 10px rgba(0, 0, 0, 0.08);
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 20px;

            border-bottom: 1px solid #e5e7eb;

            padding-bottom: 20px;
            margin-bottom: 20px;
        }}

        .finding-header h2 {{
            margin: 8px 0 0 0;
            font-size: 23px;
        }}

        .finding-number {{
            color: #6b7280;
            font-size: 13px;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .severity {{
            padding: 8px 14px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 13px;
            white-space: nowrap;
        }}

        .severity-critical {{
            background: #7f1d1d;
            color: white;
        }}

        .severity-high {{
            background: #dc2626;
            color: white;
        }}

        .severity-medium {{
            background: #f59e0b;
            color: white;
        }}

        .severity-low {{
            background: #16a34a;
            color: white;
        }}

        .severity-unknown {{
            background: #6b7280;
            color: white;
        }}

        .details-grid {{
            display: grid;
            grid-template-columns:
                repeat(auto-fit, minmax(220px, 1fr));

            gap: 15px;

            margin-bottom: 25px;
        }}

        .detail {{
            background: #f9fafb;
            padding: 15px;
            border-radius: 8px;
        }}

        .detail .label {{
            display: block;
            color: #6b7280;
            font-size: 12px;
            text-transform: uppercase;
            font-weight: bold;
            margin-bottom: 6px;
        }}

        .section-block {{
            margin-top: 25px;
        }}

        .section-block h3 {{
            font-size: 17px;
            margin-bottom: 12px;
        }}

        .section-block ul {{
            background: #f9fafb;
            padding: 18px 18px 18px 35px;
            border-radius: 8px;
        }}

        .section-block li {{
            margin-bottom: 8px;
            font-family: monospace;
            font-size: 13px;
        }}

        .remediation {{
            background: #f9fafb;
            padding: 18px;
            border-radius: 8px;
        }}

        .remediation p {{
            margin: 0;
            line-height: 1.6;
        }}

        .no-findings {{
            background: white;
            border-radius: 12px;
            padding: 40px;
            text-align: center;

            box-shadow:
                0 2px 10px rgba(0, 0, 0, 0.08);
        }}

        .no-findings h2 {{
            margin: 0 0 10px 0;
            font-size: 22px;
        }}

        .no-findings p {{
            margin: 0;
            color: #6b7280;
            line-height: 1.6;
        }}

        .footer {{
            text-align: center;
            color: #6b7280;
            font-size: 13px;
            margin-top: 30px;
        }}

        @media (max-width: 700px) {{

            .container {{
                padding: 20px 12px;
            }}

            .header {{
                padding: 25px;
            }}

            .finding {{
                padding: 20px;
            }}

            .finding-header {{
                flex-direction: column;
            }}

        }}

    </style>

</head>


<body>

<div class="container">

    <header class="header">

        <h1>AutoVulnScan</h1>

        <p>
            Automated Vulnerability Assessment Report
        </p>

        <p>
            <strong>Target:</strong>
            {html.escape(target)}
        </p>

        <p>
            <strong>Generated:</strong>
            {generated_at}
        </p>

    </header>


    <section class="summary">

        <div class="summary-card">

            <div class="number">
                {total_findings}
            </div>

            <div class="label">
                Total Findings
            </div>

        </div>


        <div class="summary-card">

            <div class="number">
                {severity_counts["Critical"]}
            </div>

            <div class="label">
                Critical
            </div>

        </div>


        <div class="summary-card">

            <div class="number">
                {severity_counts["High"]}
            </div>

            <div class="label">
                High
            </div>

        </div>


        <div class="summary-card">

            <div class="number">
                {severity_counts["Medium"]}
            </div>

            <div class="label">
                Medium
            </div>

        </div>


        <div class="summary-card">

            <div class="number">
                {severity_counts["Low"]}
            </div>

            <div class="label">
                Low
            </div>

        </div>

    </section>


    <main>

        {findings_html}

    </main>


    <div class="footer">

        Generated by AutoVulnScan

    </div>

</div>

</body>

</html>
"""

    # ---------------------------------------------------------
    # Write HTML file
    # ---------------------------------------------------------

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html_content)

    return output_file
