import json
from datetime import datetime


def generate_json_report(findings, target, output_file):
    """Generate a JSON vulnerability assessment report."""

    report = {
        "report_metadata": {
            "tool": "AutoVulnScan",
            "target": target,
            "generated_at": datetime.now().isoformat()
        },
        "summary": {
            "total_findings": len(findings),
            "vulnerabilities": 0,
            "severity": {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Unknown": 0
            }
        },
        "findings": []
    }

    # Process findings
    for finding in findings:

        data = finding.to_dict()

        report["findings"].append(data)

        # Count confirmed vulnerabilities
        if data["state"] == "VULNERABLE":
            report["summary"]["vulnerabilities"] += 1

        # Count severity
        severity = data.get("severity", "Unknown")

        if severity in report["summary"]["severity"]:
            report["summary"]["severity"][severity] += 1
        else:
            report["summary"]["severity"]["Unknown"] += 1

    # Write JSON file
    with open(output_file, "w", encoding="utf-8") as file:

        json.dump(
            report,
            file,
            indent=4
        )

    return output_file
