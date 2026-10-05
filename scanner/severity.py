SEVERITY_RULES = {
    "ssl-dh-params": "Medium",
}


def severity_from_cvss(cvss_score):
    """Convert a CVSS base score into a severity level."""

    if cvss_score is None:
        return "Unknown"

    try:
        score = float(cvss_score)
    except (TypeError, ValueError):
        return "Unknown"

    if score >= 9.0:
        return "Critical"

    if score >= 7.0:
        return "High"

    if score >= 4.0:
        return "Medium"

    if score > 0.0:
        return "Low"

    return "Unknown"


def assign_severity(finding):
    """
    Assign a severity to a vulnerability finding.

    Script-specific severity rules take priority.
    If no script-specific rule exists, CVSS is used.
    """

    script = finding.get("script", "")

    severity = SEVERITY_RULES.get(script)

    if severity is None:
        severity = severity_from_cvss(
            finding.get("cvss_score")
        )

    finding["severity"] = severity

    return finding


def assign_severities(findings):
    """Assign severity to all vulnerability findings."""

    return [
        assign_severity(finding)
        for finding in findings
    ]
