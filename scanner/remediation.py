REMEDIATION_RULES = {
    "ssl-dh-params": (
        "Disable anonymous Diffie-Hellman cipher suites and "
        "configure the service to use secure, authenticated "
        "TLS cipher suites."
    )
}


def add_remediation(finding):
    """Add remediation guidance to a vulnerability finding."""

    script = finding.get("script", "")

    recommendation = REMEDIATION_RULES.get(
        script,
        "Review the affected service, verify the finding, "
        "and apply the vendor-recommended security update or configuration."
    )

    finding["remediation"] = recommendation

    return finding


def add_remediations(findings):
    """Add remediation guidance to all findings."""

    return [add_remediation(finding) for finding in findings]
