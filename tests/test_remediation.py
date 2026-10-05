from scanner.remediation import (
    add_remediation,
    add_remediations
)


def test_known_vulnerability_remediation():
    """Test remediation for a known vulnerability."""

    finding = {
        "script": "ssl-dh-params"
    }

    result = add_remediation(finding)

    assert "anonymous Diffie-Hellman" in result["remediation"]


def test_unknown_vulnerability_remediation():
    """Test generic remediation for an unknown vulnerability."""

    finding = {
        "script": "unknown-script"
    }

    result = add_remediation(finding)

    assert result["remediation"] == (
        "Review the affected service, verify the finding, "
        "and apply the vendor-recommended security update or configuration."
    )


def test_multiple_findings_remediation():
    """Test remediation assignment for multiple findings."""

    findings = [
        {
            "script": "ssl-dh-params"
        },
        {
            "script": "unknown-script"
        }
    ]

    results = add_remediations(findings)

    assert len(results) == 2

    assert "anonymous Diffie-Hellman" in (
        results[0]["remediation"]
    )

    assert results[1]["remediation"] == (
        "Review the affected service, verify the finding, "
        "and apply the vendor-recommended security update or configuration."
    )
