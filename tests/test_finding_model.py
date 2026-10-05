from scanner.finding_model import Finding


def test_finding_creation():
    """Test that a Finding object stores the supplied data."""

    finding = Finding(
        target="127.0.0.1",
        port=443,
        service="https",
        vulnerability="Test Vulnerability",
        script="test-script",
        state="VULNERABLE",
        severity="High",
        cves=["CVE-2025-0001"],
        cvss_score=8.5,
        cvss_severity="HIGH",
        description="Test vulnerability description.",
        evidence=["Test evidence"],
        remediation="Apply the recommended fix."
    )

    data = finding.to_dict()

    assert data["target"] == "127.0.0.1"
    assert data["port"] == 443
    assert data["service"] == "https"
    assert data["vulnerability"] == "Test Vulnerability"
    assert data["script"] == "test-script"
    assert data["state"] == "VULNERABLE"
    assert data["severity"] == "High"
    assert data["cves"] == ["CVE-2025-0001"]
    assert data["cvss_score"] == 8.5
    assert data["cvss_severity"] == "HIGH"
    assert data["description"] == "Test vulnerability description."
    assert data["evidence"] == ["Test evidence"]
    assert data["remediation"] == "Apply the recommended fix."


def test_finding_default_lists():
    """Test that optional list fields default to empty lists."""

    finding = Finding(
        target="127.0.0.1"
    )

    data = finding.to_dict()

    assert data["cves"] == []
    assert data["evidence"] == []
