from scanner.finding_model import Finding
from reporting.html_report import generate_html_report


def test_generate_html_report(tmp_path):
    """Test that an HTML vulnerability report is generated correctly."""

    finding = Finding(
        target="127.0.0.1",
        port=443,
        service="https",
        vulnerability="Test Vulnerability",
        script="test-script",
        state="VULNERABLE",
        severity="High",
        cves=["CVE-2025-1234"],
        cvss_score=8.5,
        cvss_severity="HIGH",
        description="Test vulnerability description.",
        evidence=[
            "Test evidence 1",
            "Test evidence 2"
        ],
        remediation="Apply the recommended fix."
    )

    output_file = tmp_path / "test_report.html"

    result = generate_html_report(
        [finding],
        "127.0.0.1",
        str(output_file)
    )

    assert result == str(output_file)

    assert output_file.exists()

    html_content = output_file.read_text(
        encoding="utf-8"
    )

    assert "AutoVulnScan" in html_content

    assert "Automated Vulnerability Assessment Report" in (
        html_content
    )

    assert "127.0.0.1" in html_content

    assert "Test Vulnerability" in html_content

    assert "VULNERABLE" in html_content

    assert "High" in html_content

    assert "test-script" in html_content

    assert "443" in html_content

    assert "https" in html_content

    assert "CVE-2025-1234" in html_content

    assert "8.5" in html_content

    assert "HIGH" in html_content

    assert "Test evidence 1" in html_content

    assert "Test evidence 2" in html_content

    assert "Apply the recommended fix." in html_content


def test_generate_empty_html_report(tmp_path):
    """Test that an HTML report is generated with no findings."""

    output_file = tmp_path / "empty_report.html"

    generate_html_report(
        [],
        "127.0.0.1",
        str(output_file)
    )

    assert output_file.exists()

    html_content = output_file.read_text(
        encoding="utf-8"
    )

    assert "AutoVulnScan" in html_content

    assert "127.0.0.1" in html_content

    assert "No confirmed vulnerabilities were identified." in (
        html_content
    )
