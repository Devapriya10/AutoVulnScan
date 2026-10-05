from scanner.finding_model import Finding
from reporting.pdf_report import generate_pdf_report


def test_generate_pdf_report(tmp_path):
    """Test that a PDF vulnerability report is generated."""

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

    output_file = tmp_path / "test_report.pdf"

    result = generate_pdf_report(
        [finding],
        "127.0.0.1",
        str(output_file)
    )

    assert result == str(output_file)

    assert output_file.exists()

    assert output_file.stat().st_size > 0

    with open(
        output_file,
        "rb"
    ) as file:
        pdf_data = file.read()

    # PDF files begin with the %PDF header.
    assert pdf_data.startswith(
        b"%PDF"
    )


def test_generate_empty_pdf_report(tmp_path):
    """Test that a PDF report is generated with no findings."""

    output_file = tmp_path / "empty_report.pdf"

    result = generate_pdf_report(
        [],
        "127.0.0.1",
        str(output_file)
    )

    assert result == str(output_file)

    assert output_file.exists()

    assert output_file.stat().st_size > 0

    with open(
        output_file,
        "rb"
    ) as file:
        pdf_data = file.read()

    assert pdf_data.startswith(
        b"%PDF"
    )
