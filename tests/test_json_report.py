import json

from scanner.finding_model import Finding
from reporting.json_report import generate_json_report


def test_generate_json_report(tmp_path):
    """Test that a JSON vulnerability report is generated correctly."""

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
        evidence=["Test evidence"],
        remediation="Apply the recommended fix."
    )

    output_file = tmp_path / "test_report.json"

    result = generate_json_report(
        [finding],
        "127.0.0.1",
        str(output_file)
    )

    assert result == str(output_file)

    assert output_file.exists()

    with open(
        output_file,
        "r",
        encoding="utf-8"
    ) as file:
        report = json.load(file)

    assert report["report_metadata"]["tool"] == "AutoVulnScan"
    assert report["report_metadata"]["target"] == "127.0.0.1"

    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["vulnerabilities"] == 1
    assert report["summary"]["severity"]["High"] == 1

    assert len(report["findings"]) == 1

    finding_data = report["findings"][0]

    assert finding_data["vulnerability"] == "Test Vulnerability"
    assert finding_data["severity"] == "High"
    assert finding_data["cves"] == ["CVE-2025-1234"]
    assert finding_data["cvss_score"] == 8.5


def test_generate_empty_json_report(tmp_path):
    """Test that an empty findings list generates a valid report."""

    output_file = tmp_path / "empty_report.json"

    generate_json_report(
        [],
        "127.0.0.1",
        str(output_file)
    )

    assert output_file.exists()

    with open(
        output_file,
        "r",
        encoding="utf-8"
    ) as file:
        report = json.load(file)

    assert report["summary"]["total_findings"] == 0
    assert report["summary"]["vulnerabilities"] == 0
    assert report["summary"]["severity"]["Critical"] == 0
    assert report["summary"]["severity"]["High"] == 0
    assert report["summary"]["severity"]["Medium"] == 0
    assert report["summary"]["severity"]["Low"] == 0
    assert report["summary"]["severity"]["Unknown"] == 0
    assert report["findings"] == []
