from scanner.severity import (
    assign_severity,
    assign_severities,
    severity_from_cvss
)


def test_known_vulnerability_severity():
    """Test severity assignment for a known vulnerability."""

    finding = {
        "script": "ssl-dh-params"
    }

    result = assign_severity(finding)

    assert result["severity"] == "Medium"


def test_unknown_vulnerability_severity():
    """Test that unknown vulnerability scripts receive Unknown severity."""

    finding = {
        "script": "unknown-script"
    }

    result = assign_severity(finding)

    assert result["severity"] == "Unknown"


def test_multiple_findings_severity():
    """Test severity assignment for multiple findings."""

    findings = [
        {
            "script": "ssl-dh-params"
        },
        {
            "script": "unknown-script"
        }
    ]

    results = assign_severities(findings)

    assert len(results) == 2
    assert results[0]["severity"] == "Medium"
    assert results[1]["severity"] == "Unknown"


def test_cvss_critical_severity():
    """Test that CVSS 9.0 or higher is Critical."""

    finding = {
        "script": "unknown-script",
        "cvss_score": 9.0
    }

    result = assign_severity(finding)

    assert result["severity"] == "Critical"


def test_cvss_high_severity():
    """Test that CVSS 7.0 to 8.9 is High."""

    finding = {
        "script": "unknown-script",
        "cvss_score": 7.8
    }

    result = assign_severity(finding)

    assert result["severity"] == "High"


def test_cvss_medium_severity():
    """Test that CVSS 4.0 to 6.9 is Medium."""

    finding = {
        "script": "unknown-script",
        "cvss_score": 5.0
    }

    result = assign_severity(finding)

    assert result["severity"] == "Medium"


def test_cvss_low_severity():
    """Test that CVSS above 0 and below 4.0 is Low."""

    finding = {
        "script": "unknown-script",
        "cvss_score": 2.5
    }

    result = assign_severity(finding)

    assert result["severity"] == "Low"


def test_no_cvss_score():
    """Test that a missing CVSS score results in Unknown severity."""

    finding = {
        "script": "unknown-script",
        "cvss_score": None
    }

    result = assign_severity(finding)

    assert result["severity"] == "Unknown"


def test_invalid_cvss_score():
    """Test that an invalid CVSS score results in Unknown severity."""

    finding = {
        "script": "unknown-script",
        "cvss_score": "invalid"
    }

    result = assign_severity(finding)

    assert result["severity"] == "Unknown"


def test_cvss_zero_score():
    """Test that a CVSS score of zero results in Unknown severity."""

    finding = {
        "script": "unknown-script",
        "cvss_score": 0
    }

    result = assign_severity(finding)

    assert result["severity"] == "Unknown"


def test_script_specific_rule_takes_priority_over_cvss():
    """Test that script-specific severity overrides CVSS severity."""

    finding = {
        "script": "ssl-dh-params",
        "cvss_score": 9.8
    }

    result = assign_severity(finding)

    assert result["severity"] == "Medium"


def test_severity_from_cvss_directly():
    """Test the CVSS conversion function directly."""

    assert severity_from_cvss(9.8) == "Critical"
    assert severity_from_cvss(7.8) == "High"
    assert severity_from_cvss(5.0) == "Medium"
    assert severity_from_cvss(2.5) == "Low"
    assert severity_from_cvss(None) == "Unknown"
