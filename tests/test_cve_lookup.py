from scanner.cve_lookup import extract_cve_information


def test_extract_cve_information_cvss_v31():
    """Test extracting CVE information with CVSS v3.1."""

    cve_data = {
        "id": "CVE-2025-1234",

        "descriptions": [
            {
                "lang": "en",
                "value": "Example vulnerability description."
            }
        ],

        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 8.5,
                        "baseSeverity": "HIGH"
                    }
                }
            ]
        }
    }

    result = extract_cve_information(
        cve_data
    )

    assert result["cve_id"] == "CVE-2025-1234"

    assert result["description"] == (
        "Example vulnerability description."
    )

    assert result["cvss_score"] == 8.5

    assert result["cvss_severity"] == "HIGH"


def test_extract_cve_information_cvss_v30():
    """Test extracting CVE information with CVSS v3.0."""

    cve_data = {
        "id": "CVE-2024-5678",

        "descriptions": [
            {
                "lang": "en",
                "value": "CVSS v3.0 test vulnerability."
            }
        ],

        "metrics": {
            "cvssMetricV30": [
                {
                    "cvssData": {
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH"
                    }
                }
            ]
        }
    }

    result = extract_cve_information(
        cve_data
    )

    assert result["cve_id"] == "CVE-2024-5678"

    assert result["description"] == (
        "CVSS v3.0 test vulnerability."
    )

    assert result["cvss_score"] == 7.5

    assert result["cvss_severity"] == "HIGH"


def test_extract_cve_information_cvss_v2():
    """Test extracting CVE information with CVSS v2."""

    cve_data = {
        "id": "CVE-2015-1234",

        "descriptions": [
            {
                "lang": "en",
                "value": "CVSS v2 test vulnerability."
            }
        ],

        "metrics": {
            "cvssMetricV2": [
                {
                    "cvssData": {
                        "baseScore": 5.0
                    }
                }
            ]
        }
    }

    result = extract_cve_information(
        cve_data
    )

    assert result["cve_id"] == "CVE-2015-1234"

    assert result["description"] == (
        "CVSS v2 test vulnerability."
    )

    assert result["cvss_score"] == 5.0

    assert result["cvss_severity"] is None


def test_extract_cve_information_without_description():
    """Test CVE extraction when no English description exists."""

    cve_data = {
        "id": "CVE-2025-9999",

        "descriptions": [
            {
                "lang": "fr",
                "value": "Description in another language."
            }
        ],

        "metrics": {}
    }

    result = extract_cve_information(
        cve_data
    )

    assert result["cve_id"] == "CVE-2025-9999"

    assert result["description"] == ""

    assert result["cvss_score"] is None

    assert result["cvss_severity"] is None
