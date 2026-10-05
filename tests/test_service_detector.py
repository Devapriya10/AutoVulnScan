from scanner.service_detector import (
    identify_service,
    enrich_scan_results
)


def test_identify_known_services():
    """Test that known services are assigned to the correct categories."""

    assert identify_service("ssh") == "Remote Access"
    assert identify_service("ftp") == "File Transfer"
    assert identify_service("http") == "Web Server"
    assert identify_service("https") == "Web Server"
    assert identify_service("mysql") == "Database"
    assert identify_service("microsoft-ds") == "File Sharing"
    assert identify_service("netbios-ssn") == "File Sharing"
    assert identify_service("smtp") == "Mail Server"
    assert identify_service("dns") == "DNS Server"
    assert identify_service("rdp") == "Remote Desktop"


def test_identify_service_case_insensitive():
    """Test that service identification is case-insensitive."""

    assert identify_service("SSH") == "Remote Access"
    assert identify_service("MySQL") == "Database"
    assert identify_service("HTTP") == "Web Server"


def test_unknown_service():
    """Test that unknown services are categorized as Other."""

    assert identify_service("some-unknown-service") == "Other"


def test_empty_service():
    """Test that an empty service name is categorized as Unknown."""

    assert identify_service("") == "Unknown"
    assert identify_service(None) == "Unknown"


def test_enrich_scan_results():
    """Test that service categories are added to scan results."""

    results = [
        {
            "target": "127.0.0.1",
            "port": 22,
            "service": "ssh"
        },
        {
            "target": "127.0.0.1",
            "port": 3306,
            "service": "mysql"
        },
        {
            "target": "127.0.0.1",
            "port": 80,
            "service": "http"
        }
    ]

    enriched_results = enrich_scan_results(
        results
    )

    assert enriched_results[0]["category"] == "Remote Access"
    assert enriched_results[1]["category"] == "Database"
    assert enriched_results[2]["category"] == "Web Server"
