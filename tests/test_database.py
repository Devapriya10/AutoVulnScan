import database.database as database


def test_initialize_database(tmp_path, monkeypatch):
    """Test that the database tables are created."""

    database_file = tmp_path / "test.db"

    monkeypatch.setattr(
        database,
        "DATABASE_FILE",
        str(database_file)
    )

    database.initialize_database()

    assert database_file.exists()

    connection = database.get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        """
    )

    tables = {
        row["name"]
        for row in cursor.fetchall()
    }

    connection.close()

    assert "scans" in tables
    assert "findings" in tables


def test_create_scan(tmp_path, monkeypatch):
    """Test that a scan record can be created."""

    database_file = tmp_path / "test.db"

    monkeypatch.setattr(
        database,
        "DATABASE_FILE",
        str(database_file)
    )

    database.initialize_database()

    scan_id = database.create_scan(
        "127.0.0.1"
    )

    assert scan_id is not None
    assert scan_id > 0

    scan = database.get_scan(
        scan_id
    )

    assert scan is not None
    assert scan["id"] == scan_id
    assert scan["target"] == "127.0.0.1"
    assert scan["scan_time"] is not None


def test_save_and_get_finding(tmp_path, monkeypatch):
    """Test saving and retrieving a vulnerability finding."""

    database_file = tmp_path / "test.db"

    monkeypatch.setattr(
        database,
        "DATABASE_FILE",
        str(database_file)
    )

    database.initialize_database()

    scan_id = database.create_scan(
        "127.0.0.1"
    )

    finding = {
        "port": 443,
        "service": "https",
        "vulnerability": "Test Vulnerability",
        "script": "test-script",
        "state": "VULNERABLE",
        "severity": "High",
        "cves": [
            "CVE-2025-1234"
        ],
        "cvss_score": 8.5,
        "cvss_severity": "HIGH",
        "description": "Test vulnerability.",
        "evidence": [
            "Test evidence"
        ],
        "remediation": "Apply the recommended fix."
    }

    database.save_finding(
        scan_id,
        finding
    )

    findings = database.get_findings(
        scan_id
    )

    assert len(findings) == 1

    saved_finding = findings[0]

    assert saved_finding["scan_id"] == scan_id
    assert saved_finding["port"] == 443
    assert saved_finding["service"] == "https"
    assert saved_finding["vulnerability"] == "Test Vulnerability"
    assert saved_finding["script"] == "test-script"
    assert saved_finding["state"] == "VULNERABLE"
    assert saved_finding["severity"] == "High"
    assert saved_finding["cves"] == "CVE-2025-1234"
    assert saved_finding["cvss_score"] == 8.5
    assert saved_finding["cvss_severity"] == "HIGH"
    assert saved_finding["description"] == "Test vulnerability."
    assert saved_finding["evidence"] == "Test evidence"
    assert saved_finding["remediation"] == (
        "Apply the recommended fix."
    )


def test_get_findings_for_scan_with_no_findings(
    tmp_path,
    monkeypatch
):
    """Test retrieving findings when a scan has none."""

    database_file = tmp_path / "test.db"

    monkeypatch.setattr(
        database,
        "DATABASE_FILE",
        str(database_file)
    )

    database.initialize_database()

    scan_id = database.create_scan(
        "127.0.0.1"
    )

    findings = database.get_findings(
        scan_id
    )

    assert findings == []
