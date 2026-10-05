import sqlite3
from datetime import datetime


DATABASE_FILE = "autovulnscan.db"


def get_connection():
    """Create and return a connection to the SQLite database."""

    connection = sqlite3.connect(DATABASE_FILE)

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    """Create database tables if they do not already exist."""

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_time TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            port INTEGER,
            service TEXT,
            vulnerability TEXT,
            script TEXT,
            state TEXT,
            severity TEXT,
            cves TEXT,
            cvss_score REAL,
            cvss_severity TEXT,
            description TEXT,
            evidence TEXT,
            remediation TEXT,

            FOREIGN KEY (scan_id)
                REFERENCES scans(id)
        )
    """)

    connection.commit()

    connection.close()


def create_scan(target):
    """Create a new scan record and return its ID."""

    connection = get_connection()

    cursor = connection.cursor()

    scan_time = datetime.now().isoformat()

    cursor.execute(
        """
        INSERT INTO scans (target, scan_time)
        VALUES (?, ?)
        """,
        (target, scan_time)
    )

    scan_id = cursor.lastrowid

    connection.commit()

    connection.close()

    return scan_id


def save_finding(scan_id, finding):
    """Save a vulnerability finding for a scan."""

    connection = get_connection()

    cursor = connection.cursor()

    cves = ",".join(
        finding.get("cves", [])
    )

    evidence = "\n".join(
        finding.get("evidence", [])
    )

    cursor.execute(
        """
        INSERT INTO findings (
            scan_id,
            port,
            service,
            vulnerability,
            script,
            state,
            severity,
            cves,
            cvss_score,
            cvss_severity,
            description,
            evidence,
            remediation
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            finding.get("port"),
            finding.get("service"),
            finding.get("vulnerability"),
            finding.get("script"),
            finding.get("state"),
            finding.get("severity"),
            cves,
            finding.get("cvss_score"),
            finding.get("cvss_severity"),
            finding.get("description"),
            evidence,
            finding.get("remediation")
        )
    )

    connection.commit()

    connection.close()


def get_scan(scan_id):
    """Retrieve a scan by its ID."""

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM scans
        WHERE id = ?
        """,
        (scan_id,)
    )

    scan = cursor.fetchone()

    connection.close()

    return scan


def get_findings(scan_id):
    """Retrieve all vulnerability findings for a scan."""

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM findings
        WHERE scan_id = ?
        """,
        (scan_id,)
    )

    findings = cursor.fetchall()

    connection.close()

    return findings
