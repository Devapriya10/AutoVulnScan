SERVICE_CATEGORIES = {
    "ssh": "Remote Access",
    "ftp": "File Transfer",
    "http": "Web Server",
    "https": "Web Server",
    "mysql": "Database",
    "microsoft-ds": "File Sharing",
    "netbios-ssn": "File Sharing",
    "smtp": "Mail Server",
    "dns": "DNS Server",
    "rdp": "Remote Desktop",
}


def identify_service(service_name):
    """Return a category for a detected service."""

    if not service_name:
        return "Unknown"

    return SERVICE_CATEGORIES.get(
        service_name.lower(),
        "Other"
    )


def enrich_scan_results(results):
    """Add service category information to scan results."""

    for result in results:
        result["category"] = identify_service(
            result["service"]
        )

    return results
