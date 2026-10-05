import requests


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def lookup_cve(cve_id):
    """Look up a CVE using the NVD API."""

    params = {
        "cveId": cve_id
    }

    try:
        response = requests.get(
            NVD_API_URL,
            params=params,
            timeout=10
        )

        response.raise_for_status()

        data = response.json()

        vulnerabilities = data.get(
            "vulnerabilities",
            []
        )

        if not vulnerabilities:
            return None

        cve_data = vulnerabilities[0]["cve"]

        return extract_cve_information(
            cve_data
        )

    except requests.RequestException as error:

        print(
            f"[!] NVD lookup failed for "
            f"{cve_id}: {error}"
        )

        return None


def extract_cve_information(cve_data):
    """Extract useful information from NVD CVE data."""

    cve_id = cve_data.get(
        "id"
    )

    descriptions = cve_data.get(
        "descriptions",
        []
    )

    description = ""

    for item in descriptions:

        if item.get("lang") == "en":

            description = item.get(
                "value",
                ""
            )

            break

    metrics = cve_data.get(
        "metrics",
        {}
    )

    cvss_score = None
    cvss_severity = None

    if metrics.get("cvssMetricV31"):

        cvss = metrics[
            "cvssMetricV31"
        ][0]["cvssData"]

        cvss_score = cvss.get(
            "baseScore"
        )

        cvss_severity = cvss.get(
            "baseSeverity"
        )

    elif metrics.get("cvssMetricV30"):

        cvss = metrics[
            "cvssMetricV30"
        ][0]["cvssData"]

        cvss_score = cvss.get(
            "baseScore"
        )

        cvss_severity = cvss.get(
            "baseSeverity"
        )

    elif metrics.get("cvssMetricV2"):

        cvss = metrics[
            "cvssMetricV2"
        ][0]["cvssData"]

        cvss_score = cvss.get(
            "baseScore"
        )

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity
    }


def enrich_findings_with_cve(findings):
    """Add NVD information to findings that contain CVE IDs."""

    for finding in findings:

        cve_ids = finding.get(
            "cves",
            []
        )

        finding["cve_details"] = []

        # Initialize CVSS information.
        finding["cvss_score"] = None
        finding["cvss_severity"] = None
        finding["description"] = None

        for cve_id in cve_ids:

            cve_information = lookup_cve(
                cve_id
            )

            if cve_information:

                finding["cve_details"].append(
                    cve_information
                )

                # Use the first successfully
                # enriched CVE for the finding.
                if finding["cvss_score"] is None:

                    finding["cvss_score"] = (
                        cve_information.get(
                            "cvss_score"
                        )
                    )

                    finding["cvss_severity"] = (
                        cve_information.get(
                            "cvss_severity"
                        )
                    )

                    finding["description"] = (
                        cve_information.get(
                            "description"
                        )
                    )

    return findings
