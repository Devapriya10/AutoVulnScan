import argparse
import ipaddress
import os
import re
import sys


from database.database import (
    initialize_database,
    create_scan,
    save_finding
)


from scanner.nmap_scanner import (
    run_nmap,
    parse_nmap_xml
)


from scanner.vulnerability_scanner import (
    run_vulnerability_scan
)


from scanner.vulnerability_parser import (
    parse_vulnerability_output
)


from scanner.severity import (
    assign_severities
)


from scanner.remediation import (
    add_remediations
)


from scanner.cve_lookup import (
    enrich_findings_with_cve
)


from scanner.finding_model import (
    Finding
)


from reporting.json_report import (
    generate_json_report
)


from reporting.html_report import (
    generate_html_report
)


from reporting.pdf_report import (
    generate_pdf_report
)


def parse_arguments():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "AutoVulnScan - Automated Vulnerability "
            "Assessment and Reporting Tool"
        )
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help=(
            "Target IP address, hostname, or authorized "
            "network range to scan"
        )
    )

    return parser.parse_args()


def validate_target(target):
    """Validate the supplied scan target."""

    target = target.strip()

    if not target:
        raise ValueError(
            "Target cannot be empty."
        )

    if len(target) > 253:
        raise ValueError(
            "Target is too long."
        )

    if any(character.isspace() for character in target):
        raise ValueError(
            "Target must not contain spaces."
        )

    # ---------------------------------------------------------
    # Check whether target is an IP address or network
    # ---------------------------------------------------------

    try:

        ipaddress.ip_address(target)

        return target

    except ValueError:
        pass

    try:

        ipaddress.ip_network(
            target,
            strict=False
        )

        return target

    except ValueError:
        pass

    # ---------------------------------------------------------
    # Check hostname format
    # ---------------------------------------------------------

    hostname_pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        r"\.)*"
        r"[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
    )

    if hostname_pattern.match(target):

        return target

    raise ValueError(
        "Invalid target. Please provide a valid IP address, "
        "hostname, or network range."
    )


def main():
    """Main entry point for AutoVulnScan."""

    # ---------------------------------------------------------
    # Parse arguments
    # ---------------------------------------------------------

    args = parse_arguments()

    try:

        target = validate_target(
            args.target
        )

    except ValueError as error:

        print(
            f"[!] Invalid target: {error}"
        )

        sys.exit(1)

    # ---------------------------------------------------------
    # Create reports directory
    # ---------------------------------------------------------

    os.makedirs(
        "reports",
        exist_ok=True
    )

    # ---------------------------------------------------------
    # Banner
    # ---------------------------------------------------------

    print("=" * 60)
    print("AutoVulnScan")
    print("Automated Vulnerability Assessment Tool")
    print("=" * 60)

    print(
        f"Target: {target}"
    )

    # ---------------------------------------------------------
    # Database
    # ---------------------------------------------------------

    print(
        "\n[*] Initializing database..."
    )

    initialize_database()

    print(
        "[+] Database initialized successfully."
    )

    scan_id = create_scan(
        target
    )

    print(
        f"[+] Scan created with ID: {scan_id}"
    )

    # ---------------------------------------------------------
    # Nmap service detection
    # ---------------------------------------------------------

    print(
        "\n[*] Running Nmap service detection..."
    )

    print(
        "[*] Please wait...\n"
    )

    try:

        nmap_xml = run_nmap(
            target
        )

    except RuntimeError as error:

        print(
            f"[!] {error}"
        )

        sys.exit(1)

    service_results = parse_nmap_xml(
        nmap_xml
    )

    print(
        "\nDiscovered Services"
    )

    print(
        "=" * 60
    )

    if not service_results:

        print(
            "No services discovered."
        )

    else:

        for service in service_results:

            print(
                f"Port: {service['port']}/"
                f"{service['protocol']}  "
                f"Service: {service['service']}  "
                f"Product: {service['product']}  "
                f"Version: {service['version']}"
            )

    # ---------------------------------------------------------
    # Vulnerability scan
    # ---------------------------------------------------------

    print(
        "\n\n[*] Starting Nmap vulnerability scan..."
    )

    print(
        "[*] This may take around 30–45 seconds.\n"
    )

    try:

        scan_output = run_vulnerability_scan(
            target
        )

    except RuntimeError as error:

        print(
            f"[!] {error}"
        )

        sys.exit(1)

    # ---------------------------------------------------------
    # Parse vulnerabilities
    # ---------------------------------------------------------

    findings = parse_vulnerability_output(
        scan_output
    )

    print(
        f"[+] Confirmed vulnerability findings: "
        f"{len(findings)}"
    )

    # ---------------------------------------------------------
    # CVE enrichment
    # ---------------------------------------------------------

    print(
        "\n[*] Checking findings for CVE information..."
    )

    findings = enrich_findings_with_cve(
        findings
    )

    print(
        "[+] CVE enrichment completed."
    )

    # ---------------------------------------------------------
    # Severity
    # ---------------------------------------------------------

    findings = assign_severities(
        findings
    )

    # ---------------------------------------------------------
    # Remediation
    # ---------------------------------------------------------

    findings = add_remediations(
        findings
    )

    # ---------------------------------------------------------
    # Standardize findings
    # ---------------------------------------------------------

    standardized_findings = []

    for finding in findings:

        cve_score = None
        cve_severity = None
        description = None

        cve_details = finding.get(
            "cve_details",
            []
        )

        if cve_details:

            first_cve = cve_details[0]

            cve_score = first_cve.get(
                "cvss_score"
            )

            cve_severity = first_cve.get(
                "cvss_severity"
            )

            description = first_cve.get(
                "description"
            )

        standardized_finding = Finding(
            target=target,

            # Preserve the port and service detected
            # by the vulnerability parser.
            port=finding.get(
                "port"
            ),

            service=finding.get(
                "service"
            ),

            vulnerability=finding.get(
                "title"
            ),

            script=finding.get(
                "script"
            ),

            state=finding.get(
                "state"
            ),

            severity=finding.get(
                "severity"
            ),

            cves=finding.get(
                "cves",
                []
            ),

            cvss_score=cve_score,

            cvss_severity=cve_severity,

            description=description,

            evidence=finding.get(
                "evidence",
                []
            ),

            remediation=finding.get(
                "remediation"
            )
        )

        standardized_findings.append(
            standardized_finding
        )

    # ---------------------------------------------------------
    # Display findings
    # ---------------------------------------------------------

    print(
        "\n\nStandardized Vulnerability Findings"
    )

    print(
        "=" * 60
    )

    if not standardized_findings:

        print(
            "No confirmed vulnerabilities found."
        )

    else:

        for finding in standardized_findings:

            data = finding.to_dict()

            print(
                f"\nTarget:        "
                f"{data['target']}"
            )

            print(
                f"Port:          "
                f"{data['port']}"
            )

            print(
                f"Service:       "
                f"{data['service']}"
            )

            print(
                f"Vulnerability: "
                f"{data['vulnerability']}"
            )

            print(
                f"Script:        "
                f"{data['script']}"
            )

            print(
                f"State:         "
                f"{data['state']}"
            )

            print(
                f"Severity:      "
                f"{data['severity']}"
            )

            print(
                f"CVEs:          "
                f"{data['cves']}"
            )

            print(
                f"CVSS Score:    "
                f"{data['cvss_score']}"
            )

            print(
                f"CVSS Severity: "
                f"{data['cvss_severity']}"
            )

            print(
                f"Description:   "
                f"{data['description']}"
            )

            print(
                "\nEvidence:"
            )

            if data["evidence"]:

                for evidence in data["evidence"]:

                    print(
                        f"  - {evidence}"
                    )

            else:

                print(
                    "  - No technical evidence extracted."
                )

            print(
                "\nRemediation:"
            )

            print(
                f"  {data['remediation']}"
            )

            print(
                "\n" + "-" * 60
            )

    # ---------------------------------------------------------
    # Save findings to database
    # ---------------------------------------------------------

    print(
        "\n[*] Saving findings to database..."
    )

    saved_count = 0

    for finding in standardized_findings:

        save_finding(
            scan_id,
            finding.to_dict()
        )

        saved_count += 1

    print(
        f"[+] Saved {saved_count} "
        f"finding(s) to scan ID {scan_id}."
    )

    # ---------------------------------------------------------
    # JSON report
    # ---------------------------------------------------------

    json_output_file = (
        "reports/scan_report.json"
    )

    print(
        "\n[*] Generating JSON report..."
    )

    generate_json_report(
        standardized_findings,
        target,
        json_output_file
    )

    print(
        f"[+] JSON report saved to: "
        f"{json_output_file}"
    )

    # ---------------------------------------------------------
    # HTML report
    # ---------------------------------------------------------

    html_output_file = (
        "reports/scan_report.html"
    )

    print(
        "\n[*] Generating HTML report..."
    )

    generate_html_report(
        standardized_findings,
        target,
        html_output_file
    )

    print(
        f"[+] HTML report saved to: "
        f"{html_output_file}"
    )

    # ---------------------------------------------------------
    # PDF report
    # ---------------------------------------------------------

    pdf_output_file = (
        "reports/scan_report.pdf"
    )

    print(
        "\n[*] Generating PDF report..."
    )

    generate_pdf_report(
        standardized_findings,
        target,
        pdf_output_file
    )

    print(
        f"[+] PDF report saved to: "
        f"{pdf_output_file}"
    )

    # ---------------------------------------------------------
    # Completion
    # ---------------------------------------------------------

    print(
        "\n" + "=" * 60
    )

    print(
        "[+] AutoVulnScan completed successfully!"
    )

    print(
        f"[+] Scan ID: {scan_id}"
    )

    print(
        f"[+] Target: {target}"
    )

    print(
        "[+] Reports:"
    )

    print(
        "    - reports/scan_report.json"
    )

    print(
        "    - reports/scan_report.html"
    )

    print(
        "    - reports/scan_report.pdf"
    )

    print(
        "=" * 60
    )


if __name__ == "__main__":
    main()
