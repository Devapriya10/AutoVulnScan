import subprocess
import xml.etree.ElementTree as ET


def run_nmap(target):
    """Run an Nmap service/version scan and return XML output."""

    command = [
        "nmap",
        "-sV",
        "-oX",
        "-",
        target
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )

        return result.stdout

    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"Nmap scan failed: {error.stderr}"
        )

    except FileNotFoundError:
        raise RuntimeError(
            "Nmap is not installed or not available in PATH."
        )


def parse_nmap_xml(xml_data):
    """Parse Nmap XML and return structured port information."""

    root = ET.fromstring(xml_data)

    results = []

    for host in root.findall("host"):

        address_element = host.find("address")

        if address_element is not None:
            target = address_element.get("addr")
        else:
            target = "Unknown"

        ports = host.find("ports")

        if ports is None:
            continue

        for port in ports.findall("port"):

            state_element = port.find("state")
            service_element = port.find("service")

            port_data = {
                "target": target,

                "protocol": port.get(
                    "protocol"
                ),

                "port": int(
                    port.get("portid")
                ),

                "state": (
                    state_element.get("state")
                    if state_element is not None
                    else "unknown"
                ),

                "service": (
                    service_element.get("name")
                    if service_element is not None
                    else "unknown"
                ),

                "product": (
                    service_element.get("product") or ""
                    if service_element is not None
                    else ""
                ),

                "version": (
                    service_element.get("version") or ""
                    if service_element is not None
                    else ""
                )
            }

            results.append(
                port_data
            )

    return results
