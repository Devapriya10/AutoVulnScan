from scanner.nmap_scanner import parse_nmap_xml


def test_parse_nmap_xml():
    """Test parsing of Nmap service/version XML output."""

    xml_data = """<?xml version="1.0"?>
<nmaprun>
    <host>
        <address
            addr="127.0.0.1"
            addrtype="ipv4"
        />

        <ports>

            <port
                protocol="tcp"
                portid="22"
            >
                <state
                    state="open"
                />

                <service
                    name="ssh"
                    product="OpenSSH"
                    version="10.3p1"
                />
            </port>

            <port
                protocol="tcp"
                portid="3306"
            >
                <state
                    state="open"
                />

                <service
                    name="mysql"
                />
            </port>

        </ports>
    </host>
</nmaprun>
"""

    results = parse_nmap_xml(
        xml_data
    )

    assert len(results) == 2

    # ---------------------------------------------------------
    # SSH result
    # ---------------------------------------------------------

    ssh = results[0]

    assert ssh["target"] == "127.0.0.1"
    assert ssh["protocol"] == "tcp"
    assert ssh["port"] == 22
    assert ssh["state"] == "open"
    assert ssh["service"] == "ssh"
    assert ssh["product"] == "OpenSSH"
    assert ssh["version"] == "10.3p1"

    # ---------------------------------------------------------
    # MySQL result
    # ---------------------------------------------------------

    mysql = results[1]

    assert mysql["target"] == "127.0.0.1"
    assert mysql["protocol"] == "tcp"
    assert mysql["port"] == 3306
    assert mysql["state"] == "open"
    assert mysql["service"] == "mysql"
    assert mysql["product"] == ""
    assert mysql["version"] == ""


def test_parse_nmap_xml_without_ports():
    """Test that hosts without port information return no results."""

    xml_data = """<?xml version="1.0"?>
<nmaprun>
    <host>
        <address
            addr="127.0.0.1"
            addrtype="ipv4"
        />
    </host>
</nmaprun>
"""

    results = parse_nmap_xml(
        xml_data
    )

    assert results == []
