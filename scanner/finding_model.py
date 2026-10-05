class Finding:
    """Standardized vulnerability finding."""

    def __init__(
        self,
        target,
        port=None,
        service=None,
        vulnerability=None,
        script=None,
        state=None,
        severity=None,
        cves=None,
        cvss_score=None,
        cvss_severity=None,
        description=None,
        evidence=None,
        remediation=None
    ):
        self.target = target
        self.port = port
        self.service = service
        self.vulnerability = vulnerability
        self.script = script
        self.state = state
        self.severity = severity
        self.cves = cves or []
        self.cvss_score = cvss_score
        self.cvss_severity = cvss_severity
        self.description = description
        self.evidence = evidence or []
        self.remediation = remediation

    def to_dict(self):
        """Convert the finding into a dictionary."""

        return {
            "target": self.target,
            "port": self.port,
            "service": self.service,
            "vulnerability": self.vulnerability,
            "script": self.script,
            "state": self.state,
            "severity": self.severity,
            "cves": self.cves,
            "cvss_score": self.cvss_score,
            "cvss_severity": self.cvss_severity,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation
        }
