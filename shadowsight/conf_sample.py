import re

# For PyVulnerabilityLookup
vulnerability_lookup_base_url = "https://vulnerability.circl.lu/"
vulnerability_auth_token = ""

# Regular expression to match CVE, GHSA, and PySec IDs
vulnerability_patterns = re.compile(
    r"\b(CVE-\d{4}-\d{4,})\b"  # CVE pattern
    r"|\b(GHSA-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4})\b"  # GHSA pattern
    r"|\b(PYSEC-\d{4}-\d{2,5})\b"  # PYSEC pattern
    r"|\b(GSD-\d{4}-\d{4,5})\b"  # GSD pattern
    r"|\b(wid-sec-w-\d{4}-\d{4})\b"  # CERT-Bund pattern
    r"|\b(cisco-sa-\d{8}-[a-zA-Z0-9]+)\b"  # CISCO pattern
    r"|\b(RHSA-\d{4}:\d{4})\b"  # RedHat pattern
    r"|\b(msrc_CVE-\d{4}-\d{4,})\b"  # MSRC CVE pattern
    r"|\b(CERTFR-\d{4}-[A-Z]{3}-\d{3})\b",  # CERT-FR pattern
    re.IGNORECASE,
)

# Shadowserver API
key = ""
secret = ""
uri = "https://transform.shadowserver.org/api2/"
