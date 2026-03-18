import re

CLOUD_PATTERNS = [
    {
        "name": "AWS Access Key",
        "severity": "CRITICAL",
        "regex": re.compile(r'AKIA[0-9A-Z]{16}')
    },
    {
        "name": "AWS Secret Key",
        "severity": "CRITICAL",
        "regex": re.compile(r'(?i)(aws_secret|secret_key|aws_secret_access_key)\s*[=:]\s*[\'"]?([A-Za-z0-9/+=]{20,})[\'"]?')
    },
    {
        "name": "Google API Key",
        "severity": "CRITICAL",
        "regex": re.compile(r'AIza[0-9A-Za-z\-_]{35}')
    },
    {
    "name": "Firebase API Key",
    "severity": "CRITICAL",
    "regex": re.compile(r'AAAA[A-Za-z0-9_-]{1,}:[A-Za-z0-9_-]{10,}')
    },
    {
        "name": "Azure Client Secret",
        "severity": "CRITICAL",
        "regex": re.compile(r'(?i)azure.*[\'"]([A-Za-z0-9_\-~.]{34,})[\'"]')
    },
    {
        "name": "Cloudflare API Key",
        "severity": "CRITICAL",
        "regex": re.compile(r'(?i)cloudflare.*[\'"]([A-Za-z0-9_\-]{37})[\'"]')
    },
]