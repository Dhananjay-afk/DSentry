import re

AUTH_PATTERNS = [
    {
        "name": "Private SSH Key",
        "severity": "CRITICAL",
        "regex": re.compile(r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----')
    },
    {
        "name": "JWT Token",
        "severity": "HIGH",
        "regex": re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')
    },
    {
        "name": "Hardcoded Password",
        "severity": "HIGH",
        "regex": re.compile(r'(?i)(password|passwd|pwd)\s*=\s*[\'"]([^\$\'"\s][^\'"]{5,})[\'"]')
    },
]