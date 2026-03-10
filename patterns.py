import re

PATTERNS = [
    {
        "name": "AWS Access Key",
        "severity": "CRITICAL",
        "regex": re.compile(r'AKIA[0-9A-Z]{16}')
    },
    {
        "name": "AWS Secret Key",
        "severity": "CRITICAL",
        "regex": re.compile(r'(?i)aws_secret_access_key\s*=\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?')
    },
    {
        "name": "GitHub Token",
        "severity": "CRITICAL",
        "regex": re.compile(r'ghp_[A-Za-z0-9]{36}')
    },
    {
        "name": "Generic API Key",
        "severity": "HIGH",
        "regex": re.compile(r'(?i)(api_key|apikey|api-key)\s*=\s*[\'"]?([A-Za-z0-9_\-]{20,})[\'"]?')
    },
    {
        "name": "JWT Token",
        "severity": "HIGH",
        "regex": re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')
    },
    {
        "name": "Private SSH Key",
        "severity": "CRITICAL",
        "regex": re.compile(r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----')
    },
    {
        "name": "Hardcoded Password",
        "severity": "HIGH",
        "regex": re.compile(r'(?i)(password|passwd|pwd)\s*=\s*[\'"]([^\'"]{6,})[\'"]')
    },
    {
        "name": "Database Connection String",
        "severity": "CRITICAL",
        "regex": re.compile(r'(?i)(mongodb|mysql|postgres|postgresql):\/\/[^\s\'"]+')
    },
    {
        "name": ".ENV Secret",
        "severity": "MEDIUM",
        "regex": re.compile(r'(?i)^(SECRET|TOKEN|KEY|AUTH|PASS)[_A-Z]*\s*=\s*.+', re.MULTILINE)
    },
    {
        "name": "Slack Token",
        "severity": "CRITICAL",
        "regex": re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}')
    },
]