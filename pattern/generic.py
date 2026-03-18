import re

GENERIC_PATTERNS = [
    {
        "name": "Generic API Key",
        "severity": "HIGH",
        "regex": re.compile(r'(?i)(api_key|apikey|api-key)\s*=\s*[\'"]?([A-Za-z0-9_\-]{20,})[\'"]?')
    },
    {
        "name": ".ENV Secret",
        "severity": "MEDIUM",
        "regex": re.compile(r'(?i)^(SECRET|TOKEN|KEY|AUTH|PASS)[_A-Z]*\s*=\s*.+', re.MULTILINE)
    },
]