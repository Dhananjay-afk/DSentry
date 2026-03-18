import re

DATABASE_PATTERNS = [
    {
        "name": "Database Connection String",
        "severity": "CRITICAL",
        "regex": re.compile(r'(?i)(mongodb|mysql|postgres|postgresql):\/\/[^\s\'"]+')
    },
]