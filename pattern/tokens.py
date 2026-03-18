import re

TOKEN_PATTERNS = [
    {
        "name": "GitHub Token",
        "severity": "CRITICAL",
        "regex": re.compile(r'ghp_[A-Za-z0-9_]{10,}')
    },
    {
        "name": "GitLab Token",
        "severity": "CRITICAL",
        "regex": re.compile(r'glpat-[A-Za-z0-9_\-]{20,}')
    },
    {
        "name": "Slack Token",
        "severity": "CRITICAL",
        "regex": re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}')
    },
    {
    "name": "Discord Bot Token",
    "severity": "CRITICAL",
    "regex": re.compile(r'[A-Za-z0-9_-]{24,26}\.[A-Za-z0-9_-]{4,8}\.[A-Za-z0-9_-]{20,}')
    },
    {
        "name": "NPM Access Token",
        "severity": "CRITICAL",
        "regex": re.compile(r'npm_[A-Za-z0-9]{36}')
    },
    {
        "name": "Telegram Bot Token",
        "severity": "CRITICAL",
        "regex": re.compile(r'[0-9]{8,10}:[A-Za-z0-9_\-]{35}')
    },
    {
        "name": "Twitter API Key",
        "severity": "CRITICAL",
        "regex": re.compile(r'(?i)twitter.*[\'"]([A-Za-z0-9]{25,})[\'"]')
    },
    {
        "name": "Twilio Auth Token",
        "severity": "CRITICAL",
        "regex": re.compile(r'(?i)twilio.*[\'"]([a-f0-9]{32})[\'"]')
    },
    {
        "name": "SendGrid API Key",
        "severity": "CRITICAL",
        "regex": re.compile(r'SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}')
    },
    {
    "name": "Mailgun API Key",
    "severity": "CRITICAL",
    "regex": re.compile(r'key-[A-Za-z0-9]{20,}')
    },
]