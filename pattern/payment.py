import re

PAYMENT_PATTERNS = [
    {
        "name": "Stripe Secret Key",
        "severity": "CRITICAL",
        "regex": re.compile(r'sk_(live|test)_[A-Za-z0-9]{20,}')
    },
    {
        "name": "Stripe Webhook Secret",
        "severity": "HIGH",
        "regex": re.compile(r'whsec_[A-Za-z0-9]{20,}')
    },
    {
        "name": "PayPal Client Secret",
        "severity": "CRITICAL",
        "regex": re.compile(r'(?i)paypal.*[\'"]([A-Za-z0-9_\-]{20,})[\'"]')
    },
]