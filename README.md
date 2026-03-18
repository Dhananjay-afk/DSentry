# DSentry — Secret & Credential Leak Detector

A Python CLI tool that scans codebases for accidentally exposed secrets before they reach GitHub.

---

## The Problem

Developers accidentally commit API keys, passwords, and tokens to GitHub every day. Bots find them in seconds. The results range from massive cloud bills to full data breaches. DSentry catches them before that happens.

---

## How It Works

DSentry uses two detection methods:

**Pattern Matching** — Knows the exact shape of 25+ secret types. AWS keys always start with `AKIA`. GitHub tokens always start with `ghp_`. Stripe keys always start with `sk_live_`. We match these shapes across every line of every file.

**Shannon Entropy Analysis** — Measures how random a string is. Real secrets are highly random even when they don't match a known pattern. Anything scoring above 4.5 entropy gets flagged automatically.

---

## What It Detects

| Category | Secrets |
|----------|---------|
| Cloud | AWS Keys, Google API, Firebase, Azure, Cloudflare |
| Tokens | GitHub, GitLab, Slack, Discord, NPM, Telegram, Twitter |
| Database | MongoDB, PostgreSQL, MySQL connection strings |
| Payment | Stripe, PayPal, Twilio, SendGrid, Mailgun |
| Auth | SSH Private Keys, JWT Tokens, Hardcoded Passwords |
| Generic | API Keys, ENV Secrets, High Entropy Strings |

---

## Installation
```bash
git clone https://github.com/Dhananjay-afk/DSentry.git
cd DSentry
pip install rich
```

---

## Usage
```bash
# Scan a folder
python main.py --path ./your-project

# Scan a single file
python main.py --path config.py

# Scan a GitHub repo
python main.py --github https://github.com/user/repo

# Export HTML report
python main.py --path . --export-html report.html

# Export JSON report
python main.py --path . --export-json report.json
```

---

## Performance

Tested against 35 cases across three test categories.

| Test | Score |
|------|-------|
| True Positives | 21/21 — 100% detection rate |
| False Positives | 0 — 100% clean on legitimate code |
| Edge Cases | 12/14 — 85.7% detection rate |
| Overall | 33/35 — 94.3% |

Full test documentation available in the `tests/` folder.

---

## Project Structure
```
DSentry/
├── main.py            CLI entry point and report display
├── scanner.py         Core scanning engine
└── pattern/
    ├── __init__.py    Combines all patterns
    ├── cloud.py       AWS, GCP, Azure, Firebase
    ├── tokens.py      GitHub, Slack, Discord, NPM
    ├── database.py    Connection strings
    ├── payment.py     Stripe, PayPal, Twilio
    ├── auth.py        SSH, JWT, Passwords
    └── generic.py     API keys, ENV secrets
```

---

## Known Limitations

**Split secrets** — If a secret is split across multiple variables and concatenated, DSentry cannot detect it. This is an industry-wide limitation present in tools like TruffleHog and GitGuardian.

**Encoded secrets** — Secrets encoded in Base64 or other formats require a decode step before detection. Planned for a future version.

**Compiled binaries** — DSentry scans source code only. Secrets baked into compiled executables require binary analysis tools.

---

## What's Coming

- Severity filter flag
- Pre-commit hook integration
- Web dashboard
- CI/CD GitHub Action
- Git history scanning
- Base64 decode layer

---

## About

Built by Dhananjay — 4th year Cybersecurity student at the University of the Fraser Valley. This is my first real security tool, built to understand how credential leak detection works from the ground up.

Actively developing. Feedback welcome.