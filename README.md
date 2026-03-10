DSentry — Secret & Credential Leak Detector

> My first real cybersecurity project. Built from scratch in a single session while learning Python, security tooling, and what it actually means to write code that matters.

---

What is DSentry?

DSentry is a command-line tool that scans your code for accidentally exposed secrets — API keys, passwords, tokens, database credentials, and anything else that should never end up in a public repository.

Every day, developers push code to GitHub with real credentials in it. Bots find them in seconds. AWS bills skyrocket overnight. Databases get dumped. Companies get breached. DSentry catches these before they ever leave your machine.

This is a real problem that billion-dollar companies like GitGuardian and TruffleHog were built to solve. I built my own version to understand how it works from the ground up.

---

A honest note

I'm a 4th year Computer Information Systems student at the University of the Fraser Valley, concentrating in cybersecurity. This is my first serious security project and honestly — I'm still figuring a lot of things out.

I built this because I wanted to understand the fundamentals: how regex pattern matching works, what Shannon entropy actually is and why it matters in security, how real tools like TruffleHog detect secrets, and what it feels like to build something that solves a genuine problem instead of just completing an assignment.

There are things I would do differently now. There are patterns I haven't added yet. There are edge cases I haven't handled. But it works, it catches real secrets, and I learned more building this in one session than I have in months of reading about cybersecurity.

This is the beginning, not the finished product.

---

What it detects

| Secret Type | Severity | Detection Method |
|-------------|----------|-----------------|
| AWS Access Keys | 🔴 CRITICAL | Pattern |
| AWS Secret Keys | 🔴 CRITICAL | Pattern |
| Database Connection Strings | 🔴 CRITICAL | Pattern |
| GitHub Tokens | 🔴 CRITICAL | Pattern |
| Slack Tokens | 🔴 CRITICAL | Pattern |
| Private SSH Keys | 🔴 CRITICAL | Pattern |
| JWT Tokens | 🟠 HIGH | Pattern |
| Hardcoded Passwords | 🟠 HIGH | Pattern |
| Generic API Keys | 🟠 HIGH | Pattern |
| High Entropy Strings | 🟡 MEDIUM | Shannon Entropy |
| .ENV Secrets | 🟡 MEDIUM | Pattern |

---

How it works

DSentry uses two detection layers:

**Layer 1 — Pattern Matching**
Each known secret type has a specific shape. AWS keys always start with `AKIA`. GitHub tokens always start with `ghp_`. JWT tokens always start with `eyJ`. We use regex to match these exact shapes across every line of every file.

**Layer 2 — Shannon Entropy Analysis**
Not all secrets follow a known pattern. Custom API keys, internal tokens, randomly generated secrets — these don't match any regex. But they are always highly random. Shannon entropy measures how random a string is. Secrets typically score above 4.5. Normal text scores around 3.0-3.5. If we find a quoted string above the threshold that wasn't caught by a named pattern, we flag it anyway.

This dual-layer approach is the same architecture used by enterprise tools like TruffleHog.

---

Installation
```bash
# Clone the repo
git clone https://github.com/Dhananjay-afk/DSentry.git
cd DSentry

# Create a virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Mac/Linux

# Install dependencies
pip install rich
```

---

Usage

**Scan a directory:**
```bash
python main.py --path ./your-project
```

**Scan a single file:**
```bash
python main.py --path ./config.py
```

**Export an HTML report:**
```bash
python main.py --path ./your-project --export-html report.html
```

**Export a JSON report:**
```bash
python main.py --path ./your-project --export-json report.json
```

---

Example Output
```
🔴 CRITICAL  AWS Access Key  (pattern detection)
   Line 4:  aws_access_key = "AKIAIOSFODNN7EXAMPLE"
   Matched: AKIAIOSFODNN7EXAMPLE
   Fix:     Use environment variables — os.getenv('YOUR_SECRET_NAME')

🔴 CRITICAL  Database Connection String  (pattern detection)
   Line 8:  DATABASE_URL = "postgres://admin:pass@localhost/db"
   Matched: postgres://admin:pass@localhost/db
   Fix:     Use environment variables — os.getenv('YOUR_SECRET_NAME')
```

---

What I learned building this

- How regex pattern matching works in practice, not just in theory
- What Shannon entropy is and why randomness is a signal for secrets
- How real SAST tools are architected — separation of concerns, pattern files, scanner engines
- Why `.gitignore` and environment variables exist and how many people get this wrong
- How GitHub Push Protection works — it literally blocked my own test files when I tried to push them 😅
- How to build a CLI tool with argument parsing and rich terminal output
- Git, virtual environments, project structure — the real developer workflow

---

What's next

- Add more patterns (Stripe, Twilio, SendGrid, Azure, Discord)
- GitHub API scanning — scan public repos directly from a URL
- CI/CD integration — run DSentry automatically before every push
- Better entropy tuning to reduce false positives
- A web interface for non-technical users

---

Tech stack

- **Python 3.13**
- **rich** — terminal UI and colored output
- **re** — regex pattern matching
- **math** — Shannon entropy calculation
- **argparse** — CLI argument parsing
- **pathlib** — file system traversal

---

Honest difficulties I ran into

I want to document these because I think it's more valuable to show real struggle than a polished lie.

**The duplicate findings problem**
This one haunted me for a long time. The same secret on the same line was being flagged twice — once by pattern detection and once by entropy analysis. I tried five or six different approaches to deduplicate them. The fix ended up being architectural — instead of trying to deduplicate after the fact, I restructured the scanner so entropy only runs on lines where zero patterns matched. Sometimes the right fix is redesigning the logic, not patching around it.

**GitHub blocked my own push**
When I tried to push DSentry to GitHub for the first time, GitHub's own secret scanner rejected it because my test files contained fake credentials. My secret scanner tool got caught by a secret scanner. I had to rewrite git history three times to get a clean push through. Ironic, educational, and genuinely funny in hindsight.

**Python caching lying to me**
I kept editing `scanner.py` and the changes weren't taking effect. I was convinced the code was right but the output wasn't changing. Turns out Python was importing a cached `.pyc` bytecode file instead of reading the updated source. Learned about `__pycache__`, bytecode compilation, and how Python's import system actually works — none of which I expected to learn while building a security tool.

**Regex is harder than it looks**
Writing a regex that catches `AWS_SECRET_ACCESS_KEY = "..."` sounds simple until you realize variable names vary, spacing varies, quote styles vary, and your pattern needs to be flexible enough to catch real variants without being so loose it flags everything. Getting the balance right between catching real secrets and avoiding false positives took more iteration than I expected.

---

If you're reading this and have feedback, I'd genuinely love to hear it. I'm still learning and every bit helps.

---

*Built with curiosity, a lot of debugging, and one very satisfying moment when GitHub's own secret scanner blocked my push because my test files had fake credentials in them.*
