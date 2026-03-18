# DSentry Test Suite

This folder contains the test files used to evaluate DSentry's detection accuracy.

---

## How to Run Tests
```bash
# True positive test — should catch everything
python main.py --path tests/test_truepositive.py

# False positive test — should catch nothing
python main.py --path tests/test_falsepositive.py

# Edge cases test — tests tricky scenarios
python main.py --path tests/test_edgecases.py
```

---

## Test Results — v1.1

**Date:** March 2026  
**Version:** DSentry v1.1  
**Tester:** Dhananjay  

### True Positive Test
Tests whether DSentry catches all known secret types.

| Secret Type | Detected | Severity |
|-------------|----------|----------|
| AWS Access Key | ✅ | CRITICAL |
| AWS Secret Key | ✅ | CRITICAL |
| Google API Key | ✅ | CRITICAL |
| Firebase API Key | ✅ | CRITICAL |
| GitHub Token | ✅ | CRITICAL |
| GitLab Token | ✅ | CRITICAL |
| Slack Token | ✅ | CRITICAL |
| NPM Token | ✅ | CRITICAL |
| Discord Bot Token | ✅ | CRITICAL |
| Telegram Token | ✅ | CRITICAL |
| MongoDB URL | ✅ | CRITICAL |
| PostgreSQL URL | ✅ | CRITICAL |
| MySQL URL | ✅ | CRITICAL |
| Stripe Secret Key | ✅ | CRITICAL |
| Stripe Webhook | ✅ | HIGH |
| SSH Private Key | ✅ | CRITICAL |
| JWT Token | ✅ | HIGH |
| Hardcoded Password | ✅ | HIGH |
| SendGrid API Key | ✅ | CRITICAL |
| Twilio Auth Token | ✅ | CRITICAL |
| Mailgun API Key | ✅ | CRITICAL |

**Score: 21/21 — 100% detection rate**

---

### False Positive Test
Tests whether DSentry flags clean legitimate code as secrets.

| Test | Result |
|------|--------|
| Normal variables | ✅ Not flagged |
| Normal functions | ✅ Not flagged |
| Config values | ✅ Not flagged |
| Short strings | ✅ Not flagged |
| Comments about secrets | ✅ Not flagged |
| Placeholder URLs | ✅ Not flagged |

**Score: 0 false positives — 100% clean**

---

### Edge Cases Test
Tests tricky real-world scenarios.

| Scenario | Result | Notes |
|----------|--------|-------|
| Secret in a comment | ✅ Caught | Commented secrets still dangerous |
| Secret in print statement | ✅ Caught | Common debugging mistake |
| Secret reassigned from None | ✅ Caught | Real world pattern |
| Single quote style | ✅ Caught | Quote style agnostic |
| Triple quote style | ✅ Caught | Quote style agnostic |
| Secret in dictionary | ✅ Caught | Common config pattern |
| Secret in list | ✅ Caught | Partial — AWS key CRITICAL, secret MEDIUM |
| Secret in f-string context | ✅ Caught | Variable assignment caught |
| Extra whitespace | ✅ Caught | Whitespace agnostic |
| Long password | ✅ Caught | Variable name detection |
| Split secrets | ❌ Missed | Known limitation — industry-wide |
| Base64 encoded secrets | ❌ Missed | Known limitation — requires decode step |

**Score: 12/14 — 85.7% detection rate**

---

## Overall Performance

| Test | Score |
|------|-------|
| True Positives | 21/21 — 100% |
| False Positives | 0/0 — 100% clean |
| Edge Cases | 12/14 — 85.7% |
| **Overall** | **33/35 — 94.3%** |

---

## Known Limitations

**Split secrets** — If a secret is split across multiple variables and concatenated, DSentry cannot detect it. This is an industry-wide limitation present in tools like TruffleHog and GitGuardian as well.

**Base64/encoded secrets** — Secrets encoded in Base64 or other encoding formats require a decode step before detection. This is planned for a future version.

**Compiled binaries** — DSentry scans source code only. Secrets baked into compiled executables require binary analysis tools like Ghidra.

---

## Roadmap Improvements

Based on these results the following improvements are planned:

- Add entropy tuning to upgrade partial detections from MEDIUM to HIGH
- Add Base64 decode layer for encoded secret detection
- Add context awareness to lower severity for secrets in test files