import os
import re
import math
from pathlib import Path
from patterns import PATTERNS

SCANNABLE_EXTENSIONS = {
    '.py', '.js', '.ts', '.env', '.json', '.yaml', '.yml',
    '.xml', '.config', '.cfg', '.ini', '.txt', '.sh', '.bash',
    '.php', '.rb', '.go', '.java', '.cs', '.cpp', '.c', '.h'
}

IGNORED_DIRS = {
    'node_modules', '.git', 'venv', '__pycache__',
    '.idea', '.vscode', 'dist', 'build', '.env'
}

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def calculate_entropy(text):
    if not text or len(text) < 8:
        return 0
    frequency = {}
    for char in text:
        frequency[char] = frequency.get(char, 0) + 1
    entropy = 0
    length = len(text)
    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def is_high_entropy_secret(value, threshold=4.5, min_length=20):
    if len(value) < min_length:
        return False
    return calculate_entropy(value) > threshold


def get_findings_for_line(line, line_number):
    """Returns at most ONE finding per line — highest severity wins."""
    candidates = []
    matched_spans = []

    for pattern in PATTERNS:
        match = pattern["regex"].search(line)
        if match:
            candidates.append({
                "type": pattern["name"],
                "severity": pattern["severity"],
                "line_number": line_number,
                "line_content": line.strip(),
                "matched_value": match.group(0)[:50],
                "detection_method": "pattern"
            })
            matched_spans.append((match.start(), match.end()))

    if len(matched_spans) == 0:
        ep = re.compile(r'[\'"`]([A-Za-z0-9+/=_\-]{20,})[\'"`]')
        for m in ep.finditer(line):
            val = m.group(1)
            if is_high_entropy_secret(val):
                candidates.append({
                    "type": "High Entropy String (Possible Secret)",
                    "severity": "MEDIUM",
                    "line_number": line_number,
                    "line_content": line.strip(),
                    "matched_value": val[:50],
                    "detection_method": "entropy"
                })

    if not candidates:
        return None

    best = min(candidates, key=lambda f: SEVERITY_RANK.get(f["severity"], 99))
    return best


def scan_file(filepath):
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        for line_number, line in enumerate(lines, start=1):
            result = get_findings_for_line(line, line_number)
            if result:
                findings.append(result)
    except Exception:
        pass
    return findings


def scan_directory(path):
    target = Path(path)

    if not target.exists():
        return {"error": f"Path does not exist: {path}"}

    if target.is_file():
        findings = scan_file(target)
        return {
            "total_files_scanned": 1,
            "total_secrets_found": len(findings),
            "results": {str(target): findings} if findings else {}
        }

    all_results = {}
    total_files = 0

    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for filename in files:
            filepath = Path(root) / filename
            if filepath.suffix.lower() not in SCANNABLE_EXTENSIONS:
                continue
            total_files += 1
            findings = scan_file(filepath)
            if findings:
                all_results[str(filepath)] = findings

    total_secrets = sum(len(f) for f in all_results.values())

    return {
        "total_files_scanned": total_files,
        "total_secrets_found": total_secrets,
        "results": all_results
    }