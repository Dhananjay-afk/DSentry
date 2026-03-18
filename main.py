import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from scanner import scan_directory

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange1",
    "MEDIUM": "bold yellow",
    "LOW": "bold blue"
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵"
}


def print_banner():
    banner = """
██████╗ ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
██║  ██║███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ 
██║  ██║╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  
██████╔╝███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   
╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   
    """
    console.print(banner, style="bold cyan")
    console.print("  DSentry — Secret & Credential Leak Detector", style="bold white")
    console.print("  Built by Dhananjay | Cybersecurity Portfolio Project\n", style="dim white")


def print_summary(results):
    total_files = results["total_files_scanned"]
    total_secrets = results["total_secrets_found"]

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for filepath, findings in results["results"].items():
        for finding in findings:
            sev = finding["severity"]
            if sev in severity_counts:
                severity_counts[sev] += 1

    summary_text = Text()
    summary_text.append(f"  Files Scanned:     ", style="dim white")
    summary_text.append(f"{total_files}\n", style="bold white")
    summary_text.append(f"  Secrets Found:     ", style="dim white")
    summary_text.append(f"{total_secrets}\n", style="bold red" if total_secrets > 0 else "bold green")
    summary_text.append(f"\n")
    summary_text.append(f"  🔴 CRITICAL:       {severity_counts['CRITICAL']}\n", style="bold red")
    summary_text.append(f"  🟠 HIGH:           {severity_counts['HIGH']}\n", style="bold orange1")
    summary_text.append(f"  🟡 MEDIUM:         {severity_counts['MEDIUM']}\n", style="bold yellow")
    summary_text.append(f"  🔵 LOW:            {severity_counts['LOW']}\n", style="bold blue")

    console.print(Panel(summary_text, title="[bold white]Scan Summary[/bold white]", box=box.DOUBLE_EDGE))


def print_findings(results):
    if not results["results"]:
        console.print("\n✅ [bold green]No secrets found. Your code looks clean![/bold green]\n")
        return

    console.print(f"\n[bold white]📁 Findings by File:[/bold white]\n")

    for filepath, findings in results["results"].items():
        # File header
        console.print(f"[bold cyan]{'─' * 80}[/bold cyan]")
        console.print(f"[bold white]📄 {filepath}[/bold white]")
        console.print(f"[dim]   {len(findings)} secret(s) found[/dim]\n")

        for finding in findings:
            severity = finding["severity"]
            color = SEVERITY_COLORS.get(severity, "white")
            emoji = SEVERITY_EMOJI.get(severity, "⚪")

            # Severity badge + type
            console.print(
                f"  {emoji} [{color}]{severity}[/{color}]  "
                f"[bold white]{finding['type']}[/bold white]"
                f"  [dim]({finding['detection_method']} detection)[/dim]"
            )

            # File + line number
            console.print(
                f"     [dim]Line {finding['line_number']}:[/dim]  "
                f"[yellow]{finding['line_content'][:120]}[/yellow]"
            )

            # Matched value
            console.print(
                f"     [dim]Matched:[/dim]  "
                f"[bold red]{finding['matched_value']}[/bold red]"
            )

            # Remediation advice
            console.print(
                f"     [dim]Fix:[/dim]     "
                f"[green]Use environment variables — os.getenv('YOUR_SECRET_NAME')[/green]\n"
            )

    console.print(f"[bold cyan]{'─' * 80}[/bold cyan]\n")


def export_json(results, output_path):
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    console.print(f"[dim]📄 JSON report saved → {output_path}[/dim]")


def export_html(results, output_path):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_secrets = results["total_secrets_found"]
    total_files = results["total_files_scanned"]

    rows = ""
    for filepath, findings in results["results"].items():
        for f in findings:
            sev = f["severity"]
            color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#4488ff"}.get(sev, "#fff")
            rows += f"""
            <tr>
                <td style='color:{color};font-weight:bold'>{sev}</td>
                <td>{f['type']}</td>
                <td style='color:#aaa'>{filepath}</td>
                <td style='color:#aaa'>Line {f['line_number']}</td>
                <td style='color:#ff6b6b;font-family:monospace'>{f['line_content'][:100]}</td>
                <td style='color:#aaa'>{f['detection_method']}</td>
            </tr>
            """

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>DSentry Report</title>
    <style>
        body {{ background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', monospace; padding: 40px; }}
        h1 {{ color: #58a6ff; }} h2 {{ color: #8b949e; }}
        .stat {{ display: inline-block; background: #161b22; padding: 15px 25px; margin: 10px; border-radius: 8px; border: 1px solid #30363d; }}
        .stat-num {{ font-size: 2em; font-weight: bold; color: #58a6ff; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 30px; }}
        th {{ background: #161b22; padding: 12px; text-align: left; border-bottom: 1px solid #30363d; color: #8b949e; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #21262d; font-size: 0.9em; }}
        tr:hover {{ background: #161b22; }}
        .clean {{ color: #3fb950; font-size: 1.5em; }}
    </style>
</head>
<body>
    <h1>🔐 DSentry Report</h1>
    <p style='color:#8b949e'>Generated: {timestamp}</p>
    <div>
        <div class='stat'><div class='stat-num'>{total_files}</div><div>Files Scanned</div></div>
        <div class='stat'><div class='stat-num' style='color:{"#ff4444" if total_secrets > 0 else "#3fb950"}'>{total_secrets}</div><div>Secrets Found</div></div>
    </div>
    {"<p class='clean'>✅ No secrets found. Code looks clean!</p>" if total_secrets == 0 else f"<table><thead><tr><th>Severity</th><th>Type</th><th>File</th><th>Line</th><th>Content</th><th>Method</th></tr></thead><tbody>{rows}</tbody></table>"}
</body>
</html>"""

    with open(output_path, 'w') as f:
        f.write(html)
    console.print(f"[dim]🌐 HTML report saved → {output_path}[/dim]")


def main():
    parser = argparse.ArgumentParser(
        description="DSentry — Scan your code for leaked secrets and credentials"
    )
    parser.add_argument(
        "--path",
        type=str,
        default=".",
        help="Path to file or directory to scan (default: current directory)"
    )
    parser.add_argument(
        "--export-json",
        type=str,
        help="Export results to JSON file (e.g. --export-json report.json)"
    )
    parser.add_argument(
        "--export-html",
        type=str,
        help="Export results to HTML file (e.g. --export-html report.html)"
    )
    parser.add_argument(
        "--github",
        type=str,
        help="Scan a GitHub repository URL (e.g. --github https://github.com/user/repo)"
    )
    parser.add_argument(
    "--severity",
    type=str,
    help="Filter results by minimum severity (CRITICAL, HIGH, MEDIUM, LOW)"
    )

    args = parser.parse_args()

    print_banner()

    # Show what we're scanning
    console.print(f"[dim]🔍 Scanning:[/dim] [bold white]{Path(args.path).resolve()}[/bold white]\n")

    if args.github:
        console.print(f"[dim]🐙 GitHub Scan:[/dim] [bold white]{args.github}[/bold white]\n")
        from scanner import scan_github_url
        results = scan_github_url(args.github)
    else:
        results = scan_directory(args.path)

    if "error" in results:
        console.print(f"[bold red]Error: {results['error']}[/bold red]")
        sys.exit(1)

    if args.severity:
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        filter_level = args.severity.upper()
        if filter_level not in severity_order:
            console.print(f"[bold red]Invalid severity: {filter_level}. Use CRITICAL, HIGH, MEDIUM or LOW[/bold red]")
            sys.exit(1)
        allowed = severity_order[:severity_order.index(filter_level) + 1]
        filtered = {}
        for filepath, findings in results["results"].items():
            kept = [f for f in findings if f["severity"] in allowed]
            if kept:
                filtered[filepath] = kept
        results["results"] = filtered
        results["total_secrets_found"] = sum(len(f) for f in filtered.values())
    
    print_summary(results)
    print_findings(results)


    if args.export_json:
        export_json(results, args.export_json)
    if args.export_html:
        export_html(results, args.export_html)

    # Exit with error code if secrets found (useful for CI/CD pipelines)
    if results["total_secrets_found"] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()