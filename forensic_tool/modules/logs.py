"""
Log Forensics Module - Attack pattern detection and brute force analysis.
"""

import re
from pathlib import Path
from collections import defaultdict
from typing import NamedTuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

from forensic_tool.core.utils import read_log_lines

console = Console()


class AttackPattern(NamedTuple):
    """Represents a detected attack pattern."""

    name: str
    pattern: re.Pattern
    severity: str  # low, medium, high, critical


# Common attack patterns for web server logs
ATTACK_PATTERNS: list[AttackPattern] = [
    # SQL Injection
    AttackPattern(
        "SQL Injection",
        re.compile(r"(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|--|;--|1=1|1'='1|or\s+1=1)", re.IGNORECASE),
        "critical",
    ),
    # XSS
    AttackPattern(
        "XSS Attack",
        re.compile(r"(<script|javascript:|onerror=|onload=|onclick=|<img\s+src=|<iframe)", re.IGNORECASE),
        "high",
    ),
    # Path Traversal / LFI
    AttackPattern(
        "Path Traversal",
        re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self|boot\.ini|win\.ini)", re.IGNORECASE),
        "critical",
    ),
    # Command Injection
    AttackPattern(
        "Command Injection",
        re.compile(r"(;|\||`|&&|\$\(|%0a|%0d).*?(cat|ls|whoami|id|uname|wget|curl|nc|netcat|bash|sh|cmd|powershell)", re.IGNORECASE),
        "critical",
    ),
    # Common scanners/bots
    AttackPattern(
        "Scanner/Bot",
        re.compile(r"(nikto|sqlmap|nmap|masscan|zgrab|dirbuster|gobuster|wfuzz)", re.IGNORECASE),
        "medium",
    ),
    # Sensitive file access attempts
    AttackPattern(
        "Sensitive File Access",
        re.compile(r"(\.env|\.git|\.htaccess|\.htpasswd|wp-config|config\.php|\.bak|\.sql|phpinfo)", re.IGNORECASE),
        "high",
    ),
    # Authentication failures (generic)
    AttackPattern(
        "Auth Failure",
        re.compile(r"(failed\s+password|authentication\s+failure|invalid\s+user|401|403\s+forbidden)", re.IGNORECASE),
        "medium",
    ),
]


def analyze_log_file(path: str, attack_patterns: bool = True, brute_force: bool = False) -> None:
    """
    Analyze a log file for suspicious patterns.

    Args:
        path: Path to log file.
        attack_patterns: Scan for common attack patterns.
        brute_force: Detect brute force attempts.
    """
    log_file = Path(path)

    if not log_file.exists():
        console.print(f"[red]Error:[/red] Log file not found: {path}")
        return

    if not log_file.is_file():
        console.print(f"[red]Error:[/red] Path is not a file: {path}")
        return

    console.print(f"[cyan]Analyzing log file:[/cyan] {log_file.name}\n")

    findings = defaultdict(list)
    ip_counter = defaultdict(int)
    line_count = 0

    # IP address regex for brute force detection
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning logs...", total=None)

        for line in read_log_lines(log_file):
            line_count += 1

            if attack_patterns:
                for pattern in ATTACK_PATTERNS:
                    if pattern.pattern.search(line):
                        findings[pattern.name].append({
                            "line": line_count,
                            "content": line[:100] + "..." if len(line) > 100 else line,
                            "severity": pattern.severity,
                        })

            if brute_force:
                # Count IPs, especially for auth failure lines
                ip_match = ip_pattern.search(line)
                if ip_match:
                    ip = ip_match.group()
                    # Weight auth failures more
                    if any(word in line.lower() for word in ["failed", "invalid", "denied", "401", "403"]):
                        ip_counter[ip] += 5
                    else:
                        ip_counter[ip] += 1

            progress.update(task, advance=1)

    # Display findings
    if attack_patterns and findings:
        _display_attack_findings(findings)
    elif attack_patterns:
        console.print("[green]✓ No attack patterns detected.[/green]\n")

    if brute_force:
        _display_brute_force_analysis(ip_counter)

    console.print(f"\n[dim]Total lines analyzed: {line_count:,}[/dim]")


def _display_attack_findings(findings: dict) -> None:
    """Display attack pattern findings in a table."""
    severity_colors = {
        "critical": "red",
        "high": "yellow",
        "medium": "blue",
        "low": "dim",
    }

    table = Table(title="🚨 Attack Patterns Detected")
    table.add_column("Pattern", style="cyan")
    table.add_column("Severity", justify="center")
    table.add_column("Count", justify="right")
    table.add_column("Sample Line", style="dim", no_wrap=False, max_width=50)

    for pattern_name, matches in sorted(findings.items(), key=lambda x: len(x[1]), reverse=True):
        if matches:
            severity = matches[0]["severity"]
            color = severity_colors.get(severity, "white")
            sample = matches[0]["content"]
            table.add_row(
                pattern_name,
                f"[{color}]{severity.upper()}[/{color}]",
                str(len(matches)),
                sample,
            )

    console.print(table)

    total_findings = sum(len(m) for m in findings.values())
    console.print(
        Panel(
            f"[bold red]Total suspicious entries: {total_findings}[/bold red]",
            title="⚠ Summary",
            border_style="red",
        )
    )


def _display_brute_force_analysis(ip_counter: dict) -> None:
    """Display brute force analysis results."""
    if not ip_counter:
        console.print("[green]✓ No suspicious IPs detected.[/green]")
        return

    # Sort by request count and filter suspicious (>50 weighted requests)
    suspicious_ips = sorted(
        [(ip, count) for ip, count in ip_counter.items() if count > 50],
        key=lambda x: x[1],
        reverse=True,
    )[:20]  # Top 20

    if not suspicious_ips:
        console.print("[green]✓ No brute force patterns detected.[/green]")
        return

    table = Table(title="🔒 Potential Brute Force IPs")
    table.add_column("IP Address", style="red")
    table.add_column("Suspicion Score", justify="right")
    table.add_column("Risk Level", justify="center")

    for ip, score in suspicious_ips:
        if score > 500:
            risk = "[red]HIGH[/red]"
        elif score > 200:
            risk = "[yellow]MEDIUM[/yellow]"
        else:
            risk = "[blue]LOW[/blue]"

        table.add_row(ip, str(score), risk)

    console.print(table)
