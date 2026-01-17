#!/usr/bin/env python3
"""
ForensicAutomator - Main CLI Entry Point
A cross-platform cybersecurity forensic tool.
"""

import json
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from forensic_tool import __version__

# Initialize Typer app and Rich console
app = typer.Typer(
    name="specter",
    help="👻 SPECTER - Cross-platform cybersecurity forensic CLI tool.",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()

# Global state for JSON output mode
class State:
    json_output: bool = False
    output_file: Optional[str] = None

state = State()


def version_callback(value: bool):
    """Display version and exit."""
    if value:
        console.print(
            Panel(
                f"[bold cyan]SPECTER[/bold cyan] v{__version__}\n"
                "[dim]Cross-platform cybersecurity forensic tool[/dim]",
                title="👻 Version",
                border_style="cyan",
            )
        )
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output results in JSON format.",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save output to file.",
    ),
):
    """
    SPECTER - A cross-platform CLI tool for cybersecurity forensics.

    Use the subcommands below to perform various forensic tasks.
    """
    state.json_output = json_output
    state.output_file = output


# =============================================================================
# FILE FORENSICS COMMANDS
# =============================================================================
@app.command("hash")
def hash_files(
    path: str = typer.Argument(..., help="File or directory path to hash."),
    algorithm: str = typer.Option(
        "sha256", "--algo", "-a", help="Hash algorithm: md5, sha256"
    ),
    recursive: bool = typer.Option(
        False, "--recursive", "-r", help="Recursively hash files in directories."
    ),
):
    """
    Calculate file hashes (MD5/SHA256) for integrity verification.
    """
    from forensic_tool.modules.file_ops import hash_path

    hash_path(path, algorithm, recursive)


@app.command("entropy")
def check_entropy(
    path: str = typer.Argument(..., help="File or directory path to analyze."),
    threshold: float = typer.Option(
        7.5, "--threshold", "-t", help="Entropy threshold for suspicion (0-8)."
    ),
):
    """
    Calculate file entropy to detect packed/encrypted malware.
    """
    from forensic_tool.modules.file_ops import analyze_entropy

    analyze_entropy(path, threshold)


@app.command("yara")
def yara_scan(
    path: str = typer.Argument(..., help="File or directory to scan."),
    rules: str = typer.Option(
        None, "--rules", "-r", help="Path to YARA rules file (.yar)."
    ),
):
    """
    Scan files using YARA rules for malware signatures.
    """
    from forensic_tool.modules.file_ops import scan_with_yara

    scan_with_yara(path, rules)


# =============================================================================
# LOG FORENSICS COMMANDS
# =============================================================================
@app.command("logs")
def analyze_logs(
    path: str = typer.Argument(..., help="Path to log file."),
    attack_patterns: bool = typer.Option(
        True, "--attacks", "-a", help="Scan for common attack patterns (SQLi, XSS)."
    ),
    brute_force: bool = typer.Option(
        False, "--brute", "-b", help="Detect brute force attempts."
    ),
):
    """
    Analyze server logs for suspicious activity.
    """
    from forensic_tool.modules.logs import analyze_log_file

    analyze_log_file(path, attack_patterns, brute_force)


# =============================================================================
# NETWORK FORENSICS COMMANDS
# =============================================================================
@app.command("connections")
def live_connections(
    suspicious_only: bool = typer.Option(
        False, "--suspicious", "-s", help="Show only suspicious connections."
    ),
):
    """
    List active network connections with process info.
    """
    from forensic_tool.modules.network import show_connections

    show_connections(suspicious_only)


@app.command("pcap")
def analyze_pcap(
    path: str = typer.Argument(..., help="Path to PCAP file."),
    summary: bool = typer.Option(
        True, "--summary", help="Show summary statistics."
    ),
):
    """
    Analyze PCAP file for network forensics.
    """
    from forensic_tool.modules.network import analyze_pcap_file

    analyze_pcap_file(path, summary)


# =============================================================================
# THREAT INTELLIGENCE COMMANDS
# =============================================================================
@app.command("check-hash")
def check_hash_reputation(
    path: str = typer.Argument(..., help="File to check."),
    virustotal: bool = typer.Option(
        False, "--vt", help="Query VirusTotal API."
    ),
):
    """
    Check file hash against threat intelligence databases.
    """
    from forensic_tool.modules.threat_intel import check_hash_reputation as check_hash

    check_hash(path, virustotal)


@app.command("check-ip")
def check_ip_reputation(
    ip: str = typer.Argument(..., help="IP address to check."),
    abuseipdb: bool = typer.Option(
        False, "--abuse", help="Query AbuseIPDB API."
    ),
):
    """
    Check IP address reputation.
    """
    from forensic_tool.modules.threat_intel import check_ip_reputation as check_ip

    check_ip(ip, abuseipdb)


@app.command("ioc-scan")
def ioc_scan(
    path: str = typer.Argument(..., help="Directory to scan."),
    ioc_file: str = typer.Option(
        None, "--iocs", "-i", help="Path to IOC file (one hash per line)."
    ),
):
    """
    Scan files against Indicators of Compromise (IOCs).
    """
    from forensic_tool.modules.threat_intel import scan_iocs

    scan_iocs(path, ioc_file)


# =============================================================================
# TIMELINE COMMANDS
# =============================================================================
@app.command("timeline")
def build_timeline(
    path: str = typer.Argument(..., help="Directory to analyze."),
    days: int = typer.Option(
        30, "--days", "-d", help="Include events from last N days."
    ),
    output: str = typer.Option(
        None, "--output", "-o", help="Save timeline to CSV file."
    ),
):
    """
    Build forensic timeline from file metadata.
    """
    from forensic_tool.modules.timeline import build_timeline as build_tl

    build_tl(path, output, days)


# =============================================================================
# SYSTEM ANALYSIS COMMANDS
# =============================================================================
@app.command("autoruns")
def check_autoruns():
    """
    Check for persistence mechanisms (startup items, scheduled tasks).
    """
    from forensic_tool.modules.system import check_autoruns as check_ar

    check_ar()


@app.command("processes")
def analyze_processes():
    """
    Analyze running processes for suspicious activity.
    """
    from forensic_tool.modules.system import analyze_processes

    analyze_processes()


# =============================================================================
# REPORT COMMANDS
# =============================================================================
@app.command("report")
def generate_report(
    scan_type: str = typer.Argument(
        ..., help="Type of scan: full, files, network, system"
    ),
    path: str = typer.Option(
        ".", "--path", "-p", help="Path to analyze."
    ),
    output: str = typer.Option(
        "forensic_report", "--output", "-o", help="Output file name."
    ),
    format: str = typer.Option(
        "html", "--format", "-f", help="Output format: html, json"
    ),
):
    """
    Generate comprehensive forensic report.
    """
    from pathlib import Path
    from forensic_tool.core.report import ReportBuilder
    from forensic_tool.core.utils import walk_files, calculate_entropy

    console.print(f"[cyan]Generating {scan_type} report...[/cyan]\n")

    builder = ReportBuilder(f"Forensic Report - {scan_type.title()}")

    if scan_type in ("full", "files"):
        # File analysis
        target = Path(path)
        files = list(walk_files(target, recursive=True))

        file_data = []
        suspicious = 0
        for f in files[:100]:  # Limit for performance
            try:
                entropy = calculate_entropy(f)
                is_suspicious = entropy > 7.5
                if is_suspicious:
                    suspicious += 1
                file_data.append({
                    "File": f.name,
                    "Size": f"{f.stat().st_size:,}",
                    "Entropy": f"{entropy:.2f}",
                    "Status": "SUSPICIOUS" if is_suspicious else "Normal",
                })
            except Exception:
                pass

        builder.add_summary("Files Scanned", len(files), "info")
        builder.add_summary("Suspicious Files", suspicious, "critical" if suspicious > 0 else "success")
        builder.add_section("File Analysis", file_data)

    if scan_type in ("full", "network"):
        try:
            import psutil
            connections = psutil.net_connections(kind="inet")

            conn_data = []
            for conn in connections[:50]:
                if conn.status == "NONE":
                    continue
                try:
                    proc = psutil.Process(conn.pid) if conn.pid else None
                    proc_name = proc.name() if proc else "Unknown"
                except Exception:
                    proc_name = "Unknown"

                conn_data.append({
                    "Process": proc_name,
                    "Local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-",
                    "Remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-",
                    "Status": conn.status,
                })

            builder.add_summary("Active Connections", len(connections), "info")
            builder.add_section("Network Connections", conn_data)
        except ImportError:
            pass

    if scan_type in ("full", "system"):
        from forensic_tool.modules.system import check_autoruns as get_autoruns

        try:
            # Capture autoruns without printing
            autoruns = get_autoruns()
            autorun_data = [
                {
                    "Category": ar.category,
                    "Name": ar.name,
                    "Command": ar.command[:50],
                    "Status": "SUSPICIOUS" if ar.suspicious else "Normal",
                }
                for ar in autoruns[:20]
            ]
            suspicious_autoruns = sum(1 for ar in autoruns if ar.suspicious)
            builder.add_summary("Autorun Entries", len(autoruns), "info")
            builder.add_summary("Suspicious Autoruns", suspicious_autoruns, "warning" if suspicious_autoruns > 0 else "success")
            builder.add_section("Persistence Mechanisms", autorun_data)
        except Exception:
            pass

    builder.save(output, format)


@app.command("init-config")
def init_config():
    """
    Create a sample configuration file (~/.forensic.yaml).
    """
    from forensic_tool.core.config import create_sample_config

    create_sample_config()


if __name__ == "__main__":
    app()
