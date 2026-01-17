"""
Threat Intelligence Module - API integrations for hash/IP lookups.
"""

import os
import hashlib
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track

console = Console()


# Known malicious hashes (sample IOCs - in production, load from file)
KNOWN_MALICIOUS_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f",  # EICAR test file
    "3395856ce81f2b7382dee72602f798b642f14140",  # EICAR SHA1
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR SHA256
}

# Known malicious IPs (sample - in production, load from threat feeds)
KNOWN_MALICIOUS_IPS = {
    "185.220.101.1",  # Tor exit node
    "45.33.32.156",   # Scanme (test)
    "192.42.116.16",  # Tor
}

# Suspicious domains patterns
SUSPICIOUS_DOMAIN_PATTERNS = [
    r".*\.ru$",       # Russian TLD (not inherently malicious, but often flagged)
    r".*\.cn$",       # Chinese TLD
    r".*\.tk$",       # Free TLD often used for phishing
    r".*\.xyz$",      # Often used for malware
    r".*pastebin.*",  # Data exfiltration
    r".*discord.*webhook.*",  # Discord webhooks (C2)
]


def check_hash_reputation(file_path: str, use_virustotal: bool = False) -> None:
    """
    Check file hash against known malicious hashes and optionally VirusTotal.

    Args:
        file_path: Path to file to check.
        use_virustotal: If True, query VirusTotal API (requires API key).
    """
    path = Path(file_path)

    if not path.exists():
        console.print(f"[red]Error:[/red] File not found: {file_path}")
        return

    # Calculate hashes
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)

    md5 = md5_hash.hexdigest()
    sha256 = sha256_hash.hexdigest()

    console.print(f"\n[cyan]File:[/cyan] {path.name}")
    console.print(f"[dim]MD5:[/dim]    {md5}")
    console.print(f"[dim]SHA256:[/dim] {sha256}\n")

    # Check local IOC database
    is_known_malicious = (
        md5 in KNOWN_MALICIOUS_HASHES or sha256 in KNOWN_MALICIOUS_HASHES
    )

    if is_known_malicious:
        console.print(
            Panel(
                "[bold red]⚠ MALICIOUS HASH DETECTED![/bold red]\n"
                "This file matches a known malware signature.",
                title="🚨 Threat Detected",
                border_style="red",
            )
        )
    else:
        console.print("[green]✓ Hash not found in local IOC database[/green]")

    # VirusTotal lookup
    if use_virustotal:
        vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY")
        if not vt_api_key:
            console.print(
                "[yellow]⚠ VirusTotal API key not set.[/yellow]\n"
                "[dim]Set VIRUSTOTAL_API_KEY environment variable.[/dim]"
            )
            return

        _query_virustotal(sha256, vt_api_key)


def _query_virustotal(hash_value: str, api_key: str) -> None:
    """Query VirusTotal API for hash reputation."""
    try:
        import requests
    except ImportError:
        console.print(
            "[red]Error:[/red] requests library not installed.\n"
            "[dim]Install with: pip install requests[/dim]"
        )
        return

    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            if malicious > 0 or suspicious > 0:
                console.print(
                    Panel(
                        f"[bold red]VirusTotal: {malicious}/{total} engines detected this as malicious![/bold red]\n"
                        f"Suspicious: {suspicious}",
                        title="🦠 VirusTotal Result",
                        border_style="red",
                    )
                )
            else:
                console.print(
                    f"[green]✓ VirusTotal: Clean ({total} engines scanned)[/green]"
                )

        elif response.status_code == 404:
            console.print("[yellow]⚠ Hash not found in VirusTotal database[/yellow]")
        else:
            console.print(f"[red]VirusTotal API error: {response.status_code}[/red]")

    except Exception as e:
        console.print(f"[red]VirusTotal query failed:[/red] {e}")


def check_ip_reputation(ip_address: str, use_abuseipdb: bool = False) -> None:
    """
    Check IP address against known malicious IPs.

    Args:
        ip_address: IP address to check.
        use_abuseipdb: If True, query AbuseIPDB API.
    """
    console.print(f"\n[cyan]Checking IP:[/cyan] {ip_address}\n")

    # Local check
    if ip_address in KNOWN_MALICIOUS_IPS:
        console.print(
            Panel(
                "[bold red]⚠ MALICIOUS IP DETECTED![/bold red]\n"
                "This IP is in the known threat database.",
                title="🚨 Threat Detected",
                border_style="red",
            )
        )
    else:
        console.print("[green]✓ IP not in local threat database[/green]")

    # AbuseIPDB lookup
    if use_abuseipdb:
        api_key = os.environ.get("ABUSEIPDB_API_KEY")
        if not api_key:
            console.print(
                "[yellow]⚠ AbuseIPDB API key not set.[/yellow]\n"
                "[dim]Set ABUSEIPDB_API_KEY environment variable.[/dim]"
            )
            return

        _query_abuseipdb(ip_address, api_key)


def _query_abuseipdb(ip_address: str, api_key: str) -> None:
    """Query AbuseIPDB API for IP reputation."""
    try:
        import requests
    except ImportError:
        console.print("[red]Error:[/red] requests library not installed.")
        return

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)

        if response.status_code == 200:
            data = response.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            country = data.get("countryCode", "Unknown")
            isp = data.get("isp", "Unknown")

            if abuse_score > 50:
                status = "[red]HIGH RISK[/red]"
            elif abuse_score > 20:
                status = "[yellow]MEDIUM RISK[/yellow]"
            else:
                status = "[green]LOW RISK[/green]"

            console.print(
                Panel(
                    f"Abuse Score: {status} ({abuse_score}%)\n"
                    f"Total Reports: {total_reports}\n"
                    f"Country: {country}\n"
                    f"ISP: {isp}",
                    title="📊 AbuseIPDB Result",
                    border_style="cyan",
                )
            )
        else:
            console.print(f"[red]AbuseIPDB API error: {response.status_code}[/red]")

    except Exception as e:
        console.print(f"[red]AbuseIPDB query failed:[/red] {e}")


def scan_iocs(path: str, ioc_file: Optional[str] = None) -> None:
    """
    Scan files against Indicators of Compromise.

    Args:
        path: Directory to scan.
        ioc_file: Optional path to IOC file (one hash per line).
    """
    target = Path(path)

    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {path}")
        return

    # Load IOCs
    iocs = set(KNOWN_MALICIOUS_HASHES)

    if ioc_file:
        ioc_path = Path(ioc_file)
        if ioc_path.exists():
            with open(ioc_path, "r") as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        iocs.add(line)
            console.print(f"[cyan]Loaded {len(iocs)} IOCs[/cyan]\n")

    table = Table(title="🎯 IOC Scan Results")
    table.add_column("File", style="cyan")
    table.add_column("Hash", style="dim")
    table.add_column("Status", justify="center")

    matches = 0
    files = list(target.rglob("*") if target.is_dir() else [target])
    files = [f for f in files if f.is_file()]

    for file_path in track(files, description="Scanning for IOCs..."):
        try:
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()

            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)

            md5 = md5_hash.hexdigest()
            sha256 = sha256_hash.hexdigest()

            if md5 in iocs or sha256 in iocs:
                matches += 1
                table.add_row(
                    str(file_path.name),
                    sha256[:16] + "...",
                    "[red]⚠ MATCH[/red]",
                )

        except Exception:
            pass

    console.print(table)

    if matches > 0:
        console.print(
            Panel(
                f"[bold red]Found {matches} file(s) matching known IOCs![/bold red]",
                title="🚨 IOC Matches",
                border_style="red",
            )
        )
    else:
        console.print("[green]✓ No IOC matches found.[/green]")
