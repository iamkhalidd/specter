"""
Network Forensics Module - Live connections and PCAP analysis.
"""

from pathlib import Path
from collections import defaultdict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# Common suspicious ports
SUSPICIOUS_PORTS = {
    4444: "Metasploit default",
    5555: "Android ADB",
    6666: "IRC/Backdoor",
    6667: "IRC",
    31337: "Back Orifice",
    1337: "Common backdoor",
    8080: "HTTP Proxy (may be C2)",
    9001: "Tor",
    9050: "Tor SOCKS",
    12345: "NetBus",
    27374: "SubSeven",
}

# Common legitimate ports (for context)
COMMON_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    53: "DNS",
    3389: "RDP",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
}


def show_connections(suspicious_only: bool = False) -> None:
    """
    Display active network connections with process information.

    Args:
        suspicious_only: Only show connections to suspicious ports.
    """
    try:
        import psutil
    except ImportError:
        console.print(
            "[red]Error:[/red] psutil is not installed.\n"
            "[dim]Install with: pip install psutil[/dim]"
        )
        return

    table = Table(title="🌐 Active Network Connections")
    table.add_column("PID", style="dim", justify="right")
    table.add_column("Process", style="cyan")
    table.add_column("Local Address", style="green")
    table.add_column("Remote Address", style="yellow")
    table.add_column("Status")
    table.add_column("Port Info", style="dim")

    connections = psutil.net_connections(kind="inet")
    suspicious_count = 0

    for conn in connections:
        if conn.status == "NONE":
            continue

        try:
            process = psutil.Process(conn.pid) if conn.pid else None
            proc_name = process.name() if process else "Unknown"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            proc_name = "Unknown"

        local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
        remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"

        # Check for suspicious ports
        remote_port = conn.raddr.port if conn.raddr else 0
        local_port = conn.laddr.port if conn.laddr else 0

        is_suspicious = False
        port_info = ""

        if remote_port in SUSPICIOUS_PORTS:
            is_suspicious = True
            port_info = f"⚠ {SUSPICIOUS_PORTS[remote_port]}"
        elif local_port in SUSPICIOUS_PORTS:
            is_suspicious = True
            port_info = f"⚠ {SUSPICIOUS_PORTS[local_port]}"
        elif remote_port in COMMON_PORTS:
            port_info = COMMON_PORTS[remote_port]
        elif local_port in COMMON_PORTS:
            port_info = COMMON_PORTS[local_port]

        if suspicious_only and not is_suspicious:
            continue

        if is_suspicious:
            suspicious_count += 1

        status_style = "red" if is_suspicious else "green" if conn.status == "ESTABLISHED" else "dim"

        table.add_row(
            str(conn.pid or "-"),
            proc_name[:20],
            local_addr,
            remote_addr,
            f"[{status_style}]{conn.status}[/{status_style}]",
            port_info,
        )

    console.print(table)

    if suspicious_count > 0:
        console.print(
            Panel(
                f"[bold red]Found {suspicious_count} connection(s) to suspicious ports![/bold red]\n"
                "[dim]Review these connections for potential C2 or backdoor activity.[/dim]",
                title="⚠ Warning",
                border_style="red",
            )
        )


def analyze_pcap_file(path: str, summary: bool = True) -> None:
    """
    Analyze a PCAP file for network forensics.

    Args:
        path: Path to PCAP file.
        summary: Display summary statistics.
    """
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, DNS
    except ImportError:
        console.print(
            "[red]Error:[/red] scapy is not installed.\n"
            "[dim]Install with: pip install scapy[/dim]"
        )
        return

    pcap_file = Path(path)

    if not pcap_file.exists():
        console.print(f"[red]Error:[/red] PCAP file not found: {path}")
        return

    console.print(f"[cyan]Loading PCAP:[/cyan] {pcap_file.name}...")

    try:
        packets = rdpcap(str(pcap_file))
    except Exception as e:
        console.print(f"[red]Error reading PCAP:[/red] {e}")
        return

    console.print(f"[green]Loaded {len(packets)} packets[/green]\n")

    # Statistics
    src_ips = defaultdict(int)
    dst_ips = defaultdict(int)
    protocols = defaultdict(int)
    ports = defaultdict(int)
    dns_queries = []

    for pkt in packets:
        if IP in pkt:
            src_ips[pkt[IP].src] += 1
            dst_ips[pkt[IP].dst] += 1

            if TCP in pkt:
                protocols["TCP"] += 1
                ports[pkt[TCP].dport] += 1
            elif UDP in pkt:
                protocols["UDP"] += 1
                ports[pkt[UDP].dport] += 1

                # Capture DNS queries
                if DNS in pkt and pkt[DNS].qr == 0:  # Query
                    try:
                        query = pkt[DNS].qd.qname.decode()
                        dns_queries.append(query)
                    except Exception:
                        pass
        else:
            protocols["Other"] += 1

    if summary:
        _display_pcap_summary(src_ips, dst_ips, protocols, ports, dns_queries)


def _display_pcap_summary(
    src_ips: dict,
    dst_ips: dict,
    protocols: dict,
    ports: dict,
    dns_queries: list,
) -> None:
    """Display PCAP analysis summary."""

    # Protocol breakdown
    proto_table = Table(title="📊 Protocol Distribution")
    proto_table.add_column("Protocol", style="cyan")
    proto_table.add_column("Count", justify="right")

    for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
        proto_table.add_row(proto, str(count))

    console.print(proto_table)

    # Top source IPs
    src_table = Table(title="📤 Top Source IPs")
    src_table.add_column("IP Address", style="yellow")
    src_table.add_column("Packets", justify="right")

    for ip, count in sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:10]:
        src_table.add_row(ip, str(count))

    console.print(src_table)

    # Top destination IPs
    dst_table = Table(title="📥 Top Destination IPs")
    dst_table.add_column("IP Address", style="green")
    dst_table.add_column("Packets", justify="right")

    for ip, count in sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:10]:
        dst_table.add_row(ip, str(count))

    console.print(dst_table)

    # Top ports
    port_table = Table(title="🔌 Top Destination Ports")
    port_table.add_column("Port", style="cyan")
    port_table.add_column("Count", justify="right")
    port_table.add_column("Service", style="dim")

    all_ports = {**COMMON_PORTS, **SUSPICIOUS_PORTS}
    for port, count in sorted(ports.items(), key=lambda x: x[1], reverse=True)[:15]:
        service = all_ports.get(port, "")
        if port in SUSPICIOUS_PORTS:
            service = f"[red]⚠ {service}[/red]"
        port_table.add_row(str(port), str(count), service)

    console.print(port_table)

    # DNS queries
    if dns_queries:
        dns_table = Table(title="🔍 DNS Queries (Sample)")
        dns_table.add_column("Domain", style="blue")

        unique_dns = list(set(dns_queries))[:20]
        for domain in unique_dns:
            dns_table.add_row(domain)

        console.print(dns_table)
