#!/usr/bin/env python3
"""
SPECTER - Interactive Menu Mode
A user-friendly interface for the forensic tool.
"""

import os
import sys
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.text import Text

from forensic_tool import __version__

console = Console()

# ASCII Art Banner
BANNER = r"""
[bold cyan]
   ███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗ 
   ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
   ███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝
   ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗
   ███████║██║     ███████╗╚██████╗   ██║   ███████╗██║  ██║
   ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
[/bold cyan]
[dim cyan]          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          █  Cybersecurity Forensic Toolkit  █
          ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀[/dim cyan]
"""

AUTHOR_INFO = """
[dim]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim]
  [bold cyan]SPECTER[/bold cyan] v{version} | Cross-Platform Forensic Toolkit
[dim]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim]
  [green]Author:[/green]  Khalid
  [green]GitHub:[/green]  https://github.com/iamkhalidd/specter
  [green]License:[/green] MIT
[dim]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim]
"""


def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def show_banner():
    """Display the ASCII art banner."""
    console.print(BANNER)
    console.print(AUTHOR_INFO.format(version=__version__))


def show_main_menu():
    """Display the main menu and return user choice."""
    console.print()
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Option", style="cyan", width=4)
    table.add_column("Category", style="bold white", width=25)
    table.add_column("Description", style="dim")

    menu_items = [
        ("1", "📁 File Forensics", "Hash, entropy, YARA scanning"),
        ("2", "📊 Log Analysis", "Detect attacks in server logs"),
        ("3", "🌐 Network Forensics", "Connections, PCAP analysis"),
        ("4", "🎯 Threat Intelligence", "Hash/IP reputation, IOC scan"),
        ("5", "🔧 System Analysis", "Autoruns, processes"),
        ("6", "📋 Generate Report", "HTML/JSON forensic reports"),
        ("7", "⚙️  Settings", "Configure tool settings"),
        ("0", "🚪 Exit", "Quit SPECTER"),
    ]

    for option, category, description in menu_items:
        table.add_row(f"[{option}]", category, description)

    console.print(Panel(table, title="[bold]Main Menu[/bold]", border_style="cyan"))

    return Prompt.ask("\n[cyan]Select an option[/cyan]", choices=["0", "1", "2", "3", "4", "5", "6", "7"], default="0")


def file_forensics_menu():
    """File forensics submenu."""
    while True:
        console.print()
        console.print(Panel("[bold]📁 File Forensics[/bold]", border_style="green"))
        console.print("  [1] Hash files (MD5/SHA256)")
        console.print("  [2] Entropy analysis (detect packed files)")
        console.print("  [3] YARA scan (malware signatures)")
        console.print("  [0] Back to main menu")

        choice = Prompt.ask("\n[green]Select[/green]", choices=["0", "1", "2", "3"], default="0")

        if choice == "0":
            break
        elif choice == "1":
            path = Prompt.ask("[green]Enter file/directory path[/green]")
            algo = Prompt.ask("[green]Algorithm[/green]", choices=["md5", "sha256"], default="sha256")
            recursive = Confirm.ask("[green]Recursive?[/green]", default=False)
            from forensic_tool.modules.file_ops import hash_path
            hash_path(path, algo, recursive)
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]")
        elif choice == "2":
            path = Prompt.ask("[green]Enter file/directory path[/green]")
            threshold = float(Prompt.ask("[green]Entropy threshold[/green]", default="7.5"))
            from forensic_tool.modules.file_ops import analyze_entropy
            analyze_entropy(path, threshold)
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]")
        elif choice == "3":
            path = Prompt.ask("[green]Enter file/directory path[/green]")
            rules = Prompt.ask("[green]YARA rules file (or Enter for default)[/green]", default="")
            from forensic_tool.modules.file_ops import scan_with_yara
            scan_with_yara(path, rules if rules else None)
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]")


def log_analysis_menu():
    """Log analysis submenu."""
    while True:
        console.print()
        console.print(Panel("[bold]📊 Log Analysis[/bold]", border_style="yellow"))
        console.print("  [1] Scan for attack patterns (SQLi, XSS, LFI)")
        console.print("  [2] Detect brute force attempts")
        console.print("  [3] Full analysis (attacks + brute force)")
        console.print("  [0] Back to main menu")

        choice = Prompt.ask("\n[yellow]Select[/yellow]", choices=["0", "1", "2", "3"], default="0")

        if choice == "0":
            break
        else:
            path = Prompt.ask("[yellow]Enter log file path[/yellow]")
            from forensic_tool.modules.logs import analyze_log_file
            if choice == "1":
                analyze_log_file(path, attack_patterns=True, brute_force=False)
            elif choice == "2":
                analyze_log_file(path, attack_patterns=False, brute_force=True)
            elif choice == "3":
                analyze_log_file(path, attack_patterns=True, brute_force=True)
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]")


def network_forensics_menu():
    """Network forensics submenu."""
    while True:
        console.print()
        console.print(Panel("[bold]🌐 Network Forensics[/bold]", border_style="blue"))
        console.print("  [1] Show active connections")
        console.print("  [2] Show suspicious connections only")
        console.print("  [3] Analyze PCAP file")
        console.print("  [0] Back to main menu")

        choice = Prompt.ask("\n[blue]Select[/blue]", choices=["0", "1", "2", "3"], default="0")

        if choice == "0":
            break
        elif choice in ("1", "2"):
            from forensic_tool.modules.network import show_connections
            show_connections(suspicious_only=(choice == "2"))
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]")
        elif choice == "3":
            path = Prompt.ask("[blue]Enter PCAP file path[/blue]")
            from forensic_tool.modules.network import analyze_pcap_file
            analyze_pcap_file(path, summary=True)
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]")


def threat_intel_menu():
    """Threat intelligence submenu."""
    while True:
        console.print()
        console.print(Panel("[bold]🎯 Threat Intelligence[/bold]", border_style="red"))
        console.print("  [1] Check file hash reputation")
        console.print("  [2] Check IP reputation")
        console.print("  [3] IOC scan (scan against known bad hashes)")
        console.print("  [0] Back to main menu")

        choice = Prompt.ask("\n[red]Select[/red]", choices=["0", "1", "2", "3"], default="0")

        if choice == "0":
            break
        elif choice == "1":
            path = Prompt.ask("[red]Enter file path[/red]")
            vt = Confirm.ask("[red]Query VirusTotal? (requires API key)[/red]", default=False)
            from forensic_tool.modules.threat_intel import check_hash_reputation
            check_hash_reputation(path, vt)
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]")
        elif choice == "2":
            ip = Prompt.ask("[red]Enter IP address[/red]")
            abuse = Confirm.ask("[red]Query AbuseIPDB? (requires API key)[/red]", default=False)
            from forensic_tool.modules.threat_intel import check_ip_reputation
            check_ip_reputation(ip, abuse)
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]")
        elif choice == "3":
            path = Prompt.ask("[red]Enter directory to scan[/red]")
            ioc_file = Prompt.ask("[red]IOC file path (or Enter for default)[/red]", default="")
            from forensic_tool.modules.threat_intel import scan_iocs
            scan_iocs(path, ioc_file if ioc_file else None)
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]")


def system_analysis_menu():
    """System analysis submenu."""
    while True:
        console.print()
        console.print(Panel("[bold]🔧 System Analysis[/bold]", border_style="magenta"))
        console.print("  [1] Check autoruns/persistence")
        console.print("  [2] Analyze running processes")
        console.print("  [3] Build timeline from file metadata")
        console.print("  [0] Back to main menu")

        choice = Prompt.ask("\n[magenta]Select[/magenta]", choices=["0", "1", "2", "3"], default="0")

        if choice == "0":
            break
        elif choice == "1":
            from forensic_tool.modules.system import check_autoruns
            check_autoruns()
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]")
        elif choice == "2":
            from forensic_tool.modules.system import analyze_processes
            analyze_processes()
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]")
        elif choice == "3":
            path = Prompt.ask("[magenta]Enter directory path[/magenta]")
            days = int(Prompt.ask("[magenta]Days to look back[/magenta]", default="30"))
            output = Prompt.ask("[magenta]Output file (or Enter to skip)[/magenta]", default="")
            from forensic_tool.modules.timeline import build_timeline
            build_timeline(path, output if output else None, days)
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]")


def report_menu():
    """Report generation submenu."""
    console.print()
    console.print(Panel("[bold]📋 Generate Report[/bold]", border_style="cyan"))
    console.print("  [1] Full system report")
    console.print("  [2] File analysis report")
    console.print("  [3] Network report")
    console.print("  [4] System report")
    console.print("  [0] Back to main menu")

    choice = Prompt.ask("\n[cyan]Select[/cyan]", choices=["0", "1", "2", "3", "4"], default="0")

    if choice == "0":
        return

    scan_types = {"1": "full", "2": "files", "3": "network", "4": "system"}
    scan_type = scan_types[choice]

    path = Prompt.ask("[cyan]Path to analyze[/cyan]", default=".")
    output = Prompt.ask("[cyan]Output filename[/cyan]", default="forensic_report")
    fmt = Prompt.ask("[cyan]Format[/cyan]", choices=["html", "json"], default="html")

    # Import and generate report
    from pathlib import Path
    from forensic_tool.core.report import ReportBuilder
    from forensic_tool.core.utils import walk_files, calculate_entropy

    console.print(f"\n[cyan]Generating {scan_type} report...[/cyan]")
    builder = ReportBuilder(f"Forensic Report - {scan_type.title()}")

    if scan_type in ("full", "files"):
        target = Path(path)
        files = list(walk_files(target, recursive=True))
        file_data = []
        suspicious = 0
        for f in files[:100]:
            try:
                entropy = calculate_entropy(f)
                if entropy > 7.5:
                    suspicious += 1
                file_data.append({
                    "File": f.name,
                    "Size": f"{f.stat().st_size:,}",
                    "Entropy": f"{entropy:.2f}",
                    "Status": "SUSPICIOUS" if entropy > 7.5 else "Normal",
                })
            except Exception:
                pass
        builder.add_summary("Files Scanned", len(files), "info")
        builder.add_summary("Suspicious Files", suspicious, "critical" if suspicious > 0 else "success")
        builder.add_section("File Analysis", file_data)

    builder.save(output, fmt)
    Prompt.ask("\n[dim]Press Enter to continue...[/dim]")


def settings_menu():
    """Settings submenu."""
    while True:
        console.print()
        console.print(Panel("[bold]⚙️  Settings[/bold]", border_style="white"))
        console.print("  [1] Set VirusTotal API Key")
        console.print("  [2] Set AbuseIPDB API Key")
        console.print("  [3] Create config file (~/.specter.yaml)")
        console.print("  [4] Show current configuration")
        console.print("  [0] Back to main menu")

        choice = Prompt.ask("\n[white]Select[/white]", choices=["0", "1", "2", "3", "4"], default="0")

        if choice == "0":
            break
        elif choice == "1":
            api_key = Prompt.ask("[yellow]Enter VirusTotal API Key[/yellow]", password=True)
            if api_key:
                _save_api_key("virustotal_api_key", api_key)
                console.print("[green]✓ VirusTotal API key saved![/green]")
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]")
        elif choice == "2":
            api_key = Prompt.ask("[yellow]Enter AbuseIPDB API Key[/yellow]", password=True)
            if api_key:
                _save_api_key("abuseipdb_api_key", api_key)
                console.print("[green]✓ AbuseIPDB API key saved![/green]")
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]")
        elif choice == "3":
            from forensic_tool.core.config import create_sample_config
            create_sample_config()
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]")
        elif choice == "4":
            from forensic_tool.core.config import config
            console.print(Panel(
                f"Output Format: {config.output_format}\n"
                f"Hash Algorithm: {config.hash_algorithm}\n"
                f"Entropy Threshold: {config.entropy_threshold}\n"
                f"VirusTotal API: {'[green]✓ Set[/green]' if config.virustotal_api_key else '[red]✗ Not set[/red]'}\n"
                f"AbuseIPDB API: {'[green]✓ Set[/green]' if config.abuseipdb_api_key else '[red]✗ Not set[/red]'}",
                title="Current Configuration",
                border_style="cyan",
            ))
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]")


def _save_api_key(key_name: str, value: str) -> None:
    """Save an API key to the config file."""
    from pathlib import Path
    import os

    config_path = Path.home() / ".specter.yaml"

    # Read existing config or create new
    config_content = {}
    if config_path.exists():
        try:
            import yaml
            with open(config_path, "r") as f:
                config_content = yaml.safe_load(f) or {}
        except ImportError:
            # Simple parsing if no yaml
            pass

    # Update the key
    config_content[key_name] = value

    # Also set as environment variable for current session
    env_var_name = key_name.upper()
    os.environ[env_var_name] = value

    # Write back
    try:
        import yaml
        with open(config_path, "w") as f:
            yaml.dump(config_content, f, default_flow_style=False)
    except ImportError:
        # Simple write if no yaml
        with open(config_path, "w") as f:
            for k, v in config_content.items():
                f.write(f"{k}: {v}\n")

    console.print(f"[dim]Saved to {config_path}[/dim]")


def interactive_mode():
    """Run the interactive menu mode."""
    try:
        while True:
            clear_screen()
            show_banner()
            choice = show_main_menu()

            if choice == "0":
                console.print("\n[cyan]Goodbye! Stay safe. 🔐[/cyan]\n")
                sys.exit(0)
            elif choice == "1":
                file_forensics_menu()
            elif choice == "2":
                log_analysis_menu()
            elif choice == "3":
                network_forensics_menu()
            elif choice == "4":
                threat_intel_menu()
            elif choice == "5":
                system_analysis_menu()
            elif choice == "6":
                report_menu()
            elif choice == "7":
                settings_menu()

    except KeyboardInterrupt:
        console.print("\n\n[yellow]Interrupted. Exiting...[/yellow]\n")
        sys.exit(0)


if __name__ == "__main__":
    interactive_mode()
