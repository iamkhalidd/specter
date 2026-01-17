"""
System Analysis Module - Autoruns, persistence, and memory analysis.
"""

import os
import platform
from pathlib import Path
from typing import NamedTuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class AutorunEntry(NamedTuple):
    """Represents an autorun/persistence entry."""

    category: str
    name: str
    path: str
    command: str
    suspicious: bool


def check_autoruns() -> list[AutorunEntry]:
    """
    Check for persistence mechanisms (autoruns).

    Returns:
        List of autorun entries found.
    """
    entries: list[AutorunEntry] = []
    system = platform.system()

    console.print(f"[cyan]Scanning for persistence mechanisms on {system}...[/cyan]\n")

    if system == "Windows":
        entries.extend(_check_windows_autoruns())
    else:
        entries.extend(_check_linux_autoruns())

    _display_autoruns(entries)
    return entries


def _check_windows_autoruns() -> list[AutorunEntry]:
    """Check Windows autorun locations."""
    entries = []

    # Common autorun registry keys (we'll check via file system equivalents)
    startup_paths = [
        Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup",
        Path(os.environ.get("PROGRAMDATA", "")) / "Microsoft/Windows/Start Menu/Programs/StartUp",
    ]

    # Check startup folders
    for startup_path in startup_paths:
        if startup_path.exists():
            for item in startup_path.iterdir():
                suspicious = _is_suspicious_autorun(item.name, str(item))
                entries.append(
                    AutorunEntry(
                        category="Startup Folder",
                        name=item.name,
                        path=str(startup_path),
                        command=str(item),
                        suspicious=suspicious,
                    )
                )

    # Check scheduled tasks (via schtasks)
    try:
        import subprocess
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            lines = result.stdout.strip().split("\n")
            for line in lines[1:]:  # Skip header
                try:
                    parts = line.split('","')
                    if len(parts) >= 9:
                        task_name = parts[1].strip('"')
                        task_command = parts[8].strip('"') if len(parts) > 8 else ""

                        # Skip common Windows tasks
                        if any(skip in task_name.lower() for skip in [
                            "microsoft", "windows", "system", "user_feed"
                        ]):
                            continue

                        suspicious = _is_suspicious_autorun(task_name, task_command)
                        entries.append(
                            AutorunEntry(
                                category="Scheduled Task",
                                name=task_name[:50],
                                path="Task Scheduler",
                                command=task_command[:100] if task_command else "N/A",
                                suspicious=suspicious,
                            )
                        )
                except Exception:
                    pass

    except Exception:
        pass

    return entries


def _check_linux_autoruns() -> list[AutorunEntry]:
    """Check Linux autorun locations."""
    entries = []

    # Check crontab
    cron_paths = [
        Path("/etc/crontab"),
        Path("/etc/cron.d"),
        Path.home() / ".config/autostart",
        Path("/etc/xdg/autostart"),
    ]

    for cron_path in cron_paths:
        if cron_path.exists():
            if cron_path.is_file():
                try:
                    content = cron_path.read_text()
                    for line in content.split("\n"):
                        if line.strip() and not line.startswith("#"):
                            suspicious = _is_suspicious_autorun("cron", line)
                            entries.append(
                                AutorunEntry(
                                    category="Cron",
                                    name=cron_path.name,
                                    path=str(cron_path),
                                    command=line[:100],
                                    suspicious=suspicious,
                                )
                            )
                except Exception:
                    pass
            elif cron_path.is_dir():
                for item in cron_path.iterdir():
                    suspicious = _is_suspicious_autorun(item.name, str(item))
                    entries.append(
                        AutorunEntry(
                            category="Autostart",
                            name=item.name,
                            path=str(cron_path),
                            command=str(item),
                            suspicious=suspicious,
                        )
                    )

    # Check systemd user services
    systemd_user = Path.home() / ".config/systemd/user"
    if systemd_user.exists():
        for service in systemd_user.glob("*.service"):
            suspicious = _is_suspicious_autorun(service.name, str(service))
            entries.append(
                AutorunEntry(
                    category="Systemd User",
                    name=service.name,
                    path=str(systemd_user),
                    command=str(service),
                    suspicious=suspicious,
                )
            )

    return entries


def _is_suspicious_autorun(name: str, command: str) -> bool:
    """Check if an autorun entry looks suspicious."""
    name_lower = name.lower()
    command_lower = command.lower()

    suspicious_patterns = [
        "powershell",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "regsvr32",
        "rundll32",
        "certutil",
        "bitsadmin",
        "wget",
        "curl",
        "nc",
        "netcat",
        "base64",
        "hidden",
        "-enc",
        "-nop",
        "bypass",
        "iex",
        "invoke",
        "downloadstring",
        "temp",
        "tmp",
        "appdata",
    ]

    for pattern in suspicious_patterns:
        if pattern in name_lower or pattern in command_lower:
            return True

    return False


def _display_autoruns(entries: list[AutorunEntry]) -> None:
    """Display autorun entries in a table."""
    if not entries:
        console.print("[green]✓ No autorun entries found.[/green]")
        return

    table = Table(title="🔄 Autorun/Persistence Mechanisms")
    table.add_column("Category", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Command/Path", style="dim", no_wrap=False, max_width=50)
    table.add_column("Status", justify="center")

    suspicious_count = 0

    for entry in entries:
        status = "[red]⚠ SUSPICIOUS[/red]" if entry.suspicious else "[green]✓ Normal[/green]"
        if entry.suspicious:
            suspicious_count += 1

        table.add_row(
            entry.category,
            entry.name[:30],
            entry.command[:50] + "..." if len(entry.command) > 50 else entry.command,
            status,
        )

    console.print(table)

    if suspicious_count > 0:
        console.print(
            Panel(
                f"[bold red]Found {suspicious_count} suspicious autorun entries![/bold red]\n"
                "[dim]Review these for potential persistence mechanisms.[/dim]",
                title="⚠ Warning",
                border_style="red",
            )
        )


def analyze_processes() -> None:
    """
    Analyze running processes for suspicious activity.
    """
    try:
        import psutil
    except ImportError:
        console.print("[red]Error:[/red] psutil not installed.")
        return

    console.print("[cyan]Analyzing running processes...[/cyan]\n")

    table = Table(title="🔍 Running Processes Analysis")
    table.add_column("PID", style="dim", justify="right")
    table.add_column("Name", style="cyan")
    table.add_column("User", style="green")
    table.add_column("Memory", justify="right")
    table.add_column("CPU %", justify="right")
    table.add_column("Connections", justify="right")
    table.add_column("Status", justify="center")

    suspicious_count = 0

    for proc in psutil.process_iter(["pid", "name", "username", "memory_percent", "cpu_percent"]):
        try:
            info = proc.info
            proc_name = info["name"] or "Unknown"

            # Get connection count
            try:
                connections = len(proc.net_connections())
            except Exception:
                connections = 0

            # Determine if suspicious
            suspicious = False
            suspicious_reasons = []

            # High network activity
            if connections > 10:
                suspicious = True
                suspicious_reasons.append("High connections")

            # Suspicious name patterns
            if any(s in proc_name.lower() for s in ["miner", "crypto", "payload", "backdoor"]):
                suspicious = True
                suspicious_reasons.append("Suspicious name")

            # High resource usage
            if info.get("cpu_percent", 0) > 80:
                suspicious = True
                suspicious_reasons.append("High CPU")

            if not suspicious:
                continue  # Only show suspicious processes

            suspicious_count += 1
            status = f"[red]{', '.join(suspicious_reasons)}[/red]"

            table.add_row(
                str(info["pid"]),
                proc_name[:25],
                str(info.get("username", ""))[:15],
                f"{info.get('memory_percent', 0):.1f}%",
                f"{info.get('cpu_percent', 0):.1f}%",
                str(connections),
                status,
            )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    if suspicious_count > 0:
        console.print(table)
        console.print(
            Panel(
                f"[bold yellow]Found {suspicious_count} process(es) with suspicious activity[/bold yellow]",
                title="⚠ Process Analysis",
                border_style="yellow",
            )
        )
    else:
        console.print("[green]✓ No suspicious processes detected.[/green]")
