"""
File Forensics Module - Hash, Entropy, and YARA scanning.
"""

from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track

from forensic_tool.core.utils import calculate_hash, calculate_entropy, walk_files

console = Console()


def hash_path(path: str, algorithm: str = "sha256", recursive: bool = False) -> None:
    """
    Calculate hashes for files at a given path.

    Args:
        path: File or directory path.
        algorithm: Hash algorithm to use.
        recursive: Recursively process directories.
    """
    target = Path(path)

    if not target.exists():
        console.print(f"[red]Error:[/red] Path does not exist: {path}")
        return

    table = Table(title=f"🔐 File Hashes ({algorithm.upper()})")
    table.add_column("File", style="cyan", no_wrap=False)
    table.add_column("Hash", style="green")
    table.add_column("Size", justify="right")

    files = list(walk_files(target, recursive))

    if not files:
        console.print("[yellow]No files found to hash.[/yellow]")
        return

    for file_path in track(files, description="Hashing files..."):
        try:
            file_hash = calculate_hash(file_path, algorithm)
            size = file_path.stat().st_size
            size_str = f"{size:,} bytes"
            table.add_row(str(file_path.name), file_hash[:16] + "...", size_str)
        except Exception as e:
            table.add_row(str(file_path.name), f"[red]Error: {e}[/red]", "-")

    console.print(table)
    console.print(f"\n[dim]Total files processed: {len(files)}[/dim]")


def analyze_entropy(path: str, threshold: float = 7.5) -> None:
    """
    Analyze file entropy to detect packed/encrypted content.

    Args:
        path: File or directory path.
        threshold: Entropy threshold for suspicion (default 7.5).
    """
    target = Path(path)

    if not target.exists():
        console.print(f"[red]Error:[/red] Path does not exist: {path}")
        return

    table = Table(title="📊 Entropy Analysis")
    table.add_column("File", style="cyan")
    table.add_column("Entropy", justify="right")
    table.add_column("Status", justify="center")

    suspicious_count = 0
    files = list(walk_files(target, recursive=True))

    for file_path in track(files, description="Analyzing entropy..."):
        try:
            entropy = calculate_entropy(file_path)
            status = "[red]⚠ SUSPICIOUS[/red]" if entropy > threshold else "[green]✓ Normal[/green]"

            if entropy > threshold:
                suspicious_count += 1

            table.add_row(
                str(file_path.name),
                f"{entropy:.2f}",
                status,
            )
        except Exception as e:
            table.add_row(str(file_path.name), "-", f"[red]Error: {e}[/red]")

    console.print(table)

    if suspicious_count > 0:
        console.print(
            Panel(
                f"[bold red]Found {suspicious_count} file(s) with high entropy![/bold red]\n"
                "[dim]High entropy may indicate encrypted, compressed, or packed content.[/dim]",
                title="⚠ Warning",
                border_style="red",
            )
        )


def scan_with_yara(path: str, rules_path: str | None = None) -> None:
    """
    Scan files using YARA rules.

    Args:
        path: File or directory to scan.
        rules_path: Path to YARA rules file.
    """
    try:
        import yara
    except ImportError:
        console.print(
            "[red]Error:[/red] yara-python is not installed.\n"
            "[dim]Install with: pip install yara-python[/dim]"
        )
        return

    target = Path(path)

    if not target.exists():
        console.print(f"[red]Error:[/red] Path does not exist: {path}")
        return

    # Use default rules if none provided
    if rules_path is None:
        console.print("[yellow]No YARA rules file provided. Using built-in basic rules.[/yellow]")
        # Basic built-in rules for common patterns
        rules = yara.compile(source='''
            rule SuspiciousStrings {
                strings:
                    $cmd1 = "cmd.exe" nocase
                    $cmd2 = "powershell" nocase
                    $b64 = "base64" nocase
                    $wget = "wget" nocase
                    $curl = "curl" nocase
                    $nc = "netcat" nocase
                condition:
                    any of them
            }

            rule PotentialWebshell {
                strings:
                    $eval = "eval(" nocase
                    $exec = "exec(" nocase
                    $system = "system(" nocase
                    $passthru = "passthru(" nocase
                condition:
                    2 of them
            }
        ''')
    else:
        rules_file = Path(rules_path)
        if not rules_file.exists():
            console.print(f"[red]Error:[/red] Rules file not found: {rules_path}")
            return
        rules = yara.compile(filepath=str(rules_file))

    table = Table(title="🎯 YARA Scan Results")
    table.add_column("File", style="cyan")
    table.add_column("Matches", style="red")

    matches_found = 0
    files = list(walk_files(target, recursive=True))

    for file_path in track(files, description="Scanning with YARA..."):
        try:
            matches = rules.match(str(file_path))
            if matches:
                matches_found += 1
                match_names = ", ".join([m.rule for m in matches])
                table.add_row(str(file_path), f"[red]{match_names}[/red]")
        except Exception:
            pass  # Skip files that can't be scanned

    console.print(table)

    if matches_found > 0:
        console.print(
            Panel(
                f"[bold red]YARA detected {matches_found} file(s) matching rules![/bold red]",
                title="⚠ Malware Alert",
                border_style="red",
            )
        )
    else:
        console.print("[green]✓ No YARA matches found.[/green]")
