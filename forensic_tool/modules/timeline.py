"""
Timeline Builder Module - Create forensic timelines from file metadata.
"""

import os
from pathlib import Path
from datetime import datetime
from typing import NamedTuple, Optional
from rich.console import Console
from rich.table import Table
from rich.progress import track

console = Console()


class TimelineEvent(NamedTuple):
    """Represents a timeline event."""

    timestamp: datetime
    event_type: str  # created, modified, accessed
    path: str
    size: int
    details: str


def build_timeline(
    path: str,
    output_file: Optional[str] = None,
    days: int = 30,
    event_types: Optional[list[str]] = None,
) -> list[TimelineEvent]:
    """
    Build a forensic timeline from file metadata.

    Args:
        path: Directory to analyze.
        output_file: Optional path to save timeline.
        days: Only include events from last N days.
        event_types: Filter by event types (created, modified, accessed).

    Returns:
        List of timeline events.
    """
    target = Path(path)

    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {path}")
        return []

    if event_types is None:
        event_types = ["created", "modified", "accessed"]

    events: list[TimelineEvent] = []
    cutoff = datetime.now().timestamp() - (days * 86400)

    files = list(target.rglob("*") if target.is_dir() else [target])
    files = [f for f in files if f.is_file()]

    for file_path in track(files, description="Building timeline..."):
        try:
            stat = file_path.stat()

            # Creation time
            if "created" in event_types and stat.st_ctime > cutoff:
                events.append(
                    TimelineEvent(
                        timestamp=datetime.fromtimestamp(stat.st_ctime),
                        event_type="CREATED",
                        path=str(file_path),
                        size=stat.st_size,
                        details=f"File created: {file_path.name}",
                    )
                )

            # Modification time
            if "modified" in event_types and stat.st_mtime > cutoff:
                events.append(
                    TimelineEvent(
                        timestamp=datetime.fromtimestamp(stat.st_mtime),
                        event_type="MODIFIED",
                        path=str(file_path),
                        size=stat.st_size,
                        details=f"File modified: {file_path.name}",
                    )
                )

            # Access time
            if "accessed" in event_types and stat.st_atime > cutoff:
                events.append(
                    TimelineEvent(
                        timestamp=datetime.fromtimestamp(stat.st_atime),
                        event_type="ACCESSED",
                        path=str(file_path),
                        size=stat.st_size,
                        details=f"File accessed: {file_path.name}",
                    )
                )

        except Exception:
            pass

    # Sort by timestamp
    events.sort(key=lambda e: e.timestamp, reverse=True)

    # Display
    _display_timeline(events[:100])  # Show top 100

    # Save if requested
    if output_file:
        _save_timeline(events, output_file)

    return events


def _display_timeline(events: list[TimelineEvent]) -> None:
    """Display timeline events in a table."""
    if not events:
        console.print("[yellow]No events found in the specified timeframe.[/yellow]")
        return

    table = Table(title="📅 Forensic Timeline")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Event", justify="center")
    table.add_column("File", style="green", no_wrap=False, max_width=50)
    table.add_column("Size", justify="right", style="dim")

    event_colors = {
        "CREATED": "[green]CREATE[/green]",
        "MODIFIED": "[yellow]MODIFY[/yellow]",
        "ACCESSED": "[blue]ACCESS[/blue]",
    }

    for event in events:
        table.add_row(
            event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            event_colors.get(event.event_type, event.event_type),
            Path(event.path).name,
            f"{event.size:,}",
        )

    console.print(table)
    console.print(f"\n[dim]Showing {len(events)} events[/dim]")


def _save_timeline(events: list[TimelineEvent], output_file: str) -> None:
    """Save timeline to CSV file."""
    import csv

    output_path = Path(output_file)
    if not output_path.suffix:
        output_path = output_path.with_suffix(".csv")

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Event Type", "Path", "Size", "Details"])

        for event in events:
            writer.writerow([
                event.timestamp.isoformat(),
                event.event_type,
                event.path,
                event.size,
                event.details,
            ])

    console.print(f"[green]✓ Timeline saved:[/green] {output_path}")


def analyze_timeline_anomalies(events: list[TimelineEvent]) -> None:
    """
    Analyze timeline for anomalies (mass modifications, unusual times).
    """
    if not events:
        return

    # Check for mass modifications in short time period
    from collections import Counter

    hourly_counts = Counter()

    for event in events:
        hour_key = event.timestamp.strftime("%Y-%m-%d %H:00")
        hourly_counts[hour_key] += 1

    # Find suspicious hours (more than 50 events)
    suspicious_hours = [(h, c) for h, c in hourly_counts.items() if c > 50]

    if suspicious_hours:
        console.print(
            "\n[yellow]⚠ Suspicious activity detected:[/yellow]"
        )
        for hour, count in sorted(suspicious_hours, key=lambda x: x[1], reverse=True)[:5]:
            console.print(f"  • {hour}: {count} file operations")

    # Check for activity during unusual hours (midnight to 5am)
    night_events = [
        e for e in events
        if e.timestamp.hour >= 0 and e.timestamp.hour < 5
    ]

    if len(night_events) > 10:
        console.print(
            f"\n[yellow]⚠ {len(night_events)} file operations between midnight and 5am[/yellow]"
        )
