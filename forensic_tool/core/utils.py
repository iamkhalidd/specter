"""
Utility functions for ForensicAutomator.
"""

import hashlib
import math
from pathlib import Path
from typing import Generator, Iterator
from collections import Counter

from rich.console import Console

console = Console()


def calculate_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """
    Calculate hash of a file.

    Args:
        file_path: Path to the file.
        algorithm: Hash algorithm ('md5' or 'sha256').

    Returns:
        Hexadecimal hash string.
    """
    hash_func = hashlib.md5() if algorithm.lower() == "md5" else hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_func.update(chunk)

    return hash_func.hexdigest()


def calculate_entropy(file_path: Path) -> float:
    """
    Calculate Shannon entropy of a file.
    High entropy (>7.5) may indicate encryption or packing.

    Args:
        file_path: Path to the file.

    Returns:
        Entropy value (0-8 for bytes).
    """
    with open(file_path, "rb") as f:
        data = f.read()

    if not data:
        return 0.0

    # Count byte frequencies
    byte_counts = Counter(data)
    file_size = len(data)

    # Calculate entropy
    entropy = 0.0
    for count in byte_counts.values():
        if count > 0:
            probability = count / file_size
            entropy -= probability * math.log2(probability)

    return entropy


def walk_files(path: Path, recursive: bool = False) -> Generator[Path, None, None]:
    """
    Walk through files in a path (file or directory).

    Args:
        path: File or directory path.
        recursive: If True, walk subdirectories.

    Yields:
        Path objects for each file.
    """
    path = Path(path)

    if path.is_file():
        yield path
    elif path.is_dir():
        pattern = "**/*" if recursive else "*"
        for item in path.glob(pattern):
            if item.is_file():
                yield item


def read_log_lines(file_path: Path) -> Iterator[str]:
    """
    Memory-efficient log file reader (generator-based).

    Args:
        file_path: Path to log file.

    Yields:
        Each line from the log file.
    """
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            yield line.rstrip("\n\r")


def format_bytes(size: int) -> str:
    """Format bytes into human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"
