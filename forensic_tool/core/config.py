"""
Configuration Management for ForensicAutomator.
"""

import os
from pathlib import Path
from typing import Any, Optional
from rich.console import Console

console = Console()

# Default configuration
DEFAULT_CONFIG = {
    "output_format": "text",  # text, json, html
    "hash_algorithm": "sha256",
    "entropy_threshold": 7.5,
    "timeline_days": 30,
    "virustotal_api_key": None,
    "abuseipdb_api_key": None,
    "ioc_file": None,
    "report_output_dir": "./reports",
}


class Config:
    """Configuration manager for ForensicAutomator."""

    def __init__(self):
        self._config = DEFAULT_CONFIG.copy()
        self._load_config()

    def _load_config(self) -> None:
        """Load configuration from file and environment."""
        # Try to load from config file
        config_paths = [
            Path.home() / ".specter.yaml",
            Path.home() / ".specter.yml",
            Path.home() / ".config" / "specter" / "config.yaml",
            Path(".specter.yaml"),
        ]

        for config_path in config_paths:
            if config_path.exists():
                self._load_yaml_config(config_path)
                break

        # Environment variables override config file
        self._load_env_vars()

    def _load_yaml_config(self, path: Path) -> None:
        """Load configuration from YAML file."""
        try:
            import yaml
        except ImportError:
            # Fallback to simple parsing if PyYAML not available
            try:
                with open(path, "r") as f:
                    for line in f:
                        if ":" in line and not line.strip().startswith("#"):
                            key, value = line.split(":", 1)
                            key = key.strip()
                            value = value.strip().strip('"').strip("'")

                            if key in self._config:
                                # Type conversion
                                if isinstance(self._config[key], bool):
                                    value = value.lower() in ("true", "1", "yes")
                                elif isinstance(self._config[key], (int, float)):
                                    value = float(value) if "." in value else int(value)

                                self._config[key] = value
            except Exception:
                pass
            return

        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f)
                if data:
                    for key, value in data.items():
                        if key in self._config:
                            self._config[key] = value
        except Exception:
            pass

    def _load_env_vars(self) -> None:
        """Load configuration from environment variables."""
        env_mapping = {
            "FORENSIC_OUTPUT_FORMAT": "output_format",
            "FORENSIC_HASH_ALGO": "hash_algorithm",
            "FORENSIC_ENTROPY_THRESHOLD": "entropy_threshold",
            "VIRUSTOTAL_API_KEY": "virustotal_api_key",
            "ABUSEIPDB_API_KEY": "abuseipdb_api_key",
        }

        for env_var, config_key in env_mapping.items():
            value = os.environ.get(env_var)
            if value:
                if config_key == "entropy_threshold":
                    value = float(value)
                self._config[config_key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return self._config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value."""
        self._config[key] = value

    @property
    def output_format(self) -> str:
        return self._config["output_format"]

    @property
    def hash_algorithm(self) -> str:
        return self._config["hash_algorithm"]

    @property
    def entropy_threshold(self) -> float:
        return self._config["entropy_threshold"]

    @property
    def virustotal_api_key(self) -> Optional[str]:
        return self._config["virustotal_api_key"]

    @property
    def abuseipdb_api_key(self) -> Optional[str]:
        return self._config["abuseipdb_api_key"]


# Global config instance
config = Config()


def create_sample_config() -> None:
    """Create a sample configuration file."""
    sample_config = \"\"\"# SPECTER Configuration
# Place this file at ~/.specter.yaml

# Output format: text, json, html
output_format: text

# Default hash algorithm: md5, sha256
hash_algorithm: sha256

# Entropy threshold for packed file detection (0-8)
entropy_threshold: 7.5

# Timeline analysis: number of days to look back
timeline_days: 30

# API Keys (optional - for threat intelligence)
# Get your free API key at: https://www.virustotal.com/
virustotal_api_key: null

# Get your free API key at: https://www.abuseipdb.com/
abuseipdb_api_key: null

# Path to custom IOC file (one hash per line)
ioc_file: null

# Directory for report output
report_output_dir: ./reports
\"\"\"

    config_path = Path.home() / ".specter.yaml"

    if config_path.exists():
        console.print(f"[yellow]Config file already exists:[/yellow] {config_path}")
        return

    config_path.write_text(sample_config)
    console.print(f"[green]✓ Created sample config:[/green] {config_path}")
