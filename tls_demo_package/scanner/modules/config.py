"""Configuration management for TLS scanner."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    yaml = None


class ScannerConfig:
    """Configuration for TLS scanner."""
    
    def __init__(
        self,
        timeout: int = 10,
        concurrency: int = 5,
        output_format: str = "json",
        export_dir: str = "./reports",
        ssl_verify: bool = False,
    ):
        """Initialize configuration."""
        self.timeout = timeout
        self.concurrency = concurrency
        self.output_format = output_format
        self.export_dir = export_dir
        self.ssl_verify = ssl_verify
    
    def to_dict(self) -> dict:
        """Convert config to dictionary."""
        return {
            "timeout": self.timeout,
            "concurrency": self.concurrency,
            "output_format": self.output_format,
            "export_dir": self.export_dir,
            "ssl_verify": self.ssl_verify,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> ScannerConfig:
        """Create config from dictionary."""
        return cls(**data)
    
    @classmethod
    def from_yaml(cls, filepath: str) -> ScannerConfig:
        """Load configuration from YAML file."""
        if not yaml:
            raise ImportError("PyYAML not installed. Install with: pip install pyyaml")
        
        config_path = Path(filepath)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {filepath}")
        
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        
        return cls.from_dict(data)
    
    def to_yaml(self, filepath: str) -> None:
        """Save configuration to YAML file."""
        if not yaml:
            raise ImportError("PyYAML not installed. Install with: pip install pyyaml")
        
        with open(filepath, "w") as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False)


def load_config(config_path: Optional[str] = None) -> ScannerConfig:
    """Load configuration from file or use defaults."""
    if config_path:
        return ScannerConfig.from_yaml(config_path)
    
    default_locations = [
        Path("./scanner/config.yaml"),
        Path("./config.yaml"),
    ]
    
    for location in default_locations:
        if location.exists():
            return ScannerConfig.from_yaml(str(location))
    
    return ScannerConfig()

