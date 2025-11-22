"""Configuration management for TLS scanner."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    yaml = None

try:
    from pydantic import BaseModel
except ImportError:
    BaseModel = object


class ScannerConfig:
    """Configuration for TLS scanner."""
    
    def __init__(
        self,
        timeout: int = 10,
        concurrency: int = 5,
        output_format: str = "json",
        export_dir: str = "./reports",
        ssl_verify: bool = False,
        user_agent: str = "Mozilla/5.0 (TLS-Scanner/1.0)",
        max_crawl_depth: int = 2,
        max_crawl_urls: int = 50,
    ):
        """Initialize configuration.
        
        Args:
            timeout: HTTP request timeout in seconds
            concurrency: Number of concurrent requests
            output_format: Default output format (json, csv, html, markdown)
            export_dir: Directory for exporting reports
            ssl_verify: Verify SSL certificates
            user_agent: HTTP User-Agent header
            max_crawl_depth: Maximum crawl depth for URL discovery
            max_crawl_urls: Maximum URLs to crawl
        """
        self.timeout = timeout
        self.concurrency = concurrency
        self.output_format = output_format
        self.export_dir = export_dir
        self.ssl_verify = ssl_verify
        self.user_agent = user_agent
        self.max_crawl_depth = max_crawl_depth
        self.max_crawl_urls = max_crawl_urls
    
    def to_dict(self) -> dict:
        """Convert config to dictionary."""
        return {
            "timeout": self.timeout,
            "concurrency": self.concurrency,
            "output_format": self.output_format,
            "export_dir": self.export_dir,
            "ssl_verify": self.ssl_verify,
            "user_agent": self.user_agent,
            "max_crawl_depth": self.max_crawl_depth,
            "max_crawl_urls": self.max_crawl_urls,
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
    
    # Try to load from default locations
    default_locations = [
        Path("./scanner/config.yaml"),
        Path("./config.yaml"),
        Path("./config/scanner.yaml"),
    ]
    
    for location in default_locations:
        if location.exists():
            return ScannerConfig.from_yaml(str(location))
    
    # Return default config
    return ScannerConfig()


def create_default_config(filepath: str = "./config.yaml") -> None:
    """Create default configuration file."""
    config = ScannerConfig()
    config.to_yaml(filepath)
    print(f"Default config created at: {filepath}")
