"""Configuration loader for chatgpt-register-sub2api.

Loads config.yaml, validates, and merges with CLI overrides.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG_FILE = Path("config.yaml")

DEFAULT_CONFIG: dict[str, Any] = {
    "mail": {
        "providers": [
            {
                "type": "outlook_token",
                "enable": True,
                "label": "Outlook Pool",
                "mode": "graph",
                "mailboxes": "",
            },
            {
                "type": "gmail",
                "enable": False,
                "label": "Gmail Alias",
                "user": "your@gmail.com",
                "app_password": "your_app_password",
                "alias_length": 8,
                "message_limit": 10,
            },
        ],
        "request_timeout": 30,
        "wait_timeout": 30,
        "wait_interval": 2,
    },
    "proxy": {
        "url": "",
        "flaresolverr_url": "",
    },
    "registration": {
        "threads": 3,
        "total": 10,
    },
    "login": {
        "mode": "password",
        "password": "",
    },
    "workspace": {
        "enabled": True,
        "ids": [],
        "route": "request",
        "max_retries": 3,
        "retry_backoff_ms": 5000,
    },
    "sub2api": {
        "enabled": True,
        "output_file": "sub2api_bundle.json",
    },
    "logging": {
        "level": "INFO",
        "file": "",
    },
}


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load and validate config from a YAML file.

    Merges with defaults so missing keys get sensible values.
    """
    config_file = Path(path) if path else DEFAULT_CONFIG_FILE
    config = dict(DEFAULT_CONFIG)

    if config_file.exists():
        try:
            raw = yaml.safe_load(config_file.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                _deep_merge(config, raw)
        except Exception as e:
            raise ValueError(f"Failed to parse {config_file}: {e}") from e

    # Resolve relative paths from config file's directory
    config["_config_dir"] = str(config_file.parent.resolve())

    return config


def _deep_merge(base: dict, overlay: dict) -> None:
    """Merge overlay into base in-place, recursively."""
    for key, value in overlay.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def generate_default_config(path: str | Path = DEFAULT_CONFIG_FILE) -> Path:
    """Write the default config.yaml to disk.

    Returns the path written.
    """
    output = Path(path).resolve()
    if output.exists():
        raise FileExistsError(f"{output} already exists — not overwriting")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        yaml.dump(DEFAULT_CONFIG, default_flow_style=False, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return output


def get_output_dir(config: dict[str, Any], cli_output_dir: str = "") -> Path:
    """Determine the output directory for data files.

    Priority: CLI arg > config _config_dir > cwd
    """
    if cli_output_dir:
        return Path(cli_output_dir).resolve()
    config_dir = config.get("_config_dir", "")
    if config_dir:
        return Path(config_dir)
    return Path.cwd()
