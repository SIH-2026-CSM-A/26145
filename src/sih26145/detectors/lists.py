"""Analyst-maintained list files: poller allowlist and known-bad JA4 fingerprints."""

import ipaddress
import os
from pathlib import Path
from typing import Set, Tuple

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"


def list_path(env: str, default: str) -> Path:
    return Path(os.environ.get(env) or CONFIG_DIR / default)


def load_list(path) -> Set[str]:
    """Non-empty lines, without '#' comments. A missing file is an empty list."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return set()
    return {line.split("#", 1)[0].strip() for line in text.splitlines()} - {""}


def load_networks(path) -> Tuple[ipaddress._BaseNetwork, ...]:
    return tuple(ipaddress.ip_network(entry, strict=False) for entry in sorted(load_list(path)))


def in_networks(ip: str, networks) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in networks)
