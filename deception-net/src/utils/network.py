"""Network utility functions for DeceptionNet.

Provides helpers for:
- IP address manipulation and subnet generation
- Port availability checking
- Network interface discovery
- Converting GAN-generated topology tensors to real network configs
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Optional

import numpy as np

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class SubnetConfig:
    """Represents a parsed subnet configuration."""

    network: ipaddress.IPv4Network
    gateway: ipaddress.IPv4Address
    num_hosts: int


@dataclass
class ServiceConfig:
    """Represents a parsed service configuration."""

    service_type: str  # ssh, http, ftp, mysql, smtp
    port: int
    enabled: bool
    vuln_count: int

    SERVICE_TYPES = ["ssh", "http", "ftp", "mysql", "smtp"]
    DEFAULT_PORTS = {"ssh": 22, "http": 80, "ftp": 21, "mysql": 3306, "smtp": 25}


def tensor_to_subnets(
    topology_tensor: np.ndarray,
    network_prefix: str = "172.20",
) -> list[SubnetConfig]:
    """Convert a GAN-generated topology tensor to real subnet configurations.

    The topology tensor has shape (max_subnets, 7) with normalized [0,1] values:
    - [0:4] ip_range octets (mapped to 0-255)
    - [4]   cidr (mapped to /16-/28)
    - [5]   num_hosts (mapped based on CIDR)
    - [6]   gateway offset

    Args:
        topology_tensor: Numpy array of shape (max_subnets, 7).
        network_prefix: First two octets for generated subnets.

    Returns:
        List of SubnetConfig for active subnets.
    """
    subnets = []
    prefix_parts = network_prefix.split(".")

    for i, row in enumerate(topology_tensor):
        # Skip inactive subnets (very low activation)
        if row.sum() < 0.5:
            continue

        # Map normalized values to actual network values
        third_octet = int(row[2] * 255) % 256
        fourth_octet = 0

        # CIDR: map [0,1] to [16, 28]
        cidr = int(row[4] * 12) + 16
        cidr = max(16, min(28, cidr))

        # Build network address
        net_str = f"{prefix_parts[0]}.{prefix_parts[1]}.{third_octet}.{fourth_octet}/{cidr}"
        try:
            network = ipaddress.IPv4Network(net_str, strict=False)
        except ValueError:
            continue

        # Number of usable hosts
        num_hosts = max(1, min(int(row[5] * network.num_addresses), network.num_addresses - 2))

        # Gateway is first usable address
        gateway = list(network.hosts())[0] if network.num_addresses > 2 else network.network_address

        subnets.append(SubnetConfig(
            network=network,
            gateway=gateway,
            num_hosts=num_hosts,
        ))

    return subnets


def tensor_to_services(
    services_tensor: np.ndarray,
) -> list[ServiceConfig]:
    """Convert a GAN-generated services tensor to service configurations.

    The services tensor has shape (max_services, 8):
    - [0:5] service type one-hot (SSH, HTTP, FTP, MySQL, SMTP)
    - [5]   port (normalized)
    - [6]   enabled flag
    - [7]   vuln_count (normalized)

    Args:
        services_tensor: Numpy array of shape (max_services, 8).

    Returns:
        List of ServiceConfig for enabled services.
    """
    services = []
    type_names = ServiceConfig.SERVICE_TYPES
    default_ports = ServiceConfig.DEFAULT_PORTS

    for row in services_tensor:
        # Determine service type from one-hot
        type_idx = int(np.argmax(row[:5]))
        service_type = type_names[type_idx]

        # Check if enabled (threshold at 0.5)
        enabled = row[6] > 0.5
        if not enabled:
            continue

        # Port: use default for the service type, with optional offset
        port = default_ports[service_type]

        # Vulnerability count: map [0,1] to [0, 5]
        vuln_count = int(row[7] * 5)

        services.append(ServiceConfig(
            service_type=service_type,
            port=port,
            enabled=enabled,
            vuln_count=vuln_count,
        ))

    return services


def is_port_available(host: str, port: int) -> bool:
    """Check if a TCP port is available for binding.

    Args:
        host: Host address to check.
        port: Port number to check.

    Returns:
        True if the port is available.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.bind((host, port))
            return True
    except OSError:
        return False


def find_available_port(host: str = "0.0.0.0", start: int = 10000, end: int = 65535) -> Optional[int]:
    """Find an available TCP port in the given range.

    Args:
        host: Host address to bind.
        start: Start of port range (inclusive).
        end: End of port range (inclusive).

    Returns:
        An available port number, or None if no port is found.
    """
    for port in range(start, end + 1):
        if is_port_available(host, port):
            return port
    return None


def get_local_ip() -> str:
    """Get the primary local IP address of this machine."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


async def check_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Asynchronously check if a remote TCP port is open.

    Args:
        host: Target host.
        port: Target port.
        timeout: Connection timeout in seconds.

    Returns:
        True if the port is open and accepting connections.
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        return False
