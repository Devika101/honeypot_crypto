"""Docker container manager for honeypot infrastructure.

Manages the lifecycle of Docker containers that host honeypot services:
- Creating/destroying containers with resource limits
- Custom Docker network management
- Health monitoring
- Auto-scaling based on attack volume
- Rollback support
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

import docker
from docker.errors import APIError, NotFound
from docker.models.containers import Container
from docker.models.networks import Network

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ContainerSpec:
    """Specification for a honeypot container."""

    name: str
    image: str = "python:3.11-slim"
    ports: dict[str, int] = field(default_factory=dict)  # container_port -> host_port
    environment: dict[str, str] = field(default_factory=dict)
    cpu_quota: int = 50000
    mem_limit: str = "256m"
    labels: dict[str, str] = field(default_factory=dict)
    command: Optional[str] = None


@dataclass
class ContainerStatus:
    """Runtime status of a managed container."""

    container_id: str
    name: str
    status: str  # running, stopped, error
    ip_address: str = ""
    ports: dict[str, int] = field(default_factory=dict)
    created_at: float = 0.0
    health_checks_passed: int = 0
    health_checks_failed: int = 0


class ContainerManager:
    """Manages Docker containers for honeypot deployment.

    Handles container creation, destruction, network isolation,
    health monitoring, and auto-scaling.

    Args:
        network_name: Name of the Docker bridge network for honeypots.
        network_prefix: Subnet prefix for the Docker network.
        max_containers: Maximum number of containers to run.
        resource_limits: Default resource limits for containers.
    """

    def __init__(
        self,
        network_name: str = "deceptionnet",
        network_prefix: str = "172.20",
        max_containers: int = 50,
        resource_limits: Optional[dict[str, Any]] = None,
    ) -> None:
        self.network_name = network_name
        self.network_prefix = network_prefix
        self.max_containers = max_containers
        self.resource_limits = resource_limits or {"cpu_quota": 50000, "mem_limit": "256m"}

        self._client: Optional[docker.DockerClient] = None
        self._network: Optional[Network] = None
        self._containers: dict[str, ContainerStatus] = {}
        self._snapshots: list[dict[str, ContainerSpec]] = []  # For rollback

    def connect(self) -> None:
        """Connect to the Docker daemon."""
        try:
            self._client = docker.from_env()
            self._client.ping()
            logger.info("Connected to Docker daemon")
        except Exception as e:
            logger.error("Failed to connect to Docker", error=str(e))
            raise

    def ensure_network(self) -> Network:
        """Create or retrieve the Docker network for honeypots."""
        if not self._client:
            self.connect()

        try:
            self._network = self._client.networks.get(self.network_name)
            logger.info("Using existing network", network=self.network_name)
        except NotFound:
            subnet = f"{self.network_prefix}.0.0/16"
            ipam_pool = docker.types.IPAMPool(subnet=subnet)
            ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool])

            self._network = self._client.networks.create(
                name=self.network_name,
                driver="bridge",
                ipam=ipam_config,
                labels={"managed_by": "deceptionnet"},
            )
            logger.info("Created network", network=self.network_name, subnet=subnet)

        return self._network

    def create_container(self, spec: ContainerSpec) -> ContainerStatus:
        """Create and start a honeypot container.

        Args:
            spec: Container specification.

        Returns:
            ContainerStatus for the new container.

        Raises:
            RuntimeError: If max containers reached or Docker error.
        """
        if len(self._containers) >= self.max_containers:
            raise RuntimeError(
                f"Maximum container limit reached ({self.max_containers})"
            )

        if not self._client:
            self.connect()

        network = self.ensure_network()

        # Merge resource limits
        cpu_quota = spec.cpu_quota or self.resource_limits.get("cpu_quota", 50000)
        mem_limit = spec.mem_limit or self.resource_limits.get("mem_limit", "256m")

        port_bindings = {}
        for container_port, host_port in spec.ports.items():
            port_bindings[f"{container_port}/tcp"] = host_port

        labels = {
            "managed_by": "deceptionnet",
            "honeypot": "true",
            **spec.labels,
        }

        try:
            container: Container = self._client.containers.run(
                image=spec.image,
                name=spec.name,
                detach=True,
                ports=port_bindings,
                environment=spec.environment,
                cpu_quota=cpu_quota,
                mem_limit=mem_limit,
                labels=labels,
                network=self.network_name,
                command=spec.command,
                restart_policy={"Name": "unless-stopped"},
            )

            container.reload()
            networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
            ip_address = networks.get(self.network_name, {}).get("IPAddress", "")

            status = ContainerStatus(
                container_id=container.id,
                name=spec.name,
                status="running",
                ip_address=ip_address,
                ports=spec.ports,
                created_at=time.time(),
            )
            self._containers[container.id] = status

            logger.info(
                "Container created",
                name=spec.name,
                container_id=container.short_id,
                ip=ip_address,
            )

            return status

        except APIError as e:
            logger.error("Failed to create container", name=spec.name, error=str(e))
            raise RuntimeError(f"Failed to create container {spec.name}: {e}")

    def destroy_container(self, container_id: str, force: bool = True) -> None:
        """Stop and remove a container.

        Args:
            container_id: Docker container ID.
            force: Force kill if not stopping gracefully.
        """
        if not self._client:
            return

        try:
            container = self._client.containers.get(container_id)
            container.stop(timeout=10)
            container.remove(force=force)
            self._containers.pop(container_id, None)
            logger.info("Container destroyed", container_id=container_id[:12])
        except NotFound:
            self._containers.pop(container_id, None)
        except APIError as e:
            logger.error("Failed to destroy container", container_id=container_id[:12], error=str(e))

    def destroy_all(self) -> None:
        """Destroy all managed containers."""
        for cid in list(self._containers.keys()):
            self.destroy_container(cid)
        logger.info("All containers destroyed")

    def health_check(self, container_id: str) -> bool:
        """Check if a container is healthy (running).

        Args:
            container_id: Docker container ID.

        Returns:
            True if the container is running.
        """
        if not self._client:
            return False

        try:
            container = self._client.containers.get(container_id)
            is_running = container.status == "running"

            status = self._containers.get(container_id)
            if status:
                if is_running:
                    status.health_checks_passed += 1
                    status.status = "running"
                else:
                    status.health_checks_failed += 1
                    status.status = container.status

            return is_running

        except NotFound:
            status = self._containers.get(container_id)
            if status:
                status.status = "removed"
                status.health_checks_failed += 1
            return False

    def health_check_all(self) -> dict[str, bool]:
        """Run health checks on all managed containers."""
        results = {}
        for cid in list(self._containers.keys()):
            results[cid] = self.health_check(cid)
        return results

    def get_all_statuses(self) -> list[ContainerStatus]:
        """Get status of all managed containers."""
        return list(self._containers.values())

    def get_running_count(self) -> int:
        """Get the number of currently running containers."""
        return sum(1 for s in self._containers.values() if s.status == "running")

    def snapshot(self) -> None:
        """Save current container configuration for rollback."""
        self._snapshots.append(
            {cid: status for cid, status in self._containers.items()}
        )
        logger.info("Snapshot saved", snapshot_count=len(self._snapshots))

    def cleanup_network(self) -> None:
        """Remove the Docker network (after all containers are destroyed)."""
        if self._network:
            try:
                self._network.remove()
                logger.info("Network removed", network=self.network_name)
            except APIError as e:
                logger.error("Failed to remove network", error=str(e))
