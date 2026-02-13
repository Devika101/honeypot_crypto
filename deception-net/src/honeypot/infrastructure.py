"""Honeypot infrastructure orchestrator.

Ties together the GAN-generated configurations, service emulators,
vulnerability injector, and container manager to deploy and manage
a complete honeypot infrastructure.

Usage:
    python -m src.honeypot.infrastructure --config config/config.yaml
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import Any, Optional

import numpy as np
import torch
import yaml

from src.gan.generator import Generator, InfrastructureConfig
from src.honeypot.container_manager import ContainerManager, ContainerSpec
from src.honeypot.service_emulator import (
    BaseEmulator,
    FTPEmulator,
    HTTPEmulator,
    InteractionLog,
    SSHEmulator,
    load_emulators_from_config,
)
from src.honeypot.vulnerability_injector import VulnerabilityInjector
from src.utils.logger import get_logger
from src.utils.network import tensor_to_services, tensor_to_subnets

logger = get_logger(__name__)


class HoneypotInfrastructure:
    """Orchestrates the full honeypot deployment lifecycle.

    1. Loads or generates infrastructure configs from the GAN
    2. Converts tensor outputs to real network/service configs
    3. Deploys service emulators (asyncio) or Docker containers
    4. Manages vulnerability injection
    5. Collects interaction logs for the adaptive feedback engine

    Args:
        config_path: Path to the main config.yaml.
        generator: Optional pre-trained Generator for config generation.
        use_containers: If True, deploy via Docker. Otherwise, use local asyncio emulators.
    """

    def __init__(
        self,
        config_path: str = "config/config.yaml",
        generator: Optional[Generator] = None,
        use_containers: bool = False,
    ) -> None:
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.generator = generator
        self.use_containers = use_containers
        self.vuln_injector = VulnerabilityInjector()

        # Container manager (used if use_containers=True)
        hp_config = self.config.get("honeypot", {})
        self.container_manager = ContainerManager(
            network_name=hp_config.get("docker_network_name", "deceptionnet"),
            network_prefix=hp_config.get("network_prefix", "172.20"),
            max_containers=hp_config.get("max_containers", 50),
            resource_limits=hp_config.get("resource_limits"),
        )

        # Local emulators (used if use_containers=False)
        self._emulators: list[BaseEmulator] = []
        self._interaction_logs: list[InteractionLog] = []
        self._running = False

    def _log_callback(self, log: InteractionLog) -> None:
        """Callback for collecting interaction logs from emulators."""
        self._interaction_logs.append(log)

        # Check for exploit attempts
        payload = log.data.get("command", "") or log.data.get("path", "") or log.data.get("password", "")
        if payload:
            self.vuln_injector.check_exploit(log.service, payload, log.source_ip)

    def generate_config(self, condition: Optional[torch.Tensor] = None) -> InfrastructureConfig:
        """Generate a honeypot configuration using the GAN.

        Args:
            condition: Condition tensor for controlled generation.
                       If None, a random condition is used.

        Returns:
            InfrastructureConfig from the generator.

        Raises:
            RuntimeError: If no generator is available.
        """
        if self.generator is None:
            raise RuntimeError("No generator loaded. Train or load a model first.")

        gan_config = self.config.get("gan", {})
        condition_dim = gan_config.get("condition_dim", 32)

        if condition is None:
            condition = torch.randn(1, condition_dim)

        self.generator.eval()
        with torch.no_grad():
            config = self.generator.sample(1, condition)

        logger.info("Generated honeypot configuration")
        return config

    async def deploy_local(
        self,
        config: Optional[InfrastructureConfig] = None,
    ) -> None:
        """Deploy honeypot services as local asyncio servers.

        Args:
            config: Optional GAN-generated config. If None, loads from template YAML.
        """
        if config:
            # Convert GAN output to service configs
            config_dict = config.to_dict()
            services = tensor_to_services(config_dict["services"][0])
            subnets = tensor_to_subnets(config_dict["topology"][0])

            logger.info(
                "Deploying from GAN config",
                num_services=len(services),
                num_subnets=len(subnets),
            )

            for svc in services:
                if svc.service_type == "ssh":
                    self._emulators.append(SSHEmulator(
                        port=0,  # Auto-assign port
                        log_callback=self._log_callback,
                    ))
                elif svc.service_type == "http":
                    self._emulators.append(HTTPEmulator(
                        port=0,
                        log_callback=self._log_callback,
                    ))
                elif svc.service_type == "ftp":
                    self._emulators.append(FTPEmulator(
                        port=0,
                        log_callback=self._log_callback,
                    ))
        else:
            # Load from honeypot_templates.yaml
            templates_path = Path("config/honeypot_templates.yaml")
            if templates_path.exists():
                self._emulators = load_emulators_from_config(
                    str(templates_path),
                    log_callback=self._log_callback,
                )
            else:
                # Default: one of each
                self._emulators = [
                    SSHEmulator(port=0, log_callback=self._log_callback),
                    HTTPEmulator(port=0, log_callback=self._log_callback),
                    FTPEmulator(port=0, log_callback=self._log_callback),
                ]

        # Start all emulators
        for emulator in self._emulators:
            await emulator.start()

        self._running = True
        logger.info("Local deployment complete", num_emulators=len(self._emulators))

    async def stop_local(self) -> None:
        """Stop all local emulators."""
        for emulator in self._emulators:
            await emulator.stop()
        self._emulators.clear()
        self._running = False
        logger.info("Local deployment stopped")

    def deploy_containers(
        self,
        config: Optional[InfrastructureConfig] = None,
    ) -> list[str]:
        """Deploy honeypot services as Docker containers.

        Args:
            config: Optional GAN-generated config.

        Returns:
            List of container IDs.
        """
        self.container_manager.connect()
        self.container_manager.ensure_network()
        self.container_manager.snapshot()

        container_ids = []

        if config:
            config_dict = config.to_dict()
            services = tensor_to_services(config_dict["services"][0])

            for i, svc in enumerate(services):
                spec = ContainerSpec(
                    name=f"honeypot-{svc.service_type}-{i}",
                    ports={str(svc.port): 0},  # Auto-assign host port
                    labels={"service_type": svc.service_type},
                    environment={"SERVICE_TYPE": svc.service_type},
                )
                status = self.container_manager.create_container(spec)
                container_ids.append(status.container_id)
        else:
            # Deploy default set
            for svc_type, port in [("ssh", 22), ("http", 80), ("ftp", 21)]:
                spec = ContainerSpec(
                    name=f"honeypot-{svc_type}-default",
                    ports={str(port): 0},
                    labels={"service_type": svc_type},
                    environment={"SERVICE_TYPE": svc_type},
                )
                status = self.container_manager.create_container(spec)
                container_ids.append(status.container_id)

        logger.info("Container deployment complete", num_containers=len(container_ids))
        return container_ids

    def get_interaction_logs(self) -> list[dict]:
        """Get all collected interaction logs."""
        return [log.to_dict() for log in self._interaction_logs]

    def get_exploit_stats(self) -> dict[str, Any]:
        """Get exploitation attempt statistics."""
        return self.vuln_injector.get_stats()

    def get_status(self) -> dict[str, Any]:
        """Get overall infrastructure status."""
        return {
            "running": self._running,
            "local_emulators": len(self._emulators),
            "containers": self.container_manager.get_running_count(),
            "total_interactions": len(self._interaction_logs),
            "exploit_stats": self.get_exploit_stats(),
        }


async def run_local(config_path: str) -> None:
    """Run the honeypot infrastructure locally."""
    infra = HoneypotInfrastructure(config_path=config_path, use_containers=False)
    await infra.deploy_local()

    logger.info("Honeypot infrastructure running. Press Ctrl+C to stop.")

    try:
        while True:
            await asyncio.sleep(60)
            status = infra.get_status()
            logger.info("Status update", **status)
    except (KeyboardInterrupt, asyncio.CancelledError):
        await infra.stop_local()


def main() -> None:
    """CLI entry point for deploying honeypot infrastructure."""
    parser = argparse.ArgumentParser(description="Deploy DeceptionNet honeypots")
    parser.add_argument("--config", type=str, default="config/config.yaml")
    parser.add_argument("--docker", action="store_true", help="Deploy via Docker containers")
    args = parser.parse_args()

    if args.docker:
        infra = HoneypotInfrastructure(config_path=args.config, use_containers=True)
        infra.deploy_containers()
    else:
        asyncio.run(run_local(args.config))


if __name__ == "__main__":
    main()
