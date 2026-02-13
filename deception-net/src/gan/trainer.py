"""GAN training pipeline with WGAN-GP training loop.

Features:
- WGAN-GP loss with gradient penalty
- Learning rate scheduling (cosine annealing)
- Gradient clipping
- Model checkpointing
- Curriculum learning (basic -> intermediate -> advanced)
- Progressive growing support
- Metric logging
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np
import torch
import torch.nn as nn
from torch.optim import Adam
from torch.optim.lr_scheduler import CosineAnnealingLR
from torch.utils.data import DataLoader, TensorDataset

import yaml

from src.gan.discriminator import Discriminator
from src.gan.generator import Generator, InfrastructureConfig
from src.gan.losses import (
    DiversityLoss,
    FeatureMatchingLoss,
    wasserstein_discriminator_loss,
    wasserstein_generator_loss,
)
from src.gan.metrics import (
    configuration_realism_score,
    diversity_score,
    service_distribution_divergence,
    topology_coherence_score,
)
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CurriculumStage:
    """A stage in the curriculum learning schedule."""

    name: str
    epochs: int
    max_services: int
    max_subnets: int


@dataclass
class TrainingConfig:
    """Configuration for the GAN training pipeline."""

    latent_dim: int = 128
    condition_dim: int = 32
    hidden_dims: list[int] = field(default_factory=lambda: [256, 512, 1024, 512, 256])
    output_dim: int = 256
    lr_generator: float = 0.0001
    lr_discriminator: float = 0.0004
    betas: tuple[float, float] = (0.0, 0.9)
    gradient_penalty_weight: float = 10.0
    critic_iterations: int = 5
    batch_size: int = 64
    epochs: int = 500
    checkpoint_interval: int = 10
    checkpoint_dir: str = "models/saved_models"
    grad_clip_norm: float = 1.0
    diversity_loss_weight: float = 0.1
    feature_matching_weight: float = 0.1
    curriculum_enabled: bool = True
    curriculum_stages: list[CurriculumStage] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, config_path: str) -> TrainingConfig:
        """Load training config from a YAML file."""
        with open(config_path, "r") as f:
            raw = yaml.safe_load(f)

        gan = raw.get("gan", {})
        lr = gan.get("learning_rate", {})
        curriculum = gan.get("curriculum", {})

        stages = []
        if curriculum.get("enabled", False):
            for s in curriculum.get("stages", []):
                stages.append(CurriculumStage(**s))

        return cls(
            latent_dim=gan.get("latent_dim", 128),
            condition_dim=gan.get("condition_dim", 32),
            hidden_dims=gan.get("hidden_dims", [256, 512, 1024, 512, 256]),
            output_dim=gan.get("output_dim", 256),
            lr_generator=lr.get("generator", 0.0001),
            lr_discriminator=lr.get("discriminator", 0.0004),
            betas=tuple(gan.get("betas", [0.0, 0.9])),
            gradient_penalty_weight=gan.get("gradient_penalty_weight", 10.0),
            critic_iterations=gan.get("critic_iterations", 5),
            batch_size=gan.get("batch_size", 64),
            epochs=gan.get("epochs", 500),
            checkpoint_interval=gan.get("checkpoint_interval", 10),
            checkpoint_dir=gan.get("checkpoint_dir", "models/saved_models"),
            curriculum_enabled=curriculum.get("enabled", False),
            curriculum_stages=stages,
        )


class Trainer:
    """WGAN-GP Trainer with curriculum learning and progressive growing.

    Args:
        config: Training configuration.
        device: Torch device.
    """

    def __init__(
        self,
        config: TrainingConfig,
        device: Optional[torch.device] = None,
    ) -> None:
        self.config = config
        self.device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")

        # Build models
        self.generator = Generator(
            latent_dim=config.latent_dim,
            condition_dim=config.condition_dim,
            hidden_dims=config.hidden_dims,
        ).to(self.device)

        self.discriminator = Discriminator(
            condition_dim=config.condition_dim,
        ).to(self.device)

        # Optimizers
        self.opt_g = Adam(
            self.generator.parameters(),
            lr=config.lr_generator,
            betas=config.betas,
        )
        self.opt_d = Adam(
            self.discriminator.parameters(),
            lr=config.lr_discriminator,
            betas=config.betas,
        )

        # LR schedulers
        self.scheduler_g = CosineAnnealingLR(self.opt_g, T_max=config.epochs)
        self.scheduler_d = CosineAnnealingLR(self.opt_d, T_max=config.epochs)

        # Auxiliary losses
        self.feature_matching = FeatureMatchingLoss()
        self.diversity_loss = DiversityLoss()

        # Metrics history
        self.history: dict[str, list[float]] = {
            "d_loss": [],
            "g_loss": [],
            "gradient_penalty": [],
            "crs": [],
            "diversity": [],
            "topology_coherence": [],
        }

    def _train_discriminator(
        self,
        real_services: torch.Tensor,
        real_vulns: torch.Tensor,
        real_topology: torch.Tensor,
        conditions: torch.Tensor,
    ) -> tuple[float, float]:
        """Train the discriminator for one step.

        Returns:
            Tuple of (discriminator loss, gradient penalty).
        """
        self.opt_d.zero_grad()

        batch_size = real_services.size(0)
        z = torch.randn(batch_size, self.config.latent_dim, device=self.device)

        with torch.no_grad():
            fake = self.generator(z, conditions)

        # Critic scores
        real_scores = self.discriminator(real_services, real_vulns, real_topology, conditions)
        fake_scores = self.discriminator(
            fake.services, fake.vulnerabilities, fake.topology, conditions
        )

        # WGAN loss + gradient penalty
        d_loss = wasserstein_discriminator_loss(real_scores, fake_scores)
        gp = self.discriminator.gradient_penalty(
            real_services, real_vulns, real_topology,
            fake.services, fake.vulnerabilities, fake.topology,
            conditions,
        )
        total_loss = d_loss + self.config.gradient_penalty_weight * gp

        total_loss.backward()
        nn.utils.clip_grad_norm_(self.discriminator.parameters(), self.config.grad_clip_norm)
        self.opt_d.step()

        return d_loss.item(), gp.item()

    def _train_generator(
        self,
        conditions: torch.Tensor,
        batch_size: int,
    ) -> float:
        """Train the generator for one step.

        Returns:
            Generator loss value.
        """
        self.opt_g.zero_grad()

        z1 = torch.randn(batch_size, self.config.latent_dim, device=self.device)
        z2 = torch.randn(batch_size, self.config.latent_dim, device=self.device)

        fake1 = self.generator(z1, conditions)
        fake2 = self.generator(z2, conditions)

        # Critic score for fake
        fake_scores = self.discriminator(
            fake1.services, fake1.vulnerabilities, fake1.topology, conditions
        )

        # Wasserstein generator loss
        g_loss = wasserstein_generator_loss(fake_scores)

        # Diversity loss (prevent mode collapse)
        flat1 = torch.cat([
            fake1.services.view(batch_size, -1),
            fake1.vulnerabilities.view(batch_size, -1),
            fake1.topology.view(batch_size, -1),
        ], dim=-1)
        flat2 = torch.cat([
            fake2.services.view(batch_size, -1),
            fake2.vulnerabilities.view(batch_size, -1),
            fake2.topology.view(batch_size, -1),
        ], dim=-1)
        div_loss = self.diversity_loss(flat1, flat2)

        total_loss = g_loss + self.config.diversity_loss_weight * div_loss

        total_loss.backward()
        nn.utils.clip_grad_norm_(self.generator.parameters(), self.config.grad_clip_norm)
        self.opt_g.step()

        return g_loss.item()

    def _get_curriculum_stage(self, epoch: int) -> Optional[CurriculumStage]:
        """Determine the current curriculum stage based on epoch."""
        if not self.config.curriculum_enabled or not self.config.curriculum_stages:
            return None

        cumulative = 0
        for stage in self.config.curriculum_stages:
            cumulative += stage.epochs
            if epoch < cumulative:
                return stage
        return self.config.curriculum_stages[-1]

    def train(self, dataloader: DataLoader) -> dict[str, list[float]]:
        """Run the full training loop.

        Args:
            dataloader: DataLoader yielding (services, vulns, topology, conditions) batches.

        Returns:
            Training history dictionary.
        """
        logger.info(
            "Starting training",
            device=str(self.device),
            epochs=self.config.epochs,
            batch_size=self.config.batch_size,
        )

        for epoch in range(self.config.epochs):
            stage = self._get_curriculum_stage(epoch)
            if stage:
                # Progressive growing: use more blocks for later stages
                depth = {"basic": 2, "intermediate": 3, "advanced": len(self.generator.blocks)}
                self.generator.set_progressive_depth(depth.get(stage.name, len(self.generator.blocks)))

            epoch_d_loss = []
            epoch_g_loss = []
            epoch_gp = []

            for batch_idx, batch in enumerate(dataloader):
                real_svc, real_vuln, real_topo, cond = [b.to(self.device) for b in batch]
                batch_size = real_svc.size(0)

                # Train discriminator (critic) for N iterations
                for _ in range(self.config.critic_iterations):
                    d_loss, gp = self._train_discriminator(real_svc, real_vuln, real_topo, cond)
                    epoch_d_loss.append(d_loss)
                    epoch_gp.append(gp)

                # Train generator
                g_loss = self._train_generator(cond, batch_size)
                epoch_g_loss.append(g_loss)

            # Step schedulers
            self.scheduler_g.step()
            self.scheduler_d.step()

            # Record metrics
            avg_d = np.mean(epoch_d_loss) if epoch_d_loss else 0
            avg_g = np.mean(epoch_g_loss) if epoch_g_loss else 0
            avg_gp = np.mean(epoch_gp) if epoch_gp else 0
            self.history["d_loss"].append(avg_d)
            self.history["g_loss"].append(avg_g)
            self.history["gradient_penalty"].append(avg_gp)

            # Evaluate periodically
            if (epoch + 1) % self.config.checkpoint_interval == 0:
                self._evaluate_and_checkpoint(epoch, dataloader)

            if (epoch + 1) % 10 == 0:
                stage_name = stage.name if stage else "full"
                logger.info(
                    "Epoch complete",
                    epoch=epoch + 1,
                    stage=stage_name,
                    d_loss=f"{avg_d:.4f}",
                    g_loss=f"{avg_g:.4f}",
                    gp=f"{avg_gp:.4f}",
                    lr_g=f"{self.scheduler_g.get_last_lr()[0]:.6f}",
                )

        return self.history

    def _evaluate_and_checkpoint(self, epoch: int, dataloader: DataLoader) -> None:
        """Evaluate metrics and save model checkpoint."""
        self.generator.eval()

        with torch.no_grad():
            # Generate a batch for evaluation
            sample_batch = next(iter(dataloader))
            cond = sample_batch[3].to(self.device)
            batch_size = cond.size(0)

            fake = self.generator.sample(batch_size, cond, self.device)

            # Topology coherence
            tc = topology_coherence_score(fake.topology)
            self.history["topology_coherence"].append(tc)

            # Diversity
            flat = torch.cat([
                fake.services.view(batch_size, -1),
                fake.vulnerabilities.view(batch_size, -1),
                fake.topology.view(batch_size, -1),
            ], dim=-1)
            div = diversity_score(flat)
            self.history["diversity"].append(div)

        self.generator.train()

        # Save checkpoint
        self._save_checkpoint(epoch)

        logger.info(
            "Checkpoint saved",
            epoch=epoch + 1,
            topology_coherence=f"{tc:.4f}",
            diversity=f"{div:.4f}",
        )

    def _save_checkpoint(self, epoch: int) -> None:
        """Save model checkpoint to disk."""
        ckpt_dir = Path(self.config.checkpoint_dir)
        ckpt_dir.mkdir(parents=True, exist_ok=True)

        checkpoint = {
            "epoch": epoch,
            "generator_state": self.generator.state_dict(),
            "discriminator_state": self.discriminator.state_dict(),
            "opt_g_state": self.opt_g.state_dict(),
            "opt_d_state": self.opt_d.state_dict(),
            "history": self.history,
        }

        path = ckpt_dir / f"checkpoint_epoch_{epoch + 1}.pt"
        torch.save(checkpoint, path)

        # Also save as "latest"
        torch.save(checkpoint, ckpt_dir / "checkpoint_latest.pt")

    def load_checkpoint(self, path: str) -> int:
        """Load a training checkpoint.

        Args:
            path: Path to the checkpoint file.

        Returns:
            The epoch number the checkpoint was saved at.
        """
        checkpoint = torch.load(path, map_location=self.device)
        self.generator.load_state_dict(checkpoint["generator_state"])
        self.discriminator.load_state_dict(checkpoint["discriminator_state"])
        self.opt_g.load_state_dict(checkpoint["opt_g_state"])
        self.opt_d.load_state_dict(checkpoint["opt_d_state"])
        self.history = checkpoint.get("history", self.history)
        logger.info("Checkpoint loaded", path=path, epoch=checkpoint["epoch"] + 1)
        return checkpoint["epoch"]


def create_synthetic_dataset(
    num_samples: int = 1000,
    max_services: int = 20,
    max_vulns: int = 30,
    max_subnets: int = 10,
    condition_dim: int = 32,
) -> TensorDataset:
    """Create a synthetic training dataset for development/testing.

    In production, replace with real network scan data loaded from data/real_networks/.
    """
    services = torch.rand(num_samples, max_services, 8)
    # Normalize service types to be one-hot-ish
    services[..., :5] = torch.softmax(services[..., :5] * 5, dim=-1)
    services[..., 5:] = torch.sigmoid(services[..., 5:])

    vulns = torch.rand(num_samples, max_vulns, 6)
    vulns[..., :4] = torch.softmax(vulns[..., :4] * 5, dim=-1)
    vulns[..., 4:] = torch.sigmoid(vulns[..., 4:])

    topology = torch.sigmoid(torch.randn(num_samples, max_subnets, 7))
    conditions = torch.randn(num_samples, condition_dim)

    return TensorDataset(services, vulns, topology, conditions)


def main() -> None:
    """Entry point for training from CLI."""
    parser = argparse.ArgumentParser(description="Train DeceptionNet GAN")
    parser.add_argument("--config", type=str, default="config/config.yaml", help="Config file path")
    parser.add_argument("--resume", type=str, default=None, help="Checkpoint to resume from")
    parser.add_argument("--synthetic", action="store_true", help="Use synthetic data for testing")
    args = parser.parse_args()

    config = TrainingConfig.from_yaml(args.config)
    trainer = Trainer(config)

    if args.resume:
        trainer.load_checkpoint(args.resume)

    if args.synthetic:
        dataset = create_synthetic_dataset(
            num_samples=1000,
            condition_dim=config.condition_dim,
        )
    else:
        # Load real data from data/training/
        data_dir = Path("data/training")
        if not data_dir.exists() or not list(data_dir.iterdir()):
            logger.warning("No training data found, using synthetic data")
            dataset = create_synthetic_dataset(condition_dim=config.condition_dim)
        else:
            # Load .pt tensor files
            all_tensors = []
            for pt_file in sorted(data_dir.glob("*.pt")):
                all_tensors.append(torch.load(pt_file))
            dataset = TensorDataset(*all_tensors)

    dataloader = DataLoader(dataset, batch_size=config.batch_size, shuffle=True, drop_last=True)

    history = trainer.train(dataloader)

    # Save final history
    history_path = Path(config.checkpoint_dir) / "training_history.json"
    history_path.parent.mkdir(parents=True, exist_ok=True)
    with open(history_path, "w") as f:
        json.dump({k: [float(v) for v in vals] for k, vals in history.items()}, f, indent=2)

    logger.info("Training complete", history_path=str(history_path))


if __name__ == "__main__":
    main()
