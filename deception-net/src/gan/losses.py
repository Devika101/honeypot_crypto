"""Loss functions for WGAN-GP training.

Implements:
- Wasserstein critic loss (discriminator)
- Wasserstein generator loss
- Gradient penalty (computed via Discriminator.gradient_penalty)
- Feature matching loss for training stability
"""

from __future__ import annotations

import torch
import torch.nn as nn


def wasserstein_discriminator_loss(
    real_scores: torch.Tensor,
    fake_scores: torch.Tensor,
) -> torch.Tensor:
    """Wasserstein loss for the discriminator (critic).

    The critic aims to maximize E[D(real)] - E[D(fake)], so the loss
    to minimize is E[D(fake)] - E[D(real)].
    """
    return fake_scores.mean() - real_scores.mean()


def wasserstein_generator_loss(fake_scores: torch.Tensor) -> torch.Tensor:
    """Wasserstein loss for the generator.

    The generator aims to maximize E[D(fake)], so the loss to minimize is -E[D(fake)].
    """
    return -fake_scores.mean()


class FeatureMatchingLoss(nn.Module):
    """Feature matching loss comparing intermediate discriminator features.

    Encourages the generator to produce samples whose discriminator features
    match the statistics of real samples.
    """

    def __init__(self) -> None:
        super().__init__()
        self.loss_fn = nn.MSELoss()

    def forward(
        self,
        real_features: torch.Tensor,
        fake_features: torch.Tensor,
    ) -> torch.Tensor:
        """Compute L2 distance between mean feature vectors."""
        return self.loss_fn(
            fake_features.mean(dim=0),
            real_features.mean(dim=0),
        )


class DiversityLoss(nn.Module):
    """Encourages diversity in generated outputs to prevent mode collapse.

    Penalizes the generator when outputs from different noise vectors
    are too similar.
    """

    def forward(self, configs1: torch.Tensor, configs2: torch.Tensor) -> torch.Tensor:
        """Compute negative pairwise distance (to be minimized, so encouraging diversity).

        Args:
            configs1: Flattened configs from noise z1 (batch, features).
            configs2: Flattened configs from noise z2 (batch, features).

        Returns:
            Negative mean pairwise L1 distance.
        """
        distance = torch.abs(configs1 - configs2).mean(dim=1)
        return -distance.mean()
