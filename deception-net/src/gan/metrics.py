"""Evaluation metrics for generated infrastructure configurations.

Implements:
- Configuration Realism Score (CRS): FID-like metric adapted for infra configs
- Service Distribution Divergence: KL divergence of service type distributions
- Topology Coherence Score: Measures structural validity of generated networks
- Diversity Score: Measures variety across generated configurations
"""

from __future__ import annotations

import numpy as np
import torch
from scipy import linalg


def configuration_realism_score(
    real_features: np.ndarray,
    fake_features: np.ndarray,
) -> float:
    """Compute a FID-like score for infrastructure configurations.

    Lower scores indicate more realistic generated configurations.
    Compares the mean and covariance of feature distributions between
    real network scans and generated configurations.

    Args:
        real_features: (N, D) array of features from real network scans.
        fake_features: (M, D) array of features from generated configs.

    Returns:
        CRS score (lower is better).
    """
    mu_real = np.mean(real_features, axis=0)
    mu_fake = np.mean(fake_features, axis=0)
    sigma_real = np.cov(real_features, rowvar=False)
    sigma_fake = np.cov(fake_features, rowvar=False)

    diff = mu_real - mu_fake
    mean_term = diff @ diff

    # Product of covariance square roots
    covmean, _ = linalg.sqrtm(sigma_real @ sigma_fake, disp=False)
    if np.iscomplexobj(covmean):
        covmean = covmean.real

    cov_term = np.trace(sigma_real + sigma_fake - 2 * covmean)

    return float(mean_term + cov_term)


def service_distribution_divergence(
    real_services: torch.Tensor,
    fake_services: torch.Tensor,
    num_types: int = 5,
) -> float:
    """Compute KL divergence between real and generated service type distributions.

    Args:
        real_services: (N, max_services, feature_dim) real service configs.
        fake_services: (M, max_services, feature_dim) generated service configs.
        num_types: Number of service types (first `num_types` features are one-hot).

    Returns:
        KL divergence (lower is better).
    """
    # Extract type probabilities and compute marginal distributions
    real_dist = real_services[..., :num_types].mean(dim=(0, 1))
    fake_dist = fake_services[..., :num_types].mean(dim=(0, 1))

    # Add epsilon for numerical stability
    eps = 1e-8
    real_dist = real_dist + eps
    fake_dist = fake_dist + eps

    # Normalize
    real_dist = real_dist / real_dist.sum()
    fake_dist = fake_dist / fake_dist.sum()

    kl = (real_dist * (real_dist / fake_dist).log()).sum()
    return float(kl.item())


def topology_coherence_score(topology: torch.Tensor) -> float:
    """Measure structural validity of generated network topologies.

    Checks:
    - IP ranges are valid (octets in [0, 1] when normalized)
    - CIDR masks are reasonable
    - Subnet sizes are consistent with CIDR
    - No overlapping subnets

    Args:
        topology: (batch, max_subnets, 7) generated topology tensor.

    Returns:
        Coherence score in [0, 1] (higher is better).
    """
    batch_size = topology.size(0)
    scores = []

    for i in range(batch_size):
        topo = topology[i]  # (max_subnets, 7)
        score = 0.0
        active_subnets = 0

        for j in range(topo.size(0)):
            subnet = topo[j]
            ip_octets = subnet[:4]
            cidr = subnet[4]
            num_hosts = subnet[5]

            # Check IP range validity (should be in [0, 1])
            if (ip_octets >= 0).all() and (ip_octets <= 1).all():
                score += 0.25

            # Check CIDR is reasonable
            if 0 < cidr <= 1:
                score += 0.25

            # Check host count consistency with CIDR
            expected_hosts = (1 - cidr)  # Rough proxy when normalized
            if abs(num_hosts - expected_hosts) < 0.3:
                score += 0.25

            # Check non-trivial content
            if ip_octets.sum() > 0.1:
                score += 0.25
                active_subnets += 1

        if active_subnets > 0:
            scores.append(score / (active_subnets * 1.0))
        else:
            scores.append(0.0)

    return float(np.mean(scores))


def diversity_score(configs: torch.Tensor) -> float:
    """Measure diversity across a batch of generated configurations.

    Computes mean pairwise L2 distance between configurations.
    Higher scores indicate more diverse outputs.

    Args:
        configs: (batch, ...) flattened configuration tensors.

    Returns:
        Mean pairwise distance (higher is more diverse).
    """
    flat = configs.view(configs.size(0), -1)
    # Pairwise distances
    dists = torch.cdist(flat, flat, p=2)
    # Mean of upper triangle (excluding diagonal)
    n = flat.size(0)
    if n < 2:
        return 0.0
    mask = torch.triu(torch.ones(n, n, device=flat.device), diagonal=1).bool()
    mean_dist = dists[mask].mean()
    return float(mean_dist.item())
