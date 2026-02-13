"""Conditional GAN Generator for honeypot infrastructure configuration generation.

The Generator takes random noise concatenated with condition vectors (network topology
constraints) and outputs realistic infrastructure configurations including:
- Service type distributions (SSH, HTTP, FTP, DB, SMTP)
- Vulnerability placements
- Subnet structures and IP range allocations
- Port/protocol combinations

Uses progressive growing for training stability.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import torch
import torch.nn as nn


@dataclass
class InfrastructureConfig:
    """Parsed output from the Generator representing a honeypot configuration.

    Attributes:
        services: Tensor of shape (batch, max_services, service_feature_dim).
                  Each service has: [type_onehot(5), port(1), enabled(1), vuln_count(1)]
        vulnerabilities: Tensor of shape (batch, max_vulns, vuln_feature_dim).
                         Each vuln has: [type_onehot(4), severity(1), target_service_idx(1)]
        topology: Tensor of shape (batch, max_subnets, subnet_feature_dim).
                  Each subnet has: [ip_range(4), cidr(1), num_hosts(1), gateway(1)]
    """

    services: torch.Tensor
    vulnerabilities: torch.Tensor
    topology: torch.Tensor

    def to_dict(self) -> dict:
        """Convert to a dictionary of numpy arrays for deployment."""
        return {
            "services": self.services.detach().cpu().numpy(),
            "vulnerabilities": self.vulnerabilities.detach().cpu().numpy(),
            "topology": self.topology.detach().cpu().numpy(),
        }


class ResidualBlock(nn.Module):
    """Residual block with spectral normalization for stable generation."""

    def __init__(self, dim: int) -> None:
        super().__init__()
        self.block = nn.Sequential(
            nn.Linear(dim, dim),
            nn.LayerNorm(dim),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Linear(dim, dim),
            nn.LayerNorm(dim),
        )
        self.activation = nn.LeakyReLU(0.2, inplace=True)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.activation(x + self.block(x))


class ProgressiveBlock(nn.Module):
    """A block in the progressive growing pipeline.

    Each block doubles the representational capacity and can be
    faded in during training via the `alpha` blending parameter.
    """

    def __init__(self, in_dim: int, out_dim: int) -> None:
        super().__init__()
        self.main = nn.Sequential(
            nn.Linear(in_dim, out_dim),
            nn.LayerNorm(out_dim),
            nn.LeakyReLU(0.2, inplace=True),
            ResidualBlock(out_dim),
        )
        self.skip = nn.Linear(in_dim, out_dim) if in_dim != out_dim else nn.Identity()

    def forward(self, x: torch.Tensor, alpha: float = 1.0) -> torch.Tensor:
        return alpha * self.main(x) + (1 - alpha) * self.skip(x)


class ServiceHead(nn.Module):
    """Output head for service configuration generation."""

    SERVICE_TYPES = 5  # SSH, HTTP, FTP, MySQL, SMTP
    FEATURE_DIM = 8    # type_onehot(5) + port(1) + enabled(1) + vuln_count(1)

    def __init__(self, in_dim: int, max_services: int = 20) -> None:
        super().__init__()
        self.max_services = max_services
        self.net = nn.Sequential(
            nn.Linear(in_dim, in_dim // 2),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Linear(in_dim // 2, max_services * self.FEATURE_DIM),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        out = self.net(x)
        out = out.view(x.size(0), self.max_services, self.FEATURE_DIM)
        # Apply softmax to service type portion, sigmoid to the rest
        types = torch.softmax(out[..., :self.SERVICE_TYPES], dim=-1)
        attrs = torch.sigmoid(out[..., self.SERVICE_TYPES:])
        return torch.cat([types, attrs], dim=-1)


class VulnerabilityHead(nn.Module):
    """Output head for vulnerability placement generation."""

    VULN_TYPES = 4    # SQLi, CMDi, WeakAuth, Outdated
    FEATURE_DIM = 6   # type_onehot(4) + severity(1) + target_service_idx(1)

    def __init__(self, in_dim: int, max_vulns: int = 30) -> None:
        super().__init__()
        self.max_vulns = max_vulns
        self.net = nn.Sequential(
            nn.Linear(in_dim, in_dim // 2),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Linear(in_dim // 2, max_vulns * self.FEATURE_DIM),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        out = self.net(x)
        out = out.view(x.size(0), self.max_vulns, self.FEATURE_DIM)
        types = torch.softmax(out[..., :self.VULN_TYPES], dim=-1)
        severity = torch.sigmoid(out[..., self.VULN_TYPES:self.VULN_TYPES + 1])
        target = torch.sigmoid(out[..., self.VULN_TYPES + 1:])
        return torch.cat([types, severity, target], dim=-1)


class TopologyHead(nn.Module):
    """Output head for network topology generation."""

    FEATURE_DIM = 7  # ip_range(4) + cidr(1) + num_hosts(1) + gateway(1)

    def __init__(self, in_dim: int, max_subnets: int = 10) -> None:
        super().__init__()
        self.max_subnets = max_subnets
        self.net = nn.Sequential(
            nn.Linear(in_dim, in_dim // 2),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Linear(in_dim // 2, max_subnets * self.FEATURE_DIM),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        out = self.net(x)
        out = out.view(x.size(0), self.max_subnets, self.FEATURE_DIM)
        return torch.sigmoid(out)


class Generator(nn.Module):
    """Conditional GAN Generator with progressive growing.

    Architecture:
        1. Condition embedding + noise -> fused latent
        2. Progressive backbone blocks (faded in during training)
        3. Three output heads: services, vulnerabilities, topology

    Args:
        latent_dim: Dimension of the noise vector z.
        condition_dim: Dimension of the condition vector (topology constraints).
        hidden_dims: List of hidden layer dimensions for progressive blocks.
        max_services: Maximum number of services to generate.
        max_vulns: Maximum number of vulnerabilities to generate.
        max_subnets: Maximum number of subnets to generate.
    """

    def __init__(
        self,
        latent_dim: int = 128,
        condition_dim: int = 32,
        hidden_dims: Optional[list[int]] = None,
        max_services: int = 20,
        max_vulns: int = 30,
        max_subnets: int = 10,
    ) -> None:
        super().__init__()
        self.latent_dim = latent_dim
        self.condition_dim = condition_dim
        hidden_dims = hidden_dims or [256, 512, 1024, 512, 256]

        # Condition embedding
        self.condition_embed = nn.Sequential(
            nn.Linear(condition_dim, hidden_dims[0]),
            nn.LeakyReLU(0.2, inplace=True),
        )

        # Initial fusion of noise + condition
        self.initial = nn.Sequential(
            nn.Linear(latent_dim + hidden_dims[0], hidden_dims[0]),
            nn.LayerNorm(hidden_dims[0]),
            nn.LeakyReLU(0.2, inplace=True),
        )

        # Progressive blocks
        self.blocks = nn.ModuleList()
        for i in range(len(hidden_dims) - 1):
            self.blocks.append(ProgressiveBlock(hidden_dims[i], hidden_dims[i + 1]))

        # Output heads
        final_dim = hidden_dims[-1]
        self.service_head = ServiceHead(final_dim, max_services)
        self.vuln_head = VulnerabilityHead(final_dim, max_vulns)
        self.topology_head = TopologyHead(final_dim, max_subnets)

        # Track current progressive depth and fade-in alpha
        self.current_depth = len(self.blocks)
        self.alpha = 1.0

    def set_progressive_depth(self, depth: int, alpha: float = 1.0) -> None:
        """Set the number of progressive blocks to use and the fade-in alpha.

        Args:
            depth: Number of progressive blocks to activate (1 to len(blocks)).
            alpha: Blending factor for the newest block (0=skip, 1=full).
        """
        self.current_depth = min(depth, len(self.blocks))
        self.alpha = alpha

    def forward(
        self,
        z: torch.Tensor,
        condition: torch.Tensor,
    ) -> InfrastructureConfig:
        """Generate an infrastructure configuration.

        Args:
            z: Noise tensor of shape (batch, latent_dim).
            condition: Condition tensor of shape (batch, condition_dim).

        Returns:
            InfrastructureConfig with services, vulnerabilities, and topology tensors.
        """
        cond = self.condition_embed(condition)
        x = torch.cat([z, cond], dim=-1)
        x = self.initial(x)

        for i, block in enumerate(self.blocks[: self.current_depth]):
            a = self.alpha if i == self.current_depth - 1 else 1.0
            x = block(x, alpha=a)

        return InfrastructureConfig(
            services=self.service_head(x),
            vulnerabilities=self.vuln_head(x),
            topology=self.topology_head(x),
        )

    def sample(
        self,
        batch_size: int,
        condition: torch.Tensor,
        device: Optional[torch.device] = None,
    ) -> InfrastructureConfig:
        """Generate configurations by sampling random noise.

        Args:
            batch_size: Number of configurations to generate.
            condition: Condition tensor of shape (batch_size, condition_dim).
            device: Device for the noise tensor.

        Returns:
            InfrastructureConfig with generated configurations.
        """
        device = device or next(self.parameters()).device
        z = torch.randn(batch_size, self.latent_dim, device=device)
        return self.forward(z, condition)
