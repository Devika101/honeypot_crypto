"""Tests for GAN components: Generator, Discriminator, losses, and metrics."""

import pytest
import torch
import numpy as np

from src.gan.generator import Generator, InfrastructureConfig, ServiceHead, VulnerabilityHead, TopologyHead
from src.gan.discriminator import Discriminator
from src.gan.losses import wasserstein_discriminator_loss, wasserstein_generator_loss, DiversityLoss
from src.gan.metrics import topology_coherence_score, diversity_score, service_distribution_divergence


# --- Generator Tests ---

class TestGenerator:
    def test_generator_output_shapes(self):
        gen = Generator(latent_dim=64, condition_dim=16, hidden_dims=[64, 128, 64])
        z = torch.randn(4, 64)
        cond = torch.randn(4, 16)
        config = gen(z, cond)

        assert isinstance(config, InfrastructureConfig)
        assert config.services.shape == (4, 20, 8)
        assert config.vulnerabilities.shape == (4, 30, 6)
        assert config.topology.shape == (4, 10, 7)

    def test_generator_service_types_sum_to_one(self):
        gen = Generator(latent_dim=64, condition_dim=16, hidden_dims=[64, 128, 64])
        z = torch.randn(2, 64)
        cond = torch.randn(2, 16)
        config = gen(z, cond)

        # Service type probabilities (first 5 features) should sum to ~1
        type_sums = config.services[..., :5].sum(dim=-1)
        assert torch.allclose(type_sums, torch.ones_like(type_sums), atol=1e-5)

    def test_generator_topology_in_range(self):
        gen = Generator(latent_dim=64, condition_dim=16, hidden_dims=[64, 128, 64])
        z = torch.randn(2, 64)
        cond = torch.randn(2, 16)
        config = gen(z, cond)

        # Topology uses sigmoid, should be in [0, 1]
        assert config.topology.min() >= 0.0
        assert config.topology.max() <= 1.0

    def test_generator_sample(self):
        gen = Generator(latent_dim=64, condition_dim=16, hidden_dims=[64, 128, 64])
        cond = torch.randn(3, 16)
        config = gen.sample(3, cond)

        assert config.services.shape[0] == 3

    def test_generator_progressive_depth(self):
        gen = Generator(latent_dim=64, condition_dim=16, hidden_dims=[64, 128, 64])
        gen.set_progressive_depth(1, alpha=0.5)

        z = torch.randn(2, 64)
        cond = torch.randn(2, 16)
        config = gen(z, cond)

        assert config.services.shape == (2, 20, 8)

    def test_generator_to_dict(self):
        gen = Generator(latent_dim=64, condition_dim=16, hidden_dims=[64, 128, 64])
        z = torch.randn(1, 64)
        cond = torch.randn(1, 16)
        config = gen(z, cond)
        d = config.to_dict()

        assert "services" in d
        assert "vulnerabilities" in d
        assert "topology" in d
        assert isinstance(d["services"], np.ndarray)


# --- Discriminator Tests ---

class TestDiscriminator:
    def test_discriminator_output_shape(self):
        disc = Discriminator(condition_dim=16)
        services = torch.randn(4, 20, 8)
        vulns = torch.randn(4, 30, 6)
        topo = torch.randn(4, 10, 7)
        cond = torch.randn(4, 16)

        scores = disc(services, vulns, topo, cond)
        assert scores.shape == (4, 1)

    def test_discriminator_gradient_penalty(self):
        disc = Discriminator(condition_dim=16)
        batch_size = 4
        real_s = torch.randn(batch_size, 20, 8)
        real_v = torch.randn(batch_size, 30, 6)
        real_t = torch.randn(batch_size, 10, 7)
        fake_s = torch.randn(batch_size, 20, 8)
        fake_v = torch.randn(batch_size, 30, 6)
        fake_t = torch.randn(batch_size, 10, 7)
        cond = torch.randn(batch_size, 16)

        gp = disc.gradient_penalty(real_s, real_v, real_t, fake_s, fake_v, fake_t, cond)
        assert gp.shape == ()
        assert gp.item() >= 0

    def test_discriminator_features(self):
        disc = Discriminator(condition_dim=16)
        services = torch.randn(2, 20, 8)
        vulns = torch.randn(2, 30, 6)
        topo = torch.randn(2, 10, 7)
        cond = torch.randn(2, 16)

        disc(services, vulns, topo, cond)
        features = disc.get_features()
        assert features is not None
        assert features.shape[0] == 2


# --- Loss Tests ---

class TestLosses:
    def test_wasserstein_discriminator_loss(self):
        real = torch.tensor([1.0, 2.0, 3.0])
        fake = torch.tensor([0.5, 1.0, 1.5])
        loss = wasserstein_discriminator_loss(real, fake)
        # E[fake] - E[real] = 1.0 - 2.0 = -1.0
        assert torch.isclose(loss, torch.tensor(-1.0))

    def test_wasserstein_generator_loss(self):
        fake = torch.tensor([1.0, 2.0, 3.0])
        loss = wasserstein_generator_loss(fake)
        # -E[fake] = -2.0
        assert torch.isclose(loss, torch.tensor(-2.0))

    def test_diversity_loss(self):
        div_loss = DiversityLoss()
        configs1 = torch.randn(4, 100)
        configs2 = torch.randn(4, 100)
        loss = div_loss(configs1, configs2)
        # Should be negative (minimized = maximizing distance)
        assert loss.item() < 0


# --- Metrics Tests ---

class TestMetrics:
    def test_topology_coherence_score(self):
        # All values in [0, 1] from sigmoid -> should score > 0
        topo = torch.sigmoid(torch.randn(4, 10, 7))
        score = topology_coherence_score(topo)
        assert 0.0 <= score <= 1.0

    def test_diversity_score_identical(self):
        # Identical configs should have zero diversity
        config = torch.randn(5, 50)
        identical = config[0:1].expand(5, -1).clone()
        score = diversity_score(identical)
        assert score < 0.01

    def test_diversity_score_varied(self):
        configs = torch.randn(10, 50) * 10  # High variance
        score = diversity_score(configs)
        assert score > 0

    def test_service_distribution_divergence_same(self):
        services = torch.rand(10, 20, 8)
        services[..., :5] = torch.softmax(services[..., :5] * 5, dim=-1)
        kl = service_distribution_divergence(services, services)
        assert kl < 0.01  # Same distribution -> near zero KL
