"""GAN module for generating realistic honeypot infrastructure configurations."""

from src.gan.generator import Generator
from src.gan.discriminator import Discriminator

__all__ = ["Generator", "Discriminator"]
