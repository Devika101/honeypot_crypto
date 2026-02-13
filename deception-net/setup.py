"""DeceptionNet package setup."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [
        line.strip()
        for line in fh
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="deception-net",
    version="0.1.0",
    description="Adaptive GAN-based honeypot infrastructure generator",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "httpx>=0.24.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "deceptionnet-train=src.gan.trainer:main",
            "deceptionnet-deploy=src.honeypot.infrastructure:main",
            "deceptionnet-api=src.api.main:start",
        ],
    },
)
