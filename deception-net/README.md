# DeceptionNet

An adaptive GAN-based system that generates realistic honeypot infrastructures to deceive and analyze attackers.

## Overview

DeceptionNet uses a conditional Generative Adversarial Network (cGAN) to produce realistic-looking network infrastructure configurations—complete with services, vulnerabilities, and network topologies—and deploys them as honeypots. An adaptive feedback loop continuously refines the generated infrastructure based on observed attacker behavior.

### Key Components

- **GAN Core**: Conditional GAN (WGAN-GP) that generates realistic network infrastructure configurations
- **Honeypot Infrastructure**: Asyncio-based service emulators (SSH, HTTP, FTP) deployed via Docker containers
- **Attack Detector**: ML-based attacker behavior analysis (Random Forest + LSTM) and anomaly detection (Isolation Forest)
- **Adaptive Engine**: Reinforcement learning feedback loop that retrains the GAN based on honeypot effectiveness
- **REST API**: FastAPI server with JWT auth, WebSocket real-time attack feeds, and management endpoints

## Requirements

- Python 3.10+
- Docker & Docker Compose
- CUDA-capable GPU (recommended for GAN training)

## Setup

```bash
# Clone and install
git clone <repo-url>
cd deception-net
pip install -e .

# Or install dependencies directly
pip install -r requirements.txt
```

## Configuration

Edit `config/config.yaml` for GAN training parameters, honeypot settings, and logging configuration.
Edit `config/honeypot_templates.yaml` for service emulation templates.

## Usage

### Train the GAN

```bash
python -m src.gan.trainer --config config/config.yaml
```

### Deploy Honeypots

```bash
python -m src.honeypot.infrastructure --config config/config.yaml
```

### Start the API Server

```bash
uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```

### Run with Docker Compose

```bash
docker-compose -f docker/docker-compose.yml up -d
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test module
pytest tests/test_gan.py -v

# Run with coverage
pytest tests/ --cov=src --cov-report=term-missing
```

## Project Structure

```
deception-net/
├── config/             # YAML configuration files
├── src/
│   ├── gan/            # Generator, Discriminator, training pipeline
│   ├── honeypot/       # Service emulators, deployment, vulnerability injection
│   ├── detector/       # Attacker behavior analysis, anomaly detection
│   ├── adaptor/        # RL-based adaptive feedback engine
│   ├── api/            # FastAPI REST + WebSocket server
│   └── utils/          # Logging, network utilities
├── tests/              # Pytest test suites
├── docker/             # Dockerfile and docker-compose
├── data/               # Training data, network scans, attack logs
├── models/             # Saved model checkpoints
└── notebooks/          # Jupyter experiment notebooks
```

## License

MIT
