# AGENTS.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

DeceptionNet is an adaptive GAN-based system that generates realistic honeypot infrastructures to deceive and analyze attackers. It uses a conditional GAN (WGAN-GP) to produce network configs (services, vulnerabilities, topology), deploys them as honeypot emulators or Docker containers, detects attacker behavior via ML classifiers, and continuously adapts via an RL feedback loop.

## Build & Run Commands

```bash
# Install dependencies
pip install -e .
# Or: pip install -r requirements.txt

# Train the GAN (with synthetic data for dev)
python -m src.gan.trainer --config config/config.yaml --synthetic

# Train from a checkpoint
python -m src.gan.trainer --config config/config.yaml --resume models/saved_models/checkpoint_latest.pt

# Deploy honeypots locally (asyncio emulators)
python -m src.honeypot.infrastructure --config config/config.yaml

# Deploy honeypots via Docker
python -m src.honeypot.infrastructure --config config/config.yaml --docker

# Start the API server
uvicorn src.api.main:app --host 0.0.0.0 --port 8000

# Run full stack via Docker Compose
docker-compose -f docker/docker-compose.yml up -d
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run a single test file
pytest tests/test_gan.py -v

# Run a single test
pytest tests/test_gan.py::TestGenerator::test_generator_output_shapes -v

# Run with coverage
pytest tests/ --cov=src --cov-report=term-missing
```

Tests use `pytest` with `pytest-asyncio` for async emulator tests. Async test mode is set to `auto` in `pytest.ini`.

## Architecture

The system has 5 core subsystems that form a closed loop:

### 1. GAN Core (`src/gan/`)
Conditional WGAN-GP that generates honeypot infrastructure configurations as tensors:
- **Generator** (`generator.py`): Takes noise `z` + condition vector → outputs `InfrastructureConfig` with three tensors: services (batch, 20, 8), vulnerabilities (batch, 30, 6), topology (batch, 10, 7). Uses progressive growing with `ProgressiveBlock`s and three output heads (`ServiceHead`, `VulnerabilityHead`, `TopologyHead`).
- **Discriminator** (`discriminator.py`): Three parallel `FeatureExtractor`s (one per tensor type) → fusion network → unbounded critic score. Uses spectral normalization. Has built-in `gradient_penalty()` for WGAN-GP.
- **Trainer** (`trainer.py`): Orchestrates WGAN-GP training with `TrainingConfig` (loadable from YAML), curriculum learning (`CurriculumStage`), cosine annealing LR, and `create_synthetic_dataset()` for development.
- Losses in `losses.py`, metrics (CRS, KL divergence, topology coherence, diversity) in `metrics.py`.

### 2. Honeypot Infrastructure (`src/honeypot/`)
Converts GAN tensor output into deployed services:
- **service_emulator.py**: `BaseEmulator` ABC with `SSHEmulator`, `HTTPEmulator`, `FTPEmulator`. All are asyncio TCP servers that log every interaction via `InteractionLog` dataclass and an optional `log_callback`.
- **vulnerability_injector.py**: `VulnerabilityInjector` holds `VulnerabilityTemplate`s with regex detection signatures. `check_exploit()` matches incoming payloads against signatures and returns `ExploitAttempt`.
- **container_manager.py**: `ContainerManager` wraps the Docker SDK for container lifecycle, network isolation, health checks, and snapshot/rollback.
- **infrastructure.py**: `HoneypotInfrastructure` is the top-level orchestrator. It ties Generator → `tensor_to_services()`/`tensor_to_subnets()` (from `utils/network.py`) → emulators or containers. Entry point via `main()`.

### 3. Detection (`src/detector/`)
- **attacker_behavior.py**: `BehaviorAnalyzer` maintains per-IP `AttackerProfile`s. Classifies attack phases (recon, exploitation, lateral movement, exfil) by matching commands against indicator sets. Computes threat scores and skill levels. Includes a `TemporalAnalyzer` (LSTM) for sequence classification.
- **anomaly_detection.py**: `AnomalyDetector` ensembles Isolation Forest + `BehaviorAutoencoder` (reconstruction error). Generates `Alert`s with severity levels. Ensemble agreement reduces false positives.

### 4. Adaptive Engine (`src/adaptor/adaptive_engine.py`)
`AdaptiveEngine` uses PPO (`PolicyNetwork`) to adjust the GAN condition vector based on `EffectivenessMetrics` (interaction depth, credential testing rate, lateral movement). Supports A/B testing via `ConfigVariant`. Triggers GAN retraining when effectiveness drops below `retrain_threshold`.

### 5. API (`src/api/`)
FastAPI server with JWT auth (`auth.py`), REST routes (`routes.py`), and WebSocket attack feed (`/ws/attacks`). All config loaded from `config/config.yaml`. Auth endpoint: `POST /api/v1/token`. Protected routes under `/api/v1/`.

## Data Flow

```
GAN Generator → InfrastructureConfig tensors
    ↓ (tensor_to_services / tensor_to_subnets)
Service Emulators (SSH/HTTP/FTP) ← Attacker connections
    ↓ (InteractionLog via log_callback)
BehaviorAnalyzer → AttackerProfile + threat scores
    ↓
AnomalyDetector → Alerts
    ↓
AdaptiveEngine.compute_effectiveness() → EffectivenessMetrics
    ↓ (PPO policy)
Updated condition vector → GAN Generator (loop)
```

## Key Configuration

- `config/config.yaml`: All tunable parameters (GAN hyperparams, honeypot limits, detection thresholds, RL settings, API config)
- `config/honeypot_templates.yaml`: Service banners, fake credentials, command responses, vulnerability endpoints

## Conventions

- All modules use `src.utils.logger.get_logger(__name__)` for structured JSON logging via structlog.
- GAN tensors use normalized [0, 1] values (sigmoid outputs); service types use softmax for one-hot encoding.
- The Discriminator outputs unbounded scores (WGAN-style, no sigmoid).
- Emulators use `port=0` for auto-assignment during development/testing.
- All interaction data flows through `InteractionLog` dataclass and `log_callback` pattern.
