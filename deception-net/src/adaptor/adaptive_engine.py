"""Adaptive feedback engine using reinforcement learning.

Monitors honeypot effectiveness and uses PPO-style RL to:
- Compute effectiveness metrics (time-to-discovery, interaction depth, etc.)
- Decide when to retrain the GAN
- Suggest configuration modifications
- Implement A/B testing for configuration variants
- Trigger zero-downtime reconfiguration
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class EffectivenessMetrics:
    """Honeypot effectiveness measurements."""

    time_to_discovery: float = 0.0       # Avg seconds until attacker finds honeypot
    interaction_depth: float = 0.0        # Avg number of actions per attacker session
    credential_testing_rate: float = 0.0  # Fraction of sessions with auth attempts
    lateral_movement_attempts: float = 0.0  # Fraction of sessions with lateral movement
    unique_attackers: int = 0
    total_sessions: int = 0
    overall_score: float = 0.0            # Composite effectiveness score [0, 1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "time_to_discovery": self.time_to_discovery,
            "interaction_depth": self.interaction_depth,
            "credential_testing_rate": self.credential_testing_rate,
            "lateral_movement_attempts": self.lateral_movement_attempts,
            "unique_attackers": self.unique_attackers,
            "total_sessions": self.total_sessions,
            "overall_score": self.overall_score,
        }


@dataclass
class ConfigVariant:
    """An A/B test configuration variant."""

    variant_id: str
    description: str
    condition_vector: np.ndarray
    metrics: Optional[EffectivenessMetrics] = None
    sessions: int = 0


class PolicyNetwork(nn.Module):
    """PPO-style policy network for honeypot configuration decisions.

    State: current effectiveness metrics + honeypot configuration summary.
    Action: modification parameters for the GAN condition vector.

    Args:
        state_dim: Dimension of the state vector.
        action_dim: Dimension of the action (condition vector modifications).
    """

    def __init__(self, state_dim: int = 16, action_dim: int = 32) -> None:
        super().__init__()
        self.shared = nn.Sequential(
            nn.Linear(state_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
        )
        # Actor: outputs mean of action distribution
        self.actor_mean = nn.Linear(64, action_dim)
        self.actor_log_std = nn.Parameter(torch.zeros(action_dim))

        # Critic: outputs state value
        self.critic = nn.Linear(64, 1)

    def forward(self, state: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        """Compute action distribution parameters and state value.

        Args:
            state: (batch, state_dim) state vectors.

        Returns:
            Tuple of (action_mean, state_value).
        """
        features = self.shared(state)
        action_mean = self.actor_mean(features)
        value = self.critic(features)
        return action_mean, value

    def get_action(self, state: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """Sample an action from the policy.

        Returns:
            Tuple of (action, log_prob, value).
        """
        mean, value = self.forward(state)
        std = self.actor_log_std.exp()
        dist = torch.distributions.Normal(mean, std)
        action = dist.sample()
        log_prob = dist.log_prob(action).sum(dim=-1)
        return action, log_prob, value


class AdaptiveEngine:
    """RL-based adaptive feedback loop for honeypot optimization.

    Periodically evaluates honeypot effectiveness and uses a PPO policy
    to suggest modifications to the GAN condition vector, triggering
    infrastructure reconfiguration when needed.

    Args:
        condition_dim: Dimension of the GAN condition vector.
        feedback_interval: Seconds between effectiveness evaluations.
        retrain_threshold: Effectiveness score below which GAN retraining is triggered.
        rl_lr: Learning rate for the RL policy.
        gamma: Discount factor.
        epsilon_clip: PPO clipping parameter.
    """

    def __init__(
        self,
        condition_dim: int = 32,
        feedback_interval: float = 300.0,
        retrain_threshold: float = 0.6,
        rl_lr: float = 0.0003,
        gamma: float = 0.99,
        epsilon_clip: float = 0.2,
    ) -> None:
        self.condition_dim = condition_dim
        self.feedback_interval = feedback_interval
        self.retrain_threshold = retrain_threshold
        self.gamma = gamma
        self.epsilon_clip = epsilon_clip

        # Policy network
        self.policy = PolicyNetwork(state_dim=16, action_dim=condition_dim)
        self.optimizer = torch.optim.Adam(self.policy.parameters(), lr=rl_lr)

        # Experience buffer for PPO updates
        self._states: list[torch.Tensor] = []
        self._actions: list[torch.Tensor] = []
        self._log_probs: list[torch.Tensor] = []
        self._rewards: list[float] = []
        self._values: list[torch.Tensor] = []

        # Metrics history
        self._metrics_history: deque[EffectivenessMetrics] = deque(maxlen=100)
        self._current_condition = np.random.randn(condition_dim).astype(np.float32)

        # A/B testing
        self._variants: dict[str, ConfigVariant] = {}
        self._variant_counter = 0

        # State
        self._last_eval_time = 0.0
        self._retrain_requested = False

    def compute_effectiveness(
        self,
        interaction_logs: list[dict[str, Any]],
        attacker_profiles: list[dict[str, Any]],
    ) -> EffectivenessMetrics:
        """Compute current honeypot effectiveness from logs and profiles.

        Args:
            interaction_logs: Raw interaction logs from emulators.
            attacker_profiles: Attacker profile dicts from BehaviorAnalyzer.

        Returns:
            EffectivenessMetrics for the current configuration.
        """
        metrics = EffectivenessMetrics()

        if not interaction_logs:
            return metrics

        # Group logs by session
        sessions: dict[str, list[dict]] = {}
        for log in interaction_logs:
            sid = log.get("session_id", "")
            if sid:
                sessions.setdefault(sid, []).append(log)

        metrics.total_sessions = len(sessions)
        metrics.unique_attackers = len(set(log.get("source_ip", "") for log in interaction_logs))

        if not sessions:
            return metrics

        # Time to discovery: avg time from deploy to first connect
        # (approximated by time between first and second interaction per session)
        discovery_times = []
        interaction_depths = []
        auth_sessions = 0
        lateral_sessions = 0

        for sid, logs in sessions.items():
            interaction_depths.append(len(logs))

            # Check for auth attempts
            if any(l.get("action") == "auth_attempt" for l in logs):
                auth_sessions += 1

            # Check for lateral movement (multiple services in one session)
            services = set(l.get("service", "") for l in logs)
            if len(services) > 1:
                lateral_sessions += 1

        metrics.interaction_depth = float(np.mean(interaction_depths)) if interaction_depths else 0.0
        metrics.credential_testing_rate = auth_sessions / max(metrics.total_sessions, 1)
        metrics.lateral_movement_attempts = lateral_sessions / max(metrics.total_sessions, 1)

        # Composite score: weighted average of normalized metrics
        # Higher interaction depth and credential testing = more effective deception
        depth_score = min(metrics.interaction_depth / 20.0, 1.0)
        cred_score = metrics.credential_testing_rate
        lateral_score = metrics.lateral_movement_attempts
        attacker_score = min(metrics.unique_attackers / 10.0, 1.0)

        metrics.overall_score = (
            0.3 * depth_score
            + 0.3 * cred_score
            + 0.2 * lateral_score
            + 0.2 * attacker_score
        )

        self._metrics_history.append(metrics)
        return metrics

    def should_retrain(self) -> bool:
        """Check if GAN retraining is recommended based on effectiveness trends."""
        if len(self._metrics_history) < 3:
            return False

        recent = list(self._metrics_history)[-5:]
        avg_score = np.mean([m.overall_score for m in recent])

        if avg_score < self.retrain_threshold:
            logger.warning(
                "Effectiveness below threshold, retraining recommended",
                avg_score=f"{avg_score:.3f}",
                threshold=self.retrain_threshold,
            )
            return True
        return False

    def get_condition_update(self, metrics: EffectivenessMetrics) -> np.ndarray:
        """Use the RL policy to suggest a new GAN condition vector.

        Args:
            metrics: Current effectiveness metrics.

        Returns:
            Updated condition vector for the GAN.
        """
        # Build state from metrics
        state = torch.tensor([
            metrics.time_to_discovery / 3600.0,
            metrics.interaction_depth / 50.0,
            metrics.credential_testing_rate,
            metrics.lateral_movement_attempts,
            metrics.unique_attackers / 100.0,
            metrics.total_sessions / 1000.0,
            metrics.overall_score,
            # Trend features from history
            *self._get_trend_features(),
        ], dtype=torch.float32).unsqueeze(0)

        # Get action from policy
        with torch.no_grad():
            action, log_prob, value = self.policy.get_action(state)

        # Store experience
        self._states.append(state)
        self._actions.append(action)
        self._log_probs.append(log_prob)
        self._values.append(value)
        self._rewards.append(metrics.overall_score)

        # Apply action as delta to current condition
        delta = action.squeeze(0).numpy()
        self._current_condition = self._current_condition + 0.1 * delta
        # Clamp to reasonable range
        self._current_condition = np.clip(self._current_condition, -3.0, 3.0)

        logger.info(
            "Condition vector updated",
            effectiveness=f"{metrics.overall_score:.3f}",
            delta_norm=f"{np.linalg.norm(delta):.4f}",
        )

        return self._current_condition.copy()

    def _get_trend_features(self) -> list[float]:
        """Extract trend features from metrics history."""
        history = list(self._metrics_history)
        if len(history) < 2:
            return [0.0] * 9

        recent = history[-5:]
        scores = [m.overall_score for m in recent]
        depths = [m.interaction_depth for m in recent]
        creds = [m.credential_testing_rate for m in recent]

        return [
            float(np.mean(scores)),
            float(np.std(scores)),
            float(scores[-1] - scores[0]) if len(scores) > 1 else 0.0,
            float(np.mean(depths)),
            float(np.std(depths)),
            float(depths[-1] - depths[0]) if len(depths) > 1 else 0.0,
            float(np.mean(creds)),
            float(np.std(creds)),
            float(creds[-1] - creds[0]) if len(creds) > 1 else 0.0,
        ]

    def ppo_update(self, update_epochs: int = 10) -> float:
        """Run PPO policy update using collected experiences.

        Args:
            update_epochs: Number of optimization epochs.

        Returns:
            Average policy loss over update epochs.
        """
        if len(self._rewards) < 2:
            return 0.0

        # Compute returns
        returns = []
        running_return = 0.0
        for r in reversed(self._rewards):
            running_return = r + self.gamma * running_return
            returns.insert(0, running_return)

        returns_t = torch.tensor(returns, dtype=torch.float32)
        returns_t = (returns_t - returns_t.mean()) / (returns_t.std() + 1e-8)

        old_log_probs = torch.stack(self._log_probs)
        old_values = torch.cat(self._values).squeeze()
        states = torch.cat(self._states)
        actions = torch.cat(self._actions)

        advantages = returns_t - old_values.detach()

        total_loss = 0.0
        for _ in range(update_epochs):
            mean, values = self.policy(states)
            std = self.policy.actor_log_std.exp()
            dist = torch.distributions.Normal(mean, std)
            new_log_probs = dist.log_prob(actions).sum(dim=-1)

            # PPO clipped objective
            ratio = (new_log_probs - old_log_probs.detach()).exp()
            surr1 = ratio * advantages
            surr2 = torch.clamp(ratio, 1 - self.epsilon_clip, 1 + self.epsilon_clip) * advantages
            policy_loss = -torch.min(surr1, surr2).mean()

            # Value loss
            value_loss = F.mse_loss(values.squeeze(), returns_t)

            loss = policy_loss + 0.5 * value_loss
            self.optimizer.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(self.policy.parameters(), 0.5)
            self.optimizer.step()

            total_loss += loss.item()

        # Clear experience buffer
        self._states.clear()
        self._actions.clear()
        self._log_probs.clear()
        self._rewards.clear()
        self._values.clear()

        avg_loss = total_loss / update_epochs
        logger.info("PPO update complete", avg_loss=f"{avg_loss:.4f}")
        return avg_loss

    # --- A/B Testing ---

    def create_variant(self, description: str, condition: Optional[np.ndarray] = None) -> str:
        """Create a new A/B test variant.

        Args:
            description: Description of the variant.
            condition: Optional condition vector. If None, generates a random variant.

        Returns:
            Variant ID.
        """
        self._variant_counter += 1
        vid = f"variant-{self._variant_counter}"

        if condition is None:
            condition = np.random.randn(self.condition_dim).astype(np.float32)

        self._variants[vid] = ConfigVariant(
            variant_id=vid,
            description=description,
            condition_vector=condition,
        )

        logger.info("A/B variant created", variant_id=vid, description=description)
        return vid

    def update_variant_metrics(self, variant_id: str, metrics: EffectivenessMetrics) -> None:
        """Update metrics for an A/B test variant."""
        variant = self._variants.get(variant_id)
        if variant:
            variant.metrics = metrics
            variant.sessions += metrics.total_sessions

    def get_best_variant(self) -> Optional[ConfigVariant]:
        """Get the best-performing A/B test variant."""
        best = None
        best_score = -1.0
        for variant in self._variants.values():
            if variant.metrics and variant.metrics.overall_score > best_score:
                best = variant
                best_score = variant.metrics.overall_score
        return best

    def get_current_condition(self) -> np.ndarray:
        """Get the current GAN condition vector."""
        return self._current_condition.copy()

    def get_metrics_history(self) -> list[dict]:
        """Get the metrics history as a list of dicts."""
        return [m.to_dict() for m in self._metrics_history]
