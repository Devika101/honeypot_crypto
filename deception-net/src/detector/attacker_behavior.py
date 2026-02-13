"""Attacker behavior analysis and classification.

Tracks attacker actions across the honeypot infrastructure and classifies
attack patterns using:
- Random Forest for attack type classification
- LSTM for temporal sequence analysis
- Attacker profiling (skill level, tools, objectives)
- Real-time threat scoring
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import numpy as np
import torch
import torch.nn as nn
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from src.utils.logger import get_logger

logger = get_logger(__name__)


class AttackPhase(Enum):
    """Phases of an attack lifecycle."""

    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION = "exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"


class SkillLevel(Enum):
    """Estimated attacker skill level."""

    AUTOMATED = "automated"       # Script kiddie / bot
    NOVICE = "novice"             # Basic manual attacks
    INTERMEDIATE = "intermediate" # Uses multiple techniques
    ADVANCED = "advanced"         # APT-style behavior


@dataclass
class AttackerProfile:
    """Profile of an observed attacker."""

    source_ip: str
    skill_level: SkillLevel = SkillLevel.AUTOMATED
    attack_phases: list[AttackPhase] = field(default_factory=list)
    tools_detected: list[str] = field(default_factory=list)
    total_interactions: int = 0
    services_targeted: set[str] = field(default_factory=set)
    credential_attempts: int = 0
    commands_executed: list[str] = field(default_factory=list)
    threat_score: float = 0.0
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "skill_level": self.skill_level.value,
            "attack_phases": [p.value for p in self.attack_phases],
            "tools_detected": self.tools_detected,
            "total_interactions": self.total_interactions,
            "services_targeted": list(self.services_targeted),
            "credential_attempts": self.credential_attempts,
            "threat_score": self.threat_score,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class TemporalAnalyzer(nn.Module):
    """LSTM-based temporal pattern analyzer for attack sequences.

    Processes sequences of attacker action features to identify
    temporal patterns (e.g., reconnaissance -> exploitation -> lateral movement).

    Args:
        input_dim: Feature dimension per timestep.
        hidden_dim: LSTM hidden state dimension.
        num_layers: Number of LSTM layers.
        num_classes: Number of attack phase classes.
    """

    def __init__(
        self,
        input_dim: int = 16,
        hidden_dim: int = 128,
        num_layers: int = 2,
        num_classes: int = 6,
    ) -> None:
        super().__init__()
        self.lstm = nn.LSTM(
            input_dim,
            hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.2 if num_layers > 1 else 0,
        )
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim // 2, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Classify attack phase from a sequence of action features.

        Args:
            x: (batch, seq_len, input_dim) action feature sequences.

        Returns:
            (batch, num_classes) class logits.
        """
        lstm_out, _ = self.lstm(x)
        # Use the last timestep's output
        last_hidden = lstm_out[:, -1, :]
        return self.classifier(last_hidden)


class BehaviorAnalyzer:
    """Analyzes and classifies attacker behavior from interaction logs.

    Maintains per-IP attacker profiles and uses both Random Forest (for
    individual action classification) and LSTM (for temporal sequences)
    to identify attack patterns.

    Args:
        sequence_length: Number of actions to consider for temporal analysis.
        classification_threshold: Confidence threshold for classification.
    """

    # Feature names for the Random Forest classifier
    FEATURES = [
        "num_auth_attempts",
        "num_commands",
        "num_services",
        "has_recon_commands",
        "has_exploit_attempts",
        "has_lateral_commands",
        "has_exfil_commands",
        "session_duration",
        "unique_ports_probed",
        "credential_diversity",
    ]

    RECON_INDICATORS = {"nmap", "scan", "ls", "dir", "uname", "whoami", "id", "ifconfig", "netstat", "ps"}
    EXPLOIT_INDICATORS = {"wget", "curl", "python", "perl", "bash", "sh", "nc", "netcat"}
    LATERAL_INDICATORS = {"ssh", "scp", "rsync", "mount", "net", "psexec"}
    EXFIL_INDICATORS = {"tar", "zip", "scp", "ftp", "base64", "xxd", "curl"}

    def __init__(
        self,
        sequence_length: int = 50,
        classification_threshold: float = 0.7,
    ) -> None:
        self.sequence_length = sequence_length
        self.classification_threshold = classification_threshold

        # Per-IP profiles
        self._profiles: dict[str, AttackerProfile] = {}
        self._action_sequences: dict[str, list[dict]] = defaultdict(list)

        # Random Forest for action classification
        self._rf_classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
        )
        self._label_encoder = LabelEncoder()
        self._rf_trained = False

        # LSTM for temporal analysis
        self._temporal_analyzer = TemporalAnalyzer()

    def process_interaction(self, log: dict[str, Any]) -> Optional[AttackerProfile]:
        """Process a single interaction log and update attacker profile.

        Args:
            log: Interaction log dictionary with keys:
                 source_ip, service, action, data, timestamp, session_id.

        Returns:
            Updated AttackerProfile for the source IP.
        """
        source_ip = log.get("source_ip", "unknown")
        if source_ip == "unknown":
            return None

        # Get or create profile
        if source_ip not in self._profiles:
            self._profiles[source_ip] = AttackerProfile(
                source_ip=source_ip,
                first_seen=log.get("timestamp", ""),
            )

        profile = self._profiles[source_ip]
        profile.total_interactions += 1
        profile.last_seen = log.get("timestamp", "")
        profile.services_targeted.add(log.get("service", ""))

        # Track specific actions
        action = log.get("action", "")
        data = log.get("data", {})

        if action == "auth_attempt":
            profile.credential_attempts += 1

        if action == "command":
            cmd = data.get("command", "")
            profile.commands_executed.append(cmd)
            self._detect_tools(profile, cmd)

        # Store for sequence analysis
        self._action_sequences[source_ip].append(log)

        # Classify current phase
        self._update_attack_phase(profile)

        # Compute threat score
        profile.threat_score = self._compute_threat_score(profile)

        # Estimate skill level
        profile.skill_level = self._estimate_skill_level(profile)

        return profile

    def _detect_tools(self, profile: AttackerProfile, command: str) -> None:
        """Detect tools/techniques from executed commands."""
        cmd_lower = command.lower()
        tool_indicators = {
            "nmap": "nmap",
            "metasploit": "metasploit",
            "hydra": "hydra",
            "sqlmap": "sqlmap",
            "nikto": "nikto",
            "gobuster": "gobuster",
            "burp": "burpsuite",
            "john": "john_the_ripper",
            "hashcat": "hashcat",
        }
        for indicator, tool_name in tool_indicators.items():
            if indicator in cmd_lower and tool_name not in profile.tools_detected:
                profile.tools_detected.append(tool_name)

    def _update_attack_phase(self, profile: AttackerProfile) -> None:
        """Determine current attack phase based on observed behavior."""
        phases = set(profile.attack_phases)

        # Check for reconnaissance
        recon_cmds = sum(1 for c in profile.commands_executed if any(r in c.lower() for r in self.RECON_INDICATORS))
        if recon_cmds > 0:
            phases.add(AttackPhase.RECONNAISSANCE)

        # Check for exploitation
        exploit_cmds = sum(1 for c in profile.commands_executed if any(e in c.lower() for e in self.EXPLOIT_INDICATORS))
        if exploit_cmds > 0 or profile.credential_attempts > 3:
            phases.add(AttackPhase.EXPLOITATION)

        # Check for lateral movement
        lateral_cmds = sum(1 for c in profile.commands_executed if any(l in c.lower() for l in self.LATERAL_INDICATORS))
        if lateral_cmds > 0 or len(profile.services_targeted) > 2:
            phases.add(AttackPhase.LATERAL_MOVEMENT)

        # Check for exfiltration
        exfil_cmds = sum(1 for c in profile.commands_executed if any(e in c.lower() for e in self.EXFIL_INDICATORS))
        if exfil_cmds > 0:
            phases.add(AttackPhase.DATA_EXFILTRATION)

        profile.attack_phases = sorted(phases, key=lambda p: list(AttackPhase).index(p))

    def _compute_threat_score(self, profile: AttackerProfile) -> float:
        """Compute a threat score from 0.0 to 1.0.

        Based on:
        - Number of attack phases progressed
        - Credential attempts
        - Services targeted
        - Commands executed
        - Tools detected
        """
        score = 0.0

        # Phase progression (max 0.3)
        score += min(len(profile.attack_phases) * 0.05, 0.3)

        # Credential attempts (max 0.2)
        score += min(profile.credential_attempts * 0.02, 0.2)

        # Service breadth (max 0.15)
        score += min(len(profile.services_targeted) * 0.05, 0.15)

        # Command volume (max 0.15)
        score += min(len(profile.commands_executed) * 0.01, 0.15)

        # Tools (max 0.2)
        score += min(len(profile.tools_detected) * 0.05, 0.2)

        return min(score, 1.0)

    def _estimate_skill_level(self, profile: AttackerProfile) -> SkillLevel:
        """Estimate the attacker's skill level."""
        if len(profile.tools_detected) >= 3 and len(profile.attack_phases) >= 3:
            return SkillLevel.ADVANCED
        elif len(profile.tools_detected) >= 1 or len(profile.attack_phases) >= 2:
            return SkillLevel.INTERMEDIATE
        elif profile.credential_attempts > 0 and len(profile.commands_executed) > 5:
            return SkillLevel.NOVICE
        else:
            return SkillLevel.AUTOMATED

    def get_profile(self, source_ip: str) -> Optional[AttackerProfile]:
        """Get the attacker profile for a given IP."""
        return self._profiles.get(source_ip)

    def get_all_profiles(self) -> list[AttackerProfile]:
        """Get all attacker profiles."""
        return list(self._profiles.values())

    def get_high_threat_profiles(self, threshold: float = 0.5) -> list[AttackerProfile]:
        """Get profiles with threat score above the threshold."""
        return [p for p in self._profiles.values() if p.threat_score >= threshold]

    def extract_features(self, source_ip: str) -> Optional[np.ndarray]:
        """Extract feature vector for Random Forest classification.

        Args:
            source_ip: Attacker IP address.

        Returns:
            Feature vector array, or None if no data.
        """
        profile = self._profiles.get(source_ip)
        if not profile:
            return None

        cmds = profile.commands_executed
        cmd_lower = [c.lower() for c in cmds]

        features = np.array([
            profile.credential_attempts,
            len(cmds),
            len(profile.services_targeted),
            sum(1 for c in cmd_lower if any(r in c for r in self.RECON_INDICATORS)),
            sum(1 for c in cmd_lower if any(e in c for e in self.EXPLOIT_INDICATORS)),
            sum(1 for c in cmd_lower if any(l in c for l in self.LATERAL_INDICATORS)),
            sum(1 for c in cmd_lower if any(e in c for e in self.EXFIL_INDICATORS)),
            profile.total_interactions,
            0,  # unique_ports_probed placeholder
            min(profile.credential_attempts, 10) / 10.0,  # credential diversity proxy
        ], dtype=np.float32)

        return features

    def get_summary(self) -> dict[str, Any]:
        """Get summary statistics of all observed attacker behavior."""
        profiles = self.get_all_profiles()
        skill_dist = defaultdict(int)
        phase_dist = defaultdict(int)

        for p in profiles:
            skill_dist[p.skill_level.value] += 1
            for phase in p.attack_phases:
                phase_dist[phase.value] += 1

        return {
            "total_attackers": len(profiles),
            "high_threat_count": len(self.get_high_threat_profiles()),
            "skill_distribution": dict(skill_dist),
            "phase_distribution": dict(phase_dist),
            "avg_threat_score": np.mean([p.threat_score for p in profiles]) if profiles else 0.0,
        }
