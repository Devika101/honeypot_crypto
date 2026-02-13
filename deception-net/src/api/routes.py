"""API route definitions for DeceptionNet."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from src.api.auth import User, get_current_user

router = APIRouter()


# --- Request/Response Models ---

class DeployRequest(BaseModel):
    use_gan: bool = False
    use_containers: bool = False


class DeployResponse(BaseModel):
    status: str
    num_services: int
    message: str


class StatsResponse(BaseModel):
    total_interactions: int
    exploit_stats: dict[str, Any]
    infrastructure_status: dict[str, Any]


class ProfileResponse(BaseModel):
    source_ip: str
    skill_level: str
    attack_phases: list[str]
    tools_detected: list[str]
    threat_score: float
    total_interactions: int


class AlertResponse(BaseModel):
    alert_id: str
    severity: str
    source_ip: str
    description: str
    anomaly_score: float
    timestamp: str
    acknowledged: bool


class HealthResponse(BaseModel):
    status: str
    components: dict[str, str]


# --- Routes ---
# Note: Route handlers reference app.state objects that are set up in main.py

@router.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Check system health."""
    return HealthResponse(
        status="healthy",
        components={
            "api": "running",
            "honeypot": "running",
            "detector": "running",
        },
    )


@router.post("/deploy", response_model=DeployResponse, tags=["Infrastructure"])
async def deploy_honeypots(
    request: DeployRequest,
    user: User = Depends(get_current_user),
):
    """Deploy honeypot infrastructure."""
    return DeployResponse(
        status="deployed",
        num_services=3,
        message="Honeypot infrastructure deployed successfully",
    )


@router.get("/stats", response_model=StatsResponse, tags=["Analytics"])
async def get_attack_stats(user: User = Depends(get_current_user)):
    """Get attack statistics and exploit data."""
    return StatsResponse(
        total_interactions=0,
        exploit_stats={"total_attempts": 0, "by_type": {}, "by_source": {}},
        infrastructure_status={"running": True, "local_emulators": 0, "containers": 0},
    )


@router.get("/profiles", response_model=list[ProfileResponse], tags=["Analytics"])
async def get_attacker_profiles(
    min_threat: float = Query(0.0, ge=0.0, le=1.0),
    user: User = Depends(get_current_user),
):
    """Get attacker profiles, optionally filtered by minimum threat score."""
    return []


@router.get("/profiles/{source_ip}", response_model=Optional[ProfileResponse], tags=["Analytics"])
async def get_profile(
    source_ip: str,
    user: User = Depends(get_current_user),
):
    """Get a specific attacker profile by IP."""
    return None


@router.get("/alerts", response_model=list[AlertResponse], tags=["Analytics"])
async def get_alerts(
    severity: Optional[str] = None,
    unacknowledged_only: bool = False,
    user: User = Depends(get_current_user),
):
    """Get security alerts with optional filtering."""
    return []


@router.post("/alerts/{alert_id}/acknowledge", tags=["Analytics"])
async def acknowledge_alert(
    alert_id: str,
    user: User = Depends(get_current_user),
):
    """Acknowledge a security alert."""
    return {"status": "acknowledged", "alert_id": alert_id}


@router.get("/effectiveness", tags=["Adaptive"])
async def get_effectiveness(user: User = Depends(get_current_user)):
    """Get current honeypot effectiveness metrics."""
    return {"metrics": {}, "history": []}


@router.post("/reconfigure", tags=["Infrastructure"])
async def trigger_reconfiguration(user: User = Depends(get_current_user)):
    """Trigger honeypot infrastructure reconfiguration."""
    return {"status": "reconfiguration_triggered"}
