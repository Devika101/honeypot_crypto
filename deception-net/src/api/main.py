"""FastAPI application for the DeceptionNet REST API.

Provides:
- REST endpoints for honeypot management
- WebSocket for real-time attack feeds
- JWT authentication
- CORS configuration
- OpenAPI documentation
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any

import uvicorn
import yaml
from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.api import auth
from src.api.auth import (
    Token,
    User,
    authenticate_user,
    create_access_token,
    get_current_user,
)
from src.api.routes import router
from src.utils.logger import configure_logging, get_logger

logger = get_logger(__name__)


# --- Config loading ---

def load_api_config(config_path: str = "config/config.yaml") -> dict[str, Any]:
    """Load API configuration from YAML."""
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
        return config.get("api", {})
    except FileNotFoundError:
        return {}


# --- WebSocket connection manager ---

class ConnectionManager:
    """Manages WebSocket connections for real-time attack feeds."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict) -> None:
        """Send a message to all connected WebSocket clients."""
        dead: list[WebSocket] = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)
        for ws in dead:
            self.active_connections.remove(ws)


ws_manager = ConnectionManager()


# --- App lifecycle ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    api_config = load_api_config()

    # Configure auth from config
    if "jwt_secret_key" in api_config:
        auth.SECRET_KEY = api_config["jwt_secret_key"]
    if "jwt_algorithm" in api_config:
        auth.ALGORITHM = api_config["jwt_algorithm"]
    if "access_token_expire_minutes" in api_config:
        auth.ACCESS_TOKEN_EXPIRE_MINUTES = api_config["access_token_expire_minutes"]

    # Configure logging
    configure_logging(level="INFO", json_format=True)

    logger.info("DeceptionNet API starting", port=api_config.get("port", 8000))
    yield
    logger.info("DeceptionNet API shutting down")


# --- App creation ---

app = FastAPI(
    title="DeceptionNet API",
    description="REST API for the DeceptionNet adaptive honeypot system",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS
api_config = load_api_config()
app.add_middleware(
    CORSMiddleware,
    allow_origins=api_config.get("cors_origins", ["http://localhost:3000"]),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routes
app.include_router(router, prefix="/api/v1")


# --- Auth endpoint ---

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/v1/token", response_model=Token, tags=["Auth"])
async def login(request: LoginRequest):
    """Authenticate and receive a JWT token."""
    user = authenticate_user(request.username, request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return Token(access_token=access_token)


# --- WebSocket endpoint ---

@app.websocket("/ws/attacks")
async def websocket_attack_feed(websocket: WebSocket):
    """Real-time WebSocket feed of attack events.

    Clients connect and receive JSON messages for each interaction log
    as it occurs.
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep the connection alive; actual messages are broadcast
            # from the honeypot infrastructure via ws_manager.broadcast()
            data = await websocket.receive_text()
            # Echo back for keep-alive / ping-pong
            await websocket.send_json({"type": "pong", "data": data})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# --- Entry point ---

def start() -> None:
    """Start the API server."""
    config = load_api_config()
    uvicorn.run(
        "src.api.main:app",
        host=config.get("host", "0.0.0.0"),
        port=config.get("port", 8000),
        reload=False,
    )


if __name__ == "__main__":
    start()
