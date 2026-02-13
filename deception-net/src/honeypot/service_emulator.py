"""Asyncio-based service emulators for honeypot infrastructure.

Each emulator mimics a real service (SSH, HTTP, FTP) at the protocol level,
responds realistically to standard commands, and logs all interaction attempts
for attacker behavior analysis.

All emulators inherit from BaseEmulator and run as asyncio servers.
"""

from __future__ import annotations

import asyncio
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import yaml

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class InteractionLog:
    """A single attacker interaction event."""

    timestamp: str
    source_ip: str
    source_port: int
    service: str
    action: str
    data: dict[str, Any] = field(default_factory=dict)
    session_id: str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "service": self.service,
            "action": self.action,
            "data": self.data,
            "session_id": self.session_id,
        }


class BaseEmulator(ABC):
    """Abstract base class for service emulators.

    All emulators must implement `handle_connection` which is called for each
    new TCP connection. The base class manages the asyncio server lifecycle,
    connection tracking, and interaction logging.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 0,
        service_name: str = "unknown",
        log_callback: Optional[Callable[[InteractionLog], None]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.service_name = service_name
        self.log_callback = log_callback
        self._server: Optional[asyncio.AbstractServer] = None
        self._connections: dict[str, asyncio.Task] = {}
        self._session_counter = 0
        self.interaction_logs: list[InteractionLog] = []

    def _next_session_id(self) -> str:
        self._session_counter += 1
        return f"{self.service_name}-{self._session_counter}"

    def log_interaction(
        self,
        source_ip: str,
        source_port: int,
        action: str,
        data: Optional[dict] = None,
        session_id: str = "",
    ) -> None:
        """Record an interaction event."""
        entry = InteractionLog(
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_ip=source_ip,
            source_port=source_port,
            service=self.service_name,
            action=action,
            data=data or {},
            session_id=session_id,
        )
        self.interaction_logs.append(entry)
        if self.log_callback:
            self.log_callback(entry)

        logger.info(
            "Interaction logged",
            service=self.service_name,
            action=action,
            source=f"{source_ip}:{source_port}",
            session_id=session_id,
        )

    async def start(self) -> None:
        """Start the emulator server."""
        self._server = await asyncio.start_server(
            self._on_connection,
            self.host,
            self.port,
        )
        addr = self._server.sockets[0].getsockname()
        self.port = addr[1]  # Update in case port was 0 (auto-assigned)
        logger.info("Emulator started", service=self.service_name, host=self.host, port=self.port)

    async def stop(self) -> None:
        """Stop the emulator server and close all connections."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()

        for task in self._connections.values():
            task.cancel()
        self._connections.clear()

        logger.info("Emulator stopped", service=self.service_name)

    async def _on_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a new incoming connection."""
        peername = writer.get_extra_info("peername")
        source_ip = peername[0] if peername else "unknown"
        source_port = peername[1] if peername else 0
        session_id = self._next_session_id()

        self.log_interaction(source_ip, source_port, "connect", session_id=session_id)

        try:
            await self.handle_connection(reader, writer, source_ip, source_port, session_id)
        except (asyncio.CancelledError, ConnectionResetError):
            pass
        except Exception as e:
            logger.error("Connection handler error", error=str(e), session_id=session_id)
        finally:
            self.log_interaction(source_ip, source_port, "disconnect", session_id=session_id)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    @abstractmethod
    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        source_ip: str,
        source_port: int,
        session_id: str,
    ) -> None:
        """Handle a client connection. Must be implemented by subclasses."""
        ...


class SSHEmulator(BaseEmulator):
    """SSH honeypot emulator.

    Presents an SSH banner, accepts password authentication attempts (logging
    all credentials), and provides a fake shell that responds to common commands.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 22,
        banner: str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
        fake_credentials: Optional[list[dict[str, str]]] = None,
        command_responses: Optional[dict[str, str]] = None,
        log_callback: Optional[Callable[[InteractionLog], None]] = None,
    ) -> None:
        super().__init__(host, port, "ssh", log_callback)
        self.banner = banner
        self.fake_credentials = fake_credentials or [
            {"username": "admin", "password": "admin123"},
            {"username": "root", "password": "toor"},
        ]
        self.command_responses = command_responses or {
            "whoami": "root",
            "id": "uid=0(root) gid=0(root) groups=0(root)",
            "uname -a": "Linux honeypot 5.15.0-76-generic #83-Ubuntu SMP x86_64 GNU/Linux",
            "ls": "Desktop  Documents  Downloads  .ssh  .bash_history",
            "pwd": "/root",
            "hostname": "web-server-01",
            "ifconfig": "eth0: inet 172.20.1.10  netmask 255.255.255.0  broadcast 172.20.1.255",
            "cat /etc/passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false"
            ),
        }

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        source_ip: str,
        source_port: int,
        session_id: str,
    ) -> None:
        # Send SSH banner
        writer.write(f"{self.banner}\r\n".encode())
        await writer.drain()

        # Read client banner
        try:
            client_banner = await asyncio.wait_for(reader.readline(), timeout=30)
            self.log_interaction(
                source_ip, source_port, "client_banner",
                {"banner": client_banner.decode(errors="replace").strip()},
                session_id,
            )
        except asyncio.TimeoutError:
            return

        # Simulate authentication phase
        writer.write(b"Password: ")
        await writer.drain()

        auth_attempts = 0
        authenticated = False

        while auth_attempts < 6:
            try:
                data = await asyncio.wait_for(reader.readline(), timeout=60)
            except asyncio.TimeoutError:
                return

            if not data:
                return

            password = data.decode(errors="replace").strip()
            auth_attempts += 1

            self.log_interaction(
                source_ip, source_port, "auth_attempt",
                {"attempt": auth_attempts, "password": password},
                session_id,
            )

            # Check against fake credentials
            for cred in self.fake_credentials:
                if password == cred["password"]:
                    authenticated = True
                    break

            if authenticated:
                writer.write(b"\r\nWelcome to Ubuntu 22.04.2 LTS\r\n\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"\r\nPermission denied, please try again.\r\nPassword: ")
                await writer.drain()

        if not authenticated:
            return

        # Fake shell loop
        while True:
            writer.write(b"root@web-server-01:~# ")
            await writer.drain()

            try:
                cmd_data = await asyncio.wait_for(reader.readline(), timeout=300)
            except asyncio.TimeoutError:
                return

            if not cmd_data:
                return

            command = cmd_data.decode(errors="replace").strip()

            self.log_interaction(
                source_ip, source_port, "command",
                {"command": command},
                session_id,
            )

            if command in ("exit", "quit", "logout"):
                writer.write(b"logout\r\n")
                await writer.drain()
                return

            response = self.command_responses.get(command, f"-bash: {command}: command not found")
            writer.write(f"{response}\r\n".encode())
            await writer.drain()


class HTTPEmulator(BaseEmulator):
    """HTTP honeypot emulator.

    Serves fake web pages, logs all requests, and includes configurable
    vulnerable endpoints (SQL injection, directory traversal, XSS).
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 80,
        server_header: str = "Apache/2.4.54 (Ubuntu)",
        log_callback: Optional[Callable[[InteractionLog], None]] = None,
    ) -> None:
        super().__init__(host, port, "http", log_callback)
        self.server_header = server_header
        self._default_page = (
            "<html><head><title>Welcome</title></head>"
            "<body><h1>It works!</h1><p>Apache/2.4.54 (Ubuntu) Server</p></body></html>"
        )
        self._admin_page = (
            "<html><head><title>Login</title></head>"
            "<body><h2>Admin Login</h2>"
            '<form method="POST" action="/login">'
            '<input name="username" placeholder="Username">'
            '<input name="password" type="password" placeholder="Password">'
            "<button>Login</button></form></body></html>"
        )
        self._vuln_endpoints = {"/search", "/login", "/files", "/comment"}

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        source_ip: str,
        source_port: int,
        session_id: str,
    ) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=30)
        except asyncio.TimeoutError:
            return

        if not request_line:
            return

        request_str = request_line.decode(errors="replace").strip()
        parts = request_str.split(" ")
        method = parts[0] if parts else "GET"
        path = parts[1] if len(parts) > 1 else "/"

        # Read headers
        headers: dict[str, str] = {}
        while True:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
            except asyncio.TimeoutError:
                break
            if line in (b"\r\n", b"\n", b""):
                break
            decoded = line.decode(errors="replace").strip()
            if ":" in decoded:
                key, val = decoded.split(":", 1)
                headers[key.strip().lower()] = val.strip()

        self.log_interaction(
            source_ip, source_port, "http_request",
            {"method": method, "path": path, "headers": headers},
            session_id,
        )

        # Check for vulnerability exploitation attempts
        is_vuln_attempt = any(ep in path for ep in self._vuln_endpoints)
        if is_vuln_attempt:
            self.log_interaction(
                source_ip, source_port, "vuln_probe",
                {"path": path, "method": method},
                session_id,
            )

        # Generate response
        if path in ("/admin", "/wp-admin", "/phpmyadmin", "/login"):
            body = self._admin_page
            status = "200 OK"
        elif path == "/" or path == "/index.html":
            body = self._default_page
            status = "200 OK"
        else:
            body = "<html><body><h1>404 Not Found</h1></body></html>"
            status = "404 Not Found"

        response = (
            f"HTTP/1.1 {status}\r\n"
            f"Server: {self.server_header}\r\n"
            f"Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )

        writer.write(response.encode())
        await writer.drain()


class FTPEmulator(BaseEmulator):
    """FTP honeypot emulator.

    Responds to basic FTP commands, supports anonymous login, and presents
    fake directory listings with enticing filenames.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 21,
        banner: str = "220 ProFTPD 1.3.7a Server ready.",
        anonymous_access: bool = True,
        fake_files: Optional[list[dict[str, Any]]] = None,
        log_callback: Optional[Callable[[InteractionLog], None]] = None,
    ) -> None:
        super().__init__(host, port, "ftp", log_callback)
        self.banner = banner
        self.anonymous_access = anonymous_access
        self.fake_files = fake_files or [
            {"name": "backup.sql.gz", "size": 15728640},
            {"name": "config.php.bak", "size": 2048},
            {"name": "credentials.txt", "size": 512},
            {"name": ".htpasswd", "size": 256},
        ]

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        source_ip: str,
        source_port: int,
        session_id: str,
    ) -> None:
        writer.write(f"{self.banner}\r\n".encode())
        await writer.drain()

        authenticated = False
        username = ""

        while True:
            try:
                data = await asyncio.wait_for(reader.readline(), timeout=120)
            except asyncio.TimeoutError:
                return

            if not data:
                return

            line = data.decode(errors="replace").strip()
            if not line:
                continue

            parts = line.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            self.log_interaction(
                source_ip, source_port, "ftp_command",
                {"command": cmd, "argument": arg},
                session_id,
            )

            if cmd == "USER":
                username = arg
                if arg.lower() == "anonymous" and self.anonymous_access:
                    writer.write(b"331 Anonymous login ok, send your email as password.\r\n")
                else:
                    writer.write(b"331 Password required.\r\n")
                await writer.drain()

            elif cmd == "PASS":
                self.log_interaction(
                    source_ip, source_port, "ftp_auth",
                    {"username": username, "password": arg},
                    session_id,
                )
                authenticated = True
                writer.write(b"230 Login successful.\r\n")
                await writer.drain()

            elif cmd == "LIST" or cmd == "NLST":
                if not authenticated:
                    writer.write(b"530 Please login first.\r\n")
                else:
                    listing = "150 Opening data connection.\r\n"
                    for f in self.fake_files:
                        listing += f"-rw-r--r-- 1 root root {f['size']:>10} Jan 15 12:00 {f['name']}\r\n"
                    listing += "226 Transfer complete.\r\n"
                    writer.write(listing.encode())
                await writer.drain()

            elif cmd == "RETR":
                self.log_interaction(
                    source_ip, source_port, "file_download_attempt",
                    {"filename": arg},
                    session_id,
                )
                writer.write(b"550 Permission denied.\r\n")
                await writer.drain()

            elif cmd == "PWD":
                writer.write(b'257 "/" is the current directory.\r\n')
                await writer.drain()

            elif cmd == "SYST":
                writer.write(b"215 UNIX Type: L8\r\n")
                await writer.drain()

            elif cmd == "QUIT":
                writer.write(b"221 Goodbye.\r\n")
                await writer.drain()
                return

            else:
                writer.write(f"502 Command '{cmd}' not implemented.\r\n".encode())
                await writer.drain()


def load_emulators_from_config(
    config_path: str,
    log_callback: Optional[Callable[[InteractionLog], None]] = None,
) -> list[BaseEmulator]:
    """Create emulator instances from a honeypot_templates.yaml config file.

    Args:
        config_path: Path to the YAML config file.
        log_callback: Optional callback for interaction logging.

    Returns:
        List of configured BaseEmulator instances.
    """
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    emulators: list[BaseEmulator] = []
    services = config.get("services", {})

    if "ssh" in services:
        ssh_cfg = services["ssh"]
        emulators.append(SSHEmulator(
            port=ssh_cfg.get("port", 22),
            banner=ssh_cfg.get("banner", "SSH-2.0-OpenSSH_8.9p1"),
            fake_credentials=ssh_cfg.get("auth", {}).get("fake_credentials"),
            log_callback=log_callback,
        ))

    if "http" in services:
        http_cfg = services["http"]
        emulators.append(HTTPEmulator(
            port=http_cfg.get("port", 80),
            server_header=http_cfg.get("server_header", "Apache/2.4.54"),
            log_callback=log_callback,
        ))

    if "ftp" in services:
        ftp_cfg = services["ftp"]
        emulators.append(FTPEmulator(
            port=ftp_cfg.get("port", 21),
            banner=ftp_cfg.get("banner", "220 ProFTPD Server ready."),
            anonymous_access=ftp_cfg.get("anonymous_access", True),
            fake_files=ftp_cfg.get("fake_files"),
            log_callback=log_callback,
        ))

    return emulators
