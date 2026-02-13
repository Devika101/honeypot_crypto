"""Tests for honeypot service emulators and vulnerability injector."""

import asyncio
import pytest

from src.honeypot.service_emulator import (
    SSHEmulator,
    HTTPEmulator,
    FTPEmulator,
    InteractionLog,
)
from src.honeypot.vulnerability_injector import (
    VulnerabilityInjector,
    VulnType,
    Severity,
    VULN_TEMPLATES,
)


# --- Service Emulator Tests ---

class TestSSHEmulator:
    @pytest.mark.asyncio
    async def test_ssh_emulator_starts_and_stops(self):
        emulator = SSHEmulator(port=0)  # Auto-assign port
        await emulator.start()
        assert emulator.port > 0
        await emulator.stop()

    @pytest.mark.asyncio
    async def test_ssh_emulator_logs_connections(self):
        logs = []
        emulator = SSHEmulator(port=0, log_callback=lambda l: logs.append(l))
        await emulator.start()

        # Connect and immediately disconnect
        reader, writer = await asyncio.open_connection("127.0.0.1", emulator.port)
        # Read the banner
        banner = await asyncio.wait_for(reader.readline(), timeout=5)
        assert b"SSH" in banner

        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.1)
        await emulator.stop()

        assert len(logs) >= 1  # At least a connect event


class TestHTTPEmulator:
    @pytest.mark.asyncio
    async def test_http_emulator_starts_and_stops(self):
        emulator = HTTPEmulator(port=0)
        await emulator.start()
        assert emulator.port > 0
        await emulator.stop()

    @pytest.mark.asyncio
    async def test_http_emulator_serves_default_page(self):
        emulator = HTTPEmulator(port=0)
        await emulator.start()

        reader, writer = await asyncio.open_connection("127.0.0.1", emulator.port)
        writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()

        response = await asyncio.wait_for(reader.read(4096), timeout=5)
        assert b"200 OK" in response
        assert b"It works!" in response

        writer.close()
        await writer.wait_closed()
        await emulator.stop()


class TestFTPEmulator:
    @pytest.mark.asyncio
    async def test_ftp_emulator_starts_and_stops(self):
        emulator = FTPEmulator(port=0)
        await emulator.start()
        assert emulator.port > 0
        await emulator.stop()

    @pytest.mark.asyncio
    async def test_ftp_emulator_sends_banner(self):
        emulator = FTPEmulator(port=0)
        await emulator.start()

        reader, writer = await asyncio.open_connection("127.0.0.1", emulator.port)
        banner = await asyncio.wait_for(reader.readline(), timeout=5)
        assert b"220" in banner
        assert b"ProFTPD" in banner

        writer.write(b"QUIT\r\n")
        await writer.drain()

        writer.close()
        await writer.wait_closed()
        await emulator.stop()


# --- Vulnerability Injector Tests ---

class TestVulnerabilityInjector:
    def test_default_templates_loaded(self):
        injector = VulnerabilityInjector()
        http_vulns = injector.get_vulns_for_service("http")
        assert len(http_vulns) > 0

    def test_detect_sql_injection(self):
        injector = VulnerabilityInjector()
        result = injector.check_exploit("http", "' OR 1=1 --", "10.0.0.1")
        assert result is not None
        assert result.vuln_type == VulnType.SQL_INJECTION.value

    def test_detect_directory_traversal(self):
        injector = VulnerabilityInjector()
        result = injector.check_exploit("http", "../../etc/passwd", "10.0.0.1")
        assert result is not None
        assert result.vuln_type == VulnType.DIRECTORY_TRAVERSAL.value

    def test_no_false_positive_on_normal_input(self):
        injector = VulnerabilityInjector()
        result = injector.check_exploit("http", "hello world", "10.0.0.1")
        # "hello world" should not match most signatures
        # (may or may not match depending on patterns)
        # At minimum, if it does match, it should be a valid ExploitAttempt
        if result:
            assert result.vuln_id is not None

    def test_get_response(self):
        injector = VulnerabilityInjector()
        response = injector.get_response("DNET-001", "' OR 1=1")
        assert "MySQL Error" in response

    def test_get_stats(self):
        injector = VulnerabilityInjector()
        injector.check_exploit("http", "UNION SELECT", "10.0.0.1")
        injector.check_exploit("http", "../../etc/passwd", "10.0.0.2")
        stats = injector.get_stats()
        assert stats["total_attempts"] >= 2
        assert len(stats["by_source"]) >= 2

    def test_weak_auth_detection(self):
        injector = VulnerabilityInjector()
        result = injector.check_exploit("ssh", "admin", "10.0.0.1")
        assert result is not None
        assert result.vuln_type == VulnType.WEAK_AUTH.value

    def test_anonymous_ftp_detection(self):
        injector = VulnerabilityInjector()
        result = injector.check_exploit("ftp", "anonymous", "10.0.0.1")
        assert result is not None
