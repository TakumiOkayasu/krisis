"""Tests for Windows Registry Corruption Detector."""

import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# Mock winreg module for non-Windows platforms
class MockWinReg:
    """Mock winreg module for testing on non-Windows platforms."""

    HKEY_LOCAL_MACHINE = 0x80000002
    HKEY_CURRENT_USER = 0x80000001
    HKEY_CLASSES_ROOT = 0x80000000

    KEY_READ = 0x20019
    KEY_WOW64_64KEY = 0x0100
    KEY_WOW64_32KEY = 0x0200

    REG_SZ = 1
    REG_EXPAND_SZ = 2


if sys.platform != "win32":
    sys.modules["winreg"] = MockWinReg()  # type: ignore[assignment]

from krisis.check_registry import (
    BrokenEntry,
    RegistryChecker,
    Severity,
    extract_file_path,
    expand_env_vars,
)


class TestPathExtraction:
    """Tests for file path extraction from registry values."""

    def test_simple_path(self) -> None:
        result = extract_file_path(r"C:\Program Files\App\app.exe")
        assert result == r"C:\Program Files\App\app.exe"

    def test_quoted_path(self) -> None:
        result = extract_file_path(r'"C:\Program Files\App\app.exe"')
        assert result == r"C:\Program Files\App\app.exe"

    def test_path_with_arguments(self) -> None:
        result = extract_file_path(r'"C:\Program Files\App\app.exe" /arg1 /arg2')
        assert result == r"C:\Program Files\App\app.exe"

    def test_unquoted_path_with_arguments(self) -> None:
        result = extract_file_path(r"C:\Windows\System32\cmd.exe /c echo test")
        assert result == r"C:\Windows\System32\cmd.exe"

    def test_msiexec_uninstall(self) -> None:
        result = extract_file_path(
            r"MsiExec.exe /I{12345678-1234-1234-1234-123456789012}"
        )
        assert result == r"MsiExec.exe"

    def test_rundll32(self) -> None:
        result = extract_file_path(r"rundll32.exe shell32.dll,Control_RunDLL")
        assert result == r"rundll32.exe"

    def test_empty_string(self) -> None:
        result = extract_file_path("")
        assert result == ""

    def test_network_path(self) -> None:
        result = extract_file_path(r"\\server\share\app.exe")
        assert result == r"\\server\share\app.exe"


class TestEnvVarExpansion:
    """Tests for environment variable expansion."""

    @patch.dict("os.environ", {"ProgramFiles": r"C:\Program Files"})
    def test_expand_program_files(self) -> None:
        result = expand_env_vars(r"%ProgramFiles%\App\app.exe")
        assert result == r"C:\Program Files\App\app.exe"

    @patch.dict("os.environ", {"SystemRoot": r"C:\Windows"})
    def test_expand_system_root(self) -> None:
        result = expand_env_vars(r"%SystemRoot%\System32\cmd.exe")
        assert result == r"C:\Windows\System32\cmd.exe"

    def test_no_env_vars(self) -> None:
        result = expand_env_vars(r"C:\Windows\System32\cmd.exe")
        assert result == r"C:\Windows\System32\cmd.exe"

    @patch.dict("os.environ", {"HOME": r"C:\Users\test"})
    def test_expand_multiple_vars(self) -> None:
        result = expand_env_vars(r"%HOME%\Desktop")
        assert result == r"C:\Users\test\Desktop"


class TestBrokenEntry:
    """Tests for BrokenEntry dataclass."""

    def test_create_entry(self) -> None:
        entry = BrokenEntry(
            category="uninstall",
            key_path=r"HKEY_LOCAL_MACHINE\SOFTWARE\Test",
            value_name="UninstallString",
            expected_path=r"C:\Test\uninstall.exe",
            severity=Severity.MEDIUM,
            description="App Name",
        )
        assert entry.category == "uninstall"
        assert entry.severity == Severity.MEDIUM

    def test_to_dict(self) -> None:
        entry = BrokenEntry(
            category="startup",
            key_path=r"HKEY_CURRENT_USER\Software\Run",
            value_name="TestApp",
            expected_path=r"C:\TestApp.exe",
            severity=Severity.HIGH,
            description="TestApp",
        )
        d = entry.to_dict()
        assert d["category"] == "startup"
        assert d["severity"] == "HIGH"


class TestRegistryChecker:
    """Tests for RegistryChecker class."""

    def test_is_network_path(self) -> None:
        checker = RegistryChecker()
        assert checker._is_network_path(r"\\server\share\file.exe") is True
        assert checker._is_network_path(r"C:\Windows\file.exe") is False

    def test_check_file_exists_skips_network(self) -> None:
        checker = RegistryChecker()
        # Network paths should return True (skip check)
        assert checker._check_file_exists(r"\\server\share\file.exe") is True

    @patch("os.path.exists")
    def test_check_file_exists_local(self, mock_exists: MagicMock) -> None:
        mock_exists.return_value = True
        checker = RegistryChecker()
        assert checker._check_file_exists(r"C:\Windows\System32\cmd.exe") is True
        mock_exists.assert_called_once()

    def test_severity_classification(self) -> None:
        checker = RegistryChecker()
        assert checker._classify_severity("startup") == Severity.HIGH
        assert checker._classify_severity("uninstall") == Severity.MEDIUM
        assert checker._classify_severity("file_association") == Severity.MEDIUM
        assert checker._classify_severity("com_clsid") == Severity.LOW
        assert checker._classify_severity("shared_dll") == Severity.LOW


class TestReportGeneration:
    """Tests for report generation."""

    def test_json_report_structure(self, tmp_path: Path) -> None:
        checker = RegistryChecker()
        checker.broken_entries = [
            BrokenEntry(
                category="uninstall",
                key_path=r"HKEY_LOCAL_MACHINE\SOFTWARE\Test",
                value_name="UninstallString",
                expected_path=r"C:\Test\uninstall.exe",
                severity=Severity.MEDIUM,
                description="Test App",
            )
        ]

        json_path = tmp_path / "report.json"
        checker.generate_json_report(str(json_path))

        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)

        assert "scan_time" in data
        assert "total_count" in data
        assert data["total_count"] == 1
        assert "entries" in data
        assert len(data["entries"]) == 1

    def test_text_report_structure(self, tmp_path: Path) -> None:
        checker = RegistryChecker()
        checker.broken_entries = [
            BrokenEntry(
                category="startup",
                key_path=r"HKEY_CURRENT_USER\Software\Run",
                value_name="TestApp",
                expected_path=r"C:\TestApp.exe",
                severity=Severity.HIGH,
                description="TestApp",
            )
        ]

        text_path = tmp_path / "report.txt"
        checker.generate_text_report(str(text_path))

        content = text_path.read_text(encoding="utf-8")
        assert "Registry Corruption Detection Report" in content
        assert "startup" in content.lower() or "Startup" in content


class TestSeveritySummary:
    """Tests for severity summary calculation."""

    def test_count_by_severity(self) -> None:
        checker = RegistryChecker()
        checker.broken_entries = [
            BrokenEntry("startup", "k1", "v1", "p1", Severity.HIGH, "d1"),
            BrokenEntry("startup", "k2", "v2", "p2", Severity.HIGH, "d2"),
            BrokenEntry("uninstall", "k3", "v3", "p3", Severity.MEDIUM, "d3"),
            BrokenEntry("shared_dll", "k4", "v4", "p4", Severity.LOW, "d4"),
        ]

        summary = checker.get_severity_summary()
        assert summary[Severity.HIGH] == 2
        assert summary[Severity.MEDIUM] == 1
        assert summary[Severity.LOW] == 1
