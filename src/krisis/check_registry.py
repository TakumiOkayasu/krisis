"""Windows Registry Corruption Detector - Main Module."""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING or sys.platform == "win32":
    try:
        import winreg
    except ImportError:
        winreg = None  # type: ignore[assignment]
else:
    winreg = None


class Severity(Enum):
    """Severity level for broken registry entries."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class BrokenEntry:
    """Represents a broken registry entry."""

    category: str
    key_path: str
    value_name: str
    expected_path: str
    severity: Severity
    description: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "category": self.category,
            "key_path": self.key_path,
            "value_name": self.value_name,
            "expected_path": self.expected_path,
            "severity": self.severity.value,
            "description": self.description,
        }


def extract_file_path(value: str) -> str:
    """Extract file path from a registry value that may contain arguments.

    Handles:
    - Quoted paths: "C:\\Program Files\\app.exe" /args
    - Unquoted paths: C:\\Windows\\System32\\cmd.exe /c command
    - MsiExec commands: MsiExec.exe /I{GUID}
    - rundll32 commands: rundll32.exe shell32.dll,Function
    """
    if not value:
        return ""

    value = value.strip()

    # Handle quoted paths
    if value.startswith('"'):
        match = re.match(r'"([^"]+)"', value)
        if match:
            return match.group(1)

    # Handle unquoted paths - find the executable by extension
    # Match everything up to and including .exe/.dll/.com/.bat/.cmd
    match = re.match(r"(.+?\.(exe|dll|com|bat|cmd))(\s|$)", value, re.IGNORECASE)
    if match:
        return match.group(1)

    # If no extension match, handle network paths
    if value.startswith("\\\\"):
        parts = value.split()
        if parts:
            return parts[0]

    # Default: return first token
    parts = value.split()
    return parts[0] if parts else value


def expand_env_vars(path: str) -> str:
    """Expand Windows environment variables in a path.

    Handles %VAR% style environment variables.
    """
    if not path:
        return path

    # Use os.path.expandvars which handles %VAR% on Windows
    return os.path.expandvars(path)


class RegistryChecker:
    """Main class for checking registry for broken entries."""

    CATEGORY_SEVERITY = {
        "startup": Severity.HIGH,
        "uninstall": Severity.MEDIUM,
        "file_association": Severity.MEDIUM,
        "com_clsid": Severity.LOW,
        "shared_dll": Severity.LOW,
    }

    def __init__(self) -> None:
        """Initialize the registry checker."""
        self.broken_entries: list[BrokenEntry] = []
        self.scan_time: datetime | None = None
        self.errors: list[str] = []

    def _is_network_path(self, path: str) -> bool:
        """Check if the path is a network path (UNC)."""
        return path.startswith("\\\\")

    def _check_file_exists(self, path: str) -> bool:
        """Check if a file exists, skipping network paths."""
        if not path:
            return True

        # Skip network paths
        if self._is_network_path(path):
            return True

        # Expand environment variables
        expanded = expand_env_vars(path)

        # Check if file exists
        return os.path.exists(expanded)

    def _classify_severity(self, category: str) -> Severity:
        """Classify the severity of a broken entry based on its category."""
        return self.CATEGORY_SEVERITY.get(category, Severity.LOW)

    def _safe_open_key(
        self, hkey: int, subkey: str, access: int = 0
    ) -> "winreg.HKEYType | None":
        """Safely open a registry key, returning None on error."""
        if winreg is None:
            return None

        if access == 0:
            access = winreg.KEY_READ

        try:
            return winreg.OpenKey(hkey, subkey, 0, access)
        except (OSError, PermissionError):
            return None

    def _enum_subkeys(self, key: "winreg.HKEYType") -> list[str]:
        """Enumerate all subkeys of a registry key."""
        if winreg is None:
            return []

        subkeys = []
        i = 0
        while True:
            try:
                subkeys.append(winreg.EnumKey(key, i))
                i += 1
            except OSError:
                break
        return subkeys

    def _get_value(
        self, key: "winreg.HKEYType", name: str | None = None
    ) -> tuple[str, int] | None:
        """Get a registry value, returning None on error."""
        if winreg is None:
            return None

        try:
            value, reg_type = winreg.QueryValueEx(key, name or "")
            return (str(value), reg_type)
        except OSError:
            return None

    def check_uninstall_entries(self) -> None:
        """Check uninstall entries for broken file references.

        Path: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*
        """
        if winreg is None:
            return

        base_paths = [
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
            (
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
        ]

        for hkey, base_path in base_paths:
            for access in [
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
                winreg.KEY_READ | winreg.KEY_WOW64_32KEY,
            ]:
                key = self._safe_open_key(hkey, base_path, access)
                if key is None:
                    continue

                try:
                    for subkey_name in self._enum_subkeys(key):
                        subkey = self._safe_open_key(
                            hkey, f"{base_path}\\{subkey_name}", access
                        )
                        if subkey is None:
                            continue

                        try:
                            # Get display name
                            display_result = self._get_value(subkey, "DisplayName")
                            display_name = (
                                display_result[0] if display_result else subkey_name
                            )

                            # Check UninstallString
                            uninstall_result = self._get_value(subkey, "UninstallString")
                            if uninstall_result:
                                uninstall_str = uninstall_result[0]
                                file_path = extract_file_path(uninstall_str)

                                if file_path and not self._check_file_exists(file_path):
                                    hkey_name = (
                                        "HKEY_LOCAL_MACHINE"
                                        if hkey == winreg.HKEY_LOCAL_MACHINE
                                        else "HKEY_CURRENT_USER"
                                    )
                                    self.broken_entries.append(
                                        BrokenEntry(
                                            category="uninstall",
                                            key_path=f"{hkey_name}\\{base_path}\\{subkey_name}",
                                            value_name="UninstallString",
                                            expected_path=file_path,
                                            severity=Severity.MEDIUM,
                                            description=display_name,
                                        )
                                    )
                        finally:
                            winreg.CloseKey(subkey)
                finally:
                    winreg.CloseKey(key)

    def check_startup_entries(self) -> None:
        """Check startup entries for broken file references.

        Paths:
        - HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
        - HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
        """
        if winreg is None:
            return

        paths = [
            (
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                "HKEY_CURRENT_USER",
            ),
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKEY_LOCAL_MACHINE",
            ),
        ]

        for hkey, path, hkey_name in paths:
            key = self._safe_open_key(hkey, path)
            if key is None:
                continue

            try:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        file_path = extract_file_path(str(value))

                        if file_path and not self._check_file_exists(file_path):
                            self.broken_entries.append(
                                BrokenEntry(
                                    category="startup",
                                    key_path=f"{hkey_name}\\{path}",
                                    value_name=name,
                                    expected_path=file_path,
                                    severity=Severity.HIGH,
                                    description=name,
                                )
                            )
                        i += 1
                    except OSError:
                        break
            finally:
                winreg.CloseKey(key)

    def check_file_associations(self) -> None:
        """Check file associations for broken executable references.

        Path: HKEY_CLASSES_ROOT\\*\\shell\\open\\command
        """
        if winreg is None:
            return

        key = self._safe_open_key(winreg.HKEY_CLASSES_ROOT, "")
        if key is None:
            return

        try:
            for ext_name in self._enum_subkeys(key):
                # Only check file extensions (starting with .)
                if not ext_name.startswith("."):
                    continue

                command_path = f"{ext_name}\\shell\\open\\command"
                cmd_key = self._safe_open_key(winreg.HKEY_CLASSES_ROOT, command_path)
                if cmd_key is None:
                    continue

                try:
                    result = self._get_value(cmd_key)
                    if result:
                        command = result[0]
                        file_path = extract_file_path(command)

                        if file_path and not self._check_file_exists(file_path):
                            self.broken_entries.append(
                                BrokenEntry(
                                    category="file_association",
                                    key_path=f"HKEY_CLASSES_ROOT\\{command_path}",
                                    value_name="(Default)",
                                    expected_path=file_path,
                                    severity=Severity.MEDIUM,
                                    description=f"File association for {ext_name}",
                                )
                            )
                finally:
                    winreg.CloseKey(cmd_key)
        finally:
            winreg.CloseKey(key)

    def check_com_clsid(self) -> None:
        """Check COM/CLSID entries for broken DLL references.

        Path: HKEY_CLASSES_ROOT\\CLSID\\*\\InprocServer32
        """
        if winreg is None:
            return

        clsid_key = self._safe_open_key(winreg.HKEY_CLASSES_ROOT, "CLSID")
        if clsid_key is None:
            return

        try:
            for clsid in self._enum_subkeys(clsid_key):
                inproc_path = f"CLSID\\{clsid}\\InprocServer32"
                inproc_key = self._safe_open_key(
                    winreg.HKEY_CLASSES_ROOT, inproc_path
                )
                if inproc_key is None:
                    continue

                try:
                    result = self._get_value(inproc_key)
                    if result:
                        dll_path = result[0]
                        # Clean up the path
                        dll_path = extract_file_path(dll_path)

                        if dll_path and not self._check_file_exists(dll_path):
                            self.broken_entries.append(
                                BrokenEntry(
                                    category="com_clsid",
                                    key_path=f"HKEY_CLASSES_ROOT\\{inproc_path}",
                                    value_name="(Default)",
                                    expected_path=dll_path,
                                    severity=Severity.LOW,
                                    description=f"COM object {clsid}",
                                )
                            )
                finally:
                    winreg.CloseKey(inproc_key)
        finally:
            winreg.CloseKey(clsid_key)

    def check_shared_dlls(self) -> None:
        """Check shared DLLs for orphaned references.

        Path: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SharedDLLs
        """
        if winreg is None:
            return

        path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs"
        key = self._safe_open_key(winreg.HKEY_LOCAL_MACHINE, path)
        if key is None:
            return

        try:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    # name is the DLL path, value is the reference count
                    if not self._check_file_exists(name):
                        self.broken_entries.append(
                            BrokenEntry(
                                category="shared_dll",
                                key_path=f"HKEY_LOCAL_MACHINE\\{path}",
                                value_name=name,
                                expected_path=name,
                                severity=Severity.LOW,
                                description=f"Shared DLL (ref count: {value})",
                            )
                        )
                    i += 1
                except OSError:
                    break
        finally:
            winreg.CloseKey(key)

    def run_all_checks(self) -> None:
        """Run all registry checks."""
        self.scan_time = datetime.now()
        self.broken_entries.clear()

        self.check_uninstall_entries()
        self.check_startup_entries()
        self.check_file_associations()
        self.check_com_clsid()
        self.check_shared_dlls()

    def get_severity_summary(self) -> dict[Severity, int]:
        """Get a summary of entries by severity level."""
        summary: dict[Severity, int] = {
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
        }

        for entry in self.broken_entries:
            summary[entry.severity] += 1

        return summary

    def generate_json_report(self, output_path: str) -> None:
        """Generate a JSON report of broken entries."""
        report = {
            "scan_time": (
                self.scan_time.isoformat() if self.scan_time else datetime.now().isoformat()
            ),
            "total_count": len(self.broken_entries),
            "severity_summary": {
                k.value: v for k, v in self.get_severity_summary().items()
            },
            "entries": [entry.to_dict() for entry in self.broken_entries],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

    def generate_text_report(self, output_path: str) -> None:
        """Generate a human-readable text report."""
        lines = []
        lines.append("=" * 60)
        lines.append("  Registry Corruption Detection Report")
        lines.append("=" * 60)
        lines.append("")

        scan_time = self.scan_time or datetime.now()
        lines.append(f"Scan Time: {scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total Issues Found: {len(self.broken_entries)}")
        lines.append("")

        # Severity summary
        summary = self.get_severity_summary()
        lines.append("[Severity Summary]")
        lines.append(f"  HIGH:   {summary[Severity.HIGH]} (may affect system startup)")
        lines.append(f"  MEDIUM: {summary[Severity.MEDIUM]} (may cause app errors)")
        lines.append(f"  LOW:    {summary[Severity.LOW]} (minimal impact)")
        lines.append("")

        # Group by category
        categories = {
            "uninstall": "Uninstall Information Inconsistencies",
            "startup": "Invalid Startup Entries",
            "file_association": "Invalid File Associations",
            "com_clsid": "Invalid COM/CLSID References",
            "shared_dll": "Orphaned Shared DLL References",
        }

        for cat_key, cat_name in categories.items():
            cat_entries = [e for e in self.broken_entries if e.category == cat_key]
            if not cat_entries:
                continue

            lines.append("-" * 60)
            lines.append(f"[{cat_name}] {len(cat_entries)} issues")
            lines.append("-" * 60)

            # Limit detailed output if too many entries
            display_entries = cat_entries[:50] if len(cat_entries) > 50 else cat_entries

            for entry in display_entries:
                lines.append(f"  * {entry.description}")
                lines.append(f"    Key: {entry.key_path}")
                lines.append(f"    Value: {entry.value_name}")
                lines.append(f"    Expected: {entry.expected_path}")
                lines.append(f"    Severity: {entry.severity.value}")
                lines.append("")

            if len(cat_entries) > 50:
                lines.append(f"  ... and {len(cat_entries) - 50} more entries")
                lines.append("  (See JSON report for full details)")
                lines.append("")

        lines.append("=" * 60)
        lines.append("  DISCLAIMER")
        lines.append("=" * 60)
        lines.append("This report shows registry entries pointing to non-existent files.")
        lines.append("Detection does NOT mean these entries should be deleted.")
        lines.append("Some entries may be valid (virtual paths, runtime-generated, etc.).")
        lines.append("This tool does NOT modify the registry in any way.")
        lines.append("")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))


def main() -> None:
    """Entry point for the registry checker."""
    if sys.platform != "win32":
        print("Error: This tool only runs on Windows.")
        sys.exit(1)

    print("Windows Registry Corruption Detector")
    print("=" * 40)
    print()

    checker = RegistryChecker()
    print("Running checks...")

    checker.run_all_checks()

    print(f"Found {len(checker.broken_entries)} issues.")
    print()

    # Generate reports
    json_path = "registry_broken_report.json"
    text_path = "registry_broken_report.txt"

    checker.generate_json_report(json_path)
    checker.generate_text_report(text_path)

    print(f"Reports generated:")
    print(f"  - {json_path}")
    print(f"  - {text_path}")

    # Show summary
    summary = checker.get_severity_summary()
    print()
    print("Severity Summary:")
    print(f"  HIGH:   {summary[Severity.HIGH]}")
    print(f"  MEDIUM: {summary[Severity.MEDIUM]}")
    print(f"  LOW:    {summary[Severity.LOW]}")


if __name__ == "__main__":
    main()
