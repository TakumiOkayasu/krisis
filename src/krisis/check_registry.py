"""Windowsレジストリ破損検出ツール - メインモジュール."""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import winreg

if sys.platform == "win32":
    try:
        import winreg as _winreg
    except ImportError:
        _winreg = None
else:
    _winreg = None


class Severity(Enum):
    """破損エントリの重大度レベル."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class BrokenEntry:
    """破損したレジストリエントリを表すデータクラス."""

    category: str
    key_path: str
    value_name: str
    expected_path: str
    severity: Severity
    description: str = ""

    def to_dict(self) -> dict:
        """JSON出力用の辞書に変換."""
        return {
            "category": self.category,
            "key_path": self.key_path,
            "value_name": self.value_name,
            "expected_path": self.expected_path,
            "severity": self.severity.value,
            "description": self.description,
        }


def extract_file_path(value: str) -> str:
    """レジストリ値からファイルパスを抽出.

    対応形式:
    - 引用符付きパス: "C:\\Program Files\\app.exe" /args
    - 引用符なしパス: C:\\Windows\\System32\\cmd.exe /c command
    - MsiExecコマンド: MsiExec.exe /I{GUID}
    - rundll32コマンド: rundll32.exe shell32.dll,Function
    """
    if not value:
        return ""

    value = value.strip()

    # 引用符付きパスの処理
    if value.startswith('"'):
        match = re.match(r'"([^"]+)"', value)
        if match:
            return match.group(1)

    # 引用符なしパス - 拡張子で実行ファイルを特定
    match = re.match(r"(.+?\.(exe|dll|com|bat|cmd))(\s|$)", value, re.IGNORECASE)
    if match:
        return match.group(1)

    # ネットワークパスの処理
    if value.startswith("\\\\"):
        parts = value.split()
        if parts:
            return parts[0]

    # デフォルト: 最初のトークンを返す
    parts = value.split()
    return parts[0] if parts else value


def expand_env_vars(path: str) -> str:
    """パス内の環境変数を展開.

    %VAR% 形式の環境変数に対応.
    """
    if not path:
        return path

    return os.path.expandvars(path)


class RegistryChecker:
    """レジストリの破損エントリをチェックするメインクラス."""

    CATEGORY_SEVERITY = {
        "startup": Severity.HIGH,
        "uninstall": Severity.MEDIUM,
        "file_association": Severity.MEDIUM,
        "com_clsid": Severity.LOW,
        "shared_dll": Severity.LOW,
    }

    def __init__(self) -> None:
        """初期化."""
        self.broken_entries: list[BrokenEntry] = []
        self.scan_time: datetime | None = None
        self.errors: list[str] = []

    def _is_network_path(self, path: str) -> bool:
        """UNCネットワークパスかどうかを判定."""
        return path.startswith("\\\\")

    def _check_file_exists(self, path: str) -> bool:
        """ファイルの存在確認（ネットワークパスはスキップ）."""
        if not path:
            return True

        if self._is_network_path(path):
            return True

        expanded = expand_env_vars(path)
        return os.path.exists(expanded)

    def _classify_severity(self, category: str) -> Severity:
        """カテゴリに基づいて重大度を分類."""
        return self.CATEGORY_SEVERITY.get(category, Severity.LOW)

    def _safe_open_key(
        self, hkey: int, subkey: str, access: int = 0
    ) -> "winreg.HKEYType | None":
        """レジストリキーを安全にオープン（エラー時はNone）."""
        if _winreg is None:
            return None

        if access == 0:
            access = _winreg.KEY_READ

        try:
            return _winreg.OpenKey(hkey, subkey, 0, access)
        except (OSError, PermissionError):
            return None

    def _enum_subkeys(self, key: "winreg.HKEYType") -> list[str]:
        """レジストリキーのサブキーを列挙."""
        if _winreg is None:
            return []

        subkeys = []
        i = 0
        while True:
            try:
                subkeys.append(_winreg.EnumKey(key, i))
                i += 1
            except OSError:
                break
        return subkeys

    def _get_value(
        self, key: "winreg.HKEYType", name: str | None = None
    ) -> tuple[str, int] | None:
        """レジストリ値を取得（エラー時はNone）."""
        if _winreg is None:
            return None

        try:
            value, reg_type = _winreg.QueryValueEx(key, name or "")
            return (str(value), reg_type)
        except OSError:
            return None

    def check_uninstall_entries(self) -> None:
        """アンインストール情報の破損をチェック.

        対象: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*
        """
        if _winreg is None:
            return

        base_paths = [
            (
                _winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
            (
                _winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
        ]

        for hkey, base_path in base_paths:
            for access in [
                _winreg.KEY_READ | _winreg.KEY_WOW64_64KEY,
                _winreg.KEY_READ | _winreg.KEY_WOW64_32KEY,
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
                            display_result = self._get_value(subkey, "DisplayName")
                            display_name = (
                                display_result[0] if display_result else subkey_name
                            )

                            uninstall_result = self._get_value(subkey, "UninstallString")
                            if uninstall_result:
                                uninstall_str = uninstall_result[0]
                                file_path = extract_file_path(uninstall_str)

                                if file_path and not self._check_file_exists(file_path):
                                    hkey_name = (
                                        "HKEY_LOCAL_MACHINE"
                                        if hkey == _winreg.HKEY_LOCAL_MACHINE
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
                            _winreg.CloseKey(subkey)
                finally:
                    _winreg.CloseKey(key)

    def check_startup_entries(self) -> None:
        """スタートアップエントリの破損をチェック.

        対象:
        - HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
        - HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
        """
        if _winreg is None:
            return

        paths = [
            (
                _winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                "HKEY_CURRENT_USER",
            ),
            (
                _winreg.HKEY_LOCAL_MACHINE,
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
                        name, value, _ = _winreg.EnumValue(key, i)
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
                _winreg.CloseKey(key)

    def check_file_associations(self) -> None:
        """ファイル関連付けの破損をチェック.

        対象: HKEY_CLASSES_ROOT\\*\\shell\\open\\command
        """
        if _winreg is None:
            return

        key = self._safe_open_key(_winreg.HKEY_CLASSES_ROOT, "")
        if key is None:
            return

        try:
            for ext_name in self._enum_subkeys(key):
                # ファイル拡張子のみチェック（.で始まるもの）
                if not ext_name.startswith("."):
                    continue

                command_path = f"{ext_name}\\shell\\open\\command"
                cmd_key = self._safe_open_key(_winreg.HKEY_CLASSES_ROOT, command_path)
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
                                    description=f"{ext_name} のファイル関連付け",
                                )
                            )
                finally:
                    _winreg.CloseKey(cmd_key)
        finally:
            _winreg.CloseKey(key)

    def check_com_clsid(self) -> None:
        """COM/CLSIDエントリの破損をチェック.

        対象: HKEY_CLASSES_ROOT\\CLSID\\*\\InprocServer32
        """
        if _winreg is None:
            return

        clsid_key = self._safe_open_key(_winreg.HKEY_CLASSES_ROOT, "CLSID")
        if clsid_key is None:
            return

        try:
            for clsid in self._enum_subkeys(clsid_key):
                inproc_path = f"CLSID\\{clsid}\\InprocServer32"
                inproc_key = self._safe_open_key(_winreg.HKEY_CLASSES_ROOT, inproc_path)
                if inproc_key is None:
                    continue

                try:
                    result = self._get_value(inproc_key)
                    if result:
                        dll_path = result[0]
                        dll_path = extract_file_path(dll_path)

                        if dll_path and not self._check_file_exists(dll_path):
                            self.broken_entries.append(
                                BrokenEntry(
                                    category="com_clsid",
                                    key_path=f"HKEY_CLASSES_ROOT\\{inproc_path}",
                                    value_name="(Default)",
                                    expected_path=dll_path,
                                    severity=Severity.LOW,
                                    description=f"COMオブジェクト {clsid}",
                                )
                            )
                finally:
                    _winreg.CloseKey(inproc_key)
        finally:
            _winreg.CloseKey(clsid_key)

    def check_shared_dlls(self) -> None:
        """共有DLLの孤立参照をチェック.

        対象: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SharedDLLs
        """
        if _winreg is None:
            return

        path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs"
        key = self._safe_open_key(_winreg.HKEY_LOCAL_MACHINE, path)
        if key is None:
            return

        try:
            i = 0
            while True:
                try:
                    name, value, _ = _winreg.EnumValue(key, i)
                    # nameがDLLパス、valueが参照カウント
                    if not self._check_file_exists(name):
                        self.broken_entries.append(
                            BrokenEntry(
                                category="shared_dll",
                                key_path=f"HKEY_LOCAL_MACHINE\\{path}",
                                value_name=name,
                                expected_path=name,
                                severity=Severity.LOW,
                                description=f"共有DLL (参照数: {value})",
                            )
                        )
                    i += 1
                except OSError:
                    break
        finally:
            _winreg.CloseKey(key)

    def run_all_checks(self) -> None:
        """全てのチェックを実行."""
        self.scan_time = datetime.now()
        self.broken_entries.clear()

        self.check_uninstall_entries()
        self.check_startup_entries()
        self.check_file_associations()
        self.check_com_clsid()
        self.check_shared_dlls()

    def get_severity_summary(self) -> dict[Severity, int]:
        """重大度別のサマリーを取得."""
        summary: dict[Severity, int] = {
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
        }

        for entry in self.broken_entries:
            summary[entry.severity] += 1

        return summary

    def generate_json_report(self, output_path: str) -> None:
        """JSON形式のレポートを生成."""
        report = {
            "scan_time": (
                self.scan_time.isoformat() if self.scan_time else datetime.now().isoformat()
            ),
            "total_count": len(self.broken_entries),
            "severity_summary": {k.value: v for k, v in self.get_severity_summary().items()},
            "entries": [entry.to_dict() for entry in self.broken_entries],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

    def generate_text_report(self, output_path: str) -> None:
        """テキスト形式のレポートを生成."""
        lines = []
        lines.append("=" * 60)
        lines.append("  レジストリ破損検出レポート")
        lines.append("=" * 60)
        lines.append("")

        scan_time = self.scan_time or datetime.now()
        lines.append(f"スキャン日時: {scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"検出された問題: {len(self.broken_entries)} 件")
        lines.append("")

        summary = self.get_severity_summary()
        lines.append("[重大度サマリー]")
        lines.append(f"  HIGH:   {summary[Severity.HIGH]} 件 (システム起動に影響の可能性)")
        lines.append(f"  MEDIUM: {summary[Severity.MEDIUM]} 件 (アプリエラーの可能性)")
        lines.append(f"  LOW:    {summary[Severity.LOW]} 件 (影響は軽微)")
        lines.append("")

        categories = {
            "uninstall": "アンインストール情報の不整合",
            "startup": "無効なスタートアップエントリ",
            "file_association": "無効なファイル関連付け",
            "com_clsid": "無効なCOM/CLSID参照",
            "shared_dll": "孤立した共有DLL参照",
        }

        for cat_key, cat_name in categories.items():
            cat_entries = [e for e in self.broken_entries if e.category == cat_key]
            if not cat_entries:
                continue

            lines.append("-" * 60)
            lines.append(f"[{cat_name}] {len(cat_entries)} 件")
            lines.append("-" * 60)

            display_entries = cat_entries[:50] if len(cat_entries) > 50 else cat_entries

            for entry in display_entries:
                lines.append(f"  * {entry.description}")
                lines.append(f"    キー: {entry.key_path}")
                lines.append(f"    値: {entry.value_name}")
                lines.append(f"    期待パス: {entry.expected_path}")
                lines.append(f"    重大度: {entry.severity.value}")
                lines.append("")

            if len(cat_entries) > 50:
                lines.append(f"  ... 他 {len(cat_entries) - 50} 件")
                lines.append("  (詳細はJSONレポートを参照)")
                lines.append("")

        lines.append("=" * 60)
        lines.append("  注意事項")
        lines.append("=" * 60)
        lines.append(
            "このレポートは存在しないファイルを参照するレジストリエントリを表示しています。"
        )
        lines.append("検出されたエントリを削除すべきかどうかは慎重に判断してください。")
        lines.append("一部のエントリは有効な場合があります（仮想パス、実行時生成など）。")
        lines.append("このツールはレジストリを一切変更しません。")
        lines.append("")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))


def main() -> None:
    """エントリポイント."""
    if sys.platform != "win32":
        print("エラー: このツールはWindows専用です。")
        sys.exit(1)

    print("Windowsレジストリ破損検出ツール")
    print("=" * 40)
    print()

    checker = RegistryChecker()
    print("チェック実行中...")

    checker.run_all_checks()

    print(f"検出された問題: {len(checker.broken_entries)} 件")
    print()

    report_dir = "report"
    os.makedirs(report_dir, exist_ok=True)

    json_path = os.path.join(report_dir, "registry_broken_report.json")
    text_path = os.path.join(report_dir, "registry_broken_report.txt")

    checker.generate_json_report(json_path)
    checker.generate_text_report(text_path)

    print("レポート出力:")
    print(f"  - {json_path}")
    print(f"  - {text_path}")

    summary = checker.get_severity_summary()
    print()
    print("重大度サマリー:")
    print(f"  HIGH:   {summary[Severity.HIGH]} 件")
    print(f"  MEDIUM: {summary[Severity.MEDIUM]} 件")
    print(f"  LOW:    {summary[Severity.LOW]} 件")


if __name__ == "__main__":
    main()
