# Krisis - Windows Registry Corruption Detector

Detects broken registry entries that may indicate orphaned software references.

## Features

Scans 5 types of registry corruption patterns:

| Pattern           | Registry Path                    | Severity |
| ----------------- | -------------------------------- | -------- |
| Uninstall entries | `HKLM\SOFTWARE\...\Uninstall\*`  | MEDIUM   |
| Startup entries   | `HKCU/HKLM\...\Run`              | HIGH     |
| File associations | `HKCR\*\shell\open\command`      | MEDIUM   |
| COM/CLSID         | `HKCR\CLSID\*\InprocServer32`    | LOW      |
| Shared DLLs       | `HKLM\...\SharedDLLs`            | LOW      |

## Requirements

- Windows 10/11
- Python 3.12+
- Administrator privileges (recommended for full scan)

## Installation

```powershell
git clone <repository>
cd krisis
uv sync
```

## Usage

### Run with administrator privileges (recommended)

```powershell
# PowerShell (Run as Administrator)
uv run check-registry
```

### Run without administrator privileges

```powershell
uv run check-registry
```

Note: Without administrator privileges, some `HKEY_LOCAL_MACHINE` entries cannot be read.

## Output Files

| File                          | Description                  |
| ----------------------------- | ---------------------------- |
| `registry_broken_report.json` | Machine-readable JSON report |
| `registry_broken_report.txt`  | Human-readable text report   |

### JSON Structure

```json
{
  "scan_time": "2026-01-29T12:34:56",
  "total_count": 127,
  "severity_summary": {"HIGH": 3, "MEDIUM": 45, "LOW": 79},
  "entries": [...]
}
```

### Text Report Structure

```text
=== Registry Corruption Detection Report ===
Scan Time: 2026-01-29 12:34:56
Total Issues Found: 127

[Severity Summary]
  HIGH:   3 (may affect system startup)
  MEDIUM: 45 (may cause app errors)
  LOW:    79 (minimal impact)

[Uninstall Information Inconsistencies] 45 issues
  * Adobe Reader X
    Key: HKEY_LOCAL_MACHINE\SOFTWARE\...\{GUID}
    ...
```

## Comparison with Norton/CCleaner

| Aspect                | This Tool           | Norton/CCleaner    |
| --------------------- | ------------------- | ------------------ |
| Detection scope       | 5 specific patterns | Broader heuristics |
| False positives       | Lower               | May be higher      |
| Report detail         | Full path info      | Summary only       |
| Registry modification | Never               | May offer cleanup  |

Detection counts may differ because:

- Different heuristics and patterns checked
- Virtual/runtime paths may be flagged differently
- Some tools count registry keys, others count values

## Manual Cleanup (Optional)

**必ずバックアップを取ってから実行してください。**

### 1. レジストリのバックアップ

```powershell
# 全体バックアップ（推奨）
reg export HKLM backup_hklm.reg
reg export HKCU backup_hkcu.reg
reg export HKCR backup_hkcr.reg

# または特定キーのみ
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" backup_uninstall.reg
```

### 2. 復元ポイントの作成

```powershell
# 管理者権限で実行
Checkpoint-Computer -Description "Before registry cleanup"
```

### 3. 手動削除（regedit）

1. `Win + R` → `regedit` → Enter
2. レポートに記載されたキーパスに移動
3. 右クリック → 削除

### 4. コマンドで削除

```powershell
# 値の削除
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\...\{GUID}" /v UninstallString /f

# キー全体の削除
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\...\{GUID}" /f
```

### 5. 復元方法（通常時）

```powershell
# バックアップから復元
reg import backup_hklm.reg

# または復元ポイントから
rstrui.exe
```

### 6. 起動不能時の復元

#### 回復環境への入り方

1. PC電源ON → 起動ロゴ表示中に電源長押しで強制OFF
2. これを3回繰り返す → 自動修復モードに入る
3. 「詳細オプション」→「トラブルシューティング」→「詳細オプション」

#### 方法A: システムの復元

1. 詳細オプション →「システムの復元」
2. 作成した復元ポイントを選択 → 復元

#### 方法B: コマンドプロンプトから復元

1. 詳細オプション →「コマンドプロンプト」
2. バックアップファイルがあるドライブを特定:

```cmd
diskpart
list volume
exit
```

3. レジストリを復元:

```cmd
# Dドライブにバックアップがある場合
reg load HKLM\TempHive C:\Windows\System32\config\SOFTWARE
reg import D:\backup_hklm.reg
reg unload HKLM\TempHive
```

#### 方法C: RegBackから復元（最終手段）

```cmd
# Windowsが自動作成したバックアップから復元
cd C:\Windows\System32\config
copy RegBack\SOFTWARE SOFTWARE.bak
copy RegBack\SYSTEM SYSTEM.bak
copy SOFTWARE SOFTWARE.broken
copy SYSTEM SYSTEM.broken
copy RegBack\SOFTWARE SOFTWARE
copy RegBack\SYSTEM SYSTEM
```

**注意**: Windows 10 1803以降、RegBackは既定で無効。事前に有効化が必要。

## Disclaimer

**This tool does NOT modify the registry.**

- Detection does NOT mean the entry should be deleted
- Some detected entries may be valid (virtual paths, runtime-generated, etc.)
- Always backup registry before any manual modifications
- Use at your own risk

## License

MIT
