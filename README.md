# Krisis - Windows Registry Corruption Detector

Detects broken registry entries that may indicate orphaned software references.

## Features

Scans 5 types of registry corruption patterns:

| Pattern | Registry Path | Severity |
|---------|--------------|----------|
| Uninstall entries | `HKLM\SOFTWARE\...\Uninstall\*` | MEDIUM |
| Startup entries | `HKCU/HKLM\...\Run` | HIGH |
| File associations | `HKCR\*\shell\open\command` | MEDIUM |
| COM/CLSID | `HKCR\CLSID\*\InprocServer32` | LOW |
| Shared DLLs | `HKLM\...\SharedDLLs` | LOW |

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

| File | Description |
|------|-------------|
| `registry_broken_report.json` | Machine-readable JSON report |
| `registry_broken_report.txt` | Human-readable text report |

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

```
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

| Aspect | This Tool | Norton/CCleaner |
|--------|-----------|-----------------|
| Detection scope | 5 specific patterns | Broader heuristics |
| False positives | Lower | May be higher |
| Report detail | Full path info | Summary only |
| Registry modification | Never | May offer cleanup |

Detection counts may differ because:
- Different heuristics and patterns checked
- Virtual/runtime paths may be flagged differently
- Some tools count registry keys, others count values

## Disclaimer

**This tool does NOT modify the registry.**

- Detection does NOT mean the entry should be deleted
- Some detected entries may be valid (virtual paths, runtime-generated, etc.)
- Always backup registry before any manual modifications
- Use at your own risk

## License

MIT
