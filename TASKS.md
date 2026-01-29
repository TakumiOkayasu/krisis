# 🎯 Context

### 📝 背景

- Windowsレジストリの「破損」を検出する仕組みを理解するため、Norton等のクリーナーツールが行う検証を再現
- 1388件といった大量検出の正体を可視化し、実際の影響度を判定したい
- PowerShellではなくPython + winregで詳細分析を実施

### ⚠️ 制約

- Windows環境限定 (winregモジュール使用)
- レジストリ読み取り専用 (削除・修正は一切行わない)
- 管理者権限が必要な場合がある (HKEY_LOCAL_MACHINE アクセス)
- 検出結果はあくまで「参照先が存在しない」だけで、実害の有無は別途判断必要

### ✅ 決定

- Python + winreg で実装
- 5つの主要な破損パターンを検出
- レポート形式で出力 (JSON + テキスト)

---

## 📌 Tasks

### 1. レジストリ破損検出スクリプト作成

**目的**: 5種類の破損パターンを検出し、詳細レポート生成

**実装する検出項目**:

1. **アンインストール情報の不整合**
   - パス: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*`
   - チェック: `UninstallString` のファイル存在確認

2. **スタートアップの無効エントリ**
   - パス:
     - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
     - `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
   - チェック: 実行ファイルパスの存在確認

3. **ファイル関連付けの無効参照**
   - パス: `HKEY_CLASSES_ROOT\*\shell\open\command`
   - チェック: デフォルト値の実行ファイル存在確認

4. **COM/CLSIDの無効DLL参照**
   - パス: `HKEY_CLASSES_ROOT\CLSID\*\InprocServer32`
   - チェック: DLLファイルの存在確認

5. **共有DLLの孤立参照**
   - パス: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs`
   - チェック: DLLファイルの存在確認

**注意点**:

- レジストリアクセスエラー (権限不足) は無視して続行
- パス文字列から実際のファイルパスを抽出 (コマンドライン引数を除去)
- 環境変数 (`%ProgramFiles%`, `%SystemRoot%` 等) を展開
- ネットワークパス (`\\server\share`) は検証スキップ

### 2. レポート生成機能

**目的**: 検出結果を人間が読みやすい形式で出力

**出力形式**:

- **JSON**: `registry_broken_report.json` (機械可読)
- **テキスト**: `registry_broken_report.txt` (人間可読)

**レポート内容**:

```
=== レジストリ破損検出レポート ===
実行日時: 2026-01-29 12:34:56
検出件数: 127件

[1. アンインストール情報の不整合] 45件
- Adobe Reader X
  キー: HKEY_LOCAL_MACHINE\SOFTWARE\...\{GUID}
  UninstallString: C:\Program Files\Adobe\Reader\uninstall.exe
  状態: ファイルが存在しません

[2. スタートアップの無効エントリ] 12件
...

[影響度評価]
- 高: 3件 (システム起動に影響)
- 中: 45件 (アプリ起動時エラーの可能性)
- 低: 79件 (実害なし)
```

**注意点**:

- 検出件数が1000件超の場合、サマリのみ表示 (詳細はJSONへ)
- 影響度は簡易判定 (スタートアップ/システムパス = 高, その他 = 中/低)

### 3. 実行スクリプトとREADME作成

**目的**: ユーザーが簡単に実行できるようにする

**成果物**:

- `check_registry.py` (メインスクリプト)
- `README.md` (使い方説明)

**README内容**:

- 実行方法 (管理者権限での起動方法)
- 出力ファイルの見方
- 免責事項 (「検出 = 削除すべき」ではない)
- Nortonとの比較 (なぜ件数が異なるか)

**注意点**:

- 管理者権限で実行しないとHKEY_LOCAL_MACHINEの一部が読めない旨を明記
- 「このスクリプトはレジストリを変更しません」と明示

---

## 📁 Files

**作成するファイル**:

- `$(pwd)/check_registry.py` (メインスクリプト)
- `$(pwd)/README.md` (説明書)
- `$(pwd)/requirements.txt` (依存関係: なし、標準ライブラリのみ)

**出力ファイル** (実行後に生成):

- `registry_broken_report.json`
- `registry_broken_report.txt`

---

## ✅ Done when

- [ ] 5種類の破損パターン検出が実装されている
- [ ] JSON + テキストでレポート出力される
- [ ] エラーハンドリングが適切 (権限不足/アクセス拒否を無視して続行)
- [ ] 環境変数展開とパス正規化が動作する
- [ ] README.mdに実行方法と注意事項が記載されている
- [ ] コード内に日本語コメントなし (英語コメントのみ)
- [ ] ファイルは `/home/claude/registry_checker/` 配下に配置
