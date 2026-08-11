# Security Policy

## 想定する利用範囲 / Supported Use

このリポジトリは **学習・研究・体験型コンテンツ向けのデモ**です。
本番の認証システムとしてのサポートは行いません。

This repository is an educational and interactive demonstration.
It is **not** supported as a production authentication system.

---

## 適用してはいけない用途 / Limitations

以下の用途には使用しないでください。

- WebAuthn / パスキーの代替
- フィッシング耐性が必要な認証
- 暗号鍵の導出
- ウォレットのシード生成・復旧
- 金融取引の認可
- 医療上の判断

### 特に重要な制限

**利用者が自分で選んだ配置は、41.44 bit のエントロピーを提供しません。**

41.44 bit は「各面の組を暗号学的乱数で独立かつ一様に選んだ場合」の理論値です。
人間が選択した場合の実効エントロピーはこれより大幅に低くなります。
単一の完成したパスコードから実効エントロピーを推定することはできません
（この点は開発中のレビューで指摘され、bit 値を表示する機能は削除しました）。

**フィッシング耐性はありません。** 偽サイトに配置を入力すれば、そのまま盗まれます。
WebAuthn/パスキーが持つオリジン束縛のような保護は実装されていません。

---

## 既知の弱点

| 項目 | 内容 |
|---|---|
| 観察攻撃 | 12箇所のタップ動作は観察・録画されやすい |
| スマッジ攻撃 | タッチ画面の指紋跡から選択位置が推測されうる |
| 記憶保持 | 12箇所を長期間再現できるかは未測定。方式による差が大きいことが知られている |
| 色覚 | 面の識別を色に依存しており、色覚特性への配慮が未実装 |

グラフィカルパスワード一般に関する研究上の課題は
[`VERIFICATION.md`](VERIFICATION.md) に整理しています。

---

## 脆弱性の報告 / Reporting a Vulnerability

**公開 Issue に悪用可能な詳細を記載しないでください。**

GitHub の **Private Vulnerability Reporting**（Security タブ →
"Report a vulnerability"）からご報告ください。

Please report via GitHub's **Private Vulnerability Reporting**
(Security tab → "Report a vulnerability").
Do not post exploitable details in public issues.

### 報告いただきたい内容

- 影響を受けるファイル・エンドポイント
- 再現手順
- 想定される影響

このプロジェクトは本番運用を想定していないため、
修正の対応時期や恒久的な保守は保証できません。

---

## これまでのレビュー状況

Claude と Codex による **AI支援コードレビュー**を2系統実施し、
指摘された13項目について修正と回帰テスト（pytest 50件）を行っています。
詳細は [`AUDIT_FINDINGS.md`](AUDIT_FINDINGS.md) を参照してください。

**これは専門事業者による第三者セキュリティ監査や侵入テストではなく、
本番利用の安全性を保証するものではありません。**
