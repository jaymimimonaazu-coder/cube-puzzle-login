# KARAKURI / Cube Puzzle Login

立方体の継ぎ目を、登録されたキーを押しながら正しい方向へドラッグして解錠する、複合ジェスチャー認証の UI デモです。

## 操作

- ドラッグで立方体を回転して観察
- 可動部の上でドラッグを開始
- `A` `S` `D` `F` のいずれかを押したまま、登録方向へドラッグ
- 4つの複合ジェスチャーが一致すると認証成功

クリックだけでは機構は動きません。キー、対象部品、ドラッグ方向、入力順の4要素を照合します。

## 起動

ES Modules と Three.js CDN を利用するため、ローカルサーバー経由で開いてください。

```bash
python -m http.server 8000
```

ブラウザで `http://localhost:8000` を開きます。

## 実装上の注意

これは UI / インタラクションの PoC です。実際の認証に使う場合は、ジェスチャー定義をクライアントへ固定値で埋め込まず、サーバー発行の challenge、nonce、レート制限、署名済み応答、別要素認証を組み合わせてください。

## 技術

- Three.js 0.160
- OrbitControls
- RoundedBoxGeometry
- Web Crypto API（成功時の proof 表示用）

## License

MIT
