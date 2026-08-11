# Third-Party Notices

本リポジトリには、以下の第三者ソフトウェアが含まれる、または参照されています。

---

## Three.js

- **バージョン**: 0.160.0
- **ライセンス**: MIT License
- **配布元**: https://github.com/mrdoob/three.js

### 利用箇所

| ファイル | 形態 |
|---|---|
| `index.html` | CDN から読み込み（配布物に含まれない） |
| `neon/index.html` | CDN から読み込み（配布物に含まれない） |
| `server/static/index.html` | CDN から読み込み（配布物に含まれない） |
| **`preview.html`** | **バンドルして内蔵（配布物に含まれる）** |

`preview.html` は外部通信なしで動作させるため、Three.js 0.160.0 とそのアドオン
（`OrbitControls`, `EffectComposer`, `RenderPass`, `UnrealBloomPass`, `OutputPass`）を
esbuild でバンドルして埋め込んでいます。ビルド時にコメントを除去しているため
ファイル内にライセンス本文は残っていません。MIT License の条件を満たすため、
本ファイルにライセンス全文を掲載します。

### ライセンス本文

原文ファイル: [`third_party/three.js-LICENSE-r160.txt`](third_party/three.js-LICENSE-r160.txt)

```
The MIT License

Copyright © 2010-2023 three.js authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

---

## Python パッケージ（`server/`）

`server/requirements.txt` に記載のパッケージおよびその推移的依存は**配布物に含まれず**、
利用者が `pip install` で個別に取得します。

`pip-licenses` で実際に取得される依存を確認した結果は次のとおりです（推移的依存を含む）。

### 直接依存（requirements.txt）

| パッケージ | バージョン | ライセンス |
|---|---|---|
| fastapi | 0.115.6 | MIT |
| uvicorn[standard] | 0.34.0 | BSD |
| argon2-cffi | 23.1.0 | MIT |
| pydantic | 2.10.4 | MIT |
| httpx | 0.28.1 | BSD |
| pytest | 8.3.4 | MIT |

### 推移的依存

| パッケージ | ライセンス |
|---|---|
| starlette / httpcore / idna / click / pycparser / python-dotenv / websockets | BSD-3-Clause / BSD |
| annotated-types / anyio / argon2-cffi-bindings / h11 / httptools / iniconfig / pluggy / pydantic_core / PyYAML / watchfiles | MIT |
| cffi | MIT-0 |
| packaging | Apache-2.0 OR BSD-2-Clause |
| uvloop | Apache-2.0 / MIT |
| typing_extensions | PSF-2.0 |
| **certifi** | **MPL-2.0** |

**GPL / LGPL / AGPL 系の依存は含まれていません。**

`certifi` のみ MPL-2.0 ですが、これは `httpx`（テスト用）の推移的依存であり、
本リポジトリはそのソースを改変・再配布していません。

各パッケージの正確なライセンス条文は、それぞれの配布元を参照してください。
実行時依存とテスト依存は現状 `requirements.txt` にまとめており、分離していません。
