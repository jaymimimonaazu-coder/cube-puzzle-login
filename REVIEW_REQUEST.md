# クロスチェック依頼書 — NEON LATTICE Cube Passcode Auth

このドキュメントは、別のAI（Codex / ChatGPT / Gemini 等）に**独立した検証**を依頼するための資料です。
そのまま貼り付けて使えます。忖度なしの指摘を歓迎します。

---

## 0. あなたへの依頼（要約）

Claude が実装した「3D立方体パズル認証」のサーバー実装とセキュリティ主張を、**攻撃者目線で検証**してください。
特に「脆弱性が実際に成立するか」を、推測ではなく**具体的な再現手順**で示してください。
問題がなければ「問題なし」と明言してください。過剰な指摘（理論上のみ）と実害のある指摘は分けてください。

---

## 1. システム概要

- **認証方式**: 3D立方体の6面、各面 4×4=16 升から**各面2升**を選ぶ。入力順・面内順は問わない。
- **鍵空間**: 各面 C(16,2)=120 通り、6面で **120^6 = 2,985,984,000,000 ≒ 2.99兆 ≒ 41.44 bit**。
- **構成**: フロント（Three.js）→ サーバー（FastAPI）で照合。クライアントは正解もハッシュも保持しない。
- **保存**: Argon2id（time_cost=3, memory=64MiB, parallelism=2）。ソルトは自動付与。
- **レート制限**: 失敗5回で15分ロック。失敗回数・ロック期限は SQLite で管理。
- **強度判定**: 登録時に「全面同一」「パターン反復」「角偏重」「推定30bit未満」を拒否。

---

## 2. 検証してほしい主張（Claim）

| # | 主張 | 検証してほしいこと |
|---|---|---|
| C1 | 鍵空間は 120^6 = 2.99兆 ≒ 41.44 bit | 算出は正しいか |
| C2 | オンライン総当たり（5回/15分）を全探索すると最悪 **1700万年** | 桁は妥当か |
| C3 | DB漏洩時、SHA-256なら全探索 **約2.5分**（GPU 1台 20GH/s） | 妥当か |
| C4 | DB漏洩時、Argon2id なら GPU1台で **47年** / GPU1000台で **17日** | Argon2idのGPUクラック速度(~2000 H/s)の見積もりは妥当か。過大/過小評価はないか |
| C5 | レート制限はDB管理のためリロードで回避不可 | 並行リクエストや別経路でバイパスできないか |
| C6 | 強度判定で弱い配置を弾ける | estimate_bits() をすり抜ける弱配置は存在しないか |
| C7 | ユーザー有無は秘匿されている（列挙不可） | 応答時間・挙動・ステータスコードで差が出ないか |

---

## 3. 重点的に見てほしい観点

1. **レート制限の競合(TOCTOU)** — `store.py` の `authenticate()`。読み取り→検証→更新の間に別リクエストが割り込めるか。`_lock`（threading.Lock）と uvicorn のワーカー構成次第で MAX_FAILS を超えて試行できないか。マルチプロセス（`--workers 2`）だとプロセス間でロックが効かない点も評価してほしい。
2. **入力によるDoS** — `passcode.parse()` に巨大配列・深いネスト・巨大整数を渡したときの挙動。pydantic の `list[list[int]]` は要素数上限が無いので、巨大入力でメモリ/CPUを消費させられないか。
3. **強度判定のすり抜け** — `estimate_bits()` のロジック（`passcode.py`）。例えば「隣接ペアだけ」「全面が回転対称」など、多様性は満たすが実質エントロピーが低い配置を弾けているか。閾値 `MIN_ENROLL_BITS=30` の根拠は弱い（ヒューリスティック）。
4. **/api/forget の認可欠落** — username だけで他人の登録を削除できる（既知。DoS/嫌がらせのリスク評価をしてほしい）。
5. **セッション管理** — `_sessions` はインメモリ辞書。失効・有効期限・スコープが無い。実運用でのリスク。
6. **タイミング差** — 未登録ユーザーは `_dummy_verify()` を通すが、`locked_until` 分岐やDB往復の有無で登録済み/未登録の応答時間に差が出ないか。

---

## 4. コード全文

### server/app/passcode.py
```python
"""パスコードの正規化・検証・強度判定。

パスコードは「6面 × 各面2セル（0〜15）」の選択。
入力順・面内の順序は問わないため、正規化してから扱う。
"""
from __future__ import annotations

import math
from dataclasses import dataclass

FACES = 6
CELLS_PER_FACE = 16
PICKS_PER_FACE = 2

# 面あたり C(16,2)=120、6面で 120**6 ≒ 2.99兆（約41.4bit）
FACE_COMBOS = math.comb(CELLS_PER_FACE, PICKS_PER_FACE)
KEYSPACE = FACE_COMBOS ** FACES
FULL_BITS = math.log2(KEYSPACE)

# 4隅のセル番号（4×4を 0..15 の行優先で並べたとき）
CORNERS = frozenset({0, 3, 12, 15})


class InvalidPasscode(ValueError):
    """パスコードの形式が不正。"""


class WeakPasscode(ValueError):
    """形式は正しいが、推測されやすく登録を拒否した。"""

    def __init__(self, message: str, estimated_bits: float):
        super().__init__(message)
        self.estimated_bits = estimated_bits


@dataclass(frozen=True)
class Passcode:
    """正規化済みパスコード。faces[i] は昇順の2要素タプル。"""

    faces: tuple[tuple[int, int], ...]

    def canonical(self) -> str:
        # 面の並びは固定（面は色で区別され順序に意味がある）。面内のみ昇順化。
        return "|".join(f"{i}:{a},{b}" for i, (a, b) in enumerate(self.faces))


def parse(raw: object) -> Passcode:
    """クライアントからの入力を検証して正規化する。

    期待する形式: [[c,c],[c,c],[c,c],[c,c],[c,c],[c,c]]
    各面ちょうど2セル、セルは 0..15 の相異なる整数。
    """
    if not isinstance(raw, (list, tuple)) or len(raw) != FACES:
        raise InvalidPasscode(f"{FACES}面ぶんの配列が必要です")

    faces: list[tuple[int, int]] = []
    for i, face in enumerate(raw):
        if not isinstance(face, (list, tuple)) or len(face) != PICKS_PER_FACE:
            raise InvalidPasscode(f"面{i}: ちょうど{PICKS_PER_FACE}箇所を選んでください")
        cells: list[int] = []
        for c in face:
            # bool は int のサブクラスなので明示的に弾く
            if isinstance(c, bool) or not isinstance(c, int):
                raise InvalidPasscode(f"面{i}: セルは整数で指定してください")
            if not 0 <= c < CELLS_PER_FACE:
                raise InvalidPasscode(f"面{i}: セル番号は0〜{CELLS_PER_FACE - 1}です")
            cells.append(c)
        if cells[0] == cells[1]:
            raise InvalidPasscode(f"面{i}: 同じセルを2回選べません")
        faces.append(tuple(sorted(cells)))  # 面内を昇順に正規化

    return Passcode(faces=tuple(faces))


def estimate_bits(pc: Passcode) -> float:
    """この配置の「推測されにくさ」をビットで概算する。

    完全ランダムなら 41.4bit だが、人間の癖（全面同一・4隅偏重・面パターンの
    重複）を反映して割り引く。登録可否のしきい値判定に使う簡易指標。
    """
    distinct_patterns = len(set(pc.faces))
    # 面パターンの多様性: 全面同一(1)なら大幅減、6面すべて異なるなら満点
    diversity = distinct_patterns / FACES

    # 4隅だけを使っている面の割合（隅は選ばれやすく候補が狭い）
    corner_faces = sum(1 for f in pc.faces if set(f) <= CORNERS)
    corner_ratio = corner_faces / FACES

    bits = FULL_BITS
    bits -= (1.0 - diversity) * 22.0   # 反復パターンの割引（全面同一で最大 -22bit）
    bits -= corner_ratio * 8.0         # 隅偏重の割引（全面が隅のみで -8bit）
    return max(bits, 0.0)


# 登録を許可する最小の推定ビット数
MIN_ENROLL_BITS = 30.0


def assert_enrollable(pc: Passcode) -> float:
    """登録可能かを判定し、推定ビット数を返す。弱ければ WeakPasscode。"""
    distinct_patterns = len(set(pc.faces))

    if distinct_patterns == 1:
        raise WeakPasscode(
            "全ての面で同じ配置です。面ごとに変えてください。",
            estimate_bits(pc),
        )
    if distinct_patterns < 3:
        raise WeakPasscode(
            "面ごとの配置がほぼ同じです。もっとばらつかせてください。",
            estimate_bits(pc),
        )

    bits = estimate_bits(pc)
    if bits < MIN_ENROLL_BITS:
        raise WeakPasscode(
            f"推測されやすい配置です（推定 {bits:.0f} bit）。"
            f"角に偏らせず、面ごとに散らしてください。",
            bits,
        )
    return bits
```

### server/app/store.py
```python
"""SQLite による資格情報の保存とサーバー側レート制限。

- パスコードは Argon2id でストレッチして保存（生の配置もSHA-256も保存しない）
- レート制限（失敗回数・ロック期限）はDBで管理するため、リロードでは回避できない
"""
from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from argon2 import PasswordHasher, exceptions as argon2_exc

# Argon2id パラメータ。オフライン総当たりを重くするのが目的。
# time_cost/memory_cost は端末性能に合わせて調整する。
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,  # 64 MiB
    parallelism=2,
)

# レート制限の設定
MAX_FAILS = 5
LOCK_SECONDS = 900  # 15分


@dataclass
class AuthResult:
    ok: bool
    reason: str = ""
    retry_after: int = 0  # ロック中なら残り秒数


class Store:
    def __init__(self, db_path: str | Path = ":memory:"):
        # check_same_thread=False + 明示ロックで簡易にスレッド安全化
        self._db = sqlite3.connect(str(db_path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock, self._db:
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS credentials (
                    username    TEXT PRIMARY KEY,
                    argon2_hash TEXT NOT NULL,
                    enrolled_at REAL NOT NULL,
                    fail_count  INTEGER NOT NULL DEFAULT 0,
                    locked_until REAL NOT NULL DEFAULT 0
                )
                """
            )

    # ---- 登録 ----
    def enroll(self, username: str, canonical: str) -> None:
        """canonical 文字列を Argon2id でハッシュ化して保存（既存は上書き）。"""
        digest = _hasher.hash(canonical)
        now = time.time()
        with self._lock, self._db:
            self._db.execute(
                """
                INSERT INTO credentials (username, argon2_hash, enrolled_at)
                VALUES (?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    argon2_hash = excluded.argon2_hash,
                    enrolled_at = excluded.enrolled_at,
                    fail_count = 0,
                    locked_until = 0
                """,
                (username, digest, now),
            )

    def exists(self, username: str) -> bool:
        with self._lock:
            row = self._db.execute(
                "SELECT 1 FROM credentials WHERE username = ?", (username,)
            ).fetchone()
        return row is not None

    def forget(self, username: str) -> None:
        with self._lock, self._db:
            self._db.execute("DELETE FROM credentials WHERE username = ?", (username,))

    # ---- 認証 ----
    def authenticate(self, username: str, canonical: str) -> AuthResult:
        now = time.time()
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM credentials WHERE username = ?", (username,)
            ).fetchone()

        if row is None:
            # ユーザー有無を秘匿するためダミー検証で時間を合わせる
            _dummy_verify()
            return AuthResult(ok=False, reason="認証に失敗しました")

        if row["locked_until"] > now:
            return AuthResult(
                ok=False,
                reason="試行回数の上限に達しました",
                retry_after=int(row["locked_until"] - now),
            )

        try:
            _hasher.verify(row["argon2_hash"], canonical)
            matched = True
        except argon2_exc.VerifyMismatchError:
            matched = False

        if matched:
            self._reset_fails(username)
            # パラメータ更新時のリハッシュ（任意）
            if _hasher.check_needs_rehash(row["argon2_hash"]):
                self.enroll(username, canonical)
            return AuthResult(ok=True)

        # 失敗 → カウント加算、必要ならロック
        return self._register_failure(username, row["fail_count"], now)

    def _reset_fails(self, username: str) -> None:
        with self._lock, self._db:
            self._db.execute(
                "UPDATE credentials SET fail_count = 0, locked_until = 0 WHERE username = ?",
                (username,),
            )

    def _register_failure(self, username: str, prev_fails: int, now: float) -> AuthResult:
        fails = prev_fails + 1
        locked_until = 0.0
        retry_after = 0
        reason = f"認証に失敗しました（{fails}/{MAX_FAILS}）"
        if fails >= MAX_FAILS:
            locked_until = now + LOCK_SECONDS
            retry_after = LOCK_SECONDS
            reason = "試行回数の上限に達しました"
        with self._lock, self._db:
            self._db.execute(
                "UPDATE credentials SET fail_count = ?, locked_until = ? WHERE username = ?",
                (fails, locked_until, username),
            )
        return AuthResult(ok=False, reason=reason, retry_after=retry_after)


# ユーザーが存在しない場合でも一定の計算時間をかけ、応答時間差での列挙を防ぐ
_DUMMY_HASH = _hasher.hash("dummy-canonical-value")


def _dummy_verify() -> None:
    try:
        _hasher.verify(_DUMMY_HASH, "wrong")
    except argon2_exc.VerifyMismatchError:
        pass
```

### server/app/main.py
```python
"""NEON LATTICE 本番想定サーバー（FastAPI）。

クライアントからは「12箇所の選択（配置）」をそのまま送り、照合はすべてサーバー側で行う。
- 保存は Argon2id（ソルトは自動付与）
- レート制限・ロックはDBで管理
- 弱い配置は登録時に拒否
※ 生の配置を送るため、本番では必ず HTTPS(TLS) 上で運用すること。
"""
from __future__ import annotations

import os
import secrets

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from pathlib import Path

from . import passcode as pc
from .store import Store

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"
DB_PATH = os.environ.get("NEON_DB_PATH", ":memory:")

app = FastAPI(title="NEON LATTICE Auth", version="1.0.0")
store = Store(DB_PATH)

# 発行済みセッショントークン（デモ用のインメモリ保持）
_sessions: dict[str, str] = {}


class PasscodeBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    passcode: list[list[int]] = Field(description="6面×2セルの選択")


def _parse_or_400(body: PasscodeBody) -> pc.Passcode:
    try:
        return pc.parse(body.passcode)
    except pc.InvalidPasscode as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/enroll")
def enroll(body: PasscodeBody):
    parsed = _parse_or_400(body)
    try:
        bits = pc.assert_enrollable(parsed)
    except pc.WeakPasscode as e:
        raise HTTPException(
            status_code=422,
            detail={"message": str(e), "estimated_bits": round(e.estimated_bits, 1)},
        )
    store.enroll(body.username, parsed.canonical())
    return {"ok": True, "estimated_bits": round(bits, 1)}


@app.post("/api/authenticate")
def authenticate(body: PasscodeBody):
    parsed = _parse_or_400(body)
    result = store.authenticate(body.username, parsed.canonical())
    if not result.ok:
        raise HTTPException(
            status_code=429 if result.retry_after else 401,
            detail={"message": result.reason, "retry_after": result.retry_after},
        )
    token = secrets.token_urlsafe(24)
    _sessions[token] = body.username
    return {"ok": True, "session": token}


@app.post("/api/forget")
def forget(body: PasscodeBody):
    # デモ簡略化のため username のみ使用（本番は認証済みセッション必須）
    store.forget(body.username)
    return {"ok": True}


@app.get("/api/status/{username}")
def status(username: str):
    return {"enrolled": store.exists(username)}


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
```

---

## 5. 計算根拠（C2〜C4）

```
鍵空間 K = 120^6 = 2,985,984,000,000

C2 オンライン: 5回 / 15分 = 5/900 回/秒
   K / (5/900) 秒 = 5.37e14 秒 = 1.70e7 年（最悪・全件）／平均はその半分

C3 SHA-256 GPU1台 20 GH/s:
   K / 2e10 = 149 秒 ≒ 2.5 分

C4 Argon2id 概算 2,000 H/s / 高性能GPU（64MiB メモリハード）:
   GPU1台   : K / 2e3   = 1.49e9 秒 = 47.3 年
   GPU100台 : K / 2e5   = 173 日
   GPU1000台: K / 2e6   = 17.3 日
```

**特にC4のArgon2id速度(~2000 H/s)の妥当性**を、あなたの知る実測ベンチ（RTX 4090等）と照らして評価してください。
メモリ64MiB・parallelism=2 の設定でのGPU効率をどう見積もるかで結論が変わります。

---

## 6. 期待する返答フォーマット

各指摘について:
- **深刻度**: 高 / 中 / 低 / 情報
- **成立性**: 実際に再現可能 / 理論上のみ / 誤り
- **該当**: ファイル:行
- **再現手順 or 根拠**
- **修正案**

最後に、C1〜C7 の主張それぞれに「妥当 / 要修正 / 誤り」の判定を付けてください。
