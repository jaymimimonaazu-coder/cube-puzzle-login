"""SQLite による資格情報の保存・セッション管理・レート制限。

監査(H-1/H-2/M-2/M-3/M-4/M-6/L-1/L-3)を受けた設計:

- パスコードは Argon2id でストレッチして保存（生の配置もSHA-256も保存しない）
- **試行枠を先に原子的に消費してから検証する**（read→verify→write の競合を排除）
- 接続はスレッドごとに持ち、`BEGIN IMMEDIATE` でプロセス間も直列化する
- セッションはDBに保存（トークンはハッシュ化・期限付き・失効可能）
- Argon2 の同時実行数を制限し、計算資源DoSを緩和する
"""
from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from argon2 import PasswordHasher, exceptions as argon2_exc

# Argon2id パラメータ。オフライン総当たりを重くするのが目的。
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,  # 64 MiB
    parallelism=2,
)

# ---- レート制限 ----
MAX_FAILS = 5
LOCK_SECONDS = 900          # 15分
IP_MAX_ATTEMPTS = 30        # IPあたりの試行上限
IP_WINDOW_SECONDS = 300     # その観測窓（5分）

# ---- セッション ----
SESSION_TTL_SECONDS = 3600

# ---- DoS対策: Argon2 の同時実行数 ----
# 64MiB × N のメモリを同時に確保しないよう制限する。
ARGON2_MAX_CONCURRENCY = 4
ARGON2_ACQUIRE_TIMEOUT = 5.0
_argon2_slots = threading.Semaphore(ARGON2_MAX_CONCURRENCY)

# ロック中であることを応答で明かすか。
# False（既定・安全側）: ロック中も通常の認証失敗と同じ応答にし、
#                        ユーザーの存在・ロック状態を漏らさない（M-2）。
# True（デモ用）      : 429 と retry_after を返し、画面でロックを表示できる。
#                       環境変数 NEON_REVEAL_LOCK=1 で有効化。
REVEAL_LOCK_STATE = os.environ.get("NEON_REVEAL_LOCK") == "1"


class ServiceBusy(RuntimeError):
    """Argon2 の同時実行枠が取れず、処理を受け付けられない。"""


class AlreadyEnrolled(RuntimeError):
    """既に登録済みのユーザー名に、認証なしで登録しようとした。"""


@dataclass
class AuthResult:
    ok: bool
    reason: str = ""
    locked: bool = False
    retry_after: int = 0  # REVEAL_LOCK_STATE が True のときだけ意味を持つ


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@contextmanager
def _argon2_guard():
    """Argon2 実行枠を確保し、抜けるときに必ず解放する。取れなければ ServiceBusy。"""
    if not _argon2_slots.acquire(timeout=ARGON2_ACQUIRE_TIMEOUT):
        raise ServiceBusy("サーバーが混雑しています")
    try:
        yield
    finally:
        _argon2_slots.release()


class Store:
    def __init__(self, db_path: str | Path = ":memory:"):
        # スレッドごとに接続を持つ。:memory: は共有キャッシュURIにして
        # 全接続が同一DBを見るようにする（スレッドごとに別DBになるのを防ぐ）。
        if str(db_path) == ":memory:":
            self._dsn = f"file:neon_{id(self):x}?mode=memory&cache=shared"
            self._uri = True
            # 参照が全て閉じるとメモリDBが消えるため、保持用の接続を1本残す
            self._keepalive: sqlite3.Connection | None = sqlite3.connect(
                self._dsn, uri=True
            )
        else:
            self._dsn = str(db_path)
            self._uri = False
            self._keepalive = None
        self._local = threading.local()
        # 書き込みトランザクションはプロセス内で直列化する。
        # BEGIN IMMEDIATE だけではプロセス"内"の共有キャッシュ競合
        # （SQLITE_LOCKED: database table is locked）を busy_timeout で
        # 待てないため、両方を併用する。
        #   - このロック : プロセス内の直列化
        #   - BEGIN IMMEDIATE : プロセス間の直列化
        self._wlock = threading.RLock()
        self._init_schema()

    @contextmanager
    def _tx(self):
        """書き込みトランザクション。Argon2 のような重い処理は入れないこと。"""
        with self._wlock:
            conn = self._conn()
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.OperationalError:
                    pass
                raise
            else:
                conn.execute("COMMIT")

    # ---- 接続 ----
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            # isolation_level=None で明示的にトランザクションを制御する
            conn = sqlite3.connect(self._dsn, uri=self._uri, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 30000")
            self._local.conn = conn
        return conn

    def _init_schema(self) -> None:
        conn = self._conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                username     TEXT PRIMARY KEY,
                argon2_hash  TEXT NOT NULL,
                enrolled_at  REAL NOT NULL,
                fail_count   INTEGER NOT NULL DEFAULT 0,
                locked_until REAL NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                username   TEXT NOT NULL,
                expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ip_attempts (
                ip      TEXT NOT NULL,
                at      REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ip_attempts ON ip_attempts(ip, at);
            """
        )

    # ---- 登録 ----
    def enroll(self, username: str, canonical: str, *, overwrite: bool = False) -> None:
        """パスコードを登録する。

        overwrite=False（既定）では既存ユーザーへの上書きを拒否する（H-2）。
        再登録は本人確認済みの呼び出し側だけが overwrite=True を渡す。
        """
        with _argon2_guard():
            digest = _hasher.hash(canonical)
        now = time.time()
        with self._tx() as conn:
            exists = conn.execute(
                "SELECT 1 FROM credentials WHERE username = ?", (username,)
            ).fetchone()
            if exists and not overwrite:
                raise AlreadyEnrolled(username)
            conn.execute(
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
            # 資格情報が変わったら既存セッションは全て失効させる
            conn.execute("DELETE FROM sessions WHERE username = ?", (username,))

    def exists(self, username: str) -> bool:
        row = self._conn().execute(
            "SELECT 1 FROM credentials WHERE username = ?", (username,)
        ).fetchone()
        return row is not None

    def forget(self, username: str) -> None:
        with self._tx() as conn:
            conn.execute("DELETE FROM credentials WHERE username = ?", (username,))
            conn.execute("DELETE FROM sessions WHERE username = ?", (username,))

    # ---- 認証 ----
    def authenticate(self, username: str, canonical: str) -> AuthResult:
        """パスコードを照合する。

        競合対策(H-1/M-3): 検証の**前に**試行枠を原子的に消費する。
        並行リクエストは各自が `fail_count + 1` の相対更新を行うため、
        上限を超えた分は確実にロックされる。
        """
        now = time.time()
        reserved = self._reserve_attempt(username, now)

        if reserved is None:
            # 未登録。存在を秘匿するため、登録済みと同じだけ計算時間を使う。
            self._dummy_verify()
            return self._generic_failure()

        argon2_hash, locked_until = reserved

        if locked_until > now:
            # ロック中も同じ計算時間を消費する（M-2: タイミング差の除去）
            self._dummy_verify()
            return self._locked_result(int(locked_until - now))

        try:
            with _argon2_guard():
                _hasher.verify(argon2_hash, canonical)
            matched = True
        except argon2_exc.VerifyMismatchError:
            matched = False

        if not matched:
            return self._generic_failure()

        # 成功: 失敗カウントを消す（消費済みの1回ぶんも戻す）
        self._reset_fails(username)
        if _hasher.check_needs_rehash(argon2_hash):
            self.enroll(username, canonical, overwrite=True)
        return AuthResult(ok=True)

    def _reserve_attempt(self, username: str, now: float):
        """試行枠を1つ消費し、(hash, locked_until) を返す。未登録なら None。

        「読み取り → 加算 → ロック判定」を単一トランザクションで行うため、
        並行リクエストでも失敗回数が取りこぼされない。
        """
        with self._tx() as conn:
            row = conn.execute(
                "SELECT argon2_hash, fail_count, locked_until FROM credentials"
                " WHERE username = ?",
                (username,),
            ).fetchone()
            if row is None:
                return None

            locked_until = row["locked_until"]
            if locked_until > now:
                return row["argon2_hash"], locked_until

            # 期限切れロックはここで解除し、カウントを1から数え直す
            if 0 < locked_until <= now:
                conn.execute(
                    "UPDATE credentials SET fail_count = 1, locked_until = 0"
                    " WHERE username = ?",
                    (username,),
                )
                return row["argon2_hash"], 0.0

            # 相対更新。上限に達した時点で同じ文の中でロックを掛ける。
            conn.execute(
                """
                UPDATE credentials
                   SET fail_count = fail_count + 1,
                       locked_until = CASE
                           WHEN fail_count + 1 >= ? THEN ?
                           ELSE locked_until
                       END
                 WHERE username = ?
                """,
                (MAX_FAILS, now + LOCK_SECONDS, username),
            )
            # この試行自体は許可する（ロックは次回以降に効く）。
            # これにより MAX_FAILS 回ちょうどが検証され、正しい入力なら成功できる。
            return row["argon2_hash"], 0.0

    def _reset_fails(self, username: str) -> None:
        with self._tx() as conn:
            conn.execute(
                "UPDATE credentials SET fail_count = 0, locked_until = 0"
                " WHERE username = ?",
                (username,),
            )

    # ---- 応答の組み立て（L-3: 残り回数を漏らさない） ----
    @staticmethod
    def _generic_failure() -> AuthResult:
        return AuthResult(ok=False, reason="認証に失敗しました")

    @staticmethod
    def _locked_result(retry_after: int) -> AuthResult:
        if REVEAL_LOCK_STATE:
            return AuthResult(
                ok=False,
                reason="試行回数の上限に達しました",
                locked=True,
                retry_after=retry_after,
            )
        # 安全側: ロック中であることを応答から判別できないようにする
        return AuthResult(ok=False, reason="認証に失敗しました", locked=True)

    @staticmethod
    def _dummy_verify() -> None:
        try:
            with _argon2_guard():
                _hasher.verify(_DUMMY_HASH, "wrong")
        except argon2_exc.VerifyMismatchError:
            pass

    # ---- IP単位のレート制限（M-6: 他人をロックさせるDoSの緩和） ----
    def check_ip(self, ip: str, now: float | None = None) -> bool:
        """IPの試行を記録し、窓内の上限を超えていなければ True。"""
        now = time.time() if now is None else now
        with self._tx() as conn:
            conn.execute(
                "DELETE FROM ip_attempts WHERE at < ?", (now - IP_WINDOW_SECONDS,)
            )
            count = conn.execute(
                "SELECT COUNT(*) AS n FROM ip_attempts WHERE ip = ? AND at >= ?",
                (ip, now - IP_WINDOW_SECONDS),
            ).fetchone()["n"]
            if count >= IP_MAX_ATTEMPTS:
                return False
            conn.execute("INSERT INTO ip_attempts (ip, at) VALUES (?, ?)", (ip, now))
            return True

    # ---- セッション（L-1） ----
    def create_session(self, username: str, now: float | None = None) -> str:
        now = time.time() if now is None else now
        token = secrets.token_urlsafe(32)
        with self._tx() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            conn.execute(
                "INSERT INTO sessions (token_hash, username, expires_at)"
                " VALUES (?, ?, ?)",
                (_hash_token(token), username, now + SESSION_TTL_SECONDS),
            )
        return token

    def resolve_session(self, token: str, now: float | None = None) -> str | None:
        """有効なセッションならユーザー名を返す。無効/期限切れなら None。"""
        if not token:
            return None
        now = time.time() if now is None else now
        row = self._conn().execute(
            "SELECT username, expires_at FROM sessions WHERE token_hash = ?",
            (_hash_token(token),),
        ).fetchone()
        if row is None or row["expires_at"] < now:
            return None
        return row["username"]

    def revoke_sessions(self, username: str) -> None:
        with self._tx() as conn:
            conn.execute("DELETE FROM sessions WHERE username = ?", (username,))


# ユーザーが存在しない場合でも一定の計算時間をかけ、応答時間差での列挙を防ぐ
_DUMMY_HASH = _hasher.hash("dummy-canonical-value")
