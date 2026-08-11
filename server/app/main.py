"""NEON LATTICE 認証サーバー（FastAPI）。

監査(Claude / Codex)を反映した構成:

- 照合はすべてサーバー側。クライアントは正解もハッシュも持たない
- 保存は Argon2id（ソルト自動付与）
- レート制限は「試行枠を先に原子的に消費」する方式（競合バイパス不可）
- 登録の上書き・削除はセッションによる本人確認が必須（H-2）
- 弱い配置は登録時に拒否。ただし bit 値は返さない（H-3）
- 入力サイズ・Argon2 同時実行数を制限（M-1 / M-4）
- ユーザー列挙につながる応答差をなくす（M-2 / M-5 / L-3）
- IP単位のレート制限を併用（M-6）

※ 生の配置を送るため、本番では必ず HTTPS(TLS) 上で運用すること。
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from . import passcode as pc
from .store import AlreadyEnrolled, ServiceBusy, Store

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"
DB_PATH = os.environ.get("NEON_DB_PATH", ":memory:")

# 本文サイズの上限（M-1: 巨大JSONによるDoS対策）
MAX_BODY_BYTES = 4096

app = FastAPI(title="NEON LATTICE Auth", version="2.0.0")
store = Store(DB_PATH)

# L-4: 許可元を明示する。既定は同一オリジンのみ（*は使わない）。
_origins = [o for o in os.environ.get("NEON_CORS_ORIGINS", "").split(",") if o]
if _origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization"],
    )


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    """JSONを解析する前に本文サイズで弾く（M-1）。"""
    length = request.headers.get("content-length")
    if length is not None:
        try:
            if int(length) > MAX_BODY_BYTES:
                return _json_error(413, "リクエストが大きすぎます")
        except ValueError:
            return _json_error(400, "content-length が不正です")
    return await call_next(request)


def _json_error(status: int, message: str):
    from fastapi.responses import JSONResponse

    return JSONResponse(status_code=status, content={"detail": {"message": message}})


# ---- リクエストモデル（L-2: strict で "5"→5 の暗黙変換を防ぐ） ----
class PasscodeBody(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    # M-1: 外側6要素・内側2要素をスキーマで固定する
    passcode: list[list[int]] = Field(min_length=pc.FACES, max_length=pc.FACES)


class UsernameBody(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    username: str = Field(min_length=1, max_length=64)


def _parse_or_400(body: PasscodeBody) -> pc.Passcode:
    try:
        return pc.parse(body.passcode)
    except pc.InvalidPasscode as e:
        raise HTTPException(status_code=400, detail={"message": str(e)})


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _guard_ip(request: Request) -> None:
    """IP単位のレート制限（M-6: 他人を狙ったロックアウトDoSの緩和）。"""
    if not store.check_ip(_client_ip(request)):
        raise HTTPException(
            status_code=429, detail={"message": "リクエストが多すぎます"}
        )


def require_session(
    authorization: str | None = Header(default=None),
) -> str:
    """`Authorization: Bearer <token>` を検証し、ユーザー名を返す（L-1）。"""
    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    username = store.resolve_session(token)
    if username is None:
        raise HTTPException(status_code=401, detail={"message": "認証が必要です"})
    return username


# ---- 登録 ----
@app.post("/api/enroll")
def enroll(body: PasscodeBody, request: Request):
    """新規登録のみ。既存ユーザーの上書きは /api/reenroll（要認証）。"""
    _guard_ip(request)
    parsed = _parse_or_400(body)
    try:
        pc.assert_enrollable(parsed)
    except pc.WeakPasscode as e:
        # bit 値は返さない（H-3）。該当した規則のみ伝える。
        raise HTTPException(
            status_code=422, detail={"message": str(e), "reasons": e.reasons}
        )
    try:
        store.enroll(body.username, parsed.canonical())
    except AlreadyEnrolled:
        # H-2: 既存ユーザーを無認証で上書きさせない
        raise HTTPException(
            status_code=409,
            detail={"message": "この名前は登録済みです。認証してから変更してください"},
        )
    except ServiceBusy as e:
        raise HTTPException(status_code=503, detail={"message": str(e)})
    return {"ok": True}


@app.post("/api/reenroll")
def reenroll(
    body: PasscodeBody,
    request: Request,
    session_user: str = Depends(require_session),
):
    """認証済みユーザーが自分のパスコードを変更する（H-2）。"""
    _guard_ip(request)
    if body.username != session_user:
        raise HTTPException(status_code=403, detail={"message": "権限がありません"})
    parsed = _parse_or_400(body)
    try:
        pc.assert_enrollable(parsed)
    except pc.WeakPasscode as e:
        raise HTTPException(
            status_code=422, detail={"message": str(e), "reasons": e.reasons}
        )
    try:
        # 変更に伴い既存セッションは store 側で失効する
        store.enroll(session_user, parsed.canonical(), overwrite=True)
    except ServiceBusy as e:
        raise HTTPException(status_code=503, detail={"message": str(e)})
    return {"ok": True}


# ---- 認証 ----
@app.post("/api/authenticate")
def authenticate(body: PasscodeBody, request: Request):
    _guard_ip(request)
    parsed = _parse_or_400(body)
    try:
        result = store.authenticate(body.username, parsed.canonical())
    except ServiceBusy as e:
        raise HTTPException(status_code=503, detail={"message": str(e)})

    if not result.ok:
        # L-3: 残り試行回数は返さない。
        # M-2: 既定ではロック中かどうかも応答から判別できない。
        status = 429 if result.retry_after else 401
        detail = {"message": result.reason}
        if result.retry_after:
            detail["retry_after"] = result.retry_after
        raise HTTPException(status_code=status, detail=detail)

    token = store.create_session(body.username)
    return {"ok": True, "session": token}


# ---- 削除（要認証: H-2） ----
@app.post("/api/forget")
def forget(
    body: UsernameBody,
    request: Request,
    session_user: str = Depends(require_session),
):
    _guard_ip(request)
    if body.username != session_user:
        raise HTTPException(status_code=403, detail={"message": "権限がありません"})
    store.forget(session_user)
    return {"ok": True}


@app.post("/api/logout")
def logout(session_user: str = Depends(require_session)):
    store.revoke_sessions(session_user)
    return {"ok": True}


@app.get("/api/me")
def me(session_user: str = Depends(require_session)):
    """セッションの持ち主を返す（列挙にならない: 本人しか呼べない）。"""
    return {"username": session_user}


# M-5: /api/status/{username} は登録済みユーザーを直接公開していたため廃止した。
# 画面のモード（登録 or 認証）は、利用者が自分で選ぶ方式に変更している。


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
