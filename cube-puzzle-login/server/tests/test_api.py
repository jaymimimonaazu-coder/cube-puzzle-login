import threading
import time
from collections import Counter

import pytest
from fastapi.testclient import TestClient

import app.store as store_mod
from app.main import app, store
from app.store import Store

client = TestClient(app)

STRONG = [[2, 13], [0, 7], [4, 11], [5, 10], [1, 8], [6, 9]]
OTHER = [[3, 14], [1, 6], [5, 12], [4, 9], [2, 11], [7, 8]]
WRONG = [[2, 13], [0, 7], [4, 11], [5, 10], [1, 8], [6, 10]]
WEAK = [[0, 1], [4, 5], [8, 9], [0, 1], [4, 5], [8, 9]]   # Codex指摘の3種反復


@pytest.fixture(autouse=True)
def clean():
    """各テストを独立させる。

    TestClient は全リクエストが同一IP扱いになるため、IP制限(M-6)の記録も
    毎回消す。消さないとテスト間で枠を食い合って 429 になる。
    """
    def reset():
        for u in ("alice", "bob", "ghost"):
            store.forget(u)
        with store._tx() as conn:
            conn.execute("DELETE FROM ip_attempts")

    reset()
    yield
    reset()


def enroll(user=  "alice", code=None):
    return client.post("/api/enroll", json={"username": user, "passcode": code or STRONG})


def auth(user="alice", code=None):
    return client.post("/api/authenticate", json={"username": user, "passcode": code or STRONG})


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


# ---- 基本動作 ----

def test_enroll_then_authenticate():
    assert enroll().status_code == 200
    r = auth()
    assert r.status_code == 200 and "session" in r.json()


def test_enroll_does_not_leak_bits():
    """H-3: 推定ビット値を返さないことを固定する。"""
    body = enroll().json()
    assert "estimated_bits" in body or True  # 存在しないことを次行で確認
    assert "estimated_bits" not in body


def test_authenticate_order_independent():
    enroll()
    shuffled = [list(reversed(f)) for f in STRONG]
    assert auth(code=shuffled).status_code == 200


def test_wrong_passcode_rejected():
    enroll()
    assert auth(code=WRONG).status_code == 401


# ---- H-2: 無認証の上書き・削除を拒否 ----

def test_enroll_cannot_overwrite_existing_user():
    enroll()
    r = enroll(code=OTHER)          # 無認証で上書きを試みる
    assert r.status_code == 409
    assert auth().status_code == 200            # 元の資格情報は無傷
    assert auth(code=OTHER).status_code == 401  # 攻撃者の配置では入れない


def test_forget_requires_session():
    enroll()
    assert client.post("/api/forget", json={"username": "alice"}).status_code == 401
    assert auth().status_code == 200            # まだ消えていない


def test_forget_with_session_succeeds():
    enroll()
    tok = auth().json()["session"]
    assert client.post("/api/forget", json={"username": "alice"},
                       headers=bearer(tok)).status_code == 200


def test_cannot_forget_other_user_with_own_session():
    enroll("alice")
    enroll("bob", OTHER)
    tok = auth("alice").json()["session"]
    r = client.post("/api/forget", json={"username": "bob"}, headers=bearer(tok))
    assert r.status_code == 403
    assert auth("bob", OTHER).status_code == 200   # bob は無事


def test_reenroll_requires_session_and_ownership():
    enroll("alice")
    enroll("bob", OTHER)
    tok = auth("alice").json()["session"]
    # 無認証は不可
    assert client.post("/api/reenroll", json={"username": "alice", "passcode": OTHER}).status_code == 401
    # 他人のものは変更不可
    assert client.post("/api/reenroll", json={"username": "bob", "passcode": STRONG},
                       headers=bearer(tok)).status_code == 403
    # 自分のものは変更可
    assert client.post("/api/reenroll", json={"username": "alice", "passcode": OTHER},
                       headers=bearer(tok)).status_code == 200
    assert auth("alice", OTHER).status_code == 200


def test_reenroll_revokes_old_sessions():
    """L-1: 資格情報の変更で既存セッションが失効する。"""
    enroll()
    tok = auth().json()["session"]
    client.post("/api/reenroll", json={"username": "alice", "passcode": OTHER},
                headers=bearer(tok))
    assert client.get("/api/me", headers=bearer(tok)).status_code == 401


def test_logout_revokes_session():
    enroll()
    tok = auth().json()["session"]
    assert client.get("/api/me", headers=bearer(tok)).status_code == 200
    assert client.post("/api/logout", headers=bearer(tok)).status_code == 200
    assert client.get("/api/me", headers=bearer(tok)).status_code == 401


def test_invalid_session_token_rejected():
    assert client.get("/api/me", headers=bearer("not-a-real-token")).status_code == 401
    assert client.get("/api/me").status_code == 401


# ---- H-3: 弱い配置の拒否 ----

def test_weak_passcode_refused_with_reasons():
    r = enroll(code=WEAK)
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["reasons"]                       # 該当規則を返す
    assert "estimated_bits" not in detail          # bit値は返さない


# ---- M-1 / L-2: 入力検証 ----

def test_invalid_shape_rejected():
    assert client.post("/api/enroll",
                       json={"username": "alice", "passcode": [[0, 1]] * 5}).status_code == 422


def test_oversized_body_rejected_before_parsing():
    r = client.post("/api/enroll", json={"username": "alice", "passcode": [[0, 1]] * 100000})
    assert r.status_code == 413


def test_strict_types_reject_string_digits():
    r = client.post("/api/enroll",
                    json={"username": "alice",
                          "passcode": [["5", 1], [0, 7], [4, 11], [5, 10], [1, 8], [6, 9]]})
    assert r.status_code == 422


def test_extra_fields_forbidden():
    r = client.post("/api/enroll",
                    json={"username": "alice", "passcode": STRONG, "admin": True})
    assert r.status_code == 422


# ---- M-5: ユーザー列挙 ----

def test_status_endpoint_removed():
    """M-5: /api/status は登録済みユーザーを公開していたため廃止。"""
    assert client.get("/api/status/alice").status_code == 404


def test_unknown_user_is_401_not_404():
    assert auth("ghost").status_code == 401


def test_unknown_user_and_wrong_passcode_are_indistinguishable():
    """M-2: 未登録と「登録済み＋誤り」で応答が区別できない。"""
    enroll("alice")
    a = auth("alice", WRONG)
    b = auth("ghost")
    assert a.status_code == b.status_code == 401
    assert a.json()["detail"]["message"] == b.json()["detail"]["message"]


# ---- L-3: 残り試行回数を漏らさない ----

def test_failure_message_hides_attempt_count():
    enroll()
    msg = auth(code=WRONG).json()["detail"]["message"]
    assert "/" not in msg and "5" not in msg


# ---- H-1 / M-3: レート制限（store 層で検証） ----

def test_rate_limit_locks_after_max_fails():
    s = Store(":memory:")
    s.enroll("u", "correct")
    for _ in range(store_mod.MAX_FAILS):
        assert not s.authenticate("u", "wrong").ok
    r = s.authenticate("u", "correct")     # ロック後は正解でも通さない
    assert not r.ok and r.locked


def test_correct_passcode_still_works_before_lock():
    s = Store(":memory:")
    s.enroll("u", "correct")
    for _ in range(store_mod.MAX_FAILS - 1):
        s.authenticate("u", "wrong")
    assert s.authenticate("u", "correct").ok


def test_concurrent_attempts_cannot_exceed_max_fails():
    """H-1: 並行リクエストで試行上限を超えられない（旧実装では30本全通過）。"""
    s = Store(":memory:")
    s.enroll("u", "correct")
    results, errors, lock = [], [], threading.Lock()

    def attempt():
        try:
            r = s.authenticate("u", "wrong")
            with lock:
                results.append("locked" if r.locked else "verified")
        except Exception as e:  # pragma: no cover
            with lock:
                errors.append(repr(e))

    threads = [threading.Thread(target=attempt) for _ in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"並行実行で例外: {errors[:3]}"
    counts = Counter(results)
    assert counts["verified"] <= store_mod.MAX_FAILS, counts
    assert counts["locked"] > 0, counts


def test_success_and_failure_race_keeps_state_consistent():
    """M-3: 成功と失敗が並行しても状態が壊れない。"""
    s = Store(":memory:")
    s.enroll("u", "correct")
    oks, lock = [], threading.Lock()

    def go(code):
        r = s.authenticate("u", code)
        with lock:
            oks.append(r.ok)

    threads = [threading.Thread(target=go, args=("correct" if i % 2 else "wrong",))
               for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert any(oks), "正しいパスコードが一度も通っていない"
    # 正解が通った以上、ロックされたままにはならない
    assert s.authenticate("u", "correct").ok


def test_expired_lock_allows_retry():
    s = Store(":memory:")
    s.enroll("u", "correct")
    for _ in range(store_mod.MAX_FAILS):
        s.authenticate("u", "wrong")
    assert not s.authenticate("u", "correct").ok
    # ロック期限を過去にする
    with s._tx() as conn:
        conn.execute("UPDATE credentials SET locked_until = ? WHERE username = 'u'",
                     (time.time() - 1,))
    assert s.authenticate("u", "correct").ok


# ---- M-6: IP レート制限 ----

def test_ip_rate_limit_blocks_after_threshold():
    s = Store(":memory:")
    ip = "203.0.113.9"
    allowed = sum(1 for _ in range(store_mod.IP_MAX_ATTEMPTS + 5) if s.check_ip(ip))
    assert allowed == store_mod.IP_MAX_ATTEMPTS


def test_ip_rate_limit_is_per_ip():
    s = Store(":memory:")
    for _ in range(store_mod.IP_MAX_ATTEMPTS):
        s.check_ip("198.51.100.1")
    assert not s.check_ip("198.51.100.1")
    assert s.check_ip("198.51.100.2")     # 別IPは影響を受けない


# ---- セッションの期限 ----

def test_session_expires():
    s = Store(":memory:")
    s.enroll("u", "correct")
    tok = s.create_session("u", now=time.time() - store_mod.SESSION_TTL_SECONDS - 10)
    assert s.resolve_session(tok) is None


def test_session_token_is_not_stored_in_plaintext():
    s = Store(":memory:")
    s.enroll("u", "correct")
    tok = s.create_session("u")
    row = s._conn().execute("SELECT token_hash FROM sessions").fetchone()
    assert row["token_hash"] != tok
