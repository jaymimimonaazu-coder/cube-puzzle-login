import math

import pytest

from app import passcode as pc

STRONG = [[2, 13], [0, 7], [4, 11], [5, 10], [1, 8], [6, 9]]


def test_keyspace_matches_expected():
    assert pc.KEYSPACE == 120 ** 6 == 2_985_984_000_000
    assert math.isclose(pc.FULL_BITS, 41.44, abs_tol=0.05)


def test_parse_normalizes_order():
    a = pc.parse([[5, 0], [3, 12], [9, 6], [14, 1], [15, 10], [7, 2]])
    b = pc.parse([[0, 5], [12, 3], [6, 9], [1, 14], [10, 15], [2, 7]])
    assert a.canonical() == b.canonical()


@pytest.mark.parametrize("bad", [
    [[0, 1]] * 5,                                          # 面数不足
    [[0, 1]] * 7,                                          # 面数過多
    [[0, 0], [1, 2], [3, 4], [5, 6], [7, 8], [9, 10]],     # 同一セル2回
    [[0, 16], [1, 2], [3, 4], [5, 6], [7, 8], [9, 10]],    # 範囲外
    [[-1, 2], [1, 2], [3, 4], [5, 6], [7, 8], [9, 10]],    # 負値
    [[0], [1, 2], [3, 4], [5, 6], [7, 8], [9, 10]],        # 個数不足
    [[0, 1, 2], [1, 2], [3, 4], [5, 6], [7, 8], [9, 10]],  # 個数過多
    [[True, 1], [1, 2], [3, 4], [5, 6], [7, 8], [9, 10]],  # bool 混入
])
def test_parse_rejects_invalid(bad):
    with pytest.raises(pc.InvalidPasscode):
        pc.parse(bad)


# ---- 弱い配置の検出（監査 H-3） ----

@pytest.mark.parametrize("weak,label", [
    ([[0, 1]] * 6, "全面同一"),
    ([[0, 1], [4, 5], [8, 9], [0, 1], [4, 5], [8, 9]], "Codex指摘: 3種反復(実効9.5bit)"),
    ([[0, 3], [0, 12], [0, 15], [3, 12], [3, 15], [12, 15]], "Claude指摘: 全面四隅のみ(実効15.5bit)"),
    ([[0, 1], [4, 5], [8, 9], [12, 13], [1, 2], [5, 6]], "全面隣接ペア"),
    ([[0, 5], [1, 6], [2, 7], [3, 8], [4, 9], [6, 11]], "全面が同じ間隔"),
    ([[0, 4], [0, 8], [4, 8], [0, 12], [4, 12], [8, 12]], "同一列のみ"),
])
def test_weak_patterns_are_rejected(weak, label):
    parsed = pc.parse(weak)
    assert pc.find_weak_patterns(parsed), f"{label} が弱いと判定されていない"
    with pytest.raises(pc.WeakPasscode):
        pc.assert_enrollable(parsed)


def test_diverse_passcode_is_enrollable():
    good = pc.parse(STRONG)
    assert pc.find_weak_patterns(good) == []
    assert pc.assert_enrollable(good) is None      # bit値は返さない（H-3）


def test_weak_passcode_carries_reasons_not_bits():
    with pytest.raises(pc.WeakPasscode) as ei:
        pc.assert_enrollable(pc.parse([[0, 1]] * 6))
    assert ei.value.reasons                        # 該当規則が入る
    assert not hasattr(ei.value, "estimated_bits")  # bit値は持たない


def test_estimate_bits_is_gone():
    """エントロピー推定は原理的に不可能なので公開APIから外したことを固定する。"""
    assert not hasattr(pc, "estimate_bits")
    assert not hasattr(pc, "MIN_ENROLL_BITS")


# ---- サーバー生成（保証が必要な場合の経路） ----

def test_generate_random_produces_valid_strong_passcode():
    for _ in range(50):
        g = pc.generate_random()
        assert len(g.faces) == pc.FACES
        for a, b in g.faces:
            assert 0 <= a < b < pc.CELLS_PER_FACE
        # 正規化済みなので再パースしても同じ
        assert pc.parse([list(f) for f in g.faces]).canonical() == g.canonical()
