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
    """形式は正しいが、既知の弱い規則に当てはまるため登録を拒否した。

    ビット数は返さない。単一のパスコードからエントロピーは推定できないため
    （監査 H-3）、該当した規則名だけを reasons として持つ。
    """

    def __init__(self, message: str, reasons: list[str]):
        super().__init__(message)
        self.reasons = reasons


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


# --------------------------------------------------------------------------
# 規則検査（旧 estimate_bits の置き換え）
#
# 【重要】単一の完成済みパスコードから、その利用者が用いた確率分布や
# エントロピーを推定することはできない。以前の estimate_bits() は
# 「41.4bit から減点する」形で bit 値を返していたが、これは暗号学的な
# 保証ではなく、実際に弱い配置を通していた（監査 H-3）。
#   例) 3種を繰り返す [0,1][4,5][8,9]×2 → 旧実装は 30.44bit と判定して通過。
#       だが「3種から各面を選ぶ」規則なら候補は 3^6 = 729 ≒ 9.5bit しかない。
#
# よってここでは bit 値を返さず、「既知の弱い規則に当てはまるか」だけを
# 判定する。これは **強度の保証ではなく、明らかな悪手を弾くフィルタ** である。
# 高い保証が要るなら generate_random() でサーバー生成するか、WebAuthn 等を併用する。
# --------------------------------------------------------------------------

# 4×4 を 0..15 の行優先で並べたときの行・列
def _row(c: int) -> int:
    return c // 4


def _col(c: int) -> int:
    return c % 4


def find_weak_patterns(pc: Passcode) -> list[str]:
    """当てはまる弱い規則を列挙する。空リストなら既知の悪手には該当しない。"""
    reasons: list[str] = []
    faces = pc.faces
    distinct = len(set(faces))

    # 1. 面パターンの反復（全面同一・少数種の使い回し）
    if distinct == 1:
        reasons.append("全ての面が同じ配置です")
    elif distinct <= 3:
        # 3種以下の使い回しは候補が 3^6=729 程度まで縮む
        reasons.append(f"{distinct}種類の配置だけを使い回しています")

    # 2. 全面が4隅のみ（候補は 6^6 = 46,656 まで縮む）
    if all(set(f) <= CORNERS for f in faces):
        reasons.append("全ての面で四隅しか使っていません")

    # 3. 全面が同一行 / 同一列（それぞれ候補が大幅に縮む）
    if all(_row(f[0]) == _row(f[1]) for f in faces):
        reasons.append("全ての面で同じ行の2升を選んでいます")
    if all(_col(f[0]) == _col(f[1]) for f in faces):
        reasons.append("全ての面で同じ列の2升を選んでいます")

    # 4. 全面が隣接ペア（連番）
    if all(f[1] - f[0] == 1 and _row(f[0]) == _row(f[1]) for f in faces):
        reasons.append("全ての面で隣り合う2升を選んでいます")

    # 5. 全面で2升の間隔が同じ（等差＝規則的な生成）
    gaps = {f[1] - f[0] for f in faces}
    if len(gaps) == 1 and distinct > 1:
        reasons.append("全ての面で2升の間隔が同じです")

    # 6. 使われているセルの種類が極端に少ない
    used = {c for f in faces for c in f}
    if len(used) <= 4:
        reasons.append(f"使用しているセルが{len(used)}種類しかありません")

    return reasons


def assert_enrollable(pc: Passcode) -> None:
    """既知の弱い規則に該当すれば WeakPasscode。該当なしなら何も返さない。

    戻り値を持たないのは意図的で、「何ビット」という保証を呼び出し側に
    渡さないため（監査 H-3 / Codex 指摘）。
    """
    reasons = find_weak_patterns(pc)
    if reasons:
        raise WeakPasscode(
            "推測されやすい配置です: " + "、".join(reasons) + "。面ごとに散らしてください。",
            reasons,
        )


def generate_random(rng=None) -> Passcode:
    """暗号学的乱数でパスコードを生成する（保証が必要な場合の推奨経路）。

    利用者が選ぶ場合と違い、この経路でのみ 41.44bit を実際に主張できる。
    """
    import secrets

    picker = rng or secrets.SystemRandom()
    faces = []
    for _ in range(FACES):
        a, b = sorted(picker.sample(range(CELLS_PER_FACE), PICKS_PER_FACE))
        faces.append((a, b))
    return Passcode(faces=tuple(faces))
