# src/server/offline/dfa_optimizer/char_grouping.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List

ALPHABET_SIZE = 256

@dataclass(frozen=True)
class RowAlphabet:
    """
    該列的字母分群：
      - columns[c] = 此欄位包含的位元組清單（升冪）
      - byte_to_col[b] = 位元組 b 應落到哪一欄（0..num_cols-1）
    這裡產生的是「分割」（partition），因此對每個 b，有且僅有一欄包含它（cmax=1）。
    """
    columns: List[List[int]]
    byte_to_col: List[int]

    @property
    def num_cols(self) -> int:
        return len(self.columns)

    def which_col(self, b: int) -> int:
        if not (0 <= b < len(self.byte_to_col)):
            raise ValueError("byte out of range")
        return self.byte_to_col[b]

def _ensure_total_transitions(trans: List[Dict[int, int]]) -> None:
    """
    嚴格檢查 DFA 轉移是否對 0..255 全覆蓋；否則拋例外。
    （若需要，我們也可以加入一個外部「totalize」工具，但那會改變狀態數，和現有 ODFA 不一致。）
    """
    for s, mp in enumerate(trans):
        if len(mp) != ALPHABET_SIZE:
            missing = [b for b in range(ALPHABET_SIZE) if b not in mp]
            if missing:
                raise ValueError(
                    f"DFA transitions at state {s} are not total; missing {len(missing)} bytes "
                    f"(e.g., {missing[:8]} ...). Ensure regex compiler prefixes (any)* or totalizes DFA."
                )

def build_row_alphabets_from_dfa_trans(
    trans: List[Dict[int, int]],
    *,
    outmax: int,
    cmax: int = 1,
    alphabet_size: int = ALPHABET_SIZE
) -> List[RowAlphabet]:
    """
    由 DFA 的狀態轉移（state -> {byte -> next_state}）建每列的 RowAlphabet。
    分群規則：同一列中，所有映到同一 next_state 的位元組聚為一群。
    保障：每個位元組僅屬於一群（cmax=1）。若群數 > outmax -> 報錯（嚴格遵論文）。
    """
    if alphabet_size != ALPHABET_SIZE:
        raise ValueError("This builder currently assumes alphabet_size=256.")

    if cmax != 1:
        # 對照論文與我們的 pipeline，cmax=1 是自然選擇；若要 cmax>1，涉及重疊分群，這裡明確拒絕。
        raise ValueError("This builder constructs a partition per row; cmax must be 1.")

    _ensure_total_transitions(trans)

    row_alphabets: List[RowAlphabet] = []
    for s, mp in enumerate(trans):
        # group bytes by next_state
        next_to_bytes: Dict[int, List[int]] = {}
        for b in range(alphabet_size):
            t = mp[b]
            next_to_bytes.setdefault(t, []).append(b)

        # 群的個數即列外度；需 <= outmax
        groups = sorted(next_to_bytes.items(), key=lambda kv: min(kv[1]))
        num_groups = len(groups)
        if num_groups > outmax:
            raise ValueError(
                f"Row {s}: outdegree {num_groups} exceeds outmax={outmax}. "
                f"Either increase outmax per sparsity analysis, or adjust patterns."
            )

        columns: List[List[int]] = []
        byte_to_col = [-1] * alphabet_size
        for col_idx, (_t, blist) in enumerate(groups):
            blist_sorted = sorted(blist)
            columns.append(blist_sorted)
            for b in blist_sorted:
                if byte_to_col[b] != -1:
                    raise AssertionError("internal: byte assigned twice")
                byte_to_col[b] = col_idx

        # 防守：確認每個位元組都覆蓋
        if any(v == -1 for v in byte_to_col):
            missing = [i for i, v in enumerate(byte_to_col) if v == -1]
            raise AssertionError(f"internal: uncovered bytes in row {s}: {missing[:8]} ...")

        row_alphabets.append(RowAlphabet(columns=columns, byte_to_col=byte_to_col))

    return row_alphabets

# smoke (可選)
if __name__ == "__main__":
    # 小測：對一個極簡 DFA（兩列、兩群）構造分群
    trans = [
        {b: (0 if b < 128 else 1) for b in range(256)},
        {b: (1 if b % 2 else 0) for b in range(256)},
    ]
    ras = build_row_alphabets_from_dfa_trans(trans, outmax=128)
    print("row0 num_cols:", ras[0].num_cols, "row1 num_cols:", ras[1].num_cols)
