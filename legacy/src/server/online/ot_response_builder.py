# src/server/online/ot_response_builder.py
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Sequence, Optional
import json
import os

@dataclass(frozen=True)
class RowAlphMeta:
    """Metadata for row_alph.bin produced by build_gdfa_from_rules.py"""
    num_rows: int
    cols_per_row: List[int]
    format: str

    @staticmethod
    def load(meta_path: str) -> RowAlphMeta:
        with open(meta_path, "rb") as f:
            obj = json.loads(f.read().decode("utf-8"))
        if not isinstance(obj, dict):
            raise ValueError("row_alph.json malformed")
        cols = obj.get("cols_per_row")
        if not isinstance(cols, list) or not all(isinstance(x, int) and x >= 1 for x in cols):
            raise ValueError("row_alph.json: invalid cols_per_row")
        num_rows = obj.get("num_rows")
        if not isinstance(num_rows, int) or num_rows != len(cols):
            raise ValueError("row_alph.json: num_rows mismatch")
        fmt = obj.get("format", "")
        return RowAlphMeta(num_rows=num_rows, cols_per_row=list(cols), format=str(fmt))


@dataclass
class GKStore:
    """
    Server-held Group Keys for online OT:
      - table[r][c] is the GK bytes for row r, column c (0 <= c < num_cols[r]).
      - All entries in a given row must have equal length (k_bytes).
    """
    table: List[List[bytes]]

    def __post_init__(self):
        if not isinstance(self.table, list) or not self.table:
            raise ValueError("GKStore.table must be non-empty list of rows")
        # Basic row checks
        for r, row in enumerate(self.table):
            if not isinstance(row, list) or not row:
                raise ValueError(f"GKStore: row {r} must be a non-empty list")
            klen = len(row[0])
            if klen <= 0:
                raise ValueError(f"GKStore: row {r} key length must be > 0")
            for c, gk in enumerate(row):
                if not isinstance(gk, (bytes, bytearray)):
                    raise ValueError(f"GKStore: row {r} col {c} is not bytes")
                if len(gk) != klen:
                    raise ValueError(f"GKStore: row {r} has inconsistent key lengths")

    @property
    def num_rows(self) -> int:
        return len(self.table)

    def num_cols(self, row: int) -> int:
        return len(self.table[row])

    def key_len(self, row: int) -> int:
        return len(self.table[row][0])


class OTResponseBuilder:
    """
    Prepare 1-of-m OT payloads for a given DFA row using the server's GK table.

    Usage pattern:
      meta = RowAlphMeta.load("dist/zids/row_alph.json")
      gk   = GKStore(sample_gk_table(meta.num_rows, outmax=?, k_bytes=?))  # or load persisted keys
      orb  = OTResponseBuilder(meta, gk)

      payload = orb.payload_for_row(row_id)  # -> List[bytes], length = m (num_cols[row_id])
      # Then feed `payload` to your OT1ofmSender to produce network response.
    """

    def __init__(self, meta: RowAlphMeta, gk_store: GKStore):
        self.meta = meta
        self.gk = gk_store
        self._assert_consistent()

    def _assert_consistent(self) -> None:
        # Rows count must match
        if self.meta.num_rows != self.gk.num_rows:
            raise ValueError(f"Row count mismatch: row_alph has {self.meta.num_rows}, GK has {self.gk.num_rows}")
        # Each row's number of columns (groups) must match GK columns
        for r in range(self.meta.num_rows):
            m_meta = self.meta.cols_per_row[r]
            m_gk   = self.gk.num_cols(r)
            if m_meta != m_gk:
                raise ValueError(f"Row {r}: cols_per_row={m_meta} but GK has {m_gk}")
            if m_meta <= 0:
                raise ValueError(f"Row {r}: invalid m={m_meta}")
            # Sanity on key length (>=16 recommended)
            if self.gk.key_len(r) < 16:
                raise ValueError(f"Row {r}: GK length too small; got {self.gk.key_len(r)} bytes")

    def payload_for_row(self, row_id: int) -> List[bytes]:
        """
        Return the GK payload list for the given row:
          payload[c] = GK[row_id][c], for c in [0 .. m-1].
        """
        if not (0 <= row_id < self.meta.num_rows):
            raise IndexError("row_id out of range")
        # Return a shallow copy to avoid accidental mutation
        return list(self.gk.table[row_id])

    # -------- Optional helpers (thin adapters) --------

    def respond_with_ot1ofm(self, row_id: int, ot_sender) -> object:
        """
        Thin adapter: given an already-constructed OT1ofm sender, feed it the payload.

        Expected minimal interface of `ot_sender`:
            - has a method `send(payload: Sequence[bytes]) -> Any`
              (the return value is your protocol's response object)
        """
        payload = self.payload_for_row(row_id)
        if not hasattr(ot_sender, "send"):
            raise TypeError("ot_sender must provide a .send(payload) method")
        return ot_sender.send(payload)