# src/server/offline/build_gdfa_from_rules.py
from __future__ import annotations
import argparse
import json
import os
import sys
import hashlib
from typing import List, Optional, Dict, Iterable

from src.server.io.rule_loader import load_rules, LoaderConfig
from src.server.offline.dfa_combiner import rules_to_odfa_and_dfa_trans
from src.server.offline.dfa_optimizer.sparsity_analysis import analyze_odfa_sparsity
from src.server.offline.dfa_optimizer.char_grouping import build_row_alphabets_from_dfa_trans, RowAlphabet
from src.server.offline.key_generator import (
    make_offline_pad_seed_fn,
    derive_seed_from_gk,
    derive_deterministic_gk_table,   # 新增的 GK 生成器
)
from src.server.offline.gdfa_builder import build_gdfa_stream, GDFAStream, GDFAPublicHeader
from src.server.offline.export.gdfa_packager import write_container, write_jsonbin

from src.common.odfa.params import SecurityParams, SparsityParams
from src.common.odfa.seed_rules import PRG_LABEL_CELL  # for manifest only


# ---------- helpers: outputs ----------

def _write_row_alph(outdir: str, row_alph: List[RowAlphabet]) -> str:
    """
    寫出逐列 256B 的 byte->column 映射：
      - row_alph.bin:  num_states × 256 bytes，row-major
      - row_alph.json: metadata（列數、每列欄數）
    """
    os.makedirs(outdir, exist_ok=True)
    bin_path = os.path.join(outdir, "row_alph.bin")
    meta_path = os.path.join(outdir, "row_alph.json")

    with open(bin_path, "wb") as f:
        for ra in row_alph:
            if len(ra.byte_to_col) != 256:
                raise ValueError("RowAlphabet.byte_to_col must have 256 entries")
            f.write(bytes(ra.byte_to_col))

    meta = {
        "num_rows": len(row_alph),
        "cols_per_row": [ra.num_cols for ra in row_alph],
        "format": "row-major, each row has 256 bytes; value = column index (0..num_cols-1)",
    }
    with open(meta_path, "wb") as mf:
        mf.write(json.dumps(meta, indent=2, sort_keys=True).encode("utf-8"))

    return bin_path


def _write_gk_table(outdir: str, gk_table: List[List[bytes]]) -> Dict[str, str]:
    """
    寫出 GK 表：
      - gk_table.bin:  row-major，對每列串接 m 個 GK（無 padding）；變長列以 meta 還原
      - gk_meta.json:  {num_rows, cols_per_row, k_bytes, sha256(bin)}
    """
    os.makedirs(outdir, exist_ok=True)
    bin_path = os.path.join(outdir, "gk_table.bin")
    meta_path = os.path.join(outdir, "gk_meta.json")

    if not gk_table:
        raise ValueError("GK table empty")
    cols_per_row = [len(row) for row in gk_table]
    if any(m <= 0 for m in cols_per_row):
        raise ValueError("GK table row with zero columns")
    klen0 = len(gk_table[0][0])
    for r, row in enumerate(gk_table):
        for c, gk in enumerate(row):
            if len(gk) != klen0:
                raise ValueError(f"GK length mismatch at row {r} col {c}")

    with open(bin_path, "wb") as f:
        for row in gk_table:
            for gk in row:
                f.write(gk)
    with open(bin_path, "rb") as f:
        blob = f.read()
    sha = hashlib.sha256(blob).hexdigest()

    meta = {
        "num_rows": len(gk_table),
        "cols_per_row": cols_per_row,
        "k_bytes": klen0,
        "rows_sha256": sha,
        "format": "row-major; concatenate m keys per row; recover via cols_per_row & k_bytes",
    }
    with open(meta_path, "wb") as mf:
        mf.write(json.dumps(meta, indent=2, sort_keys=True).encode("utf-8"))

    return {"path": bin_path, "sha256": sha, "k_bytes": str(klen0)}


def _write_manifest(outdir: str,
                    rules_sources: List[str],
                    pub: GDFAPublicHeader,
                    outmax_used: int,
                    cmax_used: int,
                    row_alph_path: str,
                    params: Dict[str, int],
                    rows_blob_hash: Optional[str] = None,
                    gk_info: Optional[Dict[str, str]] = None,
                    seed_mode: str = "random") -> None:
    mani = {
        "sources": rules_sources,
        "alphabet_size": pub.alphabet_size,
        "outmax_used": outmax_used,
        "cmax_used": cmax_used,
        "num_states": pub.num_states,
        "cell_bytes": pub.cell_bytes,
        "row_bytes": pub.row_bytes,
        "aid_bits": pub.aid_bits,
        "start_row": pub.start_row,
        "permutation_len": len(pub.permutation),
        "row_alph_bin": os.path.basename(row_alph_path),
        "crypto_params": params,
        "prg_label": PRG_LABEL_CELL.decode() if isinstance(PRG_LABEL_CELL, (bytes, bytearray)) else str(PRG_LABEL_CELL),
        "seed_mode": seed_mode,  # "master->seed" | "master->GK->seed" | "random"
    }
    if rows_blob_hash:
        mani["rows_sha256"] = rows_blob_hash
    if gk_info:
        mani["gk_table_bin"] = os.path.basename(gk_info["path"])
        mani["gk_table_sha256"] = gk_info["sha256"]
        mani["gk_bytes"] = int(gk_info["k_bytes"])
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "manifest.json"), "wb") as f:
        f.write(json.dumps(mani, indent=2, sort_keys=True).encode("utf-8"))


def _maybe_dump_secrets(outdir: str, stream: GDFAStream, mode: str) -> None:
    if mode == "none":
        return
    obj = {"inv_permutation": stream.secrets.inv_permutation}
    if mode == "full":
        obj["pad_seeds_hex"] = [[s.hex() for s in row] for row in stream.secrets.pad_seeds]
    with open(os.path.join(outdir, "secrets.json"), "wb") as f:
        f.write(json.dumps(obj, indent=2, sort_keys=True).encode("utf-8"))


# ---------- args & main ----------

def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build GDFA (offline) directly from rule files")
    p.add_argument("rules", nargs="+", help="One or more rule sources (*.rules / *.txt)")
    p.add_argument("--outdir", default="dist/zids", help="Output directory")
    p.add_argument("--format", choices=["container", "jsonbin"], default="container")
    p.add_argument("--gzip-header", action="store_true", help="GZip header.json when using jsonbin format")
    p.add_argument("--container-path", help="Explicit output path for .gdfa")

    # rule loader config
    p.add_argument("--combine-contents", action="store_true", help="Combine multiple content in the same rule into a single regex with bounded gaps")
    p.add_argument("--content-gap-max", type=int, default=512)
    p.add_argument("--default-dotall", action="store_true", help="Default to dotall on regex ('.' matches LF)")

    # crypto/packing params
    p.add_argument("--k", type=int, default=128)
    p.add_argument("--kprime", type=int, default=128)
    p.add_argument("--kappa", type=int, default=128)
    p.add_argument("--alphabet", type=int, default=256)
    p.add_argument("--aid-bits", type=int, default=16)

    # sparsity / grouping
    p.add_argument("--outmax", type=int, help="Override suggested outmax (default: use max outdegree)")
    p.add_argument("--cmax", type=int, default=1)

    # seeds (mutually exclusive):
    p.add_argument("--master-key-hex", help="Deterministic SEEDs: seed = PRF(master, seed_info(row,col))")
    p.add_argument("--gk-from-master-hex", help="Deterministic GK then SEEDs: GK=PRF(master,'ZIDS|GK|row|col'); seed=PRF(GK,seed_info(row,col))")
    p.add_argument("--gk-bytes", type=int, default=32, help="GK byte length when using --gk-from-master-hex")

    # secrets dump
    p.add_argument("--save-secrets", choices=["none", "invperm", "full"], default="none")

    return p.parse_args(argv)


def main(argv: List[str]) -> None:
    args = parse_args(argv)

    # seeds mode sanity
    if args.master_key_hex and args.gk_from_master_hex:
        raise SystemExit("Use either --master-key-hex OR --gk-from-master-hex (they are mutually exclusive).")

    # 1) Load rules
    lcfg = LoaderConfig(
        combine_contents=args.combine_contents,
        content_gap_max=args.content_gap_max,
        default_dotall=args.default_dotall,
    )
    specs = load_rules(args.rules, cfg=lcfg)
    if not specs:
        raise SystemExit("No rules loaded.")

    # 2) Compile → (ODFA, DFA trans)
    odfa, dfa_trans = rules_to_odfa_and_dfa_trans(specs, aggregate="min")

    # 3) Sparsity analysis → suggest outmax/cmax
    rep = analyze_odfa_sparsity(odfa)
    outmax = args.outmax if args.outmax is not None else rep.suggest_outmax
    cmax = args.cmax
    if cmax != 1:
        raise SystemExit("For faithful replication of the paper, please use cmax=1 (partition per row).")

    # 4) Build per-row alphabets (public; used by client query builder)
    row_alph = build_row_alphabets_from_dfa_trans(dfa_trans, outmax=outmax, cmax=cmax)
    row_alph_path = _write_row_alph(args.outdir, row_alph)

    # 5) Security & sparsity params
    sec = SecurityParams(k_bits=args.k, kprime_bits=args.kprime, kappa=args.kappa, alphabet_size=args.alphabet)
    sp = SparsityParams(outmax=outmax, cmax=cmax)

    # 6) Decide pad_seed_fn mode
    pad_seed_fn = None
    gk_info: Optional[Dict[str, str]] = None
    seed_mode = "random"

    if args.gk_from_master_hex:
        # GK 決定性 → pad seeds 由 GK 導出（與線上端完全一致）
        try:
            master_gk = bytes.fromhex(args.gk_from_master_hex)
        except ValueError as e:
            raise SystemExit(f"invalid --gk-from-master-hex: {e}")
        if args.gk_bytes <= 0:
            raise SystemExit("--gk-bytes must be positive")
        # 依 cols_per_row 生成 GK 表
        cols_per_row = [ra.num_cols for ra in row_alph]
        gk_table = derive_deterministic_gk_table(master_gk, cols_per_row=cols_per_row, k_bytes=args.gk_bytes)
        # 輸出 GK 表供線上端載入/驗證
        gk_info = _write_gk_table(args.outdir, gk_table)

        def pad_seed_from_gk(row: int, col: int, k_bytes: int) -> bytes:
            return derive_seed_from_gk(gk_table[row][col], row, col, k_bytes)

        pad_seed_fn = pad_seed_from_gk
        seed_mode = "master->GK->seed"

    elif args.master_key_hex:
        # 直接用 master → SEED（研究/測試友善；線上須用相同規則才能解）
        try:
            master = bytes.fromhex(args.master_key_hex)
        except ValueError as e:
            raise SystemExit(f"invalid --master-key-hex: {e}")
        pad_seed_fn = make_offline_pad_seed_fn(master)
        seed_mode = "master->seed"

    else:
        # 無指定時，使用隨機（不可重現；線上需同步記錄 seeds 或改用 GK 模式）
        pad_seed_fn = None
        seed_mode = "random"

    # 7) Build GDFA stream
    stream: GDFAStream = build_gdfa_stream(odfa, sec, sp, aid_bits=args.aid_bits, pad_seed_fn=pad_seed_fn)
    pub = stream.public
    rows_list = list(stream.rows)  # materialize for hashing/packaging
    rows_blob = b"".join(rows_list)
    rows_hash = hashlib.sha256(rows_blob).hexdigest()

    # 8) Package
    if args.format == "container":
        path = args.container_path or os.path.join(args.outdir, "gdfa.gdfa")
        write_container(path, pub, rows_list)
    else:
        write_jsonbin(args.outdir, pub, rows_list, gzip_header=args.gzip_header)

    # 9) Optional secrets (CAUTION)
    _maybe_dump_secrets(args.outdir, stream, args.save_secrets)

    # 10) Manifest
    _write_manifest(
        args.outdir,
        rules_sources=list(args.rules),
        pub=pub,
        outmax_used=outmax,
        cmax_used=cmax,
        row_alph_path=row_alph_path,
        params={"k": args.k, "kprime": args.kprime, "kappa": args.kappa},
        rows_blob_hash=rows_hash,
        gk_info=gk_info,
        seed_mode=seed_mode,
    )

    # 11) Summary
    print("=== ZIDS offline build (from rules) ===")
    print(f"rules       : {len(specs)} patterns (from {len(args.rules)} file(s))")
    print(f"states      : {pub.num_states}")
    print(f"outmax/cmax : {outmax}/{cmax}")
    print(f"cell/row    : {pub.cell_bytes} B / {pub.row_bytes} B")
    print(f"start_row   : {pub.start_row}")
    print(f"row_alph    : {row_alph_path}")
    if gk_info:
        print(f"GK table    : {gk_info['path']}  (sha256={gk_info['sha256'][:16]}...)  k_bytes={gk_info['k_bytes']}")
    print(f"rows sha256 : {rows_hash}")
    print(f"seeds       : {seed_mode}")
    print("Done.")


if __name__ == "__main__":
    main(sys.argv[1:])
