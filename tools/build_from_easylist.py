# -*- coding: utf-8 -*-
import argparse, json, os
from typing import List, Tuple
from src.server.io.easylist_loader import parse_easylist
from src.server.offline.dfa_combiner import rules_to_odfa_and_dfa_trans
from src.server.offline.dfa_optimizer.sparsity_analysis import analyze_odfa_sparsity
from src.server.offline.gdfa_builder import build_gdfa_stream
from src.server.offline.export.gdfa_packager import write_container, write_jsonbin
from src.server.offline.key_generator import derive_deterministic_gk_table, make_offline_pad_seed_fn
from src.server.offline.gdfa_builder import GDFAPublicHeader
from src.server.offline.dfa_optimizer.char_grouping import RowAlphabet

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--easylist", required=True)
    ap.add_argument("--outdir", default="dist/easylist_art")
    ap.add_argument("--k", type=int, default=128, help="seed bits for pad PRG")
    ap.add_argument("--gk-bytes", type=int, default=32)
    ap.add_argument("--outmax", type=int, default=8)
    ap.add_argument("--cmax", type=int, default=4)
    ap.add_argument("--master", help="hex master for GK (optional; omit to write gk_table.bin)")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    with open(args.easylist, "r", encoding="utf-8") as f:
        rules = parse_easylist(f)

    # 1) EasyList → 正则列表（regex, label）
    pairs: List[Tuple[str,str]] = [(r.pattern, r.label) for r in rules]

    # 2) 规则 → ODFA + 转移
    odfa, dfa_trans, accepting_map = rules_to_odfa_and_dfa_trans(
        pairs, alphabet="ASCII"
    )

    # 3) 稀疏度分析（决定 outmax/cmax 的合理性）
    sparsity = analyze_odfa_sparsity(odfa)
    # 可选：你可以根据 sparsity 建议调整 outmax/cmax；这里直接使用入参

    # 4) 生成 GK（两种模式：master 或离线文件）
    cols_per_row = [len(row) for row in dfa_trans]  # 每行有效列数
    if args.master:
        master = bytes.fromhex(args.master)
        gk_table = derive_deterministic_gk_table(master, cols_per_row, args.gk_bytes)
        # 不落地 gk_table.bin —— master 模式在线生成
        gk_meta = {"num_rows": len(cols_per_row), "cols_per_row": cols_per_row, "k_bytes": args.gk_bytes}
        write_jsonbin(os.path.join(args.outdir, "gk_meta.json"), gk_meta)  # 仅用于列数验证
    else:
        # 离线 GK 文件模式
        gk_table = derive_deterministic_gk_table(os.urandom(32), cols_per_row, args.gk_bytes)
        gk_meta = {"num_rows": len(cols_per_row), "cols_per_row": cols_per_row, "k_bytes": args.gk_bytes}
        write_jsonbin(os.path.join(args.outdir, "gk_meta.json"), gk_meta)
        with open(os.path.join(args.outdir, "gk_table.bin"), "wb") as f:
            for row in gk_table:
                for gk in row: f.write(gk)

    # 5) 构建 GDFA
    seed_fn = make_offline_pad_seed_fn(args.k)
    gdfa_stream, header, row_alph = build_gdfa_stream(
        odfa, dfa_trans,
        outmax=args.outmax, cmax=args.cmax,
        seed_fn=seed_fn, accepting_map=accepting_map
    )
    assert isinstance(header, GDFAPublicHeader)
    assert isinstance(row_alph, RowAlphabet)

    # 6) 打包输出
    write_container(os.path.join(args.outdir, "gdfa.gdfa"), header, gdfa_stream)
    with open(os.path.join(args.outdir, "row_alph.json"), "wb") as f:
        f.write(row_alph.to_json())

    manifest = {
        "version": 1,
        "alphabet": "ASCII",
        "states": header.num_states,
        "outmax": header.outmax, "cmax": header.cmax,
        "aid_bits": header.aid_bits,
        "start_row": header.start_row,
        "crypto_params": {"k": args.k},
        "gk_bytes": args.gk_bytes,
        "build_from": os.path.abspath(args.easylist),
    }
    with open(os.path.join(args.outdir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()