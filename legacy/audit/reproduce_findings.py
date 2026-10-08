"""Read-only probes for the 2026-10-02 paper conformance audit.

Run from the repository root with Python 3.12 and the existing environment.
Only the requested JSON output and temporary synthetic fixtures are written.
These probes characterize the audited implementation, they do not certify it.
"""
from __future__ import annotations

import argparse
import contextlib
import csv
import dataclasses
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import struct
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
RESULTS = []


def record(name, function):
    started = time.perf_counter()
    captured = io.StringIO()
    try:
        with contextlib.redirect_stdout(captured):
            result = function()
        RESULTS.append(dict(probe=name, completed=True, result=result,
                            seconds=round(time.perf_counter() - started, 4)))
    except Exception as error:
        RESULTS.append(dict(probe=name, completed=False,
                            error=f"{type(error).__name__}: {error}"))


def exception_of(function):
    try:
        return dict(returned=function())
    except BaseException as error:
        return dict(error=f"{type(error).__name__}: {error}")


def xor_all(items):
    result = bytearray(len(items[0]))
    for item in items:
        for i, value in enumerate(item):
            result[i] ^= value
    return bytes(result)


def ot_parity():
    from src.common.ot.ot_1ofm import OT1ofmSender
    # BYTES mode does not need a group until an actual base OT is performed.
    messages = [bytes([x]) * 16 for x in (0, 1, 2, 4)]
    service = OT1ofmSender(None, messages, label=b"audit")
    leaked = xor_all(service.ciphertexts)
    return dict(ciphertext_xor=leaked.hex(), plaintext_xor=xor_all(messages).hex(),
                unchosen_messages_relation_leaked=leaked == xor_all(messages),
                ot_queries_needed=0)


def base_ot_malicious_sender():
    from src.common.crypto.ddh_group import DDHGroup
    from src.common.ot.base_ot2.ddh_ot import DDHOTReceiver
    group = DDHGroup()
    attacker_public_key = group.p - 1
    results = []
    for choice in (0, 1):
        receiver = DDHOTReceiver(group, choice)
        response = receiver.generate_B(attacker_public_key)
        inferred = 0 if pow(response, group.q, group.p) == 1 else 1
        results.append(dict(actual_choice=choice, inferred_from_public_response=inferred))
    return dict(malicious_A="p - 1", rejected=False, results=results)


def packing_and_decoder():
    from src.common.odfa.params import SecurityParams, SparsityParams, make_packing
    from src.common.odfa.packing import plan_cell_format
    from src.server.offline.gdfa_builder import _pack_bits
    from src.client.online.engine import ZIDSEngine
    from src.client.online.gdfa_evaluator import _unpack_cell, CellFormat
    pack = make_packing(SecurityParams(), SparsityParams(outmax=3, cmax=1))
    fmt = plan_cell_format(3, pack, aid_bits=16)
    engine = ZIDSEngine.__new__(ZIDSEngine)
    engine.gdfa = SimpleNamespace(num_states=3, aid_bits=16)
    plain = _pack_bits(1, 7, fmt)
    legacy = CellFormat(fmt.ns_bits, fmt.aid_bits, fmt.pad_bits)
    corrupted = b"\x00" + b"\xff" * (fmt.total_bytes - 1)
    return dict(expected=[1, 7], current_decoder=engine._decode_cell_plain(plain),
                legacy_decoder=_unpack_cell(plain, legacy),
                nonzero_padding_accepted=engine._decode_cell_plain(corrupted),
                entry_bytes=fmt.total_bytes,
                row_bytes=fmt.total_bytes * 3,
                outmax_in_entry_size=True)


def permutation_direction():
    from src.client.io.gdfa_loader import GDFAHeader, GDFAImage
    header = GDFAHeader(256, 1, 1, 3, 0, [2, 0, 1], 16, 16, 8)
    image = GDFAImage(header, bytes(48))
    return dict(public_new_to_old=header.permutation,
                expected_new_row_0_logical_state=2,
                actual_inv_permute_0=image.inv_permute(0))


def dfa_accepts(dfa, data):
    state = dfa.start
    for byte in data:
        state = dfa.trans[state].get(byte, -1)
        if state < 0:
            return False
    return state in dfa.accept


def regex_semantics():
    from src.server.offline.rules_to_dfa.regex_to_dfa import compile_regex_to_dfa, RegexFlags
    examples = [
        (r"a{2}", b"aaa", False, True),
        (r"[^a]", b"a", True, True),
        (r"\d", b"5", False, True),
        (r"^abc$", b"abc", False, False),
        (r"\x41", b"a", True, True),
        (r"abc", b"abcZ", False, False),
    ]
    results = []
    for pattern, data, ignore_case, anchored in examples:
        flags = RegexFlags(ignore_case=ignore_case, anchored=anchored, dotall=False)
        dfa = compile_regex_to_dfa(pattern, flags=flags)
        python_flags = re.IGNORECASE if ignore_case else 0
        expected = bool((re.fullmatch if anchored else re.search)(pattern.encode(), data, python_flags))
        results.append(dict(pattern=pattern, data=data.decode(), anchored=anchored,
                            ignore_case=ignore_case, expected=expected,
                            actual=dfa_accepts(dfa, data)))
    results.append(dict(pattern="a", integer_flags=exception_of(
        lambda: len(compile_regex_to_dfa("a", flags=re.IGNORECASE).trans))))
    results.append(dict(pattern="a{3,2}", invalid_repeat=exception_of(
        lambda: dfa_accepts(compile_regex_to_dfa("a{3,2}"), b"aaa"))))
    return results


def global_groups():
    from src.server.offline.rules_to_dfa.regex_to_dfa import compile_regex_to_dfa
    from src.server.offline.dfa_optimizer.char_grouping import build_row_alphabets_from_dfa_trans
    from src.server.offline.dfa_optimizer.sparsity_analysis import analyze_odfa_sparsity
    from src.server.offline.rules_to_dfa.regex_to_dfa import dfa_to_odfa
    dfa = compile_regex_to_dfa("ab")
    ras = build_row_alphabets_from_dfa_trans(dfa.trans, outmax=256)
    groups = {tuple(group) for ra in ras for group in ra.columns}
    counts = [sum(x in group for group in groups) for x in range(256)]
    return dict(pattern="ab", global_group_count=len(groups), paper_cmax=max(counts),
                implementation_suggest_cmax=analyze_odfa_sparsity(dfa_to_odfa(dfa)).suggest_cmax)


def allow_aggregation():
    from src.server.offline.rules_to_dfa.chain_rules import (
        _union_dfas, tagged_dfa_to_odfa, compile_regex_to_dfa,
    )
    from src.client.online.abp_decide import decide_from_rule_ids
    td = _union_dfas([(compile_regex_to_dfa("x"), 1), (compile_regex_to_dfa("x"), 2)])
    target = td.trans[td.start][ord("x")]
    odfa = tagged_dfa_to_odfa(td)
    returned = odfa.accepting[target]
    return dict(correct_tags=sorted(td.tags[target]), aggregated_id=returned,
                expected=decide_from_rule_ids([1, 2], {1: "BLOCK", 2: "ALLOW"}),
                actual=decide_from_rule_ids([returned], {1: "BLOCK", 2: "ALLOW"}))


def easylist_semantics():
    from src.server.io.easylist_loader import _abp_rule_to_regex
    from src.server.io.rule_loader import load_rules
    from src.common import abp_canonicalize
    from tools.build_artifacts import _sanitize_specs_for_dfa
    examples = [
        ("||ads.example^", "https://ads.example/", True),
        ("/ads/*", "https://site.example/ads/banner.js", True),
        ("|https://ads.example/", "https://ads.example/", True),
        ("||ads.example^", "https://ads.example:8443/", True),
        ("||ads.example^$script", "https://ads.example/", None),
        ("@@||ads.example^", "https://ads.example/", True),
    ]
    rows = []
    with patch.object(abp_canonicalize, "_party_char", return_value="T"):
        for rule, url, expected in examples:
            pattern, flags = _abp_rule_to_regex(rule)
            normalized = abp_canonicalize.canonicalize_for_abp(url, "", "image")
            rows.append(dict(rule=rule, raw_url=url, expected_url_match=expected,
                             regex_on_url=bool(re.search(pattern, url, flags)),
                             regex_on_abp_payload=bool(re.search(pattern, normalized, flags)),
                             converted_pattern=pattern))
    with tempfile.TemporaryDirectory(prefix="zids-audit-") as tmp:
        rulefile = Path(tmp) / "rules.abp"
        rulefile.write_text("@@||ads.example^\n", encoding="utf-8")
        spec = load_rules([str(rulefile)])[0]
        sanitized = _sanitize_specs_for_dfa([spec])[0]
        rows.append(dict(loader_action=getattr(spec, "action", "MISSING"),
                         loader_ignore_case=spec.flags.ignore_case,
                         sanitized_action=sanitized.action,
                         sanitized_flags=int(sanitized.flags),
                         sanitized_ignore_case=sanitized.ignore_case))
    return rows


def benchmark_reinitialization():
    from tools.run_dfa_with_abp import evaluate_rule_ids_via_engine
    events = []
    fake = SimpleNamespace(init_for_cli=lambda cfg: events.append("init"),
                           eval_rule_ids=lambda data: [1])
    with patch.dict(sys.modules, {"audit_fake_engine": fake}):
        for unused in range(3):
            evaluate_rule_ids_via_engine("abc", "audit_fake_engine", {"config": True})
    return dict(evaluations=3, initialization_calls=len(events))


def session_keys():
    from src.server.online.session_manager import SessionManager, SessionConfig
    from src.server.online.ot_response_builder import RowAlphMeta
    manager = SessionManager(RowAlphMeta(1, [2], "single8"),
                             SessionConfig(master_key=b"audit synthetic secret", k_bytes=32))
    a = manager.create_session()
    b = manager.create_session()
    return dict(different_sessions=a.session_id != b.session_id,
                identical_key_tables=a.gk_store.table == b.gk_store.table)


def actual_artifact_decryption():
    from src.client.online.chooser_master import MasterChooser
    from src.client.io.gdfa_loader import load_gdfa
    from src.common.odfa.seed_rules import seed_from_gk, PRG_LABEL_CELL
    from src.common.crypto.prg import prg
    cfg = json.loads((ROOT / "configs/engine_init_small.json").read_text())
    chooser = MasterChooser(master_hex=cfg["chooser_kwargs"]["master_hex"], gk_bytes=32)
    image = load_gdfa(str(ROOT / cfg["gdfa"]))
    ns_bits = max(1, (image.num_states - 1).bit_length())
    valid = 0
    for row in range(image.num_states):
        for col in range(image.outmax):
            seed = seed_from_gk(chooser.choose_one(row, col), row, col, 32)
            plain = bytes(a ^ b for a, b in zip(image.get_cell_cipher(row, col),
                                              prg(seed, PRG_LABEL_CELL, image.cell_bytes)))
            value = int.from_bytes(plain, "little")
            next_state = value & ((1 << ns_bits) - 1)
            valid += int(value >> (ns_bits + image.aid_bits) == 0 and next_state < image.num_states)
    return dict(artifact="artifacts/small/gdfa.bin", cells=image.num_states * image.outmax,
                valid_decrypted_cells=valid, server_requests=0,
                key_source="Existing client configuration, value omitted")


def actual_small_engine():
    from src.client.online.engine import ZIDSEngine, EngineConfig
    from src.client.online.chooser_master import MasterChooser
    from src.client.io.gdfa_loader import load_gdfa
    from src.client.io.row_alph_loader import load_row_alph
    from src.common import abp_canonicalize
    cfg = json.loads((ROOT / "configs/engine_init_small.json").read_text())
    engine = ZIDSEngine(load_gdfa(str(ROOT / cfg["gdfa"])),
                        load_row_alph(str(ROOT / cfg["rowalph"])),
                        MasterChooser(master_hex=cfg["chooser_kwargs"]["master_hex"], gk_bytes=32),
                        EngineConfig(session_id="audit", k_bytes=32))
    engine._pad_mode = "rowcol"
    engine._gk_row_index_mode = "per"
    results = []
    with patch.object(abp_canonicalize, "_party_char", return_value="T"):
        for url in ("https://0cf.io/", "https://adv.gg/", "https://unmatched.example/"):
            payload = abp_canonicalize.canonicalize_for_abp(url, "", "image")
            results.append(dict(url=url, direct_bytes_ids=engine._run_bytes(url.encode()),
                                public_run_ids=engine.run(url.encode()),
                                abp_payload_ids=engine.run_abp_payload(payload)))
    return dict(actual_network_requests=0, results=results)


def http_wire_semantics():
    from src.client.online.token_http import _OTRowChooser
    from src.server.ot.dev_ot_server import Handler
    calls = []
    synthetic_master = "ab" * 32

    def post(url, **kwargs):
        payload = kwargs["json"]
        calls.append(dict(endpoint=url.rsplit("/", 1)[-1],
                          fields=sorted(payload), row=payload.get("row"), col=payload.get("col")))
        sink = io.BytesIO()
        fake = SimpleNamespace(path="/ot/" + url.rsplit("/", 1)[-1],
                               _read_json=lambda: payload, wfile=sink,
                               send_response=lambda *a: None,
                               send_header=lambda *a: None, end_headers=lambda: None)
        Handler.do_POST(fake)
        content = sink.getvalue()
        return SimpleNamespace(content=content, raise_for_status=lambda: None,
                               json=lambda: json.loads(content))

    with patch("src.client.online.token_http.requests.post", side_effect=post):
        chooser = _OTRowChooser("http://audit.invalid", synthetic_master)
        key0 = chooser.choose_one(5, 0)
        key1 = chooser.choose_one(5, 1)
    return dict(captured_json_fields=calls, different_columns_same_key=key0 == key1,
                actual_network_requests=0)


def legacy_garbling():
    from src.common.odfa.matrix import ODFA, ODFARow, ODFAEdge
    from src.common.odfa.params import SecurityParams, SparsityParams
    from src.server.offline.gdfa_builder import build_gdfa_stream
    from src.common.crypto.prg import G_bits, prg
    from src.common.odfa.seed_rules import PRG_LABEL_CELL
    from src.client.online.gdfa_evaluator import LocalSeedOracle
    odfa = ODFA(2, 0, {1: 1}, [ODFARow([ODFAEdge(0, 1)]), ODFARow([ODFAEdge(0, 1)])])
    stream = build_gdfa_stream(odfa, SecurityParams(), SparsityParams(1, 1))
    seed = stream.secrets.pad_seeds[0][0]
    legacy_pad = LocalSeedOracle(stream.public, stream.secrets).derive_for_row(0, 0)[1]
    current_pad = prg(seed, PRG_LABEL_CELL, stream.public.cell_bytes)
    return dict(same_seed=True, pad_matches=legacy_pad == current_pad,
                builder_label=PRG_LABEL_CELL.decode(), legacy_label="PRG|GDFA|cell")


def default_build_and_idmap():
    from src.server.io.rule_loader import load_rules
    from tools.build_artifacts import _prefilter_specs, _sanitize_specs_for_dfa
    from src.server.offline.dfa_combiner import rules_to_odfa_and_dfa_trans
    from src.server.offline.gdfa_builder import build_gdfa_stream
    from src.common.odfa.params import SecurityParams, SparsityParams
    with tempfile.TemporaryDirectory(prefix="zids-audit-") as tmp:
        p = Path(tmp) / "r.abp"
        p.write_text("||ads.example^\n", encoding="utf-8")
        specs = load_rules([str(p)])
        prefiltered = _prefilter_specs(specs, profile=False)
        sanitized = _sanitize_specs_for_dfa(prefiltered)
        odfa, trans = rules_to_odfa_and_dfa_trans(sanitized)
        def build():
            stream = build_gdfa_stream(odfa, SecurityParams(), SparsityParams(256, 1))
            return next(iter(stream.rows))
        # The build API receives no master, so regenerated rows differ and no
        # online chooser in this pipeline is given the randomly sampled seeds.
        a = build()
        b = build()
        return dict(prefiltered=len(prefiltered), rebuilt_ciphertexts_differ=a != b,
                    online_key_material_exported_by_tools_build_artifacts=False)


def optional_backend_and_helpers():
    from src.common.ot.base_ot2.iknp_extention import OTExtension
    from src.scripts.easylist_make_smallset import Rule, pos_neg_for_rule
    from src.server.io.easylist_loader import _abp_rule_to_regex
    from tools import bench_zids, run_dfa_with_abp
    from src.client.online.abp_decide import decide_from_rule_ids
    neg = pos_neg_for_rule(Rule("ads"))[1]
    pattern, flags = _abp_rule_to_regex("ads")
    result = dict(iknp_backend=type(OTExtension(SimpleNamespace(q=23), backend="iknp").impl).__name__,
                  generated_negative=neg,
                  negative_actually_matches=bool(re.search(pattern, neg, flags)),
                  singleton_percentile=exception_of(lambda: bench_zids._percentile([1.0], 50)),
                  unknown_id_library=decide_from_rule_ids([999], {1: "BLOCK"}),
                  unknown_id_cli=run_dfa_with_abp.decide_from_rule_ids([999], {"1": "BLOCK"}),
                  offline_setup_import=exception_of(lambda: str(importlib.import_module("src.client.offline.param_setup"))))
    from src.client.online import engine
    with tempfile.TemporaryDirectory(prefix="zids-audit-") as tmp:
        p = Path(tmp) / "r.abp"
        p.write_text("foo\n", encoding="utf-8")
        with patch.object(engine, "ENGINE", None), patch.object(engine, "_REGEX_COMPILED", []):
            engine.init_for_cli({"easylist": str(p)})
            result["regex_fallback_first_rule_id"] = engine.eval_rule_ids("foo")
    return result


def rule_id_drift():
    from src.server.offline.rules_to_dfa.chain_rules import RuleSpec
    from tools.build_artifacts import _prefilter_specs, _sanitize_specs_for_dfa
    from src.server.io.rule_loader import load_rules
    previous = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="zids-audit-") as tmp:
        try:
            os.chdir(tmp)
            specs = [RuleSpec("(", 1), RuleSpec("good", 2)]
            kept = _prefilter_specs(specs, profile=False)
            normalized = _sanitize_specs_for_dfa(kept)
            one = Path("one.regex")
            two = Path("two.regex")
            one.write_text("one\n")
            two.write_text("two\n")
            combined = load_rules([str(one), str(two)])
            return dict(original_survivor_id=kept[0].attack_id,
                        id_after_sanitizing=normalized[0].attack_id,
                        multi_file_rule_ids=[s.attack_id for s in combined])
        finally:
            os.chdir(previous)


def data_and_artifacts():
    artifacts, configs, rulefiles, datasets, csv_files, summaries = [], [], [], [], [], []
    for directory in (ROOT / "artifacts", ROOT / "out"):
        for path in sorted(directory.rglob("gdfa.bin")):
            with path.open("rb") as f:
                magic = f.read(7)
                if magic != b"ZIDSv1\0":
                    artifacts.append(dict(file=path.relative_to(ROOT).as_posix(), error="magic"))
                    continue
                hlen = struct.unpack(">I", f.read(4))[0]
                h = json.loads(f.read(hlen))
            meta = json.loads(path.with_name("row_alph.json").read_text(encoding="utf-8-sig"))
            mapping = path.with_name("row_alph.bin").read_bytes()
            aids_path = path.with_name("row_aids.bin")
            aids = []
            if aids_path.exists():
                blob = aids_path.read_bytes()
                width = len(blob) // h["num_states"]
                if width in (2, 4) and len(blob) == width * h["num_states"]:
                    aids = [int.from_bytes(blob[i:i + width], "little") for i in range(0, len(blob), width)]
            invalid = sum(mapping[r * 256 + b] >= meta["cols_per_row"][r]
                          for r in range(meta["num_rows"]) for b in range(256))
            artifacts.append(dict(file=path.relative_to(ROOT).as_posix(), bytes=path.stat().st_size,
                                  states=h["num_states"], outmax=h["outmax"], cmax=h["cmax"],
                                  start_row=h["start_row"], cell_bytes=h["cell_bytes"], row_bytes=h["row_bytes"],
                                  actual_outmax=max(meta["cols_per_row"]),
                                  identity_permutation=h["permutation"] == list(range(h["num_states"])),
                                  structure_length_ok=path.stat().st_size == 11 + hlen + h["num_states"] * h["row_bytes"] + 32,
                                  alphabet_rows_match=meta["num_rows"] == h["num_states"],
                                  invalid_alphabet_entries=invalid,
                                  distinct_positive_aids=len(set(aids) - {0}),
                                  body_hash_recomputed=False))
    for path in sorted((ROOT / "configs").glob("*.json")):
        cfg = json.loads(path.read_text(encoding="utf-8-sig"))
        configs.append(dict(file=path.relative_to(ROOT).as_posix(),
                            gdfa=cfg.get("gdfa"), rowalph=cfg.get("rowalph"),
                            artifact_exists=(ROOT / cfg.get("gdfa", "")).exists(),
                            chooser=cfg.get("chooser_cls"),
                            contains_master="master_hex" in cfg.get("chooser_kwargs", {}),
                            reads_gk_index="gk_index" in cfg,
                            ignored_gk_index_mode="gk_index_mode" in cfg))
    for path in sorted((ROOT / "rules").rglob("*")):
        if not path.is_file():
            continue
        lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        useful = [s.strip() for s in lines if s.strip() and not s.startswith(("!", "["))]
        row = dict(file=path.relative_to(ROOT).as_posix(), lines=len(lines), useful=len(useful), unique=len(set(useful)))
        if "dataset" in path.parts:
            row["all_url_only"] = all("|" not in s for s in useful)
            level = path.stem.removeprefix("dataset_L").removesuffix("_urls")
            rule_path = ROOT / "rules" / "input200" / f"easylist_{level}.abp"
            domains = {s.strip()[2:-1] for s in rule_path.read_text(encoding="utf-8-sig").splitlines()
                       if s.strip().startswith("||") and s.strip().endswith("^")}
            from urllib.parse import urlsplit
            expected_positive = sum(any((urlsplit(s).hostname or "").lower() == d.lower() or
                                       (urlsplit(s).hostname or "").lower().endswith("." + d.lower())
                                       for d in domains) for s in useful)
            row["expected_domain_rule_positives"] = expected_positive
            datasets.append(row)
        else:
            row.update(domain_anchor=sum(s.startswith("||") for s in useful),
                       allow=sum(s.startswith("@@") for s in useful), options=sum("$" in s for s in useful),
                       cosmetic=sum("##" in s or "#@#" in s for s in useful))
            rulefiles.append(row)
    for path in sorted((ROOT / "out").rglob("*.csv")):
        with path.open(encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
        csv_files.append(dict(file=path.relative_to(ROOT).as_posix(), rows=len(rows),
                              engine_nomatch=sum(r.get("engine_verdict") == "NOMATCH" for r in rows),
                              regex_nomatch=sum(r.get("regex_verdict") == "NOMATCH" for r in rows),
                              agreement_cells=sum(bool(r.get("agree")) for r in rows)))
    for path in sorted((ROOT / "out").rglob("pipeline_summary.json")):
        summary = json.loads(path.read_text(encoding="utf-8-sig"))
        summaries.append(dict(file=path.relative_to(ROOT).as_posix(), **summary))
    return dict(artifacts=artifacts, configs=configs, rulefiles=rulefiles, datasets=datasets,
                csv_files=csv_files, summaries=summaries)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    probes = [ot_parity, base_ot_malicious_sender, packing_and_decoder, permutation_direction, regex_semantics,
              global_groups, allow_aggregation, easylist_semantics,
              benchmark_reinitialization, session_keys, actual_artifact_decryption, actual_small_engine,
              http_wire_semantics, legacy_garbling,
              default_build_and_idmap, optional_backend_and_helpers, rule_id_drift, data_and_artifacts]
    for probe in probes:
        record(probe.__name__, probe)
    output = json.dumps(RESULTS, ensure_ascii=False, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output + "\n", encoding="utf-8")
    for item in RESULTS:
        result = item.get("result", {})
        if item["probe"] == "data_and_artifacts" and item["completed"]:
            result = {key: len(value) for key, value in result.items()}
        print(json.dumps(dict(probe=item["probe"], completed=item["completed"],
                              result=result, error=item.get("error")), ensure_ascii=False))
    return int(any(not item["completed"] for item in RESULTS))


if __name__ == "__main__":
    raise SystemExit(main())
