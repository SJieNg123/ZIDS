# tools/build_artifacts.py
from __future__ import annotations
import argparse, sys
from pathlib import Path
import runpy

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Build gdfa.bin & row_alph.* from EasyList using your offline builder"
    )
    ap.add_argument("--easylist", required=True, help="Path to EasyList (.txt)")
    ap.add_argument("--outdir", default="artifacts", help="Output directory")
    ap.add_argument("--format", choices=["container", "jsonbin"], default="container")
    ap.add_argument("--gzip-header", action="store_true", dest="gzip_header",
                    help="When using jsonbin format, also gzip header.json")
    ap.add_argument("--outmax", type=int, default=128)
    ap.add_argument("--cmax", type=int, default=1)
    ap.add_argument("--aid-bits", type=int, default=16)
    ap.add_argument("--master-key-hex")
    ap.add_argument("--gk-from-master-hex", dest="gk_from_master_hex")
    ap.add_argument("--gk-bytes", type=int, default=32)
    args = ap.parse_args()

    easylist = Path(args.easylist)
    if not easylist.exists():
        print(f"[error] EasyList not found: {easylist}", file=sys.stderr)
        sys.exit(2)

    # 準備要餵給 builder 的 argv（第一個位置參數就是規則檔）
    argv = [
        str(easylist),
        "--outdir", str(Path(args.outdir)),
        "--format", args.format,
        "--aid-bits", str(args.aid_bits),
        "--outmax", str(args.outmax),
        "--cmax", str(args.cmax),
    ]
    if args.gzip_header and args.format == "jsonbin":
        argv += ["--gzip-header"]
    if args.master_key_hex and args.gk_from_master_hex:
        print("[error] use either --master-key-hex or --gk-from-master-hex, not both.", file=sys.stderr)
        sys.exit(2)
    if args.master_key_hex:
        argv += ["--master-key-hex", args.master_key_hex]
    if args.gk_from_master_hex:
        argv += ["--gk-from-master-hex", args.gk_from_master_hex, "--gk-bytes", str(args.gk_bytes)]

    # 用 runpy 把模組當 __main__ 執行，**先把 sys.argv 塞成 [模組名] + argv**
    modname = "src.server.offline.build_gdfa_from_rules"
    old_argv = sys.argv
    try:
        sys.argv = [modname] + argv
        print("[dbg] invoking builder with argv:", sys.argv, file=sys.stderr)
        runpy.run_module(modname, run_name="__main__")
    except SystemExit as e:
        code = int(getattr(e, "code", 0) or 0)
        if code != 0:
            print(f"[error] builder exited with code {code}", file=sys.stderr)
            sys.exit(code)
    except Exception as e:
        print(f"[error] builder failed: {e}", file=sys.stderr)
        sys.exit(2)
    finally:
        sys.argv = old_argv

    print("[ok] artifacts built under:", args.outdir)

if __name__ == "__main__":
    main()