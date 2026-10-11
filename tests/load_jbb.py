"""Convert JailbreakBench (JBB-Behaviors) into this repo's test-case schema.

    python tests/load_jbb.py                       # downloads, writes tests/jbb_cases.json
    python tests/load_jbb.py --harmful h.csv --benign b.csv   # offline, from local CSVs
    python tests/test_script.py --cases tests/jbb_cases.json --list-misses

JBB-Behaviors has 100 harmful and 100 thematically matched benign behaviors
(columns: Index, Goal, Target, Behavior, Category, Source). Sentinel only has policies for
prompt injection, data extraction and malicious code, so cases are tagged:

  in_scope      benign behaviors (false-positive measurement) and harmful "Malware/Hacking"
                behaviors (map to MALICIOUS_CODE).
  out_of_scope  all other harmful categories (harassment, disinformation, fraud, ...).
                Sentinel has no policy for these, so ALLOW here is a coverage gap, not a
                detection failure. Report them separately, or add a harmful-content policy.

Requires `datasets` (pip install datasets) or network access to the raw CSVs, unless local
CSV paths are given. Dataset: https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors
(MIT licensed; cite Chao et al., 2024 when reporting results).
"""
import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

HERE = Path(__file__).resolve().parent
HF_DATASET = "JailbreakBench/JBB-Behaviors"
CSV_URLS = {
    "harmful": f"https://huggingface.co/datasets/{HF_DATASET}/resolve/main/data/harmful-behaviors.csv",
    "benign": f"https://huggingface.co/datasets/{HF_DATASET}/resolve/main/data/benign-behaviors.csv",
}


def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def fetch_rows(split: str, local_csv: Optional[Path]) -> List[Dict[str, str]]:
    """Local CSV if given, else the `datasets` library, else a direct CSV download."""
    if local_csv:
        return read_csv_rows(local_csv)
    try:
        from datasets import load_dataset
        ds = load_dataset(HF_DATASET, "behaviors", split=split)
        return [dict(row) for row in ds]
    except Exception as e:  # missing package, offline, or hub error: try plain HTTP
        print(f"[info] `datasets` route failed for '{split}' ({type(e).__name__}); trying direct CSV download.",
              file=sys.stderr)
    import io
    import httpx
    resp = httpx.get(CSV_URLS[split], follow_redirects=True, timeout=60.0)
    resp.raise_for_status()
    return list(csv.DictReader(io.StringIO(resp.text)))


def convert(harmful: List[Dict[str, str]], benign: List[Dict[str, str]]) -> List[Dict[str, str]]:
    cases: List[Dict[str, str]] = []
    for row in harmful:
        in_scope = "malware" in row["Category"].lower()
        cases.append({
            "prompt": row["Goal"],
            "expected_action": "BLOCK",
            "expected_intent": "MALICIOUS_CODE" if in_scope else "N/A",
            "category": "JBB_HARMFUL",
            "scope": "in_scope" if in_scope else "out_of_scope",
            "jbb_category": row["Category"],
            "jbb_behavior": row["Behavior"],
            "source": "JBB-Behaviors",
        })
    for row in benign:
        cases.append({
            "prompt": row["Goal"],
            "expected_action": "ALLOW",
            "expected_intent": "BENIGN",
            "category": "JBB_BENIGN",
            "scope": "in_scope",
            "jbb_category": row["Category"],
            "jbb_behavior": row["Behavior"],
            "source": "JBB-Behaviors",
        })
    return cases


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--harmful", type=Path, default=None, help="local harmful-behaviors CSV (skips download)")
    ap.add_argument("--benign", type=Path, default=None, help="local benign-behaviors CSV (skips download)")
    ap.add_argument("--out", type=Path, default=HERE / "jbb_cases.json")
    args = ap.parse_args()

    try:
        harmful = fetch_rows("harmful", args.harmful)
        benign = fetch_rows("benign", args.benign)
    except Exception as e:
        print(f"[ERROR] Could not load JBB-Behaviors: {type(e).__name__}: {e}\n"
              f"Download harmful-behaviors.csv and benign-behaviors.csv from "
              f"https://huggingface.co/datasets/{HF_DATASET} and pass them with --harmful / --benign.")
        return 1

    cases = convert(harmful, benign)
    args.out.write_text(json.dumps(cases, indent=2, ensure_ascii=False), encoding="utf-8")

    n_in = sum(1 for c in cases if c["category"] == "JBB_HARMFUL" and c["scope"] == "in_scope")
    n_out = sum(1 for c in cases if c["category"] == "JBB_HARMFUL" and c["scope"] == "out_of_scope")
    print(f"Wrote {len(cases)} cases to {args.out}")
    print(f"  harmful in scope (Malware/Hacking): {n_in} | harmful out of scope: {n_out} | benign: {len(benign)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
