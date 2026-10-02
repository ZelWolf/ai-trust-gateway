import asyncio
import time
import httpx
import json
import os
from typing import List, Dict, Any
from statistics import mean, quantiles

API_URL = "http://localhost:8000/v1/inspect"

def load_test_cases(filepath: str) -> List[Dict[str, Any]]:
    """Loads the exact test cases from a JSON file without any mutations."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Cannot find '{filepath}'. Make sure it is in the same directory as this script.")
        
    with open(filepath, "r", encoding="utf-8") as f:
        test_suite = json.load(f)
        
    return test_suite

async def run_single_test(client: httpx.AsyncClient, item: Dict[str, Any], idx: int) -> Dict[str, Any]:
    payload = {"prompt": item["prompt"]}
    start = time.perf_counter()
    try:
        resp = await client.post(API_URL, json=payload, timeout=30.0)
        elapsed = (time.perf_counter() - start) * 1000
        
        if resp.status_code == 200:
            data = resp.json()
            
            # --- ROBUST EXTRACTION LOGIC ---
            sec_decision = data.get("security_decision") or {}
            
            raw_decision = str(sec_decision.get("decision") or sec_decision.get("action") or 
                               data.get("decision") or data.get("action") or "").upper()
            
            intent = str(sec_decision.get("intent") or sec_decision.get("layer_2_intent") or 
                         data.get("intent") or data.get("layer_2_intent") or "")
            
            reasoning = str(sec_decision.get("reason") or sec_decision.get("layer_2_reasoning") or 
                            data.get("reason") or data.get("layer_2_reasoning") or "")
            
            policy_id = str(sec_decision.get("policy_id") or data.get("policy_id") or "")
            timing = sec_decision.get("timing") or data.get("timing") or {}
            
            # Action Mapping
            if not raw_decision:
                actual_action = "PARSE_ERR" 
            else:
                is_blocked = "BLOCK" in raw_decision
                actual_action = "BLOCK" if is_blocked else "ALLOW"
            
            # Match Logic
            if item["category"] == "PII_CREDENTIAL":
                intent_match = (intent == item["expected_intent"]) or (actual_action == "BLOCK")
            else:
                intent_match = (intent == item["expected_intent"])

            return {
                "id": idx + 1,
                "category": item["category"],
                "expected_action": item["expected_action"],
                "actual_action": actual_action,
                "expected_intent": item["expected_intent"],
                "actual_intent": intent,
                "action_match": actual_action == item["expected_action"],
                "intent_match": intent_match,
                "policy_cited": bool(policy_id) or "POL-" in reasoning,
                "l1_ms": timing.get("layer_1_ms", 0.0),
                "l2_ms": timing.get("layer_2_ms", 0.0),
                "total_ms": timing.get("total_ms", elapsed),
                "error": None
            }
        else:
            return {"id": idx + 1, "category": item["category"], "error": f"HTTP {resp.status_code}: {resp.text}"}
    except Exception as e:
        return {"id": idx + 1, "category": item["category"], "error": str(e)}

async def main():
    try:
        # Load whatever is in the JSON file directly
        test_suite = load_test_cases("test_cases.json")
    except FileNotFoundError as e:
        print(f"[ERROR] {e}")
        return
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON format in test_cases.json: {e}")
        return

    total_suite_size = len(test_suite)

    print("=" * 80)
    print("      AI TRUST GATEWAY: DYNAMIC EVALUATION & BENCHMARK HARNESS")
    print("=" * 80)
    print(f"Target Endpoint: {API_URL}")
    print(f"Total Test Cases Loaded: {total_suite_size}\n")

    results = []
    async with httpx.AsyncClient() as client:
        for idx, item in enumerate(test_suite):
            # Dynamic progress string based on total size (e.g., [ 5/ 42] or [005/500])
            pad_len = len(str(total_suite_size))
            print(f"Running [{idx+1:0{pad_len}d}/{total_suite_size}] ({item.get('category', 'UNKNOWN')})... ", end="", flush=True)
            
            res = await run_single_test(client, item, idx)
            results.append(res)
            
            if res.get("error"):
                print(f"[FAILED] {res['error']}")
            else:
                status = "PASS" if res["action_match"] else "FAIL"
                print(f"[{status}] [Cat: {res['category']}] Action: {res['actual_action']} | Intent: {res['actual_intent']} ({res['total_ms']:.1f}ms)")
            
            # Slight delay to prevent overloading localhost
            await asyncio.sleep(0.05) 

    valid_runs = [r for r in results if not r.get("error")]
    if not valid_runs:
        print("\nAll tests failed due to connectivity errors. Ensure FastAPI is running on port 8000.")
        return

    # ---------------------------------------------------------
    # METRICS CALCULATION
    # ---------------------------------------------------------
    total_tests = len(valid_runs)
    benign_tests = [r for r in valid_runs if r["expected_action"] == "ALLOW"]
    malicious_tests = [r for r in valid_runs if r["expected_action"] == "BLOCK"]

    fp_count = sum(1 for r in benign_tests if r["actual_action"] == "BLOCK")
    fn_count = sum(1 for r in malicious_tests if r["actual_action"] == "ALLOW")
    
    classification_acc = (sum(1 for r in valid_runs if r["intent_match"]) / total_tests) * 100 if total_tests > 0 else 0.0
    threat_block_rate = ((len(malicious_tests) - fn_count) / len(malicious_tests)) * 100 if malicious_tests else 0.0

    l1_times = [r["l1_ms"] for r in valid_runs if r["l1_ms"] > 0]
    l2_times = [r["l2_ms"] for r in valid_runs if r["l2_ms"] > 0]
    tot_times = [r["total_ms"] for r in valid_runs]

    def p95(vals): 
        if not vals: return 0.0
        return quantiles(vals, n=20)[18] if len(vals) >= 20 else max(vals)

    print("\n" + "=" * 80)
    print("                    FINAL EVALUATION METRICS")
    print("=" * 80)
    print(f" Total Executed Tests      : {total_tests}/{total_suite_size}")
    print(f" Classification Accuracy   : {classification_acc:.2f}%")
    print(f" End-to-End Threat Block Rate: {threat_block_rate:.2f}%")
    
    if benign_tests:
        print(f" False Positives (Benign blocked): {fp_count}/{len(benign_tests)} ({(fp_count/len(benign_tests)*100):.1f}%)")
    else:
        print(" False Positives (Benign blocked): N/A (No benign tests executed)")

    if malicious_tests:
        print(f" False Negatives (Attack allowed): {fn_count}/{len(malicious_tests)} ({(fn_count/len(malicious_tests)*100):.1f}%)")
    else:
        print(" False Negatives (Attack allowed): N/A (No malicious tests executed)")

    print("-" * 80)
    print(" LATENCY BENCHMARK (ms)")
    print(f"  Layer 1 (Pre-Check)      : Avg = {mean(l1_times) if l1_times else 0:.1f}ms | p95 = {p95(l1_times):.1f}ms")
    print(f"  Layer 2 (LLM Eval)       : Avg = {mean(l2_times) if l2_times else 0:.1f}ms | p95 = {p95(l2_times):.1f}ms")
    print(f"  Gateway Total            : Avg = {mean(tot_times) if tot_times else 0:.1f}ms | p95 = {p95(tot_times):.1f}ms")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(main())