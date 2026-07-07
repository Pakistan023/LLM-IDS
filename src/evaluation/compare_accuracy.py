"""
Evaluation harness — runs all three detectors against the SAME labeled
synthetic traffic set and reports precision/recall/F1/accuracy for each,
so you can quantitatively back the "LLM vs signature-based IDS" comparison
called for in the assignment.

Run: python -m src.evaluation.compare_accuracy
"""

import argparse
import json
import time

from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                              precision_score, recall_score)

from src.capture.traffic_simulator import TrafficSimulator
from src.detection.llm_analyzer import LLMAnalyzer
from src.detection.ml_classifier import MLClassifier
from src.detection.signature_engine import SignatureEngine
from src.utils.logger import get_logger

log = get_logger(__name__)


def evaluate(n_flows: int = 300, include_llm: bool = True, attack_ratio: float = 0.25):
    sim = TrafficSimulator(attack_ratio=attack_ratio, seed=7)
    flows = sim.generate_window(n=n_flows)
    y_true = [1 if f.label == "malicious" else 0 for f in flows]

    results = {}

    # ---- Signature engine ---- #
    log.info("Evaluating signature engine ...")
    sig_engine = SignatureEngine()
    flagged_ids = {m.flow_id for m in sig_engine.evaluate_batch(flows)}
    y_pred_sig = [1 if f.flow_id in flagged_ids else 0 for f in flows]
    results["signature"] = _score("Signature Engine (Suricata/Snort-style)", y_true, y_pred_sig)

    # ---- ML classifier ---- #
    log.info("Evaluating ML classifier ...")
    ml = MLClassifier()
    ml_preds = ml.predict(flows)
    y_pred_ml = [1 if pred == "malicious" else 0 for _, _, pred in ml_preds]
    results["ml"] = _score("ML Classifier (RandomForest)", y_true, y_pred_ml)

    # ---- LLM analyzer ---- #
    if include_llm:
        log.info("Evaluating LLM analyzer (this makes real API calls, may take a while) ...")
        try:
            llm = LLMAnalyzer(use_rag=True)
            y_pred_llm = [0] * len(flows)
            id_to_idx = {f.flow_id: i for i, f in enumerate(flows)}

            # Batch in windows of 20 flows per LLM call to control cost/latency.
            batch_size = 20
            for start in range(0, len(flows), batch_size):
                batch = flows[start:start + batch_size]
                result = llm.analyze_window(batch)
                for finding in result.findings:
                    idx = id_to_idx.get(finding.flow_id)
                    if idx is not None and finding.verdict in ("malicious", "suspicious"):
                        y_pred_llm[idx] = 1
                time.sleep(0.5)  # gentle rate-limit courtesy

            results["llm"] = _score("LLM Analyzer (Claude/GPT-4 + RAG)", y_true, y_pred_llm)
        except Exception as e:
            log.error(f"LLM evaluation skipped due to error: {e}")
            results["llm"] = {"error": str(e)}

    return results


def _score(name: str, y_true, y_pred) -> dict:
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred).tolist()

    summary = {
        "name": name,
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "confusion_matrix": cm,
    }
    log.info(f"{name}: acc={acc:.3f} precision={prec:.3f} recall={rec:.3f} f1={f1:.3f}")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compare signature/ML/LLM detection accuracy.")
    parser.add_argument("--n-flows", type=int, default=300)
    parser.add_argument("--attack-ratio", type=float, default=0.25)
    parser.add_argument("--no-llm", action="store_true", help="Skip the LLM detector (no API calls).")
    args = parser.parse_args()

    output = evaluate(n_flows=args.n_flows, include_llm=not args.no_llm, attack_ratio=args.attack_ratio)
    print(json.dumps(output, indent=2))
