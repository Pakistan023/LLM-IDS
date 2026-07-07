"""
Alert Manager — orchestrates the three detectors (signature engine, ML
classifier, LLM analyzer) over a traffic window, normalizes their outputs
into a common alert shape, and persists everything to the AlertStore so
the dashboard and evaluation harness have one place to query.
"""

from typing import List

from src.capture.traffic_simulator import FlowRecord
from src.db.database import AlertStore
from src.detection.llm_analyzer import LLMAnalyzer
from src.detection.ml_classifier import MLClassifier
from src.detection.signature_engine import SignatureEngine
from src.utils.logger import get_logger

log = get_logger(__name__)


class AlertManager:
    def __init__(self, use_llm: bool = True, use_rag: bool = True):
        self.signature_engine = SignatureEngine()
        self.ml_classifier = MLClassifier()
        self.llm_analyzer = LLMAnalyzer(use_rag=use_rag) if use_llm else None
        self.store = AlertStore()

    def process_window(self, flows: List[FlowRecord]) -> dict:
        if not flows:
            return {"signature": [], "ml": [], "llm": None}

        flow_by_id = {f.flow_id: f for f in flows}

        # 1) Signature engine (baseline)
        sig_matches = self.signature_engine.evaluate_batch(flows)
        for m in sig_matches:
            flow = flow_by_id[m.flow_id]
            self.store.insert_alert(
                flow_id=flow.flow_id, src_ip=flow.src_ip, dst_ip=flow.dst_ip,
                dst_port=flow.dst_port, protocol=flow.protocol,
                detector="signature", verdict="malicious", severity=m.severity,
                confidence=1.0, technique=m.rule_name, mitre_id=m.mitre,
                explanation=m.description, recommended_action="Follow standard IR runbook for " + m.rule_name,
                ground_truth_label=flow.label,
            )

        # 2) ML classifier
        ml_results = self.ml_classifier.predict(flows)
        for flow, prob, pred in ml_results:
            if pred == "malicious":
                self.store.insert_alert(
                    flow_id=flow.flow_id, src_ip=flow.src_ip, dst_ip=flow.dst_ip,
                    dst_port=flow.dst_port, protocol=flow.protocol,
                    detector="ml", verdict=pred, severity=self._prob_to_severity(prob),
                    confidence=prob, technique=None, mitre_id=None,
                    explanation=f"RandomForest anomaly probability={prob:.2f}",
                    recommended_action="Review flow against ML feature importances for root cause.",
                    ground_truth_label=flow.label,
                )

        # 3) LLM analyzer (batched — one call per window)
        llm_result = None
        if self.llm_analyzer:
            llm_result = self.llm_analyzer.analyze_window(flows)
            for finding in llm_result.findings:
                flow = flow_by_id.get(finding.flow_id)
                if not flow or finding.verdict == "benign":
                    continue
                self.store.insert_alert(
                    flow_id=finding.flow_id,
                    src_ip=flow.src_ip, dst_ip=flow.dst_ip, dst_port=flow.dst_port,
                    protocol=flow.protocol, detector="llm", verdict=finding.verdict,
                    severity=llm_result.overall_severity, confidence=finding.confidence,
                    technique=finding.attack_technique, mitre_id=finding.mitre_id,
                    explanation=finding.explanation, recommended_action=finding.recommended_action,
                    ground_truth_label=flow.label,
                )

        return {"signature": sig_matches, "ml": ml_results, "llm": llm_result}

    @staticmethod
    def _prob_to_severity(prob: float) -> str:
        if prob >= 0.9:
            return "critical"
        if prob >= 0.75:
            return "high"
        if prob >= 0.5:
            return "medium"
        if prob >= 0.3:
            return "low"
        return "info"
