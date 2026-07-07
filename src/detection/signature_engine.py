"""
Signature-based detection engine — a simplified stand-in for Suricata/Snort,
used as the traditional baseline that the ML classifier and LLM analyzer
are benchmarked against.

Rules are declarative (config/signatures.yaml) and evaluated as safe,
restricted Python expressions against each flow's attribute dict. This is
NOT a full Suricata rule-language implementation, but it mirrors its
signature-matching philosophy: fixed conditions, no generalization, fast
and deterministic, prone to missing novel/unseen attack variants.
"""

from dataclasses import dataclass
from typing import List

import yaml

from src.capture.traffic_simulator import FlowRecord
from src.utils.config_loader import load_config
from src.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class SignatureMatch:
    rule_id: str
    rule_name: str
    severity: str
    mitre: str
    description: str
    flow_id: str


# Restricted eval environment — only flow fields + safe builtins.
_SAFE_BUILTINS = {"True": True, "False": False, "None": None}


class SignatureEngine:
    def __init__(self, rules_path: str = None):
        cfg = load_config()
        path = rules_path or cfg["_abs"](cfg["signature_engine"]["rules_file"])
        with open(path, "r") as f:
            self.rules = yaml.safe_load(f)["rules"]
        log.info(f"Loaded {len(self.rules)} signature rules from {path}")

    def _eval_condition(self, condition: str, flow_dict: dict) -> bool:
        try:
            return bool(eval(condition, {"__builtins__": {}}, {**_SAFE_BUILTINS, **flow_dict}))
        except Exception:
            return False

    def evaluate_flow(self, flow: FlowRecord) -> List[SignatureMatch]:
        flow_dict = flow.to_dict()
        matches = []
        for rule in self.rules:
            if self._eval_condition(rule["condition"], flow_dict):
                matches.append(SignatureMatch(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    severity=rule["severity"],
                    mitre=rule.get("mitre", ""),
                    description=rule["description"],
                    flow_id=flow.flow_id,
                ))
        return matches

    def evaluate_batch(self, flows: List[FlowRecord]) -> List[SignatureMatch]:
        results = []
        for flow in flows:
            results.extend(self.evaluate_flow(flow))
        return results
