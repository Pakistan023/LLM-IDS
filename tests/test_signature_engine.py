import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.capture.traffic_simulator import make_attack_flow, make_benign_flow
from src.detection.signature_engine import SignatureEngine


def test_port_scan_detected():
    engine = SignatureEngine()
    flow = make_attack_flow("port_scan")
    matches = engine.evaluate_flow(flow)
    assert any(m.rule_id == "SIG-1001" for m in matches), "Port scan should trigger SIG-1001"


def test_syn_flood_detected():
    engine = SignatureEngine()
    flow = make_attack_flow("syn_flood")
    matches = engine.evaluate_flow(flow)
    assert any(m.rule_id == "SIG-1002" for m in matches), "SYN flood should trigger SIG-1002"


def test_benign_flow_mostly_clean():
    engine = SignatureEngine()
    flow = make_benign_flow()
    matches = engine.evaluate_flow(flow)
    # Benign flows should rarely trigger high/critical signatures
    assert not any(m.severity == "critical" for m in matches)


def test_dns_tunneling_detected():
    engine = SignatureEngine()
    flow = make_attack_flow("dns_tunneling")
    matches = engine.evaluate_flow(flow)
    assert any(m.rule_id == "SIG-1003" for m in matches)


if __name__ == "__main__":
    test_port_scan_detected()
    test_syn_flood_detected()
    test_benign_flow_mostly_clean()
    test_dns_tunneling_detected()
    print("All signature_engine tests passed.")
