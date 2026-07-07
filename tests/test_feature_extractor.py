import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.capture.traffic_simulator import TrafficSimulator
from src.features.feature_extractor import (batch_to_llm_summary,
                                              extract_feature_matrix,
                                              flow_to_llm_summary)


def test_feature_matrix_shape():
    sim = TrafficSimulator(seed=1)
    flows = sim.generate_window(n=20)
    X = extract_feature_matrix(flows)
    assert X.shape[0] == 20
    assert X.shape[1] == 13  # len(NUMERIC_FIELDS)


def test_llm_summary_contains_key_fields():
    sim = TrafficSimulator(seed=1)
    flows = sim.generate_window(n=5)
    summary = flow_to_llm_summary(flows[0])
    assert flows[0].flow_id in summary
    assert flows[0].src_ip in summary


def test_batch_summary_truncates():
    sim = TrafficSimulator(seed=1)
    flows = sim.generate_window(n=50)
    summary = batch_to_llm_summary(flows, max_flows=10)
    assert summary.count("flow_id=") == 10


if __name__ == "__main__":
    test_feature_matrix_shape()
    test_llm_summary_contains_key_fields()
    test_batch_summary_truncates()
    print("All feature_extractor tests passed.")
