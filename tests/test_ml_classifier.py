import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.capture.traffic_simulator import TrafficSimulator
from src.detection.ml_classifier import MLClassifier


def test_ml_classifier_trains_and_predicts():
    clf = MLClassifier()
    sim = TrafficSimulator(attack_ratio=0.3, seed=99)
    flows = sim.generate_window(n=50)
    results = clf.predict(flows)
    assert len(results) == 50
    for flow, prob, pred in results:
        assert 0.0 <= prob <= 1.0
        assert pred in ("benign", "malicious")


def test_ml_classifier_reasonable_recall_on_obvious_attacks():
    clf = MLClassifier()
    sim = TrafficSimulator(attack_ratio=1.0, seed=123)  # all attacks
    flows = [f for f in sim.generate_window(n=60) if f.label == "malicious"]
    results = clf.predict(flows)
    malicious_flagged = sum(1 for _, _, pred in results if pred == "malicious")
    # Expect the model to catch a solid majority of obvious synthetic attacks
    assert malicious_flagged / len(results) > 0.5


if __name__ == "__main__":
    test_ml_classifier_trains_and_predicts()
    test_ml_classifier_reasonable_recall_on_obvious_attacks()
    print("All ml_classifier tests passed.")
