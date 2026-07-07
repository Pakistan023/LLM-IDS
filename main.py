"""
Headless CLI runner — continuously generates/captures traffic windows and
runs all detectors, printing a live console report. Useful for servers
without a Streamlit UI, or for piping output into other tools.

Usage:
    python main.py --mode simulate --interval 5 --batch-size 30
    python main.py --mode live --interface eth0
    python main.py --no-llm            # skip LLM calls (no API key needed)
"""

import argparse
import json
import time

from src.alerts.alert_manager import AlertManager
from src.utils.logger import get_logger

log = get_logger("main")


def run_simulate(interval: float, batch_size: int, attack_ratio: float, manager: AlertManager, max_iterations: int):
    from src.capture.traffic_simulator import TrafficSimulator
    sim = TrafficSimulator(attack_ratio=attack_ratio)

    i = 0
    for flows in sim.stream(interval_seconds=interval, batch_size=batch_size):
        i += 1
        log.info(f"--- Window {i}: {len(flows)} flows ---")
        result = manager.process_window(flows)
        _print_summary(result)
        if max_iterations and i >= max_iterations:
            break


def run_live(interface: str, manager: AlertManager, max_iterations: int):
    from src.capture.packet_capture import LiveCapture
    capture = LiveCapture(interface=interface)

    i = 0
    for flows in capture.stream():
        i += 1
        log.info(f"--- Window {i}: {len(flows)} flows ---")
        result = manager.process_window(flows)
        _print_summary(result)
        if max_iterations and i >= max_iterations:
            break


def _print_summary(result: dict):
    n_sig = len(result["signature"])
    n_ml = sum(1 for _, _, pred in result["ml"] if pred == "malicious")
    print(f"  Signature engine flagged: {n_sig}")
    print(f"  ML classifier flagged:    {n_ml}")

    llm_result = result.get("llm")
    if llm_result:
        print(f"  LLM overall severity:     {llm_result.overall_severity}")
        print(f"  LLM summary: {llm_result.executive_summary}")
        for finding in llm_result.findings:
            if finding.verdict != "benign":
                print(f"    -> [{finding.verdict}] {finding.flow_id}: {finding.explanation}")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LLM-IDS headless runner")
    parser.add_argument("--mode", choices=["simulate", "live"], default="simulate")
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--batch-size", type=int, default=30)
    parser.add_argument("--attack-ratio", type=float, default=0.15)
    parser.add_argument("--no-llm", action="store_true")
    parser.add_argument("--no-rag", action="store_true")
    parser.add_argument("--max-iterations", type=int, default=0, help="0 = run forever")
    args = parser.parse_args()

    manager = AlertManager(use_llm=not args.no_llm, use_rag=not args.no_rag)

    try:
        if args.mode == "simulate":
            run_simulate(args.interval, args.batch_size, args.attack_ratio, manager, args.max_iterations)
        else:
            run_live(args.interface, manager, args.max_iterations)
    except KeyboardInterrupt:
        log.info("Stopped by user.")
