"""
Turns raw FlowRecord objects into:
  1) a numeric feature matrix for the ML classifier, and
  2) a compact natural-language summary for the LLM analyzer
     (keeps token usage low while preserving the signals that matter).
"""

from typing import List

import numpy as np
import pandas as pd

from src.capture.traffic_simulator import FlowRecord

NUMERIC_FIELDS = [
    "duration_seconds", "packet_count", "bytes_out", "bytes_in",
    "syn_count", "syn_ack_ratio", "unique_dst_ports", "dns_query_count",
    "avg_dns_query_length", "icmp_count", "connection_count",
    "avg_duration", "beacon_score",
]


def flows_to_dataframe(flows: List[FlowRecord]) -> pd.DataFrame:
    return pd.DataFrame([f.to_dict() for f in flows])


def extract_feature_matrix(flows: List[FlowRecord]) -> np.ndarray:
    df = flows_to_dataframe(flows)
    for col in NUMERIC_FIELDS:
        if col not in df.columns:
            df[col] = 0
    return df[NUMERIC_FIELDS].fillna(0).to_numpy(dtype=float)


def flow_to_llm_summary(flow: FlowRecord) -> str:
    """A dense, human-readable one-flow summary for LLM prompting."""
    return (
        f"flow_id={flow.flow_id} | {flow.src_ip} -> {flow.dst_ip}:{flow.dst_port} "
        f"[{flow.protocol}] | duration={flow.duration_seconds}s | packets={flow.packet_count} | "
        f"bytes_out={flow.bytes_out} bytes_in={flow.bytes_in} | "
        f"syn={flow.syn_count} syn_ack_ratio={flow.syn_ack_ratio} | "
        f"unique_dst_ports={flow.unique_dst_ports} | "
        f"dns_queries={flow.dns_query_count} avg_dns_len={flow.avg_dns_query_length:.1f} | "
        f"icmp={flow.icmp_count} | connections={flow.connection_count} "
        f"avg_duration={flow.avg_duration} | beacon_score={flow.beacon_score} | "
        f"new_host={flow.dst_is_new_host}"
    )


def batch_to_llm_summary(flows: List[FlowRecord], max_flows: int = 25) -> str:
    """Summarize an entire window compactly for a single LLM call (batch mode)."""
    lines = [flow_to_llm_summary(f) for f in flows[:max_flows]]
    header = f"Traffic window: {len(flows)} flows captured (showing top {min(max_flows, len(flows))}).\n"
    return header + "\n".join(lines)
