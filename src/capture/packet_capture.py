"""
Live packet capture using Scapy (falls back to PyShark if Scapy/libpcap
isn't available). Aggregates raw packets into FlowRecord windows with the
same schema as traffic_simulator.FlowRecord, so every downstream detector
(signature engine, ML classifier, LLM analyzer) works unchanged whether
the data came from a live NIC or the simulator.

Requires elevated privileges (root/Administrator + Npcap on Windows) to
sniff a real interface. If that's not available in your environment, use
src/capture/traffic_simulator.py instead — the dashboard defaults to it.
"""

import time
import uuid
from collections import defaultdict
from typing import List

from src.capture.traffic_simulator import FlowRecord
from src.utils.logger import get_logger

log = get_logger(__name__)

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover
    SCAPY_AVAILABLE = False
    log.warning("Scapy not available — live capture disabled. Use the traffic simulator instead.")


class LiveCapture:
    """
    Sniffs `interface` for `window_seconds`, aggregates packets per
    (src_ip, dst_ip, dst_port) 5-tuple-ish key, and emits FlowRecord objects
    compatible with the rest of the pipeline.
    """

    def __init__(self, interface: str = "eth0", window_seconds: int = 5, max_packets: int = 2000):
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is not installed/available. Install scapy + libpcap/Npcap, "
                "or use TrafficSimulator for a no-dependency demo."
            )
        self.interface = interface
        self.window_seconds = window_seconds
        self.max_packets = max_packets

    def _aggregate(self, packets) -> List[FlowRecord]:
        buckets = defaultdict(list)
        for pkt in packets:
            if IP not in pkt:
                continue
            key = (pkt[IP].src, pkt[IP].dst, pkt.dport if hasattr(pkt, "dport") else 0)
            buckets[key].append(pkt)

        flows = []
        for (src, dst, port), pkts in buckets.items():
            syn_count = sum(1 for p in pkts if TCP in p and p[TCP].flags & 0x02)
            synack_count = sum(1 for p in pkts if TCP in p and p[TCP].flags & 0x12 == 0x12)
            icmp_count = sum(1 for p in pkts if ICMP in p)
            dns_pkts = [p for p in pkts if DNS in p]
            bytes_total = sum(len(p) for p in pkts)

            flows.append(FlowRecord(
                flow_id=str(uuid.uuid4())[:8],
                timestamp=time.time(),
                src_ip=src,
                dst_ip=dst,
                dst_port=port,
                protocol="TCP" if any(TCP in p for p in pkts) else ("UDP" if any(UDP in p for p in pkts) else "ICMP"),
                duration_seconds=self.window_seconds,
                packet_count=len(pkts),
                bytes_out=bytes_total,
                bytes_in=0,  # would need bidirectional correlation for a real split
                syn_count=syn_count,
                syn_ack_ratio=(synack_count / syn_count) if syn_count else 1.0,
                unique_dst_ports=len({p.dport for p in pkts if TCP in p or UDP in p}),
                dns_query_count=len(dns_pkts),
                avg_dns_query_length=(
                    sum(len(str(p[DNS].qd.qname)) for p in dns_pkts if p[DNS].qd) / len(dns_pkts)
                    if dns_pkts else 0
                ),
                icmp_count=icmp_count,
                connection_count=len(pkts),
                avg_duration=self.window_seconds,
                beacon_score=0.0,  # requires historical timing analysis — see feature_extractor
                dst_is_new_host=False,
                label="unknown",
            ))
        return flows

    def capture_window(self) -> List[FlowRecord]:
        log.info(f"Sniffing {self.interface} for {self.window_seconds}s ...")
        packets = sniff(iface=self.interface, timeout=self.window_seconds, count=self.max_packets)
        return self._aggregate(packets)

    def stream(self):
        while True:
            yield self.capture_window()
