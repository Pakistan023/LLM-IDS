"""
Synthetic network traffic simulator.

Generates realistic-looking flow records — including injected attack
patterns (port scans, SYN floods, DNS tunneling, exfiltration, brute
force, C2 beaconing) — so the whole pipeline (feature extraction ->
signature engine -> ML classifier -> LLM analyzer -> dashboard) can be
demoed and evaluated without needing a live NIC, root privileges, or
Npcap/libpcap installed.

Swap this out for src/capture/packet_capture.py (scapy/pyshark) when
you want to run against a real interface.
"""

import random
import string
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class FlowRecord:
    """One aggregated 'flow window' — the unit fed to every detector."""

    flow_id: str
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    duration_seconds: float
    packet_count: int
    bytes_out: int
    bytes_in: int
    syn_count: int
    syn_ack_ratio: float
    unique_dst_ports: int
    dns_query_count: int
    avg_dns_query_length: float
    icmp_count: int
    connection_count: int
    avg_duration: float
    beacon_score: float
    dst_is_new_host: bool
    label: str = "benign"          # ground truth, used only for evaluation
    attack_type: Optional[str] = None

    def to_dict(self):
        return self.__dict__


BENIGN_PORTS = [443, 443, 443, 80, 22, 53, 123, 3306, 8443]
INTERNAL_SUBNET = "10.0.0."
EXTERNAL_POOL = [f"185.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(40)]


def _rand_ip(internal=True):
    if internal:
        return INTERNAL_SUBNET + str(random.randint(2, 254))
    return random.choice(EXTERNAL_POOL)


def _random_domain_token(n):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def make_benign_flow() -> FlowRecord:
    return FlowRecord(
        flow_id=str(uuid.uuid4())[:8],
        timestamp=time.time(),
        src_ip=_rand_ip(True),
        dst_ip=_rand_ip(False),
        dst_port=random.choice(BENIGN_PORTS),
        protocol=random.choice(["TCP", "TCP", "UDP", "HTTP"]),
        duration_seconds=round(random.uniform(0.5, 30), 2),
        packet_count=random.randint(5, 200),
        bytes_out=random.randint(500, 200_000),
        bytes_in=random.randint(500, 500_000),
        syn_count=random.randint(1, 3),
        syn_ack_ratio=round(random.uniform(0.9, 1.0), 2),
        unique_dst_ports=1,
        dns_query_count=random.randint(0, 5),
        avg_dns_query_length=random.uniform(8, 20),
        icmp_count=0,
        connection_count=random.randint(1, 4),
        avg_duration=round(random.uniform(1, 10), 2),
        beacon_score=round(random.uniform(0.0, 0.3), 2),
        dst_is_new_host=random.random() < 0.05,
        label="benign",
    )


def make_attack_flow(attack_type: str) -> FlowRecord:
    base = make_benign_flow()
    base.label = "malicious"
    base.attack_type = attack_type

    if attack_type == "port_scan":
        base.unique_dst_ports = random.randint(25, 120)
        base.duration_seconds = round(random.uniform(1, 8), 2)
        base.packet_count = base.unique_dst_ports * random.randint(1, 2)
        base.syn_ack_ratio = round(random.uniform(0.05, 0.3), 2)

    elif attack_type == "syn_flood":
        base.syn_count = random.randint(300, 5000)
        base.syn_ack_ratio = round(random.uniform(0.0, 0.09), 2)
        base.packet_count = base.syn_count
        base.duration_seconds = round(random.uniform(1, 5), 2)

    elif attack_type == "dns_tunneling":
        base.protocol = "DNS"
        base.dst_port = 53
        base.dns_query_count = random.randint(120, 900)
        base.avg_dns_query_length = random.uniform(45, 90)
        base.dst_ip = f"{_random_domain_token(10)}.exfil-c2.net"

    elif attack_type == "data_exfil":
        base.bytes_out = random.randint(60_000_000, 900_000_000)
        base.dst_is_new_host = True
        base.duration_seconds = round(random.uniform(30, 300), 2)

    elif attack_type == "brute_force":
        base.dst_port = random.choice([22, 3389, 21])
        base.connection_count = random.randint(16, 200)
        base.avg_duration = round(random.uniform(0.1, 2.5), 2)

    elif attack_type == "c2_beacon":
        base.beacon_score = round(random.uniform(0.85, 0.99), 2)
        base.connection_count = random.randint(20, 60)
        base.bytes_out = random.randint(200, 2000)   # small, regular check-ins

    elif attack_type == "icmp_flood":
        base.icmp_count = random.randint(600, 5000)
        base.protocol = "ICMP"
        base.packet_count = base.icmp_count

    elif attack_type == "http_evasion":
        base.protocol = "HTTP"
        base.dst_port = random.choice([4444, 8081, 31337, 9999])

    return base


ATTACK_TYPES = [
    "port_scan", "syn_flood", "dns_tunneling", "data_exfil",
    "brute_force", "c2_beacon", "icmp_flood", "http_evasion",
]


class TrafficSimulator:
    """Yields a continuous stream of FlowRecord windows."""

    def __init__(self, attack_ratio: float = 0.12, seed: Optional[int] = None):
        self.attack_ratio = attack_ratio
        if seed is not None:
            random.seed(seed)

    def generate_window(self, n: int = 40) -> List[FlowRecord]:
        flows = []
        for _ in range(n):
            if random.random() < self.attack_ratio:
                flows.append(make_attack_flow(random.choice(ATTACK_TYPES)))
            else:
                flows.append(make_benign_flow())
        return flows

    def stream(self, interval_seconds: float = 5.0, batch_size: int = 40):
        """Generator — yields a fresh list[FlowRecord] every `interval_seconds`."""
        while True:
            yield self.generate_window(batch_size)
            time.sleep(interval_seconds)
