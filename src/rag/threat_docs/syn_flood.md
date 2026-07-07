# SYN Flood / Denial of Service (T1499 — Endpoint Denial of Service)

**Summary:** A SYN flood exploits the TCP three-way handshake by sending a
high volume of SYN packets without completing the handshake (never
responding to the SYN-ACK), exhausting the target's connection table and
denying service to legitimate users.

**Typical indicators:**
- Very high SYN packet counts from one or a small number of sources.
- Extremely low SYN-ACK completion ratio (often near 0).
- Short-lived flows with high packet rate and minimal payload.
- Frequently spoofed or randomized source IPs in volumetric variants.

**Recommended response:**
1. Enable SYN cookies / SYN proxy on the affected host or upstream load
   balancer.
2. Apply rate limiting and connection-table protections at the perimeter
   firewall or DDoS mitigation service.
3. If source IPs appear spoofed, coordinate with the upstream ISP/CDN for
   scrubbing rather than local blocking alone.
4. Monitor service availability metrics in parallel — the goal of the
   attack is impact, not stealth, so downstream effects confirm severity.

**False positive considerations:** Sudden legitimate traffic spikes (e.g.
flash-crowd events, marketing campaigns) can resemble a flood but usually
show a healthy SYN-ACK ratio and diverse, plausible source geography.
