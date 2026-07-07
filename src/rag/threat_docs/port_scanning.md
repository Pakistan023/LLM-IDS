# Port Scanning (T1046 — Network Service Discovery)

**Summary:** Port scanning is a reconnaissance technique where an attacker
probes a range of ports on one or more hosts to discover open services,
running software versions, and potential entry points before launching a
targeted attack.

**Common variants:**
- Horizontal scan: one source probes many hosts on the same port.
- Vertical scan: one source probes many ports on a single host.
- Stealth/SYN scan: sends only SYN packets, never completes the handshake,
  to avoid logging on some legacy systems.

**Typical indicators:**
- A single source IP contacting an unusually high number of distinct
  destination ports within a short time window.
- Low SYN-ACK completion ratio (many SYNs, few completed connections).
- Sequential or pseudo-random port access patterns.

**Recommended response:**
1. Rate-limit or temporarily block the source IP at the firewall.
2. Check whether the scanned ports expose any vulnerable services and patch
   or restrict access immediately.
3. Correlate with authentication logs — scans often precede brute-force or
   exploitation attempts within minutes to hours.
4. Log the full flow for forensic follow-up; scans are frequently automated
   and repeat from rotating infrastructure.

**False positive considerations:** legitimate vulnerability scanners (e.g.
Nessus, Qualys) and monitoring tools produce very similar traffic patterns
— verify against your asset inventory of authorized scanning sources before
escalating.
