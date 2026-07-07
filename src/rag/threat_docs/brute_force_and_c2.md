# Brute Force (T1110) & C2 Beaconing (T1071)

## Brute Force Login Attempts

**Summary:** Repeated automated login attempts against exposed
authentication services (SSH, RDP, FTP, web logins) to guess valid
credentials.

**Typical indicators:**
- Many short-lived connections to a single authentication port from one
  source in a short time span.
- Very short average connection duration (fail-fast credential attempts).
- Attempts across a dictionary of usernames or a single username with many
  passwords.

**Recommended response:**
1. Enforce account lockout / exponential backoff on the authentication
   service.
2. Block the offending source IP after a low threshold of failures.
3. Require MFA on all externally reachable authentication endpoints.
4. Review whether any attempt succeeded — pivot to full incident response
   if so.

---

## Command & Control (C2) Beaconing

**Summary:** Compromised hosts periodically "check in" with attacker-
controlled infrastructure to receive commands or exfiltrate small amounts
of data, typically at highly regular intervals with low jitter to mimic
scheduled software behavior.

**Typical indicators:**
- Near-identical time intervals between connections to the same external
  host (low variance / high "beacon score").
- Small, consistent payload sizes per check-in.
- Long-running pattern that persists across days or weeks.
- Destination domain/IP with poor or no reputation history.

**Recommended response:**
1. Isolate the host and perform forensic triage (running processes,
   scheduled tasks, persistence mechanisms).
2. Block the C2 domain/IP at DNS and firewall layers.
3. Hunt for the same beacon signature across the rest of the environment.
4. Preserve memory/disk images before remediation if this may be part of a
   broader incident.

**False positive considerations:** Legitimate software (telemetry,
license checks, update checkers) also beacons regularly — validate against
known-good software inventories and vendor domains before escalating.
