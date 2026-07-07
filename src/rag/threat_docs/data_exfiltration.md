# Data Exfiltration (T1041 — Exfiltration Over C2 Channel)

**Summary:** Data exfiltration is the unauthorized transfer of data from an
internal host to an external destination, often as the final stage of an
intrusion after reconnaissance, lateral movement, and privilege escalation.

**Typical indicators:**
- Large outbound byte volume relative to the host's historical baseline.
- Transfer to a destination host not previously seen from that source.
- Transfers occurring outside normal business hours or at unusual
  frequency.
- Use of encryption or compression that obscures payload inspection.

**Recommended response:**
1. Isolate the source host from the network immediately if exfiltration is
   confirmed or highly likely.
2. Identify and preserve evidence of what data was accessed prior to
   transfer (file access logs, database query logs).
3. Block the destination IP/domain and check threat intelligence feeds for
   known malicious infrastructure association.
4. Notify incident response and, depending on data sensitivity, legal/
   compliance teams for breach-notification obligations.

**False positive considerations:** Legitimate large transfers (backups,
scheduled replication, cloud storage sync) can trigger the same signal —
correlate with change-management records and known scheduled jobs before
declaring an incident.
