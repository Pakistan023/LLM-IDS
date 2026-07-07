# DNS Tunneling (T1071.004 — Application Layer Protocol: DNS)

**Summary:** DNS tunneling encodes data (commands, files, or C2 traffic)
inside DNS queries and responses to bypass network controls that trust or
under-inspect DNS traffic, since DNS is almost always allowed outbound.

**Typical indicators:**
- Abnormally high volume of DNS queries to a single domain or a small set
  of related domains.
- Unusually long or high-entropy subdomain labels (encoded payload).
- Queries to domains registered very recently or with no legitimate
  business purpose.
- Consistent query timing suggesting automation rather than human lookups.

**Recommended response:**
1. Block or sinkhole the destination domain at the DNS resolver / firewall.
2. Inspect endpoint(s) generating the traffic for malware or unauthorized
   tunneling software (e.g. iodine, dnscat2).
3. Review DNS logs retroactively for the same domain across the
   environment — tunneling infrastructure is often reused.
4. Consider enabling DNS query logging and anomaly detection permanently if
   not already in place, since this technique is otherwise hard to see.

**False positive considerations:** Some legitimate services (CDNs, mobile
push notification frameworks, certain antivirus cloud lookups) generate
high-volume DNS traffic with long subdomains — validate against known
vendor domain patterns before blocking broadly.
