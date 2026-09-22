from scapy.all import DNS, DNSQR


class DNSMonitor:
    """Extracts and analyzes DNS queries from captured packets."""

    SUSPICIOUS_KEYWORDS = (
        "malware",
        "c2",
        "botnet",
        "exfil",
        "tunnel",
        "phish",
        "onion",
    )

    def __init__(self, suspicious_length=80):
        self.suspicious_length = suspicious_length

    def analyze(self, packet, src_ip):
        if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
            return []

        results = []
        for i in range(packet[DNS].qdcount or 1):
            try:
                qname = packet[DNSQR][i].qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace")
                qname = qname.rstrip(".")
                qtype = self._qtype_name(packet[DNSQR][i].qtype)
            except (IndexError, AttributeError):
                continue

            is_suspicious, reason = self._check_suspicious(qname)
            results.append(
                {
                    "src_ip": src_ip,
                    "query_name": qname,
                    "query_type": qtype,
                    "is_suspicious": is_suspicious,
                    "reason": reason,
                }
            )

        return results

    def _qtype_name(self, qtype):
        types = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS"}
        return types.get(qtype, str(qtype))

    def _check_suspicious(self, qname):
        lower = qname.lower()
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in lower:
                return True, f"Suspicious DNS query containing '{keyword}': {qname}"

        if len(qname) > self.suspicious_length:
            return True, f"Unusually long DNS query ({len(qname)} chars): {qname}"

        labels = qname.split(".")
        if any(len(label) > 63 for label in labels):
            return True, f"Oversized DNS label in query: {qname}"

        return False, None
