import time
from collections import defaultdict


class PortScanDetector:
    """
    Detects port scans: many distinct destination ports from one source
    within a time window (typical SYN scan behavior).
    """

    def __init__(self, threshold=15, window_seconds=60):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._activity = defaultdict(list)  # src_ip -> [(timestamp, dst_port)]
        self._alerted = set()

    def analyze(self, src_ip, dst_port, flags):
        if dst_port is None:
            return None

        now = time.time()
        window_start = now - self.window_seconds

        entries = self._activity[src_ip]
        entries.append((now, dst_port))
        self._activity[src_ip] = [(t, p) for t, p in entries if t >= window_start]

        unique_ports = {p for _, p in self._activity[src_ip]}
        if len(unique_ports) >= self.threshold and src_ip not in self._alerted:
            self._alerted.add(src_ip)
            return (
                f"Port scan detected from {src_ip}: "
                f"{len(unique_ports)} unique ports in {self.window_seconds}s"
            )

        if len(unique_ports) < self.threshold // 2:
            self._alerted.discard(src_ip)

        return None
