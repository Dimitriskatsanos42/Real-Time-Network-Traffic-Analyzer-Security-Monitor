"""
Brute-Force & Failed Login Detection.

Αναλύει TCP traffic προς authentication ports (SSH, RDP, FTP, κ.λπ.)
και εντοπίζει:
  - Αποτυχημένες προσπάθειες σύνδεσης (RST/FIN patterns)
  - Brute-force επιθέσεις (πολλές προσπάθειες σε σύντομο χρονικό παράθυρο)
"""

import time
from collections import defaultdict

# Γνωστά authentication ports και τα αντίστοιχα services
AUTH_PORTS = {
    22: "SSH",
    23: "Telnet",
    21: "FTP",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    445: "SMB",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}


class BruteForceDetector:
    """
    Ανιχνευτής brute-force και failed login attacks.

    Λογική:
      - Κάθε SYN προς auth port καταγράφεται ως προσπάθεια σύνδεσης
      - RST flag θεωρείται αποτυχημένη σύνδεση
      - Αν ξεπεραστεί το threshold σε window → brute-force alert
    """

    def __init__(self, brute_threshold=10, brute_window=120, failed_threshold=5):
        self.brute_threshold = brute_threshold
        self.brute_window = brute_window
        self.failed_threshold = failed_threshold
        # src_ip -> [(timestamp, dst_ip, dst_port, failed)]
        self._attempts = defaultdict(list)
        self._alerted_brute = set()
        self._alerted_failed = set()

    def analyze(self, src_ip, dst_ip, dst_port, flags):
        """
        Αναλύει ένα TCP packet προς auth port.

        Returns:
            dict με keys: type ('failed_login'|'brute_force'), service, message
            ή None αν δεν εντοπίστηκε απειλή.
        """
        if dst_port not in AUTH_PORTS:
            return None

        service = AUTH_PORTS[dst_port]
        now = time.time()
        window_start = now - self.brute_window

        # Καθαρισμός παλιών εγγραφών
        self._attempts[src_ip] = [
            (t, d, p, f) for t, d, p, f in self._attempts[src_ip] if t >= window_start
        ]

        # Εντοπισμός αποτυχημένης σύνδεσης (RST flag)
        is_failed = flags and "R" in str(flags)
        self._attempts[src_ip].append((now, dst_ip, dst_port, is_failed))

        failed_count = sum(1 for _, _, p, f in self._attempts[src_ip] if f and p == dst_port)
        total_count = sum(1 for _, _, p, _ in self._attempts[src_ip] if p == dst_port)

        # Brute-force: πολλές προσπάθειες (επιτυχημένες ή όχι) σε σύντομο διάστημα
        brute_key = f"{src_ip}:{dst_port}"
        if total_count >= self.brute_threshold and brute_key not in self._alerted_brute:
            self._alerted_brute.add(brute_key)
            return {
                "type": "brute_force",
                "service": service,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "message": (
                    f"Brute-force attack detected: {total_count} connection attempts "
                    f"from {src_ip} to {service} ({dst_ip}:{dst_port}) "
                    f"in {self.brute_window}s"
                ),
                "failed": is_failed,
            }

        # Failed login: πολλές αποτυχημένες προσπάθειες
        failed_key = f"{src_ip}:{dst_port}:failed"
        if failed_count >= self.failed_threshold and failed_key not in self._alerted_failed:
            self._alerted_failed.add(failed_key)
            return {
                "type": "failed_login",
                "service": service,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "message": (
                    f"Failed login attempts: {failed_count} rejected connections "
                    f"from {src_ip} to {service} ({dst_ip}:{dst_port})"
                ),
                "failed": True,
            }

        # Reset alerts αν η δραστηριότητα μειωθεί
        if total_count < self.brute_threshold // 2:
            self._alerted_brute.discard(brute_key)
        if failed_count < self.failed_threshold // 2:
            self._alerted_failed.discard(failed_key)

        return None
