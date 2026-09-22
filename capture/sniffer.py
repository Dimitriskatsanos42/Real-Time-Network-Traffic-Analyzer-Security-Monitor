import logging
import threading

from scapy.all import sniff

logger = logging.getLogger(__name__)


class PacketSniffer:
    """Background packet capture using Scapy."""

    def __init__(self, processor, interface=None):
        self.processor = processor
        self.interface = interface
        self._thread = None
        self._running = False
        self._lock = threading.Lock()

    @property
    def is_running(self):
        return self._running

    def start(self):
        with self._lock:
            if self._running:
                return False
            self._running = True
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            logger.info("Packet sniffer started on interface: %s", self.interface or "auto")
            return True

    def stop(self):
        with self._lock:
            self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        self.processor.flush()
        logger.info("Packet sniffer stopped")

    def _run(self):
        try:
            sniff(
                iface=self.interface,
                prn=self.processor.process,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except PermissionError:
            logger.error(
                "Permission denied. Run as Administrator (Windows) or root (Linux)."
            )
            self._running = False
        except Exception:
            logger.exception("Sniffer error")
            self._running = False
