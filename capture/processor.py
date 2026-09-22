"""
Packet Processor — Κεντρικός επεξεργαστής captured packets.

Λαμβάνει κάθε packet από τον Scapy sniffer και:
  1. Αποθηκεύει το packet στη βάση
  2. Εκτελεί GeoIP lookup
  3. Ελέγχει blacklist
  4. Τρέχει detection engines (port scan, DNS, brute-force)
  5. Ενημερώνει Top IPs statistics
"""

import logging
from collections import defaultdict

from scapy.all import DNS, IP, TCP, UDP
from scapy.layers.inet6 import IPv6

from alerts.manager import AlertManager
from detection.brute_force import BruteForceDetector
from detection.dns_monitor import DNSMonitor
from detection.port_scan_detector import PortScanDetector
from extensions import db
from models import DNSQuery, LoginAttempt, PacketRecord, TopIP, utcnow
from services.blacklist import BlacklistService
from services.geoip import GeoIPService

logger = logging.getLogger(__name__)


class PacketProcessor:
    """Επεξεργασία captured packets με ενσωματωμένη threat detection."""

    def __init__(self, app):
        self.app = app

        # ── Detection engines ─────────────────────────────────────
        self.port_scan_detector = PortScanDetector(
            threshold=app.config["PORT_SCAN_THRESHOLD"],
            window_seconds=app.config["PORT_SCAN_WINDOW_SECONDS"],
        )
        self.dns_monitor = DNSMonitor(
            suspicious_length=app.config["DNS_SUSPICIOUS_QUERY_LENGTH"]
        )
        self.brute_force_detector = BruteForceDetector(
            brute_threshold=app.config["BRUTE_FORCE_THRESHOLD"],
            brute_window=app.config["BRUTE_FORCE_WINDOW_SECONDS"],
            failed_threshold=app.config["FAILED_LOGIN_THRESHOLD"],
        )

        # ── Supporting services ─────────────────────────────────────
        self.geoip = GeoIPService(
            db_path=app.config.get("GEOIP_DB_PATH"),
            fallback_api=app.config.get("GEOIP_FALLBACK_API"),
        )
        self.blacklist = BlacklistService(
            blacklist_file=app.config.get("BLACKLIST_FILE")
        )
        self.blacklist.load()

        self.alert_manager = AlertManager()
        self._ip_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
        self._packet_count = 0

    def process(self, packet):
        """Entry point — καλείται από τον sniffer για κάθε packet."""
        with self.app.app_context():
            try:
                self._handle_packet(packet)
            except Exception:
                logger.exception("Error processing packet")

    def _handle_packet(self, packet):
        """Κύρια λογική επεξεργασίας ενός packet."""
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if not ip_layer:
            return

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        length = len(packet)
        protocol = "OTHER"
        src_port = None
        dst_port = None
        flags = None

        # GeoIP lookup για source και destination
        src_geo = self.geoip.lookup(src_ip)
        dst_geo = self.geoip.lookup(dst_ip)

        # ── Blacklist check ───────────────────────────────────────
        for ip, geo in ((src_ip, src_geo), (dst_ip, dst_geo)):
            if self.blacklist.is_blacklisted(ip):
                self.alert_manager.create_alert(
                    severity="critical",
                    alert_type="blacklist",
                    source_ip=ip,
                    message=f"Blacklisted IP detected in traffic: {ip}",
                    country=geo.get("country"),
                )

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = str(packet[TCP].flags)

            # Port scan detection
            scan_alert = self.port_scan_detector.analyze(src_ip, dst_port, flags)
            if scan_alert:
                self.alert_manager.create_alert(
                    severity="high",
                    alert_type="port_scan",
                    source_ip=src_ip,
                    message=scan_alert,
                    country=src_geo.get("country"),
                )

            # Brute-force / failed login detection
            bf_result = self.brute_force_detector.analyze(
                src_ip, dst_ip, dst_port, flags
            )
            if bf_result:
                severity = "critical" if bf_result["type"] == "brute_force" else "high"
                self.alert_manager.create_alert(
                    severity=severity,
                    alert_type=bf_result["type"],
                    source_ip=src_ip,
                    message=bf_result["message"],
                    country=src_geo.get("country"),
                )
                # Καταγραφή login attempt
                db.session.add(
                    LoginAttempt(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        service=bf_result["service"],
                        success=not bf_result.get("failed", False),
                        country=src_geo.get("country"),
                    )
                )

        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            # DNS monitoring
            if packet.haslayer(DNS) and packet[DNS].qr == 0:
                dns_results = self.dns_monitor.analyze(packet, src_ip)
                for result in dns_results:
                    db.session.add(
                        DNSQuery(
                            src_ip=result["src_ip"],
                            query_name=result["query_name"],
                            query_type=result["query_type"],
                            is_suspicious=result["is_suspicious"],
                            src_country=src_geo.get("country"),
                        )
                    )
                    if result["is_suspicious"]:
                        self.alert_manager.create_alert(
                            severity="medium",
                            alert_type="suspicious_dns",
                            source_ip=result["src_ip"],
                            message=result["reason"],
                            country=src_geo.get("country"),
                        )

        # ── Αποθήκευση packet record ────────────────────────────────
        db.session.add(
            PacketRecord(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=length,
                flags=flags,
                src_country=src_geo.get("country"),
                dst_country=dst_geo.get("country"),
            )
        )

        # Ενημέρωση Top IP stats
        for ip, geo in ((src_ip, src_geo), (dst_ip, dst_geo)):
            self._ip_stats[ip]["packets"] += 1
            self._ip_stats[ip]["bytes"] += length
            self._ip_stats[ip]["country"] = geo.get("country")
            self._ip_stats[ip]["country_code"] = geo.get("country_code")
            self._ip_stats[ip]["blacklisted"] = self.blacklist.is_blacklisted(ip)

        self._packet_count += 1
        if self._packet_count % 50 == 0:
            self._flush_top_ips()
            db.session.commit()

    def _flush_top_ips(self):
        """Μαζική ενημέρωση Top IPs πίνακα."""
        for ip, stats in self._ip_stats.items():
            top = TopIP.query.filter_by(ip_address=ip).first()
            if top:
                top.packet_count += stats["packets"]
                top.byte_count += stats["bytes"]
                top.last_seen = utcnow()
                top.country = stats.get("country") or top.country
                top.country_code = stats.get("country_code") or top.country_code
                top.is_blacklisted = stats.get("blacklisted", False)
            else:
                db.session.add(
                    TopIP(
                        ip_address=ip,
                        packet_count=stats["packets"],
                        byte_count=stats["bytes"],
                        country=stats.get("country"),
                        country_code=stats.get("country_code"),
                        is_blacklisted=stats.get("blacklisted", False),
                    )
                )
        self._ip_stats.clear()

    def flush(self):
        """Flush pending data — καλείται κατά το stop του sniffer."""
        with self.app.app_context():
            self._flush_top_ips()
            db.session.commit()
