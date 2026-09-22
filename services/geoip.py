"""
GeoIP Service — Εντοπισμός χώρας/πόλης για IP addresses.

Στρατηγική lookup (με σειρά προτεραιότητας):
  1. In-memory + database cache
  2. Τοπική MaxMind GeoLite2 βάση (.mmdb)
  3. Fallback HTTP API (ip-api.com)
"""

import ipaddress
import json
import logging
import urllib.request

from extensions import db
from models import IPGeoCache, utcnow

logger = logging.getLogger(__name__)

# Private/reserved ranges — δεν χρειάζεται GeoIP lookup
_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
)


class GeoIPService:
    """Υπηρεσία γεωγραφικού εντοπισμού IP με caching."""

    def __init__(self, db_path=None, fallback_api=None):
        self.db_path = db_path
        self.fallback_api = fallback_api
        self._reader = None
        self._memory_cache = {}
        self._init_maxmind()

    def _init_maxmind(self):
        """Φόρτωση MaxMind GeoLite2 database αν υπάρχει."""
        if not self.db_path:
            return
        try:
            import geoip2.database

            self._reader = geoip2.database.Reader(self.db_path)
            logger.info("GeoIP: MaxMind database loaded from %s", self.db_path)
        except FileNotFoundError:
            logger.warning("GeoIP: MaxMind DB not found at %s — using API fallback", self.db_path)
        except ImportError:
            logger.warning("GeoIP: geoip2 package not installed — using API fallback")

    def _is_private(self, ip_str):
        """Ελέγχει αν το IP ανήκει σε private/local range."""
        try:
            addr = ipaddress.ip_address(ip_str)
            return any(addr in net for net in _PRIVATE_NETWORKS)
        except ValueError:
            return True

    def lookup(self, ip_str):
        """
        Επιστρέφει dict με country, country_code, city, isp.
        Αποθηκεύει αποτέλεσμα στο cache για μελλοντικά lookups.
        """
        if not ip_str or self._is_private(ip_str):
            return self._result("Private/Local", "—", "Local", "LAN")

        # 1. Memory cache
        if ip_str in self._memory_cache:
            return self._memory_cache[ip_str]

        # 2. Database cache
        cached = IPGeoCache.query.filter_by(ip_address=ip_str).first()
        if cached:
            result = cached.to_dict()
            self._memory_cache[ip_str] = result
            return result

        # 3. MaxMind lookup
        result = self._lookup_maxmind(ip_str)

        # 4. HTTP API fallback
        if not result:
            result = self._lookup_api(ip_str)

        if not result:
            result = self._result("Unknown", "??", "Unknown", "Unknown")

        self._save_cache(ip_str, result)
        self._memory_cache[ip_str] = result
        return result

    def _lookup_maxmind(self, ip_str):
        """Lookup μέσω τοπικής MaxMind βάσης."""
        if not self._reader:
            return None
        try:
            response = self._reader.country(ip_str)
            return self._result(
                country=response.country.name or "Unknown",
                country_code=response.country.iso_code or "??",
                city="",
                isp="",
            )
        except Exception:
            return None

    def _lookup_api(self, ip_str):
        """Fallback lookup μέσω δωρεάν HTTP API."""
        if not self.fallback_api:
            return None
        try:
            url = self.fallback_api.format(ip=ip_str)
            req = urllib.request.Request(url, headers={"User-Agent": "NetworkMonitor/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode())
            if data.get("status") == "fail":
                return None
            return self._result(
                country=data.get("country", "Unknown"),
                country_code=data.get("countryCode", "??"),
                city=data.get("city", ""),
                isp=data.get("isp", ""),
            )
        except Exception as exc:
            logger.debug("GeoIP API fallback failed for %s: %s", ip_str, exc)
            return None

    def _save_cache(self, ip_str, result):
        """Αποθήκευση αποτελέσματος στη βάση."""
        cached = IPGeoCache.query.filter_by(ip_address=ip_str).first()
        if cached:
            cached.country = result.get("country")
            cached.country_code = result.get("country_code")
            cached.city = result.get("city")
            cached.isp = result.get("isp")
            cached.updated_at = utcnow()
        else:
            db.session.add(
                IPGeoCache(
                    ip_address=ip_str,
                    country=result.get("country"),
                    country_code=result.get("country_code"),
                    city=result.get("city"),
                    isp=result.get("isp"),
                )
            )
        db.session.commit()

    @staticmethod
    def _result(country, country_code, city, isp):
        return {
            "ip_address": None,
            "country": country,
            "country_code": country_code,
            "city": city,
            "isp": isp,
        }
