"""
Blacklist Service — Διαχείριση μαύρης λίστας IP addresses.

Φορτώνει IPs από αρχείο (data/blacklist.txt) και από τη βάση δεδομένων.
Χρησιμοποιείται για άμεση ανίχνευση γνωστών κακόβουλων διευθύνσεων.
"""

import logging
import os

from extensions import db
from models import BlacklistEntry

logger = logging.getLogger(__name__)


class BlacklistService:
    """Υπηρεσία ελέγχου και διαχείρισης blacklist."""

    def __init__(self, blacklist_file=None):
        self.blacklist_file = blacklist_file
        self._cache = set()

    def load(self):
        """Φόρτωση blacklist από αρχείο και database στη μνήμη."""
        self._cache.clear()
        self._load_from_file()
        self._load_from_db()
        logger.info("Blacklist loaded: %d entries", len(self._cache))

    def _load_from_file(self):
        """Διάβασμα IPs από text αρχείο (μία IP ανά γραμμή, # για σχόλια)."""
        if not self.blacklist_file or not os.path.exists(self.blacklist_file):
            return

        with open(self.blacklist_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ip = line.split()[0]
                self._cache.add(ip)
                # Συγχρονισμός στη βάση αν δεν υπάρχει
                if not BlacklistEntry.query.filter_by(ip_address=ip).first():
                    db.session.add(
                        BlacklistEntry(
                            ip_address=ip,
                            reason="Loaded from blacklist file",
                            source="file",
                        )
                    )
        db.session.commit()

    def _load_from_db(self):
        """Φόρτωση ενεργών entries από τη βάση."""
        entries = BlacklistEntry.query.filter_by(active=True).all()
        for entry in entries:
            self._cache.add(entry.ip_address)

    def is_blacklisted(self, ip_str):
        """Ελέγχει αν μια IP βρίσκεται στη μαύρη λίστα."""
        return ip_str in self._cache

    def add(self, ip_str, reason="Manual entry", source="manual"):
        """Προσθήκη IP στη blacklist."""
        if ip_str in self._cache:
            return False

        entry = BlacklistEntry(ip_address=ip_str, reason=reason, source=source)
        db.session.add(entry)
        db.session.commit()
        self._cache.add(ip_str)
        return True

    def remove(self, ip_str):
        """Απενεργοποίηση IP από τη blacklist (soft delete)."""
        entry = BlacklistEntry.query.filter_by(ip_address=ip_str).first()
        if entry:
            entry.active = False
            db.session.commit()
            self._cache.discard(ip_str)
            return True
        return False

    def get_all(self):
        """Επιστρέφει όλες τις ενεργές blacklist entries."""
        return BlacklistEntry.query.filter_by(active=True).all()
