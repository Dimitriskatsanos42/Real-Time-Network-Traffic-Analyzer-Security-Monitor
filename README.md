# Real-Time Network Traffic Analyzer & Security Monitor

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-green)
![SQLAlchemy](https://img.shields.io/badge/Database-SQLAlchemy-orange)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED)
![Security](https://img.shields.io/badge/Security-JWT%20%7C%20Fernet-red)

Πλήρες σύστημα real-time network monitoring και security analysis βασισμένο σε Flask και Scapy. Η εφαρμογή συλλέγει δικτυακά πακέτα, αναλύει TCP/UDP/DNS traffic, εντοπίζει ύποπτη δραστηριότητα και παρουσιάζει τα αποτελέσματα σε web dashboard και REST API.

Το project είναι σχεδιασμένο για local development, εργαστηριακή χρήση και Docker deployment. Για production χρήση απαιτούνται ισχυρά secrets, HTTPS, reverse proxy, κατάλληλη βάση δεδομένων και περιορισμός πρόσβασης στο packet capture.

## Περιεχόμενα

- [Δυνατότητες](#δυνατότητες)
- [Αρχιτεκτονική](#αρχιτεκτονική)
- [Απαιτήσεις](#απαιτήσεις)
- [Εγκατάσταση σε Windows](#εγκατάσταση-σε-windows)
- [Εκκίνηση](#εκκίνηση)
- [Authentication και χρήστες](#authentication-και-χρήστες)
- [Κρυπτογράφηση](#κρυπτογράφηση)
- [API](#api)
- [Docker](#docker)
- [Configuration](#configuration)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Production checklist](#production-checklist)
- [Δομή project](#δομή-project)

## Δυνατότητες

### Network monitoring

- Real-time packet capture μέσω Scapy.
- Ανάλυση IPv4/IPv6 traffic όπου υποστηρίζεται από το capture interface.
- Παρακολούθηση TCP, UDP και DNS.
- Καταγραφή source/destination IP, ports, protocol, packet length και TCP flags.
- Top IPs με packet count, byte count, χώρα και blacklist status.
- Dashboard statistics για συνολικά packets, traffic ανά protocol και πρόσφατη κίνηση.

### Threat detection

- Port scan detection με configurable threshold και χρονικό παράθυρο.
- Brute-force detection για αποτυχημένες προσπάθειες σύνδεσης.
- DNS monitoring και εντοπισμός ύποπτων ή υπερβολικά μεγάλων queries.
- Blacklist matching για γνωστές ή χειροκίνητα αποκλεισμένες IPs.
- Alerts με severity: `low`, `medium`, `high` και `critical`.
- Acknowledgement workflow για alerts.
- GeoIP lookup με προαιρετική MaxMind database και fallback API.

### Reports και operations

- CSV export για packets, alerts, DNS queries και top IPs.
- PDF security report για επιλεγμένο χρονικό διάστημα.
- Health endpoint για monitoring και Docker healthcheck.
- Start, stop και status control του packet capture.
- Structured application logging και configurable data retention.

### Authentication και security

- JWT authentication για protected API endpoints.
- Password hashing με Werkzeug, χωρίς αποθήκευση plaintext passwords.
- Ρόλοι `admin`, `analyst` και `viewer`.
- Public registration που δημιουργεί `viewer` λογαριασμούς.
- Admin-only δημιουργία και λίστα χρηστών.
- Ισχυρή password policy.
- Προσωρινό login lockout μετά από πολλές αποτυχημένες προσπάθειες.
- Encrypted user profiles με Fernet.
- Production guard που απορρίπτει default development secrets.

## Αρχιτεκτονική

```text
+-------------------+
| Scapy Packet      |
| Sniffer           |
+---------+---------+
          |
          v
+-------------------+
| Packet Processor  |
| Normalize/Store   |
+---------+---------+
          |
          v
+-------------------+       +----------------------+
| Detection Modules | ----> | Alerts / Login Data |
| Port / DNS / Auth |       +----------------------+
+---------+---------+
          |
          v
+-------------------+       +----------------------+
| SQLAlchemy        | ----> | SQLite / PostgreSQL |
| Models            |       +----------------------+
+---------+---------+
          |
          v
+-------------------+       +----------------------+
| Flask REST API    | ----> | Web Dashboard       |
| JWT Protected     |       | HTML/CSS/JavaScript |
+-------------------+       +----------------------+
```

### Βασική ροή δεδομένων

1. Το `PacketSniffer` λαμβάνει πακέτα από το network interface.
2. Το `PacketProcessor` εξάγει τα χρήσιμα network fields.
3. Τα detection modules ελέγχουν για ύποπτα patterns.
4. Τα models αποθηκεύουν packets, DNS queries, alerts και statistics.
5. Το REST API παρέχει authenticated πρόσβαση στα δεδομένα.
6. Το dashboard εμφανίζει live monitoring και actions.

## Απαιτήσεις

- Python 3.10 ή νεότερο.
- Windows, Linux ή macOS.
- Npcap στα Windows ή αντίστοιχη packet capture υποστήριξη.
- Administrator/root permissions μπορεί να απαιτούνται για capture.
- Docker Desktop, αν χρησιμοποιηθεί Docker.
- Προαιρετικά: GeoLite2-Country `.mmdb` database.
- Για production: PostgreSQL, HTTPS reverse proxy και μόνιμο secrets management.

## Εγκατάσταση σε Windows

Άνοιξε PowerShell στον φάκελο του project:

```powershell
cd "c:\Users\usr1\Documents\Real-Time Network Traffic Analyzer & Security Monitor"
py -3 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Αν το PowerShell μπλοκάρει την ενεργοποίηση του virtual environment:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Στη συνέχεια κλείσε και ξανάνοιξε το PowerShell, ενεργοποίησε το `venv` και συνέχισε με την εκκίνηση.

## Εκκίνηση

### Development mode

Για local development:

```powershell
$env:APP_ENV="development"
$env:FLASK_HOST="127.0.0.1"
$env:FLASK_PORT="5000"
$env:FLASK_DEBUG="false"
$env:AUTO_START_CAPTURE="false"
python app.py
```

Η εφαρμογή θα είναι διαθέσιμη στα:

- Dashboard: http://127.0.0.1:5000/
- Health check: http://127.0.0.1:5000/api/health

Για να σταματήσεις την εφαρμογή, πάτησε `Ctrl+C`.

### Packet capture

Από το dashboard χρησιμοποίησε το `Start Capture`. Εναλλακτικά, μπορείς να ορίσεις interface:

```powershell
$env:CAPTURE_INTERFACE="Ethernet"
$env:AUTO_START_CAPTURE="true"
python app.py
```

Το ακριβές όνομα interface εξαρτάται από το λειτουργικό σύστημα και τη ρύθμιση δικτύου. Σε Windows μπορεί να απαιτείται εκτέλεση του PowerShell ως Administrator.

## Authentication και χρήστες

### Αρχικός admin

Σε development, αν δεν υπάρχει χρήστης με το configured username, δημιουργείται ένας admin από:

```powershell
$env:ADMIN_USERNAME="admin"
$env:ADMIN_PASSWORD="StrongAdminPassword!123"
```

Μην χρησιμοποιήσεις `admin123` σε production. Αν ο admin υπάρχει ήδη στη βάση, η εφαρμογή δεν αλλάζει αυτόματα τον κωδικό του.

### Password policy

Οι νέοι κωδικοί πρέπει να έχουν:

- Τουλάχιστον 12 χαρακτήρες.
- Τουλάχιστον ένα κεφαλαίο γράμμα.
- Τουλάχιστον ένα πεζό γράμμα.
- Τουλάχιστον έναν αριθμό.
- Τουλάχιστον ένα σύμβολο.

### Registration

Το public endpoint δημιουργεί νέο `viewer` user:

```powershell
$body = @{
    username = "analyst1"
    password = "StrongPassword!123"
    email = "analyst@example.com"
    full_name = "Network Analyst"
} | ConvertTo-Json

Invoke-RestMethod `
    -Method Post `
    -Uri http://127.0.0.1:5000/api/auth/register `
    -ContentType "application/json" `
    -Body $body
```

### Login

```powershell
$loginBody = @{
    username = "analyst1"
    password = "StrongPassword!123"
} | ConvertTo-Json

$login = Invoke-RestMethod `
    -Method Post `
    -Uri http://127.0.0.1:5000/api/auth/login `
    -ContentType "application/json" `
    -Body $loginBody

$token = $login.token
```

Το token χρησιμοποιείται στα protected endpoints:

```powershell
$headers = @{ Authorization = "Bearer $token" }
Invoke-RestMethod -Uri http://127.0.0.1:5000/api/stats -Headers $headers
```

### Roles

- `admin`: user management και πλήρης διαχείριση.
- `analyst`: πρόσβαση σε monitoring και analysis λειτουργίες.
- `viewer`: read-only πρόσβαση στα διαθέσιμα monitoring δεδομένα.

Ο admin δημιουργεί χρήστες μέσω `POST /api/users`. Το endpoint απαιτεί JWT token με role `admin`.

## Κρυπτογράφηση

Τα passwords αποθηκεύονται ως one-way hashes και δεν μπορούν να διαβαστούν από τη βάση.

Τα προσωπικά profile fields (`email`, `full_name`, `phone`, `notes`) αποθηκεύονται encrypted με Fernet στο `UserProfile` table.

### Δημιουργία Fernet key

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Αποθήκευσε το αποτέλεσμα ως `DATA_ENCRYPTION_KEY`. Το key πρέπει να παραμένει σταθερό και να αποθηκεύεται με ασφάλεια. Αν χαθεί ή αλλάξει χωρίς migration, τα ήδη encrypted profile fields δεν μπορούν να αποκρυπτογραφηθούν.

### Προσωπικό profile

```powershell
$profileBody = @{
    email = "private@example.com"
    full_name = "Private User"
    phone = "+30 210 0000000"
    notes = "Personal notes"
} | ConvertTo-Json

Invoke-RestMethod `
    -Method Patch `
    -Uri http://127.0.0.1:5000/api/auth/me `
    -Headers $headers `
    -ContentType "application/json" `
    -Body $profileBody
```

## API

Όλα τα protected endpoints απαιτούν:

```text
Authorization: Bearer <JWT_TOKEN>
```

### Public endpoints

| Method | Endpoint | Περιγραφή |
|---|---|---|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/auth/login` | Login και JWT token |
| `POST` | `/api/auth/register` | Δημιουργία viewer account |

### Authentication και users

| Method | Endpoint | Πρόσβαση |
|---|---|---|
| `GET` | `/api/auth/me` | Authenticated user |
| `PATCH` | `/api/auth/me` | Authenticated user |
| `GET` | `/api/users` | Admin |
| `POST` | `/api/users` | Admin |

### Monitoring

| Method | Endpoint | Περιγραφή |
|---|---|---|
| `GET` | `/api/stats` | Συνολικά statistics |
| `GET` | `/api/packets` | Πρόσφατα packets |
| `GET` | `/api/alerts` | Security alerts |
| `POST` | `/api/alerts/<id>/acknowledge` | Acknowledge alert |
| `GET` | `/api/dns` | DNS queries |
| `GET` | `/api/top-ips` | Top IPs |
| `GET` | `/api/login-attempts` | Failed login attempts |

### Capture, blacklist και exports

| Method | Endpoint | Περιγραφή |
|---|---|---|
| `GET` | `/api/capture/status` | Capture status |
| `POST` | `/api/capture/start` | Start capture |
| `POST` | `/api/capture/stop` | Stop capture |
| `GET` | `/api/blacklist` | Active blacklist entries |
| `POST` | `/api/blacklist` | Add blacklist entry |
| `DELETE` | `/api/blacklist/<ip>` | Remove blacklist entry |
| `GET` | `/api/export/csv/<data_type>` | CSV export |
| `GET` | `/api/export/pdf` | PDF security report |

## Configuration

Το βασικό template βρίσκεται στο `.env.example`.

### Σημαντικές μεταβλητές

| Variable | Περιγραφή |
|---|---|
| `APP_ENV` | `development` ή `production` |
| `SECRET_KEY` | Flask application secret |
| `JWT_SECRET_KEY` | JWT signing secret |
| `DATA_ENCRYPTION_KEY` | Fernet key για encrypted profiles |
| `ADMIN_USERNAME` | Αρχικός admin username |
| `ADMIN_PASSWORD` | Αρχικός admin password |
| `DATABASE_URL` | SQLite ή PostgreSQL connection string |
| `CAPTURE_INTERFACE` | Network interface για capture |
| `AUTO_START_CAPTURE` | Αυτόματο start capture |
| `FLASK_HOST` | Bind address |
| `FLASK_PORT` | HTTP port |
| `JWT_EXPIRATION_HOURS` | JWT expiration σε ώρες |
| `PORT_SCAN_THRESHOLD` | Port scan sensitivity |
| `BRUTE_FORCE_THRESHOLD` | Brute-force sensitivity |
| `DNS_SUSPICIOUS_QUERY_LENGTH` | DNS query length threshold |
| `GEOIP_DB_PATH` | MaxMind database path |
| `BLACKLIST_FILE` | Blacklist file path |

### Local `.env` και Docker

Το Docker Compose φορτώνει το `.env` μέσω `env_file`. Το απλό `python app.py` δεν φορτώνει αυτόματα `.env`, επομένως σε local PowerShell όρισε τις μεταβλητές με `$env:NAME="value"` ή χρησιμοποίησε environment loader.

## Docker

Δημιούργησε το local environment file:

```powershell
Copy-Item .env.example .env
```

Πριν το production deployment, αντικατάστησε όλα τα placeholder secrets στο `.env`.

Εκκίνηση:

```powershell
docker compose up --build
```

Έλεγχος:

```powershell
Invoke-RestMethod http://127.0.0.1:5000/api/health
```

Τερματισμός:

```powershell
docker compose down
```

Το Docker χρησιμοποιεί persistent volumes για `data/` και `reports/`.

## Database

By default χρησιμοποιείται SQLite και δημιουργείται αυτόματα το `network_monitor.db`.

Για production μπορεί να χρησιμοποιηθεί PostgreSQL μέσω `DATABASE_URL`:

```text
DATABASE_URL=postgresql://username:password@host:5432/network_monitor
```

Για σοβαρό production deployment συνιστάται migration tool, backup policy, connection pooling και περιορισμός των database credentials.

## Testing

Syntax check:

```powershell
python -m compileall -q app.py api auth config models.py services tests
```

Εγκατάσταση και εκτέλεση tests:

```powershell
python -m pip install pytest
python -m pytest -q
```

Το test suite καλύπτει application startup, health endpoint, dashboard loading, login, protected routes, registration, encrypted profiles και role authorization.

## Troubleshooting

### `ModuleNotFoundError`

Ενεργοποίησε το virtual environment και εγκατέστησε ξανά τα dependencies:

```powershell
python -m pip install -r requirements.txt
```

### Το packet capture δεν ξεκινά

Έλεγξε ότι:

1. Το Npcap είναι εγκατεστημένο στα Windows.
2. Το `CAPTURE_INTERFACE` έχει το σωστό όνομα.
3. Το PowerShell εκτελείται με Administrator permissions.
4. Το `AUTO_START_CAPTURE` δεν ενεργοποιείται πριν επιβεβαιώσεις το interface.

### Το port χρησιμοποιείται

```powershell
$env:FLASK_PORT="5001"
python app.py
```

### Production startup error για secrets

Σε `APP_ENV=production` δεν επιτρέπονται development defaults. Όρισε ισχυρά και μοναδικά:

- `SECRET_KEY`
- `JWT_SECRET_KEY`
- `ADMIN_PASSWORD`
- `DATA_ENCRYPTION_KEY`

### Πρόβλημα αποκρυπτογράφησης profile

Έλεγξε ότι χρησιμοποιείται ακριβώς το ίδιο `DATA_ENCRYPTION_KEY` που χρησιμοποιήθηκε κατά την αποθήκευση. Μην το αλλάξεις χωρίς σχεδιασμένο key migration.

### GeoIP database δεν υπάρχει

Αν λείπει το `GeoLite2-Country.mmdb`, η εφαρμογή χρησιμοποιεί το configured fallback API. Για production συνιστάται τοπική GeoIP database και περιορισμός των external requests.

## Production checklist

- [ ] Ισχυρά, μοναδικά secrets σε secret manager ή protected environment.
- [ ] `APP_ENV=production`.
- [ ] `FLASK_DEBUG=false`.
- [ ] HTTPS μέσω reverse proxy.
- [ ] Firewall και περιορισμός πρόσβασης στο dashboard/API.
- [ ] PostgreSQL ή άλλη production database.
- [ ] Backups για database, `data/` και `reports/`.
- [ ] Σταθερό και προστατευμένο `DATA_ENCRYPTION_KEY`.
- [ ] Npcap/packet capture permissions ελεγχόμενα.
- [ ] Log rotation και monitoring.
- [ ] Rate limiting σε reverse proxy για public endpoints.
- [ ] Περιοδικές ενημερώσεις dependencies.
- [ ] Αλλαγή του αρχικού admin password.

## Δομή project

```text
app.py                         Application factory και Flask server
extensions.py                  SQLAlchemy extension
models.py                      Database models
config/                        Application settings και logging
api/                           REST API routes
auth/                          JWT authentication και security policy
capture/                       Packet sniffer και packet processor
detection/                     Port scan, DNS και brute-force detection
services/                      Encryption, GeoIP και blacklist services
alerts/                        Alert management
reports/                       CSV και PDF exports
templates/                     Dashboard HTML
static/                        Dashboard CSS και JavaScript
data/                          Blacklist και optional GeoIP data
tests/                         Automated tests
docker-compose.yml             Application Docker deployment
Dockerfile                     Container image definition
requirements.txt               Python dependencies
.env.example                   Environment template
```

## Σημαντικές σημειώσεις

- Η εφαρμογή είναι monitoring/security εργαλείο και πρέπει να χρησιμοποιείται μόνο σε δίκτυα για τα οποία υπάρχει εξουσιοδότηση.
- Το packet capture μπορεί να περιέχει ευαίσθητα network metadata. Προστάτεψε τη βάση, τα logs και τα reports.
- Μην κάνεις commit το `.env`, secrets, database files ή production reports.
- Για production deployment χρειάζεται ξεχωριστός έλεγχος ασφαλείας, backup strategy και operational monitoring.
