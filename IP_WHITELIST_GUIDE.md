# Guida completa alle IP Whitelist in FUCO

## 📋 Panoramica

FUCO ha **DUE tipi di whitelist IP** con scopi diversi:

| Whitelist | File config | Scopo | Endpoint protetti |
|-----------|-------------|-------|-------------------|
| **CSRF_WHITELIST** | `config.py` | Bypass protezione CSRF per API client | Tutti gli endpoint che modificano dati |
| **ALLOWED_IPS** | `config.py` | Restringe accesso a API admin | `/api/cache/stats`, `/api/cache/clear` |

---

## 🔍 Differenza tra le due whitelist

### CSRF_WHITELIST
**Quando usarla:** Client API automatici che non possono gestire CSRF token.

**Cosa fa:** 
- Disabilita la validazione CSRF per IP fidati
- Permette POST/PUT/DELETE senza token CSRF
- NON restringe l'accesso (solo bypass CSRF)

**Esempio tipico:**
```python
# Script automatico che fa POST a /api/submit
CSRF_WHITELIST = ['192.168.1.50']  # IP del server con lo script
```

### ALLOWED_IPS
**Quando usarla:** Restringere accesso a endpoint sensibili solo ad admin.

**Cosa fa:**
- Blocca totalmente l'accesso se IP non è nella lista
- Protegge endpoint di amministrazione cache
- Restituisce 403 Forbidden se IP non autorizzato

**Esempio tipico:**
```python
# Solo admin può vedere/cancellare cache
ALLOWED_IPS = ['192.168.1.10', '192.168.1.11']  # IP degli admin
```

---

## 🌐 Configurazione con Nginx (IMPORTANTE!)

### ⚠️ Il problema

Con nginx come reverse proxy:
```
Client (IP: 192.168.1.100)
    ↓
Nginx (localhost:80)
    ↓ proxy_pass
Flask (127.0.0.1:8000)
```

**SENZA header proxy:** Flask vede sempre `127.0.0.1` → whitelist inutile!  
**CON header proxy:** Flask legge `X-Forwarded-For` → rileva IP reale ✅

### ✅ Configurazione nginx corretta

La configurazione in `deploy/nginx/fuco.conf` è già corretta:

```nginx
location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;           # ✅ Necessario
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  # ✅ Necessario
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

### 🔧 Come FUCO rileva l'IP reale

`_get_client_ip()` in `security.py`:

1. **Prima** legge `X-Forwarded-For` (se presente) → primo IP nella lista
2. **Poi** legge `X-Real-IP` (se presente)
3. **Infine** usa `request.remote_addr` (solo se nessun header)

**Con nginx configurato**: rileva sempre l'IP reale del client ✅

---

## 🛠️ Come configurare le whitelist

### Step 1: Scopri quale IP viene rilevato

**Metodo A - Via browser/curl:**
```bash
curl http://your-server/debug/ip-info
```

Risposta:
```json
{
  "detected_client_ip": "192.168.1.100",  ← Usa questo!
  "is_whitelisted": false,
  "raw_data": {
    "remote_addr": "127.0.0.1",
    "x_forwarded_for": "192.168.1.100",
    "x_real_ip": "192.168.1.100"
  }
}
```

**Metodo B - Via script test:**
```bash
cd test
python test_ip_whitelist.py http://your-server
```

**Metodo C - Nei log (con LOG_LEVEL=DEBUG):**
```
DEBUG:security:IP from X-Forwarded-For: 192.168.1.100 (full: 192.168.1.100)
```

### Step 2: Aggiungi IP nelle whitelist appropriate

#### Esempio 1: Client API da server remoto

**Scenario:** Script su server `192.168.1.50` fa POST a `/api/submit`

**Soluzione:**
```python
# config.py
CSRF_WHITELIST = ['192.168.1.50']  # Bypass CSRF per lo script
ALLOWED_IPS = ['127.0.0.1', '::1']  # Cache API solo da localhost
```

#### Esempio 2: Admin da workstation

**Scenario:** Admin da `192.168.1.10` vuole accedere a `/api/cache/stats`

**Soluzione:**
```python
# config.py
CSRF_WHITELIST = []  # Browser gestisce CSRF normalmente
ALLOWED_IPS = ['192.168.1.10']  # Solo questo IP può accedere a cache API
```

#### Esempio 3: Script locale + admin remoto

**Scenario:** Script sulla stessa macchina + admin da `10.0.0.5`

**Soluzione:**
```python
# config.py
CSRF_WHITELIST = ['127.0.0.1', '::1']  # Script locale bypass CSRF
ALLOWED_IPS = ['127.0.0.1', '::1', '10.0.0.5']  # Locale + admin remoto
```

---

## 📊 Log e debugging

### Attivare logging dettagliato

In `config.py`:
```python
LOG_LEVEL = logging.DEBUG
```

### Log CSRF Whitelist

**IP in whitelist:**
```
DEBUG:security:IP from X-Forwarded-For: 192.168.1.50
DEBUG:security:CSRF check bypassed for whitelisted IP: 192.168.1.50
```

**IP NON in whitelist (CSRF fallisce):**
```
DEBUG:security:IP from X-Forwarded-For: 192.168.1.100
DEBUG:security:CSRF check enforced: IP 192.168.1.100 not in whitelist ['192.168.1.50']
WARNING:fuco:CSRF validation failed: The CSRF token is missing. | IP: 192.168.1.100 | Path: /api/submit | Method: POST
```

### Log ALLOWED_IPS

**IP autorizzato:**
```
DEBUG:routes:IP whitelist check: 192.168.1.10 vs ['192.168.1.10'] | Path: /api/cache/stats
DEBUG:routes:IP whitelist: 192.168.1.10 authorized for /api/cache/stats
```

**IP NON autorizzato (accesso negato):**
```
DEBUG:routes:IP whitelist check: 192.168.1.100 vs ['192.168.1.10'] | Path: /api/cache/stats
WARNING:routes:IP whitelist: Access denied for 192.168.1.100 | Path: /api/cache/stats | Allowed: ['192.168.1.10']
```

---

## 🧪 Testing

### Test manuale via curl

**Test 1: Verifica IP rilevato**
```bash
curl http://your-server/debug/ip-info
```

**Test 2: Test CSRF whitelist**
```bash
# Dovrebbe fallire se IP non in CSRF_WHITELIST
curl -X POST http://your-server/api/submit \
  -H "Content-Type: application/json" \
  -d '{"dataType":"ip","data":"8.8.8.8"}'

# Risposta attesa (se non in whitelist):
# {"success": false, "error": "CSRF validation failed", "message": "The CSRF token is missing."}
```

**Test 3: Test ALLOWED_IPS**
```bash
# Dovrebbe fallire se IP non in ALLOWED_IPS
curl http://your-server/api/cache/stats

# Risposta attesa (se non in whitelist):
# {"error": "Access denied", "message": "Your IP address is not authorized to access this resource"}
```

### Test automatico

```bash
cd test
python test_ip_whitelist.py http://your-server
```

Output esempio:
```
[1/3] Verifica IP rilevato dal server...
✅ IP rilevato: 192.168.1.100

[2/3] Test accesso a /api/cache/stats (GET)...
❌ ACCESSO NEGATO (403 Forbidden)
   Il tuo IP (192.168.1.100) non è in ALLOWED_IPS

RIEPILOGO:
IP rilevato dal server: 192.168.1.100

Per autorizzare questo IP, aggiungi in config.py:
ALLOWED_IPS = ['192.168.1.100']
```

---

## ⚠️ Problemi comuni

### 1. Whitelist non funziona, vedo sempre 403/CSRF error

**Cause possibili:**
- IP in `ALLOWED_IPS`/`CSRF_WHITELIST` è sbagliato
- Nginx non passa header `X-Forwarded-For`
- IP cambia dinamicamente (DHCP)

**Debugging:**
1. Visita `/debug/ip-info` e vedi quale IP viene rilevato
2. Confronta con quello in `config.py`
3. Aggiungi il logging: `LOG_LEVEL = logging.DEBUG`
4. Verifica nginx config (deve avere `proxy_set_header X-Forwarded-For`)

### 2. Tutti i client vengono rilevati come 127.0.0.1

**Causa:** Nginx non passa header proxy

**Soluzione:**
```nginx
# Aggiungi in nginx config
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

Poi riavvia nginx:
```bash
sudo nginx -t
sudo systemctl reload nginx
```

### 3. IPv6 vs IPv4

**Problema:** Client si connette con IPv6 (`::1`, `2001:db8::1`) ma whitelist ha IPv4

**Soluzione:** Aggiungi entrambe le versioni
```python
ALLOWED_IPS = [
    '127.0.0.1',  # IPv4
    '::1',        # IPv6
]
```

### 4. IP dinamico (DHCP)

**Problema:** L'IP del client cambia ogni giorno

**Soluzioni:**
- Assegna IP statico al client nel DHCP server
- Usa autenticazione invece di IP whitelist
- Configura subnet/range (richiede codice custom)

---

## 🔒 Considerazioni di sicurezza

### ❌ NON FARE

```python
# ❌ PERICOLOSO: Con nginx, TUTTI i client sembreranno 127.0.0.1
ALLOWED_IPS = ['127.0.0.1']  # Solo se nginx PASSA X-Forwarded-For!

# ❌ PERICOLOSO: Disabilita protezione per tutti
CSRF_WHITELIST = ['0.0.0.0']  # NON FARE!
```

### ✅ BEST PRACTICES

```python
# ✅ IP specifici e documentati
ALLOWED_IPS = [
    '192.168.1.10',  # Admin - John Doe
    '192.168.1.11',  # Admin - Jane Smith
]

CSRF_WHITELIST = [
    '192.168.1.50',  # API Server - monitoring script
    '10.0.0.100',    # API Server - automation
]
```

### 🗑️ Rimuovere endpoint debug in produzione

L'endpoint `/debug/ip-info` espone informazioni sensibili!

**Opzione 1 - Rimuovere:**
```python
# Commenta in routes.py
# @routes_bp.route('/debug/ip-info', methods=['GET', 'POST'])
# def debug_ip_info():
#     ...
```

**Opzione 2 - Proteggere con IP whitelist:**
```python
@routes_bp.route('/debug/ip-info', methods=['GET', 'POST'])
@ip_whitelist_required(['127.0.0.1', '::1'])  # Solo localhost
def debug_ip_info():
    ...
```

---

## 📞 Riferimenti

- **File di configurazione**: [`config.py`](config.py)
- **Logica IP detection**: [`security.py`](security.py) - `_get_client_ip()`
- **Decorator ALLOWED_IPS**: [`routes.py`](routes.py) - `ip_whitelist_required()`
- **Nginx config**: [`deploy/nginx/fuco.conf`](deploy/nginx/fuco.conf)
- **Test script**: [`test/test_ip_whitelist.py`](test/test_ip_whitelist.py)
- **Guida CSRF+Nginx**: [`CSRF_NGINX_GUIDE.md`](CSRF_NGINX_GUIDE.md)
