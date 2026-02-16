# Guida CSRF con Nginx Reverse Proxy

## 🔍 Diagnosi: Quale IP viene rilevato?

### Metodo 1: Endpoint di debug

Visita (o fai una richiesta a):
```bash
http://your-server/debug/ip-info
```

Vedrai un JSON con tutte le informazioni:
```json
{
  "detected_client_ip": "192.168.1.100",
  "is_whitelisted": false,
  "csrf_whitelist": [],
  "raw_data": {
    "remote_addr": "127.0.0.1",
    "x_forwarded_for": "192.168.1.100",
    "x_real_ip": "192.168.1.100"
  }
}
```

### Metodo 2: Log dell'applicazione

Con `LOG_LEVEL = logging.DEBUG` in `config.py`, vedrai nei log:
```
DEBUG:security:IP from X-Forwarded-For: 192.168.1.100 (full: 192.168.1.100)
DEBUG:security:CSRF check enforced: IP 192.168.1.100 not in whitelist []
```

---

## ⚙️ Come funziona con Nginx

```
Client (IP: 192.168.1.100)
    ↓
Nginx (proxy su localhost:80)
    ↓ proxy_pass + header X-Forwarded-For
Flask/Gunicorn (ascolta su 127.0.0.1:8000)
    ↓ _get_client_ip() legge X-Forwarded-For
Rilevato IP: 192.168.1.100 ✅
```

**Nginx passa automaticamente:**
- `X-Forwarded-For: 192.168.1.100` (IP reale del client)
- `X-Real-IP: 192.168.1.100`
- `remote_addr: 127.0.0.1` (ignorato se ci sono gli header)

---

## 📋 Configurazione CSRF Whitelist

### Scenario 1: Client API da rete locale
```python
# config.py
CSRF_WHITELIST = ['192.168.1.50', '10.0.0.100']
```

### Scenario 2: Script/cronjob sulla stessa macchina
```python
# config.py
CSRF_WHITELIST = ['127.0.0.1', '::1']  # IPv4 + IPv6
```

### Scenario 3: Client API dietro Nginx (IP pubblico)
```python
# config.py
CSRF_WHITELIST = ['203.0.113.42']  # IP pubblico del client
```

### Scenario 4: Range di IP (subnet)
⚠️ Flask non supporta CIDR nativamente, usa IP singoli o implementa un custom check.

---

## 🛠️ Verificare la configurazione Nginx

La configurazione corretta è già presente in `deploy/nginx/fuco.conf`:

```nginx
location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;           # ✅ IP reale
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  # ✅ Chain di proxy
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Se mancano questi header, aggiungerli!

---

## 🐛 Troubleshooting

### Problema: Tutte le richieste risultano da 127.0.0.1

**Causa:** Nginx non passa gli header `X-Forwarded-For`/`X-Real-IP`

**Soluzione:** Verifica la configurazione nginx (vedi sopra), poi riavvia:
```bash
sudo nginx -t
sudo systemctl reload nginx
```

---

### Problema: CSRF fallisce anche con IP in whitelist

**Diagnosi:**
1. Controlla `/debug/ip-info` per vedere l'IP rilevato
2. Verifica il log con `LOG_LEVEL = logging.DEBUG`
3. Cerca nel log:
   ```
   WARNING:fuco:CSRF validation failed: ... | IP: X.X.X.X | ...
   ```

**Cause comuni:**
- IP rilevato è diverso da quello in whitelist (es. IPv6 vs IPv4)
- Whitelist malformata (stringhe invece di lista)
- Client passa per più proxy (prendi il primo IP in X-Forwarded-For)

---

### Problema: Client API non ha token CSRF

**Causa normale:** I client API non usano form HTML, non hanno token CSRF

**Soluzione:** Aggiungi l'IP del client API alla whitelist:
```python
CSRF_WHITELIST = ['192.168.1.50']  # IP del server che fa le chiamate API
```

---

## 📊 Log degli errori CSRF

Quando una richiesta fallisce la validazione CSRF, vedrai:

```
WARNING:fuco:CSRF validation failed: The CSRF token is missing. | IP: 192.168.1.100 | Path: /api/submit | Method: POST | Referrer: none
```

Oppure:

```
WARNING:fuco:CSRF validation failed: The CSRF token is invalid. | IP: 10.0.0.5 | Path: /bulk_responder | Method: POST | Referrer: http://localhost/
```

Il client riceve:
```json
{
  "success": false,
  "error": "CSRF validation failed",
  "message": "The CSRF token is missing."
}
```

---

## 🔒 Sicurezza

### ⚠️ NON fare:

```python
# ❌ PERICOLOSO: Disabilita CSRF per TUTTI
CSRF_WHITELIST = ['127.0.0.1']  # Se nginx fa proxy, TUTTE le richieste sembrano da 127.0.0.1!
```

### ✅ Fare invece:

```python
# ✅ SICURO: Whitelist solo client API fidati (IP reale)
CSRF_WHITELIST = ['192.168.1.50', '10.0.0.100']
```

---

## 🧪 Test rapido

### Da riga di comando (dietro nginx):

```bash
# Senza token CSRF (dovrebbe fallire se IP non in whitelist)
curl -X POST http://your-server/api/submit \
  -H "Content-Type: application/json" \
  -d '{"data": "test"}'

# Risposta attesa:
# {"success": false, "error": "CSRF validation failed", "message": "The CSRF token is missing."}
```

### Aggiungere il tuo IP alla whitelist:

1. Scopri il tuo IP: visita `/debug/ip-info`
2. Aggiungi in `config.py`:
   ```python
   CSRF_WHITELIST = ['IL_TUO_IP_QUI']
   ```
3. Riavvia l'applicazione
4. Riprova la richiesta curl (ora dovrebbe funzionare)

---

## 🗑️ Rimuovere l'endpoint di debug in produzione

L'endpoint `/debug/ip-info` è utile per debug ma espone informazioni sensibili.

**In produzione, commentare o rimuovere** da `routes.py`:

```python
# @routes_bp.route('/debug/ip-info', methods=['GET', 'POST'])
# def debug_ip_info():
#     ...
```

Oppure proteggerlo con autenticazione.

---

## 📞 Supporto

Se hai ancora problemi:
1. Attiva `LOG_LEVEL = logging.DEBUG`
2. Controlla `/debug/ip-info`
3. Cerca nei log i messaggi `CSRF validation failed`
4. Verifica che nginx passi gli header corretti
