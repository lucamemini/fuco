"""
Script per testare IP Whitelist delle API /api/cache/*

Testa se il tuo IP è autorizzato ad accedere agli endpoint protetti.
"""
import requests
import sys

def test_ip_whitelist(base_url='http://localhost'):
    """
    Testa l'accesso agli endpoint protetti da IP whitelist.
    
    Args:
        base_url: URL base del server FUCO (default: http://localhost)
    """
    print("\n" + "="*70)
    print("TEST IP WHITELIST - Cache API")
    print("="*70)
    
    # 1. Prima verifica quale IP viene rilevato
    print("\n[1/3] Verifica IP rilevato dal server...")
    try:
        response = requests.get(f"{base_url}/debug/ip-info")
        if response.status_code == 200:
            data = response.json()
            detected_ip = data.get('detected_client_ip')
            is_whitelisted = data.get('is_whitelisted')
            csrf_whitelist = data.get('csrf_whitelist', [])
            
            print(f"✅ IP rilevato: {detected_ip}")
            print(f"   CSRF Whitelist: {is_whitelisted}")
            print(f"   CSRF Lista: {csrf_whitelist}")
        else:
            print(f"⚠️  Endpoint /debug/ip-info non disponibile (status: {response.status_code})")
            detected_ip = "sconosciuto"
    except Exception as e:
        print(f"❌ Errore: {e}")
        detected_ip = "sconosciuto"
    
    # 2. Testa /api/cache/stats
    print("\n[2/3] Test accesso a /api/cache/stats (GET)...")
    try:
        response = requests.get(f"{base_url}/api/cache/stats")
        
        if response.status_code == 200:
            print(f"✅ ACCESSO CONSENTITO (200 OK)")
            data = response.json()
            print(f"   Cache entries: {data.get('total_entries', 'N/A')}")
        elif response.status_code == 403:
            print(f"❌ ACCESSO NEGATO (403 Forbidden)")
            error = response.json()
            print(f"   Errore: {error.get('message', 'IP non autorizzato')}")
            print(f"   Il tuo IP ({detected_ip}) non è in ALLOWED_IPS")
        else:
            print(f"⚠️  Risposta inattesa: {response.status_code}")
            print(f"   {response.text[:200]}")
    except Exception as e:
        print(f"❌ Errore connessione: {e}")
    
    # 3. Testa /api/cache/clear
    print("\n[3/3] Test accesso a /api/cache/clear (POST)...")
    try:
        response = requests.post(
            f"{base_url}/api/cache/clear",
            json={},
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            print(f"✅ ACCESSO CONSENTITO (200 OK)")
            print(f"   ⚠️  Nota: La cache potrebbe essere stata cancellata!")
        elif response.status_code == 403:
            print(f"❌ ACCESSO NEGATO (403 Forbidden)")
            error = response.json()
            print(f"   Errore: {error.get('message', 'IP non autorizzato')}")
            print(f"   Il tuo IP ({detected_ip}) non è in ALLOWED_IPS")
        elif response.status_code == 400:
            # Potrebbe fallire per CSRF
            print(f"⚠️  CSRF Error (400 Bad Request)")
            print(f"   Questo è normale se l'endpoint richiede CSRF token")
            print(f"   Ma indica che l'IP whitelist è OK!")
        else:
            print(f"⚠️  Risposta inattesa: {response.status_code}")
            print(f"   {response.text[:200]}")
    except Exception as e:
        print(f"❌ Errore connessione: {e}")
    
    # Riepilogo
    print("\n" + "="*70)
    print("RIEPILOGO")
    print("="*70)
    print(f"IP rilevato dal server: {detected_ip}")
    print(f"\nPer autorizzare questo IP, aggiungi in config.py:")
    print(f"")
    print(f"ALLOWED_IPS = [")
    print(f"    '{detected_ip}',  # Il tuo IP")
    print(f"    # Altri IP autorizzati...")
    print(f"]")
    print("="*70 + "\n")


if __name__ == '__main__':
    # Prendi URL da riga di comando o usa default
    base_url = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost'
    
    print(f"\nTesting IP whitelist su: {base_url}")
    print("(Usa: python test_ip_whitelist.py http://your-server per testare altro server)\n")
    
    test_ip_whitelist(base_url)
