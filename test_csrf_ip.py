"""
Script per testare quale IP viene rilevato dalla funzione _get_client_ip()
"""
from flask import Flask, request
import sys
import os

# Aggiungi la directory parent al path per importare security
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

app = Flask(__name__)

def _get_client_ip() -> str:
    """Copia della funzione da security.py"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr or ''


@app.route('/test-ip', methods=['GET', 'POST'])
def test_ip():
    client_ip = _get_client_ip()
    
    info = {
        'detected_ip': client_ip,
        'remote_addr': request.remote_addr,
        'x_forwarded_for': request.headers.get('X-Forwarded-For'),
        'x_real_ip': request.headers.get('X-Real-IP'),
        'all_headers': dict(request.headers)
    }
    
    print("\n" + "="*60)
    print("TEST IP DETECTION")
    print("="*60)
    print(f"IP rilevato: {client_ip}")
    print(f"request.remote_addr: {request.remote_addr}")
    print(f"X-Forwarded-For: {request.headers.get('X-Forwarded-For', 'Non presente')}")
    print(f"X-Real-IP: {request.headers.get('X-Real-IP', 'Non presente')}")
    print("="*60)
    
    return info


if __name__ == '__main__':
    print("\n" + "="*60)
    print("AVVIA IL SERVER DI TEST")
    print("="*60)
    print("Visita: http://localhost:5001/test-ip")
    print("Per testare con curl:")
    print("  curl http://localhost:5001/test-ip")
    print("  curl -H 'X-Forwarded-For: 192.168.1.100' http://localhost:5001/test-ip")
    print("="*60 + "\n")
    
    app.run(debug=True, port=5001)
