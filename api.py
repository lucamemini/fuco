"""
FUCO - Search Engine for Cortex
Entry point dell'applicazione Flask
"""
import logging
from flask import Flask
from urllib.parse import quote

import config
from routes import routes_bp

# Configurazione logging
logging.basicConfig(
    level=config.LOG_LEVEL,
    format=config.LOG_FORMAT
)
logger = logging.getLogger(__name__)

# Inizializzazione app Flask
app = Flask(__name__,
            static_url_path='',
            static_folder='web/static',
            template_folder=config.TEMPLATE_FOLDER)

# Registrazione del blueprint delle route
app.register_blueprint(routes_bp)

# Template filters
@app.template_filter('fang')
def fang(s):
    """Custom filter: upper-case a string"""
    try:
        return s.upper()
    except Exception:
        return s


@app.template_filter('urlencode')
def urlencode_filter(s):
    """Custom filter: URL encode a string"""
    return quote(str(s))


# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Handler per errori 404"""
    logger.warning("Pagina non trovata (404)")
    from flask import make_response
    return make_response("404", 404)


@app.errorhandler(500)
def internal_error(error):
    """Handler per errori 500"""
    logger.error(f"Errore interno del server: {str(error)}")
    from flask import jsonify
    return jsonify({"error": "Errore interno del server"}), 500


if __name__ == '__main__':
    logger.info("Avvio dell'applicazione FUCO")
    app.run(debug=False)
