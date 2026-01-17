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

# ============ Template Filters ============

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


# ============ Application Entry Point ============

if __name__ == '__main__':
    app.run(debug=False)