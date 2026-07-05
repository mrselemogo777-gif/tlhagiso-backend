# app.py
from flask import Flask, jsonify
from flask_cors import CORS
from routes.sms_routes import sms_bp
from routes.url_routes import url_bp

app = Flask(__name__)
CORS(app)

# Register blueprints
app.register_blueprint(sms_bp)
app.register_blueprint(url_bp)

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'app': 'Tlhagiso',
        'version': '1.0.0',
        'models': {'sms': 'loaded', 'url': 'loaded'}
    })

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'app': 'Tlhagiso',
        'version': '1.0.0',
        'status': 'running',
        'endpoints': [
            'POST /api/scan/sms',
            'POST /api/scan/url',
            'POST /api/scan/batch',
            'GET /api/health'
        ]
    })

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 TLHAGISO API SERVER")
    print("=" * 60)
    print("   Server: http://0.0.0.0:5001")
    print("=" * 60)
    print("\n📋 Endpoints:")
    print("   POST /api/scan/sms")
    print("   POST /api/scan/url")
    print("   POST /api/scan/batch")
    print("   GET  /api/health")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5001, debug=False)
