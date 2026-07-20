from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import sys
import traceback

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)
CORS(app)

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'app': 'Tlhagiso',
        'status': 'running',
        'version': '1.0.0',
        'endpoints': [
            'POST /api/scan/url',
            'GET /api/health'
        ]
    })

# URL Scan Endpoint
@app.route('/api/scan/url', methods=['POST'])
def scan_url():
    try:
        data = request.get_json()
        if not data or ('url' not in data and 'text' not in data):
            return jsonify({'error': 'No URL/text provided'}), 400
        
        url_text = data.get('url') or data.get('text')
        
        from services.url_service import URLService
        url_service = URLService()
        
        result = url_service.detect(url_text)
        result['type'] = 'url'
        result['url'] = url_text
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Error in scan_url: {str(e)}")
        print(traceback.format_exc())
        return jsonify({
            'error': str(e),
            'type': 'url',
            'is_phishing': False,
            'probability': 0.0,
            'result': 'error'
        }), 500

# Root endpoint
@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'app': 'Tlhagiso',
        'endpoints': [
            'POST /api/scan/url',
            'GET /api/health'
        ],
        'status': 'running',
        'version': '1.0.0'
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    print("=" * 60)
    print("🚀 TLHAGISO API SERVER")
    print("=" * 60)
    print(f"   Server: http://0.0.0.0:{port}")
    print("=" * 60)
    print("\n📋 Endpoints:")
    print("   POST /api/scan/url")
    print("   GET  /api/health")
    print("=" * 60)
    app.run(host='0.0.0.0', port=port, debug=False)
