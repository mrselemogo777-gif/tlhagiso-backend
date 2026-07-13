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
            'POST /api/scan/sms',
            'POST /api/scan/url',
            'POST /api/scan/batch',
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

# SMS Scan Endpoint - FIXED
@app.route('/api/scan/sms', methods=['POST'])
def scan_sms():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Support both 'message' and 'text' parameters
        sms_text = data.get('message') or data.get('text')
        if not sms_text:
            return jsonify({'error': 'No message/text provided'}), 400
        
        from services.sms_service import SMSService
        sms_service = SMSService()
        
        result = sms_service.detect(sms_text)
        result['type'] = 'sms'
        result['message'] = sms_text
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Error in scan_sms: {str(e)}")
        print(traceback.format_exc())
        return jsonify({
            'error': str(e),
            'type': 'sms',
            'is_phishing': False,
            'probability': 0.0,
            'result': 'error'
        }), 500

# Batch Scan Endpoint
@app.route('/api/scan/batch', methods=['POST'])
def scan_batch():
    try:
        data = request.get_json()
        if not data or ('messages' not in data and 'urls' not in data):
            return jsonify({'error': 'No messages provided'}), 400
        
        from services.sms_service import SMSService
        sms_service = SMSService()
        
        results = []
        items = data.get('messages') or data.get('urls', [])
        for msg in items:
            try:
                result = sms_service.detect(msg)
                result['type'] = 'sms'
                results.append(result)
            except Exception as e:
                results.append({
                    'error': str(e),
                    'message': msg,
                    'is_phishing': False,
                    'probability': 0.0,
                    'result': 'error'
                })
        
        return jsonify({
            'results': results,
            'total': len(results)
        })
        
    except Exception as e:
        print(f"Error in scan_batch: {str(e)}")
        return jsonify({'error': str(e)}), 500

# SMS Health Check
@app.route('/api/sms/health', methods=['GET'])
def sms_health():
    try:
        from services.sms_service import SMSService
        sms_service = SMSService()
        return jsonify({
            'status': 'healthy',
            'service': 'sms',
            'layer1_keywords': 24,
            'layer2_shortcodes': 12,
            'layer3_ml': 'active'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

# Root endpoint
@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'app': 'Tlhagiso',
        'endpoints': [
            'POST /api/scan/sms',
            'POST /api/scan/url',
            'POST /api/scan/batch',
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
    print("   POST /api/scan/sms")
    print("   POST /api/scan/url")
    print("   POST /api/scan/batch")
    print("   GET  /api/health")
    print("=" * 60)
    app.run(host='0.0.0.0', port=port, debug=False)
