# routes/url_routes.py
from flask import request, jsonify, Blueprint
import traceback

url_bp = Blueprint('url', __name__, url_prefix='/api')

def get_url_service():
    from services.url_service import URLService
    return URLService()

def get_sms_service():
    from services.sms_service import SMSService
    return SMSService()

@url_bp.route('/scan/url', methods=['POST'])
def scan_url():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        url = data.get('url', '')
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        service = get_url_service()
        result = service.detect(url)
        result['type'] = 'url'
        result['url'] = url
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Error in scan_url: {str(e)}")
        return jsonify({'error': str(e)}), 500

@url_bp.route('/scan/batch', methods=['POST'])
def scan_batch():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        items = data.get('items', [])
        if not items:
            return jsonify({'error': 'No items provided'}), 400
        
        results = []
        sms_service = get_sms_service()
        url_service = get_url_service()
        
        for item in items:
            try:
                if item.get('type') == 'sms':
                    result = sms_service.detect(item.get('text', ''))
                    result['text'] = item.get('text', '')
                    result['type'] = 'sms'
                elif item.get('type') == 'url':
                    result = url_service.detect(item.get('url', ''))
                    result['url'] = item.get('url', '')
                    result['type'] = 'url'
                else:
                    result = {'error': f'Unknown type: {item.get("type", "unknown")}'}
                results.append(result)
            except Exception as e:
                results.append({'error': str(e), 'type': item.get('type', 'unknown')})
        
        return jsonify({'results': results, 'total': len(results)})
        
    except Exception as e:
        print(f"Error in scan_batch: {str(e)}")
        return jsonify({'error': str(e)}), 500
