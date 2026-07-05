# routes/sms_routes.py
from flask import request, jsonify, Blueprint
import traceback

sms_bp = Blueprint('sms', __name__, url_prefix='/api')

# Lazy import to avoid circular imports
def get_sms_service():
    from services.sms_service import SMSService
    return SMSService()

@sms_bp.route('/scan/sms', methods=['POST'])
def scan_sms():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        text = data.get('text', '')
        threshold = data.get('threshold', None)
        
        if not text:
            return jsonify({'error': 'No text provided'}), 400
        
        print(f"Processing SMS: {text[:50]}...")
        
        service = get_sms_service()
        result = service.detect(text, threshold)
        
        # Add metadata
        result['type'] = 'sms'
        result['text'] = text
        
        print(f"Result: {result}")
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Error in scan_sms: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500
