# services/sms_service.py
import re
import numpy as np
from config import Config
from models.sms_model import SMSModel

class SMSService:
    def __init__(self):
        self.model = SMSModel()
        self.threshold = Config.SMS_THRESHOLD
        self.brands = Config.BOTSWANA_BRANDS
        self.alerts = Config.HIGH_RISK_WORDS
    
    def clean(self, text):
        text = str(text).lower()
        text = re.sub(r'http\S+|www\S+|https\S+', 'URL', text)
        text = re.sub(r'\S+@\S+', 'EMAIL', text)
        text = re.sub(r'[^a-zA-Z0-9\s]', '', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text
    
    def detect(self, text, threshold=None):
        if threshold is None:
            threshold = self.threshold
        
        # Clean and transform
        cleaned = self.clean(text)
        features = self.model.transform([cleaned])
        
        # Get probability - convert to Python float
        prob_array = self.model.predict_proba(features)[0]
        prob = float(prob_array[1])  # Convert to Python float
        
        # Botswana guardrails
        txt = text.lower()
        has_brand = any(b in txt for b in self.brands)
        has_alert = any(a in txt for a in self.alerts)
        
        # Blacklist: Zero-Tolerance
        if has_brand and has_alert:
            return {
                'is_spam': True,
                'probability': prob,
                'reason': 'Blacklist: Brand + Alert'
            }
        
        # ML Decision - convert to Python bool
        is_spam = bool(prob >= threshold)
        
        return {
            'is_spam': is_spam,
            'probability': prob,
            'reason': 'Machine Learning'
        }
