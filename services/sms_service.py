# services/sms_service.py - Enhanced URL + Phishing detection
import re
import pandas as pd
import math
import json
import traceback
import os
from collections import Counter
from models.sms_model import SMSModel

# ============================================================
# PHISHING KEYWORDS (Expanded)
# ============================================================
PHISHING_KEYWORDS = [
    "compromised", "blocked", "suspended", "frozen", "deactivated", 
    "verify", "validate", "authenticate", "secure", "unusual",
    "suspicious", "unauthorized", "attempt", "fraud", "scam",
    "phishing", "hacked", "stolen", "locked", "disabled",
    "revoked", "cancelled", "terminated", "closed", "unlock",
    "alert", "urgent", "immediate", "action required", "click here",
    "confirm", "update", "review", "restore", "reactivate"
]

URGENCY_KEYWORDS = [
    "urgent", "immediately", "now", "today", "immediate", 
    "asap", "right away", "don't delay", "act now", "hurry"
]

# ============================================================
# BOTSWANA BRANDS (Safe)
# ============================================================
TELECOM_UTILITY = {
    "mascom": ["balance", "bundle", "data", "airtime", "recharge", "expires", "payment", "pula"],
    "orange": ["balance", "bundle", "data", "airtime", "recharge", "expires", "payment", "pula"],
    "btc": ["balance", "bundle", "data", "airtime", "recharge", "expires", "payment", "pula"],
    "mtn": ["balance", "bundle", "data", "airtime", "recharge", "expires", "payment", "pula"],
}

BANK_UTILITY = {
    "fnb": ["transaction", "deposit", "withdrawal", "balance", "transfer", "payment"],
    "stanbic": ["transaction", "deposit", "withdrawal", "balance", "transfer", "payment"],
    "bank of botswana": ["transaction", "deposit", "withdrawal", "balance", "transfer"],
}

# ============================================================
# OFFICIAL SHORTCODES
# ============================================================
OFFICIAL_SHORTCODES = {
    "MASCOM": ["MASCOM", "MASCOM1", "MASCOM2"],
    "ORANGE": ["ORANGE", "ORANGE1"],
    "BTC": ["BTC", "BTC1"],
    "MTN": ["MTN", "MTN1"],
    "FNB": ["FNB", "FNBALERT", "FNB-BOTSWANA"],
    "STANBIC": ["STANBIC", "STANBICALERT"],
    "BOB": ["BOB", "BANKOFBOTSWANA"],
    "GOV": ["GOV-BW", "BURS", "BOFINET"],
    "DHL": ["DHL", "DHLBOTSWANA"],
}

# ============================================================
# SMS FEATURE EXTRACTOR
# ============================================================
class SMSFeatureExtractor:
    def __init__(self):
        self.phishing_keywords = set(PHISHING_KEYWORDS)
        self.urgency_keywords = set(URGENCY_KEYWORDS)
        self.official_shortcodes = set()
        for shortcodes in OFFICIAL_SHORTCODES.values():
            self.official_shortcodes.update(shortcodes)
    
    def extract_features(self, sms):
        sms = str(sms).lower()
        features = {}
        
        features['length'] = len(sms)
        features['word_count'] = len(sms.split())
        features['digit_ratio'] = sum(1 for c in sms if c.isdigit()) / max(len(sms), 1)
        features['upper_ratio'] = sum(1 for c in sms if c.isupper()) / max(len(sms), 1)
        features['special_ratio'] = sum(1 for c in sms if not c.isalnum() and not c.isspace()) / max(len(sms), 1)
        
        features['has_url'] = 1 if re.search(r'http\S+|www\S+', sms) else 0
        features['has_phone'] = 1 if re.search(r'\+267|7[123]\d{6,7}', sms) else 0
        features['phishing_score'] = sum(1 for word in self.phishing_keywords if word in sms)
        features['urgency_score'] = sum(1 for word in self.urgency_keywords if word in sms)
        
        features['brand_score'] = 0
        all_brands = list(TELECOM_UTILITY.keys()) + list(BANK_UTILITY.keys())
        for brand in all_brands:
            if brand in sms:
                features['brand_score'] += 1
        
        features['has_official_sender'] = 0
        sender_id = sms.split()[0] if sms.split() else ""
        sender_upper = sender_id.upper()
        if sender_upper.endswith(':'):
            sender_upper = sender_upper[:-1]
        if sender_upper in self.official_shortcodes:
            features['has_official_sender'] = 1
        
        features['is_shortcode'] = 1 if re.match(r'^[A-Z0-9\-]{3,10}', sender_upper) else 0
        
        features['has_utility'] = 0
        utility_patterns = [
            r'(?:your|my|our)\s+(?:balance|bundle|data|airtime)\s+(?:is|has|of)\s+[\d,]+\.?\d*',
            r'(?:recharge|top-up|load)\s+(?:success|complete|done)',
            r'(?:transaction|payment|transfer|deposit)\s+(?:of|for)\s+[\d,]+\.?\d*',
            r'balance\s+is\s+[\d,]+\.?\d*',
        ]
        for pattern in utility_patterns:
            if re.search(pattern, sms, re.IGNORECASE):
                features['has_utility'] = 1
                break
        
        features['risk_score'] = features['phishing_score'] + features['urgency_score']
        features['safety_score'] = features['brand_score'] + features['has_utility'] + features['has_official_sender']
        features['has_url_flag'] = features['has_url']
        
        return features

# ============================================================
# MAIN SMS DETECTOR
# ============================================================
def detect_sms_3layer(sms):
    sms_text = str(sms).lower().strip()
    
    # CRITICAL: URL + Brand + Phishing = 100% SPAM
    has_url = re.search(r'http\S+|www\S+', sms_text)
    phishing_count = sum(1 for word in PHISHING_KEYWORDS if word in sms_text)
    urgency_count = sum(1 for word in URGENCY_KEYWORDS if word in sms_text)
    
    all_brands = list(TELECOM_UTILITY.keys()) + list(BANK_UTILITY.keys())
    
    # 1. URL + Brand + ANY phishing keyword = 100% PHISHING
    if has_url:
        for brand in all_brands:
            if brand in sms_text:
                for keyword in PHISHING_KEYWORDS:
                    if keyword in sms_text:
                        return {
                            'is_phishing': True,
                            'probability': 1.0,
                            'reason': f'Layer 1: Brand "{brand}" + URL + phishing keyword "{keyword}"',
                            'layer': 1,
                            'flag': 'url_brand_phishing'
                        }
    
    # 2. URL + 2+ phishing keywords = 100% PHISHING
    if has_url and phishing_count >= 2:
        return {
            'is_phishing': True,
            'probability': 1.0,
            'reason': f'Layer 1: URL + {phishing_count} phishing keywords',
            'layer': 1,
            'flag': 'url_phishing'
        }
    
    # 3. URL + urgency = PHISHING
    if has_url and urgency_count >= 1:
        return {
            'is_phishing': True,
            'probability': 1.0,
            'reason': f'Layer 1: URL + urgency keyword',
            'layer': 1,
            'flag': 'url_urgency'
        }
    
    # 4. Brand + phishing keyword = PHISHING
    for brand in all_brands:
        if brand in sms_text:
            for keyword in PHISHING_KEYWORDS:
                if keyword in sms_text:
                    return {
                        'is_phishing': True,
                        'probability': 1.0,
                        'reason': f'Layer 1: Brand "{brand}" + phishing keyword "{keyword}"',
                        'layer': 1,
                        'flag': 'brand_phishing'
                    }
    
    # 5. Check utility messages (SAFE)
    for brand, keywords in TELECOM_UTILITY.items():
        if brand in sms_text:
            if any(u in sms_text for u in ['balance', 'bundle', 'data', 'recharge']):
                if phishing_count == 0:
                    return {
                        'is_phishing': False,
                        'probability': 0.0,
                        'reason': f'Layer 1: Telecom utility - {brand}',
                        'layer': 1,
                        'flag': 'telecom_utility'
                    }
    
    for brand, keywords in BANK_UTILITY.items():
        if brand in sms_text:
            if any(u in sms_text for u in ['transaction', 'deposit', 'payment', 'balance']):
                if phishing_count == 0:
                    return {
                        'is_phishing': False,
                        'probability': 0.0,
                        'reason': f'Layer 1: Bank utility - {brand}',
                        'layer': 1,
                        'flag': 'bank_utility'
                    }
    
    # 6. Multiple phishing keywords
    if phishing_count >= 2 and urgency_count >= 1:
        return {
            'is_phishing': True,
            'probability': 1.0,
            'reason': f'Layer 1: {phishing_count} phishing keywords + urgency',
            'layer': 1,
            'flag': 'phishing_keywords'
        }
    
    # 7. Official shortcode
    sender_id = sms_text.split()[0] if sms_text.split() else ""
    sender_upper = sender_id.upper()
    if sender_upper.endswith(':'):
        sender_upper = sender_upper[:-1]
    
    for service, shortcodes in OFFICIAL_SHORTCODES.items():
        if sender_upper in shortcodes:
            if phishing_count == 0:
                return {
                    'is_phishing': False,
                    'probability': 0.0,
                    'reason': f'Layer 2: Official shortcode "{sender_upper}" from {service}',
                    'layer': 2,
                    'flag': 'official_shortcode'
                }
    
    # 8. ML Engine
    return {
        'is_phishing': None,
        'probability': None,
        'reason': 'Layer 3: ML Analysis needed',
        'layer': 3,
        'flag': 'ml_analysis'
    }

# ============================================================
# SMS SERVICE
# ============================================================
class SMSService:
    def __init__(self):
        self.model = SMSModel()
        self.feature_extractor = SMSFeatureExtractor()
        
        self.features = [
            'length', 'word_count', 'digit_ratio', 'upper_ratio', 'special_ratio',
            'has_url', 'has_phone', 'phishing_score', 'urgency_score',
            'brand_score', 'has_official_sender', 'is_shortcode',
            'has_utility', 'risk_score', 'safety_score', 'has_url_flag'
        ]
        
        print("   SMS 3-Layer Defense System Initialized (Enhanced)")
        print(f"   Layer 1: {len(PHISHING_KEYWORDS)} phishing keywords")
        print(f"   Layer 1: URL + Brand + Phishing = 100% SPAM")
        print(f"   Layer 2: {len(OFFICIAL_SHORTCODES)} official shortcode services")
        print(f"   Layer 3: Naive Bayes ML Engine (Active)")
    
    def extract_features(self, sms):
        features = self.feature_extractor.extract_features(sms)
        features_df = pd.DataFrame([features])
        
        for col in self.features:
            if col not in features_df.columns:
                features_df[col] = 0
        
        return features_df[self.features]
    
    def detect(self, sms):
        try:
            layer_result = detect_sms_3layer(sms)
            
            if layer_result['is_phishing'] is not None:
                return {
                    'is_phishing': layer_result['is_phishing'],
                    'probability': layer_result['probability'],
                    'result': 'phishing' if layer_result['is_phishing'] else 'legitimate',
                    'reason': layer_result['reason'],
                    'layer': layer_result['layer'],
                    'flag': layer_result.get('flag', 'detected'),
                    'type': 'sms',
                    'message': sms
                }
            
            # ML Layer
            features = self.extract_features(sms)
            scaled = self.model.scale(features)
            pred = self.model.predict(scaled)[0]
            prob = self.model.predict_proba(scaled)[0]
            result = self.model.decode(pred)
            confidence = float(max(prob))
            
            # Boost for URL
            feature_dict = features.iloc[0].to_dict()
            if feature_dict.get('has_url', 0) == 1:
                confidence = min(confidence * 1.5, 0.95)
            if feature_dict.get('phishing_score', 0) > 0:
                confidence = min(confidence * 1.2, 0.95)
            
            return {
                'is_phishing': bool(result == 1),
                'probability': confidence,
                'result': 'phishing' if result == 1 else 'legitimate',
                'reason': 'Layer 3: ML Analysis',
                'layer': 3,
                'flag': 'ml_analysis',
                'type': 'sms',
                'message': sms
            }
            
        except Exception as e:
            print(f"Error in detect: {str(e)}")
            print(traceback.format_exc())
            return {
                'is_phishing': False,
                'probability': 0.0,
                'result': 'error',
                'error': str(e),
                'type': 'sms'
            }
