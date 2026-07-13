# services/sms_service.py - Updated with better utility detection
import re
import pandas as pd
import math
import json
import traceback
import os
from collections import Counter
from config import Config
from models.sms_model import SMSModel

# ============================================================
# LAYER 1: KEYWORD IDENTIFICATION (With URL Detection)
# ============================================================

# BOTSWANA TELECOM - Utility Keywords (Safe)
TELECOM_UTILITY = {
    "mascom": ["balance", "bundle", "data", "airtime", "recharge", "expires", "payment", "pula"],
    "orange": ["balance", "bundle", "data", "airtime", "recharge", "expires", "payment", "pula"],
    "mtn": ["balance", "bundle", "data", "airtime", "recharge", "expires", "payment", "pula"],
}

# BOTSWANA BANKS - Transaction Keywords (Safe)
BANK_UTILITY = {
    "fnb": ["transaction", "deposit", "withdrawal", "balance", "transfer", "payment", "alert"],
    "stanbic": ["transaction", "deposit", "withdrawal", "balance", "transfer", "payment", "alert"],
    "bank of botswana": ["transaction", "deposit", "withdrawal", "balance", "transfer"],
    "bob": ["transaction", "deposit", "withdrawal", "balance", "transfer"],
    "bancabc": ["transaction", "deposit", "withdrawal", "balance", "transfer"],
}

# BOTSWANA GOVERNMENT - Official Keywords (Safe)
GOVERNMENT_UTILITY = {
    "gov.bw": ["notification", "update", "reminder", "document", "renewal"],
    "immigration": ["visa", "permit", "passport", "renewal", "application"],
    "bofinet": ["tax", "payment", "submission", "filing", "deadline"],
    "burs": ["tax", "refund", "return", "submission", "deadline"],
}

# DELIVERY SERVICES - Tracking Keywords (Safe)
DELIVERY_UTILITY = {
    "dhl": ["package", "delivery", "tracking", "arrived", "shipped"],
    "aramex": ["package", "delivery", "tracking", "arrived", "shipped"],
    "fedex": ["package", "delivery", "tracking", "arrived", "shipped"],
}

# PHISHING KEYWORDS (High Risk - Immediate Flag)
PHISHING_KEYWORDS = [
    "compromised", "blocked", "suspended", "frozen", "deactivated", 
    "verify", "validate", "authenticate", "secure", "unusual",
    "suspicious", "unauthorized", "attempt", "fraud", "scam",
    "phishing", "hacked", "stolen", "locked", "disabled",
    "revoked", "cancelled", "terminated", "closed", "disconnected",
    "disconnection", "outstanding", "fees", "renew"
]

# URGENCY KEYWORDS (Risk Amplifier)
URGENCY_KEYWORDS = [
    "urgent", "immediately", "now", "today", "immediate", 
    "asap", "right away", "don't delay", "act now", "hurry"
]

# ============================================================
# LAYER 2: SENDER VERIFICATION (Official Shortcodes ONLY)
# ============================================================

# Official Sender IDs (Shortcodes) - These are ALWAYS trusted
OFFICIAL_SHORTCODES = {
    "MASCOM": ["MASCOM", "MASCOM1", "MASCOM2"],
    "ORANGE": ["ORANGE", "ORANGE1"],
    "MTN": ["MTN", "MTN1"],
    "FNB": ["FNB", "FNBALERT", "FNB-BOTSWANA"],
    "STANBIC": ["STANBIC", "STANBICALERT"],
    "BOB": ["BOB", "BANKOFBOTSWANA"],
    "GOV": ["GOV-BW", "BURS", "BOFINET"],
    "IMMIGRATION": ["IMMIGRATION-BW"],
    "DHL": ["DHL", "DHLBOTSWANA"],
    "ARAMEX": ["ARAMEX"],
    "FEDEX": ["FEDEX"],
}

# Official Sender Patterns
OFFICIAL_SENDER_PATTERNS = [
    r'^MASCOM\s+(?:balance|bundle|data)',
    r'^ORANGE\s+(?:balance|bundle|data)',
    r'^MTN\s+(?:balance|bundle|data)',
    r'^FNB\s+(?:alert|transaction)',
    r'^STANBIC\s+(?:alert|transaction)',
    r'^BURS\s+notification',
    r'^BOFINET\s+reminder',
    r'^DHL\s+(?:tracking|delivery)',
    r'^ARAMEX\s+(?:tracking|delivery)',
]

# ============================================================
# SMS FEATURE EXTRACTOR
# ============================================================

class SMSFeatureExtractor:
    def __init__(self):
        self.safe_brands = {}
        self.safe_brands.update(TELECOM_UTILITY)
        self.safe_brands.update(BANK_UTILITY)
        self.safe_brands.update(GOVERNMENT_UTILITY)
        self.safe_brands.update(DELIVERY_UTILITY)
        
        self.phishing_keywords = set(PHISHING_KEYWORDS)
        self.urgency_keywords = set(URGENCY_KEYWORDS)
        
        self.official_shortcodes = set()
        for shortcodes in OFFICIAL_SHORTCODES.values():
            self.official_shortcodes.update(shortcodes)
    
    def extract_features(self, sms):
        sms = str(sms).lower()
        features = {}
        
        # Basic features
        features['length'] = len(sms)
        features['word_count'] = len(sms.split())
        features['digit_ratio'] = sum(1 for c in sms if c.isdigit()) / max(len(sms), 1)
        features['upper_ratio'] = sum(1 for c in sms if c.isupper()) / max(len(sms), 1)
        features['special_ratio'] = sum(1 for c in sms if not c.isalnum() and not c.isspace()) / max(len(sms), 1)
        
        # Keyword features
        features['has_url'] = 1 if re.search(r'http\S+|www\S+', sms) else 0
        features['has_phone'] = 1 if re.search(r'\+267|7[123]\d{6,7}', sms) else 0
        features['phishing_score'] = sum(1 for word in self.phishing_keywords if word in sms)
        features['urgency_score'] = sum(1 for word in self.urgency_keywords if word in sms)
        
        # Brand presence
        features['brand_score'] = 0
        for brand in self.safe_brands.keys():
            if brand in sms:
                features['brand_score'] += 1
        
        # Sender verification
        features['has_official_sender'] = 0
        sender_id = sms.split()[0] if sms.split() else ""
        sender_upper = sender_id.upper()
        if sender_upper.endswith(':'):
            sender_upper = sender_upper[:-1]
        if sender_upper in self.official_shortcodes:
            features['has_official_sender'] = 1
        
        features['is_shortcode'] = 1 if re.match(r'^[A-Z0-9\-]{3,10}', sender_upper) else 0
        
        # Utility detection - IMPROVED
        features['has_utility'] = 0
        utility_patterns = [
            r'(?:your|my|our)\s+(?:balance|bundle|data|airtime)\s+(?:is|has|of)\s+[\d,]+\.?\d*',
            r'(?:recharge|top-up|load)\s+(?:success|complete|done)',
            r'(?:transaction|payment|transfer|deposit)\s+(?:of|for)\s+[\d,]+\.?\d*',
            r'(?:package|delivery|parcel)\s+[A-Z0-9]+\s+(?:arrived|delivered|shipped)',
            r'balance\s+is\s+[\d,]+\.?\d*',
            r'balance:\s+[\d,]+\.?\d*',
        ]
        for pattern in utility_patterns:
            if re.search(pattern, sms, re.IGNORECASE):
                features['has_utility'] = 1
                break
        
        # Composite scores
        features['risk_score'] = features['phishing_score'] + features['urgency_score']
        features['safety_score'] = features['brand_score'] + features['has_utility'] + features['has_official_sender']
        features['has_url_flag'] = features['has_url']
        
        return features

# ============================================================
# MAIN SMS DETECTOR
# ============================================================

def detect_sms_3layer(sms):
    sms_text = str(sms).lower().strip()
    
    # ============================================================
    # LAYER 1: KEYWORD IDENTIFICATION
    # ============================================================
    
    # BTC Phishing Detection - Force SPAM
    if "btc" in sms_text:
        btc_phishing_words = ["disconnected", "disconnection", "pay", "fees", "outstanding", "renew", "line"]
        if any(word in sms_text for word in btc_phishing_words):
            return {
                'is_phishing': True,
                'probability': 1.0,
                'reason': 'Layer 1: BTC phishing detected - disconnection scam',
                'layer': 1,
                'flag': 'btc_phishing'
            }
    
    # Check for utility messages FIRST (before phishing)
    # Telecom utility
    for brand, keywords in TELECOM_UTILITY.items():
        if brand in sms_text:
            if any(u in sms_text for u in ['balance', 'bundle', 'data', 'recharge']):
                phishing_check = sum(1 for word in PHISHING_KEYWORDS if word in sms_text)
                if phishing_check == 0:
                    return {
                        'is_phishing': False,
                        'probability': 0.0,
                        'reason': f'Layer 1: Telecom utility - {brand}',
                        'layer': 1,
                        'flag': 'telecom_utility'
                    }
    
    # Bank utility
    for brand, keywords in BANK_UTILITY.items():
        if brand in sms_text:
            if any(u in sms_text for u in ['transaction', 'deposit', 'payment', 'balance']):
                phishing_check = sum(1 for word in PHISHING_KEYWORDS if word in sms_text)
                if phishing_check == 0:
                    return {
                        'is_phishing': False,
                        'probability': 0.0,
                        'reason': f'Layer 1: Bank utility - {brand}',
                        'layer': 1,
                        'flag': 'bank_utility'
                    }
    
    # Any URL goes to ML
    if re.search(r'http\S+|www\S+', sms_text):
        return {
            'is_phishing': None,
            'probability': None,
            'reason': 'Layer 1: URL detected → ML Analysis',
            'layer': 1,
            'flag': 'url_detected'
        }
    
    # Check for phishing keywords
    phishing_count = sum(1 for word in PHISHING_KEYWORDS if word in sms_text)
    urgency_count = sum(1 for word in URGENCY_KEYWORDS if word in sms_text)
    
    # Multiple phishing keywords + urgency = HIGH RISK
    if phishing_count >= 2 and urgency_count >= 1:
        return {
            'is_phishing': True,
            'probability': 1.0,
            'reason': f'Layer 1: {phishing_count} phishing keywords + urgency',
            'layer': 1,
            'flag': 'phishing_keywords'
        }
    
    # Brand + phishing keyword = SMISHING
    all_brands = list(TELECOM_UTILITY.keys()) + list(BANK_UTILITY.keys()) + list(GOVERNMENT_UTILITY.keys())
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
    
    # ============================================================
    # LAYER 2: SENDER VERIFICATION
    # ============================================================
    
    sender_id = sms_text.split()[0] if sms_text.split() else ""
    sender_upper = sender_id.upper()
    if sender_upper.endswith(':'):
        sender_upper = sender_upper[:-1]
    
    for service, shortcodes in OFFICIAL_SHORTCODES.items():
        if sender_upper in shortcodes:
            phishing_check = sum(1 for word in PHISHING_KEYWORDS if word in sms_text)
            if phishing_check == 0:
                return {
                    'is_phishing': False,
                    'probability': 0.0,
                    'reason': f'Layer 2: Official shortcode "{sender_upper}" from {service}',
                    'layer': 2,
                    'flag': 'official_shortcode'
                }
    
    # Check official sender patterns
    for pattern in OFFICIAL_SENDER_PATTERNS:
        if re.search(pattern, sms_text, re.IGNORECASE):
            phishing_check = sum(1 for word in PHISHING_KEYWORDS if word in sms_text)
            if phishing_check == 0:
                return {
                    'is_phishing': False,
                    'probability': 0.0,
                    'reason': 'Layer 2: Verified official sender pattern',
                    'layer': 2,
                    'flag': 'official_pattern'
                }
    
    # ============================================================
    # LAYER 3: ML ENGINE
    # ============================================================
    return {
        'is_phishing': None,
        'probability': None,
        'reason': 'Layer 3: ML Analysis needed',
        'layer': 3,
        'flag': 'ml_analysis'
    }

# ============================================================
# SMS SERVICE CLASS
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
        
        print("   SMS 3-Layer Defense System Initialized (Production-Optimized)")
        print(f"   Layer 1: {len(PHISHING_KEYWORDS)} phishing keywords, {len(URGENCY_KEYWORDS)} urgency keywords")
        print(f"   Layer 1: URLs → ML Analysis (flag)")
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
            # LAYER 1 & 2
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
            
            # URL detected → ML
            if layer_result.get('flag') == 'url_detected':
                features = self.extract_features(sms)
                scaled = self.model.scale(features)
                pred = self.model.predict(scaled)[0]
                prob = self.model.predict_proba(scaled)[0]
                result = self.model.decode(pred)
                confidence = float(max(prob))
                
                feature_dict = features.iloc[0].to_dict()
                if feature_dict.get('phishing_score', 0) > 0:
                    confidence = min(confidence * 1.3, 0.95)
                
                return {
                    'is_phishing': bool(result == 1),
                    'probability': confidence,
                    'result': 'phishing' if result == 1 else 'legitimate',
                    'reason': 'Layer 3: URL detected → ML Analysis',
                    'layer': 3,
                    'flag': 'url_ml_analysis',
                    'type': 'sms',
                    'message': sms
                }
            
            # LAYER 3: ML
            features = self.extract_features(sms)
            scaled = self.model.scale(features)
            pred = self.model.predict(scaled)[0]
            prob = self.model.predict_proba(scaled)[0]
            result = self.model.decode(pred)
            confidence = float(max(prob))
            
            feature_dict = features.iloc[0].to_dict()
            
            # Adjust confidence
            if feature_dict.get('phishing_score', 0) > 0:
                confidence = min(confidence * 1.2, 0.95)
            
            if feature_dict.get('has_official_sender', 0) == 1:
                confidence = max(confidence * 0.5, 0.05)
            
            if feature_dict.get('has_utility', 0) == 1 and feature_dict.get('phishing_score', 0) == 0:
                confidence = max(confidence * 0.4, 0.05)
            
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

    # Prize/Lottery Scam Detection
    prize_words = ["won", "win", "winner", "prize", "claim", "reward", "congratulations", "congrats", "lucky", "selected"]
    if any(word in sms_text for word in prize_words):
        has_url = re.search(r'http\S+|www\S+', sms_text)
        has_money = re.search(r'\d+[\s,]*Pula|\d+[\s,]*P\b|\d+\.?\d*\s*(?:million|billion|thousand)', sms_text)
        if has_url or has_money:
            return {
                'is_phishing': True,
                'probability': 1.0,
                'reason': 'Layer 1: Prize/Lottery scam detected',
                'layer': 1,
                'flag': 'prize_scam'
            }
