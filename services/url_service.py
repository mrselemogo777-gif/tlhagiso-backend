# services/url_service.py
import re
import pandas as pd
import math
import numpy as np
from collections import Counter
from urllib.parse import urlparse
import json
import os
import traceback
from config import Config
from models.url_model import URLModel

class URLService:
    def __init__(self):
        self.model = URLModel()
        # Load features using Config
        features_path = os.path.join(Config.MODEL_PATH, 'url_features.json')
        with open(features_path, 'r') as f:
            self.features = json.load(f)
        print(f"   URL features loaded: {len(self.features)} features")
    
    def extract_features(self, url):
        url = str(url).lower()
        features = {}
        
        features['url_len'] = len(url)
        features['dot_cnt'] = url.count('.')
        features['slash_cnt'] = url.count('/')
        features['dash_cnt'] = url.count('-')
        features['under_cnt'] = url.count('_')
        features['digit_cnt'] = sum(c.isdigit() for c in url)
        features['special_cnt'] = len(re.findall(r'[^a-zA-Z0-9]', url))
        features['is_https'] = 1 if 'https' in url else 0
        features['eq_cnt'] = url.count('=')
        features['qm_cnt'] = url.count('?')
        features['amp_cnt'] = url.count('&')
        features['letter_cnt'] = sum(c.isalpha() for c in url)
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            parts = domain.split('.')
            features['dom_len'] = len(parts[-1]) if parts else 0
            features['subdom_cnt'] = max(0, len(parts) - 2)
            features['tld_len'] = len(parts[-1]) if len(parts) > 1 else 0
            if parts and re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[0]):
                features['is_ip'] = 1
            else:
                features['is_ip'] = 0
        except:
            features['dom_len'] = 0
            features['subdom_cnt'] = 0
            features['tld_len'] = 0
            features['is_ip'] = 0
        
        total_chars = len(url) if len(url) > 0 else 1
        features['letter_ratio'] = features['letter_cnt'] / total_chars
        features['digit_ratio'] = features['digit_cnt'] / total_chars
        features['spec_ratio'] = features['special_cnt'] / total_chars
        
        try:
            parsed = urlparse(url)
            features['path_len'] = len(parsed.path)
            features['query_len'] = len(parsed.query)
        except:
            features['path_len'] = 0
            features['query_len'] = 0
        
        if len(url) > 0:
            freq = Counter(url)
            entropy = -sum((count/len(url)) * math.log2(count/len(url)) for count in freq.values())
            features['entropy'] = entropy
        else:
            features['entropy'] = 0
        
        # Create DataFrame
        features_df = pd.DataFrame([features])
        
        # Ensure all features exist
        for col in self.features:
            if col not in features_df.columns:
                features_df[col] = 0
        
        # Reorder columns
        features_df = features_df[self.features]
        
        return features_df
    
    def detect(self, url):
        try:
            # Extract features
            features_df = self.extract_features(url)
            
            # Convert to numpy array
            features_array = features_df.values
            
            # Scale
            scaled = self.model.scale(features_array)
            
            # Predict
            pred = self.model.predict(scaled)[0]
            prob = self.model.predict_proba(scaled)[0]
            
            result = self.model.decode(pred)
            confidence = float(max(prob))
            
            return {
                'is_phishing': bool(result == 1),
                'probability': confidence,
                'result': 'phishing' if result == 1 else 'legitimate'
            }
        except Exception as e:
            print(f"Error in detect: {str(e)}")
            print(traceback.format_exc())
            return {
                'is_phishing': False,
                'probability': 0.0,
                'result': 'error',
                'error': str(e)
            }
