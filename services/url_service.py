# services/url_service.py
import re
import pandas as pd
import math
from collections import Counter
from urllib.parse import urlparse
from config import Config
from models.url_model import URLModel
import json
import traceback

# ============================================================
# LAYER 1: EXACT MATCHES (Verified Trusted Domains)
# ============================================================
TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "drive.google.com",
    "docs.google.com", "mail.google.com", "calendar.google.com",
    "maps.google.com", "analytics.google.com", "googleapis.com",
    "microsoft.com", "office.com", "live.com", "outlook.com",
    "hotmail.com", "azure.com", "github.com", "gitlab.com",
    "bitbucket.org", "stackoverflow.com", "apple.com", "icloud.com",
    "amazon.com", "amazonaws.com", "netflix.com", "spotify.com",
    "facebook.com", "fb.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "whatsapp.com", "telegram.org", "discord.com",
    "slack.com", "zoom.us", "skype.com", "wikipedia.org",
    "gov.bw", "parliament.gov.bw", "mascom.bw", "orange.co.bw",
    "btc.co.bw", "mtn.co.bw", "bankofbotswana.bw", "bob.bw",
    "fnb.co.bw", "stanbic.co.bw", "standardbank.co.bw", "absa.co.bw",
    "nedbank.co.bw", "barclays.co.bw", "ub.bw", "bca.bw",
    "biust.ac.bw", "bufm.ac.bw", "dailynews.gov.bw", "mmegi.bw",
    "airbotswana.co.bw", "mackair.co.bw", "choppies.co.bw",
    "gov.za", "parliament.gov.za", "saps.gov.za", "sars.gov.za",
    "eskom.co.za", "transnet.co.za", "telkom.co.za",
    "un.org", "unicef.org", "who.int", "worldbank.org", "imf.org",
}

# ============================================================
# LAYER 2: PLATFORM WILDCARDS
# ============================================================
PLATFORM_WILDCARDS = {
    "github.io", "vercel.app", "netlify.app", "pages.dev",
    "gitlab.io", "herokuapp.com", "azurewebsites.net", "cloudfront.net",
    "s3.amazonaws.com", "wordpress.com", "blogger.com", "medium.com",
    "substack.com", "hashnode.dev", "dev.to", "notion.site",
}

# ============================================================
# LAYER 3: STRICT INSTITUTIONAL TLDs
# ============================================================
STRICT_TLDS = {
    ".gov", ".gov.bw", ".gov.za", ".gov.uk", ".edu", ".ac.bw",
    ".ac.za", ".ac.uk", ".edu.za", ".mil",
}

# ============================================================
# MAIN WHITELIST CHECKER - FIXED TO HANDLE FULL URLs
# ============================================================
def is_trusted_domain(domain_or_url):
    """4-Layer Defense Matrix - Handles both domains and full URLs"""
    domain = str(domain_or_url).lower().strip()
    
    # Clean the input
    # If it's a full URL, parse it
    if domain.startswith(('http://', 'https://')):
        parsed = urlparse(domain)
        domain = parsed.netloc
    else:
        # If it's a domain with path, extract just the domain part
        if '/' in domain:
            domain = domain.split('/')[0]
    
    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]
    
    # Remove www prefix
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # LAYER 1: Exact Match
    if domain in TRUSTED_DOMAINS:
        return True
    
    # LAYER 2: Platform Wildcards
    for wildcard in PLATFORM_WILDCARDS:
        if domain == wildcard or domain.endswith('.' + wildcard):
            return True
    
    # LAYER 3: Strict Institutional TLDs
    for tld in STRICT_TLDS:
        if domain.endswith(tld):
            return True
    
    # LAYER 4: NOT WHITELISTED → ML ENGINE
    return False

# ============================================================
# URL SERVICE CLASS
# ============================================================
class URLService:
    def __init__(self):
        self.model = URLModel()
        with open('/home/cheezboi/models/url_features.json', 'r') as f:
            self.features = json.load(f)
        print(f"   URL features loaded: {len(self.features)} features")
        print(f"   L1 Trusted Domains: {len(TRUSTED_DOMAINS)}")
        print(f"   L2 Platform Wildcards: {len(PLATFORM_WILDCARDS)}")
        print(f"   L3 Strict TLDs: {len(STRICT_TLDS)}")
        print(f"   L4 ML Engine: Active")
    
    def _is_whitelisted(self, url):
        try:
            return is_trusted_domain(url)
        except Exception as e:
            print(f"Whitelist check error: {e}")
            return False
    
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
            features['is_ip'] = 1 if parts and re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[0]) else 0
        except:
            features['dom_len'] = features['subdom_cnt'] = features['tld_len'] = features['is_ip'] = 0
        
        total_chars = len(url) if len(url) > 0 else 1
        features['letter_ratio'] = features['letter_cnt'] / total_chars
        features['digit_ratio'] = features['digit_cnt'] / total_chars
        features['spec_ratio'] = features['special_cnt'] / total_chars
        
        try:
            parsed = urlparse(url)
            features['path_len'] = len(parsed.path)
            features['query_len'] = len(parsed.query)
        except:
            features['path_len'] = features['query_len'] = 0
        
        if len(url) > 0:
            freq = Counter(url)
            features['entropy'] = -sum((count/len(url)) * math.log2(count/len(url)) for count in freq.values())
        else:
            features['entropy'] = 0
        
        features_df = pd.DataFrame([features])
        for col in self.features:
            if col not in features_df.columns:
                features_df[col] = 0
        return features_df[self.features]
    
    def detect(self, url):
        try:
            # LAYER 1-3: Whitelist Check
            if self._is_whitelisted(url):
                return {
                    'is_phishing': False,
                    'probability': 0.0,
                    'result': 'legitimate',
                    'reason': 'Verified Trusted Domain',
                    'type': 'url',
                    'url': url
                }
            
            # LAYER 4: ML Engine
            features = self.extract_features(url)
            scaled = self.model.scale(features)
            pred = self.model.predict(scaled)[0]
            prob = self.model.predict_proba(scaled)[0]
            result = self.model.decode(pred)
            confidence = float(max(prob))
            
            return {
                'is_phishing': bool(result == 1),
                'probability': confidence,
                'result': 'phishing' if result == 1 else 'legitimate',
                'reason': 'ML Analysis',
                'type': 'url',
                'url': url
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
