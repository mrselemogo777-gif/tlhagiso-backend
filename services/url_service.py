# services/url_service.py
import re
import pandas as pd
import math
import os
import json
import traceback
from collections import Counter
from urllib.parse import urlparse
from config import Config
from models.url_model import URLModel

# ============================================================
# LAYER 1: EXACT MATCHES (Verified Trusted Domains)
# ============================================================
TRUSTED_DOMAINS = {
    # GLOBAL TECH
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
    
    # BOTSWANA TRUSTED DOMAINS
    "gov.bw", "parliament.gov.bw", "presidency.gov.bw",
    "justice.gov.bw", "health.gov.bw", "education.gov.bw",
    "transport.gov.bw", "agriculture.gov.bw", "lands.gov.bw",
    "water.gov.bw", "energy.gov.bw", "tourism.gov.bw",
    "trade.gov.bw", "finance.gov.bw", "homeaffairs.gov.bw",
    "police.gov.bw", "defence.gov.bw", "immigration.gov.bw",
    "bocra.bw", "bica.bw", "boip.bw", "bog.bw", "bops.bw",
    "mascom.bw", "orange.co.bw", "btc.co.bw", "mtn.co.bw",
    "bankofbotswana.bw", "bob.bw", "fnb.co.bw", "stanbic.co.bw",
    "standardbank.co.bw", "absa.co.bw", "nedbank.co.bw",
    "barclays.co.bw", "abcbank.co.bw", "debswana.com", "debswana.bw",
    "ub.bw", "bca.bw", "biust.ac.bw", "bufm.ac.bw",
    "dailynews.gov.bw", "mmegi.bw", "airbotswana.co.bw",
    "mackair.co.bw", "choppies.co.bw", "game.co.za", "shoprite.co.za",
    "picknpay.co.za", "woolworths.co.za",
    
    # SOUTH AFRICA TRUSTED
    "gov.za", "parliament.gov.za", "saps.gov.za", "sars.gov.za",
    "eskom.co.za", "transnet.co.za", "telkom.co.za",
    "fnb.co.za", "standardbank.co.za", "absa.co.za", "nedbank.co.za",
    "capitec.co.za", "discovery.co.za", "mtn.co.za", "vodacom.co.za",
    
    # INTERNATIONAL
    "un.org", "unicef.org", "who.int", "worldbank.org", "imf.org",
    "oecd.org", "nato.int", "europa.eu", "redcross.org", "icc-cpi.int",
}

# ============================================================
# LAYER 1.5: BOTSWANA BRAND PROTECTION
# ============================================================
BOTSWANA_BRANDS = {
    "mascom": {
        "trusted": ["mascom.bw"],
        "keywords": ["mascom", "mascom.bw"],
        "suspicious_keywords": ["rewards", "promo", "free", "verify", "login", "claim", "winner", "cash", "prize"]
    },
    "orange": {
        "trusted": ["orange.co.bw"],
        "keywords": ["orange", "orange.co.bw"],
        "suspicious_keywords": ["promo", "free", "rewards", "claim", "winner", "cash", "prize", "verify"]
    },
    "fnb": {
        "trusted": ["fnb.co.bw", "fnb.co.za"],
        "keywords": ["fnb", "fnb.co.bw", "fnb.co.za"],
        "suspicious_keywords": ["verify", "secure", "unlock", "alert", "login", "blocked", "suspended", "fraud"]
    },
    "btc": {
        "trusted": ["btc.co.bw"],
        "keywords": ["btc", "btc.co.bw"],
        "suspicious_keywords": ["payment", "renew", "disconnect", "verify", "fees", "outstanding", "line"]
    },
    "stanbic": {
        "trusted": ["stanbic.co.bw"],
        "keywords": ["stanbic", "stanbic.co.bw"],
        "suspicious_keywords": ["verify", "secure", "unlock", "alert", "login", "blocked"]
    },
    "bank of botswana": {
        "trusted": ["bankofbotswana.bw", "bob.bw"],
        "keywords": ["bank of botswana", "bankofbotswana.bw", "bob.bw"],
        "suspicious_keywords": ["frozen", "verify", "secure", "login", "blocked", "suspended"]
    },
    "bofinet": {
        "trusted": ["bofinet.co.bw"],
        "keywords": ["bofinet", "bofinet.co.bw"],
        "suspicious_keywords": ["tax", "payment", "submission", "filing", "deadline", "refund"]
    },
    "burs": {
        "trusted": ["burs.org.bw"],
        "keywords": ["burs", "burs.org.bw"],
        "suspicious_keywords": ["tax", "refund", "return", "submission", "deadline", "payment"]
    },
    "dhl": {
        "trusted": ["dhl.co.bw", "dhl.com"],
        "keywords": ["dhl", "dhl.co.bw", "dhl.com"],
        "suspicious_keywords": ["tracking", "delivery", "package", "arrived", "shipped", "customs", "fee"]
    },
    "choppies": {
        "trusted": ["choppies.co.bw"],
        "keywords": ["choppies", "choppies.co.bw"],
        "suspicious_keywords": ["voucher", "gift", "winner", "cash", "prize", "reward"]
    }
}

# ============================================================
# LAYER 1.5: SUSPICIOUS PATTERNS
# ============================================================
SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.club', '.online', '.info', '.site',
    '.live', '.fun', '.tk', '.ml', '.ga', '.cf', '.pw',
    '.cc', '.co', '.io', '.bz', '.name', '.work', '.click',
    '.link', '.press', '.store', '.shop', '.tech', '.cloud',
    '.host', '.web', '.app', '.dev', '.blog', '.site',
    '.gq', '.eu', '.su', '.by', '.kz', '.uz'
}

SUSPICIOUS_KEYWORDS = [
    "verify", "validate", "authenticate", "confirm", "secure",
    "protect", "login", "signin", "update", "upgrade", "renew",
    "restore", "urgent", "immediate", "alert", "warning",
    "blocked", "suspended", "frozen", "locked", "deactivated",
    "terminated", "cancelled", "unauthorized", "suspicious",
    "fraud", "free", "won", "winner", "prize", "reward",
    "claim", "cash", "money", "pula", "promo", "offer",
    "discount", "gift", "click", "here", "link", "connect",
    "access", "account", "profile", "settings", "help",
    "support", "admin", "service"
]

SUSPICIOUS_PATTERNS = [
    r'(mascom|orange|fnb|btc|stanbic|bankofbotswana|bofinet|burs|dhl|choppies).*(promo|free|rewards|cash|prize|verify|login|claim)',
    r'(fnb|stanbic|bank).*(login|secure|verify|blocked|suspended)',
    r'.*act\s+now.*',
    r'.*immediate\s+action.*',
    r'.*your\s+account\s+(will\s+be|is|has\s+been)\s+(blocked|suspended|frozen|locked)',
    r'.*click\s+here\s+to\s+(verify|confirm|unlock|claim)',
    r'.*you\s+(won|have\s+won|are\s+a\s+winner).*',
    r'.*claim\s+your\s+(prize|reward|cash|money).*',
    r'.*congratulations.*(won|winner|prize|cash).*',
    r'.*login.*(secure|verify).*',
    r'.*signin.*(secure|verify).*',
    r'.*(account|profile|payment).*(update|verify|confirm).*',
    r'.*security\s+alert.*',
    r'.*fraud\s+alert.*',
]

# ============================================================
# LAYER 2: PLATFORM WILDCARDS
# ============================================================
PLATFORM_WILDCARDS = {
    "github.io", "vercel.app", "netlify.app", "pages.dev",
    "gitlab.io", "herokuapp.com", "azurewebsites.net", "cloudfront.net",
    "s3.amazonaws.com", "wordpress.com", "blogger.com", "medium.com",
    "substack.com", "hashnode.dev", "dev.to", "notion.site",
    "glitch.com", "replit.app", "codesandbox.io", "stackblitz.com",
    "codepen.io", "jsfiddle.net", "observablehq.com",
    "colab.research.google.com", "kaggle.com", "huggingface.co",
    "replicate.com", "gradio.app", "streamlit.app", "render.com",
    "fly.io", "railway.app", "cyclic.sh", "deno.dev",
    "cloudflare.dev", "workers.dev", "raw.githubusercontent.com",
    "blob.core.windows.net", "storage.googleapis.com",
    "firebasestorage.googleapis.com",
}

# ============================================================
# LAYER 3: STRICT INSTITUTIONAL TLDs
# ============================================================
STRICT_TLDS = {
    ".gov", ".gov.bw", ".gov.za", ".gov.uk", ".edu", ".ac.bw",
    ".ac.za", ".ac.uk", ".edu.za", ".mil",
}

# ============================================================
# MAIN WHITELIST CHECKER
# ============================================================

def is_trusted_domain(domain):

    # ─── PIRACY SITE DETECTION ───
    piracy_keywords = ['123movies', 'fmovies', 'soap2day', 'putlocker', 'gomovies', 
                       'watchseries', 'moviebox', 'thepiratebay', 'yts', 'rarbg']
    if any(kw in domain for kw in piracy_keywords):
        return False  # Mark as phishing (RED)

    domain = domain.lower().strip()
    
    if domain.startswith('http://') or domain.startswith('https://'):
        parsed = urlparse(domain)
        domain = parsed.netloc or domain
    if '/' in domain:
        domain = domain.split('/')[0]
    if ':' in domain:
        domain = domain.split(':')[0]
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # LAYER 1: Exact Match
    if domain in TRUSTED_DOMAINS:
        return True
    
    # LAYER 1.5: Botswana Brand Protection
    for brand, data in BOTSWANA_BRANDS.items():
        brand_found = False
        for keyword in data["keywords"]:
            if keyword in domain:
                brand_found = True
                break
        if brand_found:
            for trusted in data["trusted"]:
                if domain == trusted or domain.endswith('.' + trusted):
                    return True
            for sus in data["suspicious_keywords"]:
                if sus in domain:
                    return False
    
    # LAYER 1.5: Phishing Patterns
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, domain, re.IGNORECASE):
            return False
    
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return False
    
    # LAYER 2: Platform Wildcards
    for wildcard in PLATFORM_WILDCARDS:
        if domain == wildcard or domain.endswith('.' + wildcard):
            return True
    
    # LAYER 3: Strict TLDs
    for tld in STRICT_TLDS:
        if domain.endswith(tld):
            return True
    
    # LAYER 4: ML Engine
    return False

# ============================================================
# URL SERVICE CLASS
# ============================================================

class URLService:
    def __init__(self):
        self.model = URLModel()
        
        # Flexible path loading for features file
        feature_paths = [
            '/home/cheezboi/models/url_features.json',
            'models/url_features.json',
            '../models/url_features.json',
            os.path.join(os.path.dirname(__file__), '../models/url_features.json'),
            os.path.join(os.getcwd(), 'models/url_features.json')
        ]
        
        features_loaded = False
        for path in feature_paths:
            try:
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        self.features = json.load(f)
                    print(f"   URL features loaded from: {path}")
                    features_loaded = True
                    break
            except:
                continue
        
        if not features_loaded:
            print("   WARNING: url_features.json not found, using default features")
            self.features = [
                'url_len', 'dot_cnt', 'slash_cnt', 'dash_cnt', 
                'under_cnt', 'digit_cnt', 'special_cnt', 'is_https',
                'eq_cnt', 'qm_cnt', 'amp_cnt', 'letter_cnt',
                'dom_len', 'subdom_cnt', 'tld_len', 'is_ip',
                'letter_ratio', 'digit_ratio', 'spec_ratio',
                'path_len', 'query_len', 'entropy'
            ]
        
        print(f"   URL features loaded: {len(self.features)} features")
        print(f"   L1 Trusted Domains: {len(TRUSTED_DOMAINS)}")
        print(f"   L1.5 Botswana Brands: {len(BOTSWANA_BRANDS)}")
        print(f"   L2 Platform Wildcards: {len(PLATFORM_WILDCARDS)}")
        print(f"   L3 Strict TLDs: {len(STRICT_TLDS)}")
        print(f"   L4 ML Engine: Active")
    
    def _is_whitelisted(self, url):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]
            if ":" in domain:
                domain = domain.split(":")[0]
            return is_trusted_domain(domain)
        except Exception:
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
        
        features_df = pd.DataFrame([features])
        for col in self.features:
            if col not in features_df.columns:
                features_df[col] = 0
        features_df = features_df[self.features]
        
        return features_df
    
    def detect(self, url):
        try:
            if self._is_whitelisted(url):
                return {
                    'is_phishing': False,
                    'probability': 0.0,
                    'result': 'legitimate',
                    'reason': 'Verified Trusted Domain'
                }
            
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
                'reason': 'ML Analysis'
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
