# services/url_service.py — COMPLETE WITH PIRACY DETECTION
import re
import pandas as pd
import math
import os
import json
import traceback
from collections import Counter
from urllib.parse import urlparse
from models.url_model import URLModel

# ============================================================
# DIRECT BLACKLIST — PIRACY SITES
# ============================================================
BLACKLISTED_DOMAINS = {
    "123movieszone.online",
    "123movies.to",
    "123movies.org",
    "123movies.com",
    "fmovies.to",
    "fmovies.org",
    "fmovies.com",
    "soap2day.to",
    "soap2day.org",
    "soap2day.com",
    "putlocker.to",
    "putlocker.org",
    "putlocker.com",
    "gomovies.to",
    "gomovies.org",
    "gomovies.com",
    "watchseries.to",
    "watchseries.org",
    "watchseries.com",
    "moviebox.ph",
    "moviebox.to",
    "moviebox.org",
    "moviebox.com",
    "thepiratebay.org",
    "thepiratebay.com",
    "yts.to",
    "yts.org",
    "yts.com",
    "rarbg.to",
    "rarbg.org",
    "rarbg.com",
}

# ============================================================
# LAYER 1: EXACT MATCHES — WORLDWIDE + BOTSWANA
# ============================================================
TRUSTED_DOMAINS = {
    # ─── GLOBAL TECH ───
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
    "paypal.com", "ebay.com", "etsy.com", "shopify.com",
    "cloudflare.com", "digitalocean.com", "linode.com",
    "heroku.com", "docker.com", "kubernetes.io", "jenkins.io",
    "wordpress.org", "drupal.org", "joomla.org",
    
    # ─── BOTSWANA ───
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
    "mackair.co.bw", "choppies.co.bw",
    
    # ─── SOUTH AFRICA ───
    "gov.za", "parliament.gov.za", "saps.gov.za", "sars.gov.za",
    "eskom.co.za", "transnet.co.za", "telkom.co.za",
    "fnb.co.za", "standardbank.co.za", "absa.co.za", "nedbank.co.za",
    "capitec.co.za", "discovery.co.za", "mtn.co.za", "vodacom.co.za",
    
    # ─── INTERNATIONAL ORGANIZATIONS ───
    "un.org", "unicef.org", "who.int", "worldbank.org", "imf.org",
    "oecd.org", "nato.int", "europa.eu", "redcross.org",
    "undp.org", "unesco.org", "ilo.org", "fao.org", "wfp.org",
    
    # ─── EDUCATION ───
    "harvard.edu", "stanford.edu", "mit.edu", "oxford.ac.uk",
    "cambridge.ac.uk", "ucl.ac.uk", "imperial.ac.uk",
    "ub.bw", "bca.bw", "biust.ac.bw", "bufm.ac.bw",
    
    # ─── RETAIL & SHOPPING ───
    "game.co.za", "shoprite.co.za", "picknpay.co.za", "woolworths.co.za",
    "takealot.com", "superbalist.com", "amazon.com", "ebay.com",
    "etsy.com", "walmart.com", "target.com", "bestbuy.com",
    "costco.com", "ikea.com",
    
    # ─── BANKING — GLOBAL ───
    "chase.com", "wellsfargo.com", "bankofamerica.com",
    "citibank.com", "capitalone.com", "usbank.com",
    "hsbc.com", "barclays.com", "lloydsbank.co.uk",
    "bnpparibas.com", "societegenerale.com",
    "deutsche-bank.de", "commerzbank.de", "unicredit.it",
    "bbva.com", "santander.com",
    
    # ─── GOVERNMENT — GLOBAL ───
    "usa.gov", "whitehouse.gov", "state.gov", "defense.gov",
    "nsa.gov", "fbi.gov", "cia.gov", "nasa.gov",
    "uk.gov", "parliament.uk", "mod.uk", "gov.uk",
    "europa.eu", "ec.europa.eu", "bundesregierung.de",
    "elysee.fr", "mfa.gov.cn", "gov.cn",
    
    # ─── NEWS & MEDIA ───
    "bbc.com", "bbc.co.uk", "cnn.com", "edition.cnn.com",
    "nytimes.com", "washingtonpost.com", "theguardian.com",
    "reuters.com", "apnews.com", "aljazeera.com",
    "foxnews.com",
    
    # ─── SOCIAL MEDIA ───
    "facebook.com", "fb.com", "instagram.com", "twitter.com",
    "x.com", "linkedin.com", "whatsapp.com", "telegram.org",
    "discord.com", "reddit.com", "tumblr.com", "pinterest.com",
    "snapchat.com", "tiktok.com",
    
    # ─── SEARCH ENGINES ───
    "google.com", "bing.com", "yahoo.com", "duckduckgo.com",
    "baidu.com", "yandex.ru", "naver.com",
}

# ============================================================
# LAYER 1.5: BOTSWANA BRAND PROTECTION
# ============================================================
BOTSWANA_BRANDS = {
    "mascom": {"trusted": ["mascom.bw"], "suspicious": ["rewards", "promo", "free", "verify", "login", "claim", "winner", "cash", "prize"]},
    "orange": {"trusted": ["orange.co.bw"], "suspicious": ["promo", "free", "rewards", "claim", "winner", "cash", "prize", "verify"]},
    "fnb": {"trusted": ["fnb.co.bw", "fnb.co.za"], "suspicious": ["verify", "secure", "unlock", "alert", "login", "blocked", "suspended", "fraud"]},
    "btc": {"trusted": ["btc.co.bw"], "suspicious": ["payment", "renew", "disconnect", "verify", "fees", "outstanding", "line"]},
    "stanbic": {"trusted": ["stanbic.co.bw"], "suspicious": ["verify", "secure", "unlock", "alert", "login", "blocked"]},
    "bank of botswana": {"trusted": ["bankofbotswana.bw", "bob.bw"], "suspicious": ["frozen", "verify", "secure", "login", "blocked", "suspended"]},
    "bofinet": {"trusted": ["bofinet.co.bw"], "suspicious": ["tax", "payment", "submission", "filing", "deadline", "refund"]},
    "burs": {"trusted": ["burs.org.bw"], "suspicious": ["tax", "refund", "return", "submission", "deadline", "payment"]},
    "dhl": {"trusted": ["dhl.co.bw", "dhl.com"], "suspicious": ["tracking", "delivery", "package", "arrived", "shipped", "customs", "fee"]},
    "choppies": {"trusted": ["choppies.co.bw"], "suspicious": ["voucher", "gift", "winner", "cash", "prize", "reward"]}
}

# ============================================================
# LAYER 1.5: SUSPICIOUS PATTERNS — WORLDWIDE + PIRACY
# ============================================================
SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.club', '.online', '.info', '.site',
    '.live', '.fun', '.tk', '.ml', '.ga', '.cf', '.pw',
    '.cc', '.co', '.io', '.bz', '.name', '.work', '.click',
    '.link', '.press', '.store', '.shop', '.tech', '.cloud',
    '.host', '.web', '.app', '.dev', '.blog', '.site',
    '.gq', '.eu', '.su', '.by', '.kz', '.uz',
    '.win', '.bid', '.date', '.download', '.review', '.trade',
    '.men', '.party', '.loan', '.racing', '.accountant', '.science',
    '.website', '.space', '.tech', '.store', '.shop', '.online',
    '.ph', '.to', '.run',
}

SUSPICIOUS_PATTERNS = [
    r".*123movieszone.*",
    r".*fmovies.*",
    r".*soap2day.*",
    r".*putlocker.*",
    r".*gomovies.*",
    r".*watchseries.*",
    r".*moviebox.*",
    r".*thepiratebay.*",
    r'(mascom|orange|fnb|btc|stanbic|bankofbotswana|bofinet|burs|dhl|choppies).*(promo|free|rewards|cash|prize|verify|login|claim)',
    r'(fnb|stanbic|bank).*(login|secure|verify|blocked|suspended)',
    r'(paypal|amazon|apple|microsoft|google|facebook|instagram|whatsapp|telegram).*(verify|confirm|login|secure|unlock)',
    r'(chase|wellsfargo|bankofamerica|citibank|hsbc|barclays).*(verify|login|secure|unlock)',
    r'(fedex|dhl|ups|usps).*(tracking|delivery|package|customs|fee)',
    r'.*act\s+now.*',
    r'.*immediate\s+action.*',
    r'.*your\s+account\s+(will\s+be|is|has\s+been)\s+(blocked|suspended|frozen|locked)',
    r'.*click\s+here\s+to\s+(verify|confirm|unlock|claim)',
    r'.*you\s+(won|have\s+won|are\s+a\s+winner).*',
    r'.*claim\s+your\s+(prize|reward|cash|money|gift|voucher).*',
    r'.*congratulations.*(won|winner|prize|cash|gift).*',
    r'.*login.*(secure|verify|confirm|update).*',
    r'.*security\s+alert.*',
    r'.*fraud\s+alert.*',
    r'.*unusual\s+activity.*',
    r'.*suspicious\s+activity.*',
    r'.*nigerian\s+prince.*',
    # ─── PIRACY PATTERNS ───
    r'.*123movies.*',
    r'.*fmovies.*',
    r'.*soap2day.*',
    r'.*putlocker.*',
    r'.*gomovies.*',
    r'.*watchseries.*',
    r'.*moviebox.*',
    r'.*thepiratebay.*',
    r'.*yts.*',
    r'.*rarbg.*',
    r'.*popcorntime.*',
    r'.*showbox.*',
    r'.*cinemahd.*',
]

# ============================================================
# LAYER 2: PLATFORM WILDCARDS — WORLDWIDE
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
    "github.dev", "gitpod.io", "codespaces.com",
    "pythonanywhere.com", "replit.com",
    "glitch.me", "surge.sh", "neocities.org",
    "netlify.com", "vercel.com", "cloudflare.com",
    "page.dev", "workers.dev", "popsy.co",
    "webflow.io", "editorx.io", "duda.co",
    "wixsite.com", "godaddysites.com", "weebly.com",
}

# ============================================================
# LAYER 3: STRICT INSTITUTIONAL TLDs — WORLDWIDE
# ============================================================
STRICT_TLDS = {
    ".gov", ".gov.bw", ".gov.za", ".gov.uk", ".gov.au", ".gov.ca",
    ".gov.in", ".gov.ng", ".gov.ke", ".gov.gh", ".gov.eg",
    ".edu", ".edu.bw", ".edu.za", ".edu.au", ".edu.ca",
    ".edu.in", ".edu.ng", ".edu.ke", ".edu.gh", ".edu.eg",
    ".ac.bw", ".ac.za", ".ac.uk", ".ac.in", ".ac.ke",
    ".mil", ".mil.za", ".mil.uk", ".mil.au", ".mil.ca",
}

# ============================================================
# URL NORMALIZATION — Fix trailing slash issues
# ============================================================
def normalize_url(url):
    """Remove trailing slash for consistent detection"""
    if url and url.endswith('/'):
        url = url[:-1]
    return url

# ============================================================
# MAIN WHITELIST CHECKER
# ============================================================

def is_trusted_domain(domain):
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
    
    # ─── BLACKLIST CHECK ───
    if domain in BLACKLISTED_DOMAINS:
        return False
    
    # EXCEPTION: Whitelist your own backend
    if domain.endswith('.vercel.app'):
        return True
    
    # LAYER 1: Exact Match
    if domain in TRUSTED_DOMAINS:
        return True
    
    # LAYER 1.5: Botswana Brand Protection
    for brand, data in BOTSWANA_BRANDS.items():
        if brand in domain:
            if any(domain == trusted or domain.endswith('.' + trusted) for trusted in data["trusted"]):
                return True
            if any(sus in domain for sus in data["suspicious"]):
                return False
    
    # LAYER 1.5: Phishing Patterns
    if any(re.search(pattern, domain, re.IGNORECASE) for pattern in SUSPICIOUS_PATTERNS):
        return False
    
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        return False
    
    # LAYER 2: Platform Wildcards
    if any(domain == wc or domain.endswith('.' + wc) for wc in PLATFORM_WILDCARDS):
        return True
    
    # LAYER 3: Strict TLDs
    if any(domain.endswith(tld) for tld in STRICT_TLDS):
        return True
    
    # LAYER 4: ML Engine
    return False

# ============================================================
# URL SERVICE CLASS
# ============================================================

class URLService:
    def __init__(self):
        self.model = URLModel()
        
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
            # Normalize URL (remove trailing slash)
            url = normalize_url(url)
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
            features['is_ip'] = 1 if parts and re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[0]) else 0
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
            # Normalize URL (remove trailing slash)
            url = normalize_url(url)
            
            # LAYER 1-3: Whitelist Check
            if self._is_whitelisted(url):
                return {
                    'is_phishing': False,
                    'probability': 0.0,
                    'result': 'legitimate',
                    'reason': 'Verified Trusted Domain'
                }
            
            # LAYER 4: ML Engine for ALL other domains
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
