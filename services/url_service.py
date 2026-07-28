# services/url_service.py — Professional 5-Layer Hybrid Defense
import re
import pandas as pd
import math
import os
import json
import traceback
from collections import Counter
from urllib.parse import urlparse
from models.url_model import URLModel
import requests


# ============================================================
# LAYER 1: TRUSTED WHITELIST (DOMAINS ONLY)
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
    "paypal.com", "ebay.com", "etsy.com", "shopify.com",
    
    # BOTSWANA
    "gov.bw", "parliament.gov.bw", "presidency.gov.bw",
    "justice.gov.bw", "health.gov.bw", "education.gov.bw",
    "mascom.bw", "orange.co.bw", "btc.co.bw", "mtn.co.bw",
    "bankofbotswana.bw", "bob.bw", "fnb.co.bw", "stanbic.co.bw",
    "standardbank.co.bw", "absa.co.bw", "nedbank.co.bw",
    "ub.bw", "bca.bw", "biust.ac.bw", "bufm.ac.bw",
    "dailynews.gov.bw", "mmegi.bw", "choppies.co.bw",
    
    # SOUTH AFRICA
    "gov.za", "parliament.gov.za", "saps.gov.za", "sars.gov.za",
    "eskom.co.za", "transnet.co.za", "telkom.co.za",
    "fnb.co.za", "standardbank.co.za", "absa.co.za", "nedbank.co.za",
    "capitec.co.za", "discovery.co.za", "mtn.co.za", "vodacom.co.za",
    
    # INTERNATIONAL
    "un.org", "unicef.org", "who.int", "worldbank.org", "imf.org",
    "oecd.org", "nato.int", "europa.eu", "redcross.org",
    
    # NEWS & MEDIA 
    "tmz.com", "www.tmz.com", "foxnews.com", "cnn.com", "edition.cnn.com",
    "bbc.com", "bbc.co.uk", "reuters.com", "apnews.com", "aljazeera.com",
    "nytimes.com", "washingtonpost.com", "theguardian.com",
}


# ============================================================
# LAYER 2: LOCAL BLACKLIST (DOMAINS ONLY)
# ============================================================

BLACKLISTED_DOMAINS = {
    # STREAMING & PIRACY
    "123movieszone.online", "123movies.to", "123movies.org", "123movies.com",
    "fmovies.to", "fmovies.org", "fmovies.com",
    "soap2day.to", "soap2day.org", "soap2day.com",
    "putlocker.to", "putlocker.org", "putlocker.com",
    "gomovies.to", "gomovies.org", "gomovies.com",
    "watchseries.to", "watchseries.org", "watchseries.com",
    "moviebox.ph", "moviebox.to", "moviebox.org", "moviebox.com",
    "goojara.to", "thepiratebay.org", "thepiratebay.com",
    "yts.to", "yts.org", "yts.com",
    "rarbg.to", "rarbg.org", "rarbg.com",
    "popcorntime.to", "showbox.to", "cinemahd.to", "teatv.to",
    "cyberflix.to", "lookmovie.to", "solarfilm.to", "primewire.to",
    "yesmovies.to", "azmovies.to", "moviesjoy.to",
    "movie4k.to", "xmovies8.to", "watchmovies.to",
    "freemovies.to", "hdmovies.to", "4kmovies.to",
    
    # GLOBAL PHISHING
    "paypal-verify.com", "paypal-secure.com", "paypal-login.xyz",
    "amazon-verify.com", "amazon-secure.com", "amazon-login.xyz",
    "apple-verify.com", "apple-id.xyz", "icloud-verify.com",
    "microsoft-verify.com", "outlook-verify.com", "hotmail-verify.com",
    "google-verify.com", "gmail-verify.com", "drive-verify.com",
    "facebook-login.xyz", "instagram-verify.com", "twitter-verify.com",
    "linkedin-verify.com", "whatsapp-verify.com", "telegram-verify.com",
    
    # BANKING PHISHING
    "chase-login.com", "chase-verify.com",
    "bankofamerica-verify.com", "wellsfargo-verify.com",
    "citibank-verify.com", "hsbc-verify.com",
    "barclays-verify.com", "lloyds-verify.com",
    "natwest-verify.com", "santander-verify.com",
    
    # BOTSWANA PHISHING
    "mascom-promo.com", "mascom-rewards.com", "mascom-login.xyz",
    "orange-promo.com", "orange-rewards.com", "orange-login.xyz",
    "btc-payment.com", "btc-renew.com", "btc-login.xyz",
    "fnb-secure.com", "fnb-login.xyz", "fnb-verify.com",
    "stanbic-login.xyz", "stanbic-verify.com",
    "bankofbotswana-login.xyz", "bob-login.xyz",
    "bofinet-payment.com", "burs-refund.com",
    
    # URL SHORTENERS (EXPANDED – SCAM‑PRONE)
    "bit.ly", "tinyurl.com", "adf.ly", "shorte.st",
    "buff.ly", "cutt.ly", "ow.ly", "goo.gl", "is.gd", "linktr.ee",
    "tiny.gdn", "tiny.one", "short.link", "shorturl.at", "rb.gy",
    "v.gd", "clck.ru", "soo.gd", "s.id", "urlz.fr", "j.mp",
    "qrco.de", "qr.net", "ow.li", "shrtco.de", "9qr.de",
    "gg.gg", "bitly.com", "yourls.org", "kutt.it", "t.co",
    "lnkd.in", "smly.co", "dlvr.it", "pixly.me",
    "mcaf.ee", "tiny.cc", "tr.im", "vzti.me", "x.co",
    "yfrog.com", "zpr.io", "ad.vu", "bc.vc", "cli.gs",
    "easyurl.net", "flic.kr", "fuuu.be", "go.usa.gov", "h2m.com",
    "kip.it", "l9k.net", "lt.tl", "m1p.de", "merky.de",
    "notlong.com", "nsfw.in", "nxy.in", "oiip.io", "q.gs",
    "qrl.li", "r.im", "redir.ec", "rl.fm", "s7y.us",
    "scrnch.me", "shorl.com", "shortie.me", "shoutkey.com",
    "snipr.com", "snipurl.com", "sp2.ro", "tinyarrow.com",
    "twitclicks.com", "twitthis.com", "u.bb", "ul.to",
    "url.ie", "url4e.com", "urlborg.com", "whurl.com",
    "xrl.us", "yep.it", "zip.net",

    # SUSPICIOUS TLDs OFTEN USED FOR SCAMS
    "gdn", "link", "click", "work", "space",
    "website", "site", "online", "tech", "fun",
    "top", "xyz", "club", "shop", "live",
    "stream", "bid", "win", "loan", "review",
}


# ============================================================
# LAYER 3: GOOGLE SAFE BROWSING API
# ============================================================

GOOGLE_SAFE_BROWSING_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_KEY', '')

def check_google_safe_browsing(url):
    """Query Google's global commercial threat database"""
    if not GOOGLE_SAFE_BROWSING_KEY:
        return False, "Google API key missing"
    
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    
    payload = {
        "client": {"clientId": "tlhagiso", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        response = requests.post(f"{api_url}?key={GOOGLE_SAFE_BROWSING_KEY}", json=payload, timeout=5)
        
        if response.status_code == 200:
            result = response.json()
            if "matches" in result:
                return True, "Google flagged this URL"
            return False, "Google says safe"
        else:
            return False, f"Google API error: {response.status_code}"
    except requests.exceptions.Timeout:
        return False, "Google timeout"
    except Exception as e:
        return False, f"Error: {str(e)}"


# ============================================================
# LAYER 4: SVM ML ENGINE
# ============================================================

PLATFORM_WILDCARDS = {
    "github.io", "vercel.app", "netlify.app", "pages.dev",
    "gitlab.io", "herokuapp.com", "azurewebsites.net", "cloudfront.net",
}

STRICT_TLDS = {
    ".gov", ".gov.bw", ".gov.za", ".gov.uk", ".edu", ".ac.bw",
    ".ac.za", ".ac.uk", ".edu.za", ".mil",
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def normalize_url(url):
    """Normalize URL: strip spaces, add https:// if missing, remove trailing slash"""
    if not url:
        return ""
    url = str(url).strip().lower()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.rstrip('/')

def is_whitelisted_domain(domain):
    """Check if domain is in whitelist (exact match OR subdomain)"""
    domain = domain.lower().strip()
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith('.' + trusted):
            return True
    return False

def is_blacklisted_domain(domain):
    """Check if domain is in blacklist (exact match OR subdomain)"""
    domain = domain.lower().strip()
    for blocked in BLACKLISTED_DOMAINS:
        if domain == blocked or domain.endswith('.' + blocked):
            return True
    return False

def is_trusted_domain(domain):
    """Legacy function – kept for compatibility"""
    return is_whitelisted_domain(domain)


# ============================================================
# URL SERVICE CLASS
# ============================================================

class URLService:
    def __init__(self):
        self.model = URLModel()
        self.features = [
            'url_len', 'dot_cnt', 'slash_cnt', 'dash_cnt', 
            'under_cnt', 'digit_cnt', 'special_cnt', 'is_https',
            'eq_cnt', 'qm_cnt', 'amp_cnt', 'letter_cnt',
            'dom_len', 'subdom_cnt', 'tld_len', 'is_ip',
            'letter_ratio', 'digit_ratio', 'spec_ratio',
            'path_len', 'query_len', 'entropy'
        ]
        print(" Professional 5-Layer Hybrid Defense System Initialized")
        print(f"   Layer 1: Whitelist ({len(TRUSTED_DOMAINS)} domains)")
        print(f"   Layer 2: Blacklist ({len(BLACKLISTED_DOMAINS)} domains)")
        print(f"   Layer 3: Safe Browsing API (Active)")
        print(f"   Layer 4: SVM ML Engine (97.66% accuracy)")
        print(f"   Layer 5: Final Verdict (Default Safe)")
    
    def _is_whitelisted(self, url):
        """Check if URL is whitelisted – called by detect()"""
        try:
            url = normalize_url(url)
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]
            if ":" in domain:
                domain = domain.split(":")[0]
            return is_whitelisted_domain(domain)
        except Exception:
            return False
    
    def _is_blacklisted(self, url):
        """Check if URL is blacklisted – called by detect()"""
        try:
            url = normalize_url(url)
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]
            if ":" in domain:
                domain = domain.split(":")[0]
            return is_blacklisted_domain(domain)
        except Exception:
            return False
    
    def extract_features(self, url):
        """Extract features for ML model"""
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
        return features_df[self.features]
    
    def detect(self, url):
        """Main detection method – runs all 5 layers"""
        try:
            # Normalize URL FIRST
            url = normalize_url(url)
            
            # ============================================================
            # LAYER 1: TRUSTED WHITELIST
            # ============================================================
            if self._is_whitelisted(url):
                return {
                    'is_phishing': False,
                    'probability': 0.0,
                    'result': 'legitimate',
                    'reason': 'Layer 1: Trusted Whitelist'
                }
            
            # ============================================================
            # LAYER 2: LOCAL BLACKLIST
            # ============================================================
            if self._is_blacklisted(url):
                return {
                    'is_phishing': True,
                    'probability': 1.0,
                    'result': 'phishing',
                    'reason': 'Layer 2: Local Blacklist'
                }
            
            # ============================================================
            # LAYER 3: GOOGLE SAFE BROWSING
            # ============================================================
            is_threat, reason = check_google_safe_browsing(url)
            
            # Only stop if Google finds a threat
            if is_threat:
                return {
                    'is_phishing': True,
                    'probability': 1.0,
                    'result': 'phishing',
                    'reason': 'Layer 3: Safe Browsing'
                }
            
            # If Google says safe or errors → CONTINUE TO LAYER 4
            # (Google is advisory, not authoritative)
            
            # ============================================================
            # LAYER 4: SVM ML ENGINE
            # ============================================================
            features = self.extract_features(url)
            scaled = self.model.scale(features)
            pred = self.model.predict(scaled)[0]
            prob = self.model.predict_proba(scaled)[0]
            result = self.model.decode(pred)
            confidence = float(max(prob))
            
            # Only flag phishing if ML predicts phishing AND confidence >= 35%
            if (result == 1 or result == "phishing") and confidence >= 0.35:
                return {
                    'is_phishing': True,
                    'probability': confidence,
                    'result': 'phishing',
                    'reason': f'Layer 4: SVM ML ({confidence:.2%} confidence)'
                }
            
            # ============================================================
            # LAYER 5: FINAL VERDICT
            # ============================================================
            return {
                'is_phishing': False,
                'probability': 0.0,
                'result': 'legitimate',
                'reason': 'Layer 5: Final Verdict (Safe)'
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
