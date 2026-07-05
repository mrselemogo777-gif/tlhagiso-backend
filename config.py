# config.py
import os

class Config:
    # Use relative path - works locally and on Vercel
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    MODEL_PATH = os.path.join(BASE_DIR, 'models')
    
    PORT = 5001
    SMS_THRESHOLD = 0.35
    
    BOTSWANA_BRANDS = ['mascom', 'orange', 'btc', 'mtn', 'choppies', 'fnb', 'bank of botswana']
    HIGH_RISK_WORDS = ['verify', 'compromised', 'blocked', 'suspended', 'urgent', 'win', 'claim', 'free', 'reward']
    
    URL_FEATURES = [
        'url_len', 'dom_len', 'is_ip', 'tld_len', 'subdom_cnt', 
        'letter_cnt', 'digit_cnt', 'special_cnt', 'eq_cnt', 'qm_cnt',
        'amp_cnt', 'dot_cnt', 'dash_cnt', 'under_cnt', 'letter_ratio',
        'digit_ratio', 'spec_ratio', 'is_https', 'slash_cnt', 
        'entropy', 'path_len', 'query_len'
    ]
