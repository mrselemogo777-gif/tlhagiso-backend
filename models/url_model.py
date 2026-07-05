# models/url_model.py
import joblib
import os
import numpy as np
from config import Config

class URLModel:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_models()
        return cls._instance
    
    def _load_models(self):
        print("🔗 Loading URL models...")
        self.model = joblib.load(os.path.join(Config.MODEL_PATH, 'url_model.pkl'))
        self.scaler = joblib.load(os.path.join(Config.MODEL_PATH, 'url_scaler.pkl'))
        self.encoder = joblib.load(os.path.join(Config.MODEL_PATH, 'url_label_encoder.pkl'))
        print("   ✅ URL models loaded")
    
    def predict(self, features):
        return self.model.predict(features)
    
    def predict_proba(self, features):
        return self.model.predict_proba(features)
    
    def scale(self, features):
        return self.scaler.transform(features)
    
    def decode(self, pred):
        return self.encoder.inverse_transform([pred])[0]
