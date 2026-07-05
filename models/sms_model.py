# models/sms_model.py
import joblib
import os
import numpy as np
from config import Config

class SMSModel:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_models()
        return cls._instance
    
    def _load_models(self):
        print("📱 Loading SMS models...")
        self.model = joblib.load(os.path.join(Config.MODEL_PATH, 'message_model.pkl'))
        self.vectorizer = joblib.load(os.path.join(Config.MODEL_PATH, 'tfidf_vectorizer.pkl'))
        self.encoder = joblib.load(os.path.join(Config.MODEL_PATH, 'label_encoder.pkl'))
        print("   ✅ SMS models loaded")
    
    def predict(self, features):
        return self.model.predict(features)
    
    def predict_proba(self, features):
        return self.model.predict_proba(features)
    
    def transform(self, text):
        return self.vectorizer.transform(text)
    
    def decode(self, pred):
        return self.encoder.inverse_transform(pred)[0]
