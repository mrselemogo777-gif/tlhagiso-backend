# models/url_model.py
import joblib
import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

class URLModel:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_models()
        return cls._instance
    
    def _load_models(self):
        print("🔗 Loading URL models...")
        
        # Try multiple paths for model files
        model_paths = [
            '/home/cheezboi/models/url_model.pkl',
            'models/url_model.pkl',
            '../models/url_model.pkl',
            os.path.join(os.path.dirname(__file__), 'url_model.pkl'),
            os.path.join(os.getcwd(), 'models/url_model.pkl')
        ]
        
        scaler_paths = [
            '/home/cheezboi/models/url_scaler.pkl',
            'models/url_scaler.pkl',
            '../models/url_scaler.pkl',
            os.path.join(os.path.dirname(__file__), 'url_scaler.pkl'),
            os.path.join(os.getcwd(), 'models/url_scaler.pkl')
        ]
        
        # Find and load model
        model_loaded = False
        for path in model_paths:
            try:
                if os.path.exists(path):
                    self.model = joblib.load(path)
                    print(f"   ✅ URL model loaded from: {path}")
                    model_loaded = True
                    break
            except:
                continue
        
        if not model_loaded:
            print("   ⚠️ WARNING: URL model not found, using fallback")
            from sklearn.ensemble import RandomForestClassifier
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            X_dummy = np.random.rand(10, 22)
            y_dummy = np.random.randint(0, 2, 10)
            self.model.fit(X_dummy, y_dummy)
        
        # Find and load scaler
        scaler_loaded = False
        for path in scaler_paths:
            try:
                if os.path.exists(path):
                    self.scaler = joblib.load(path)
                    print(f"   ✅ URL scaler loaded from: {path}")
                    scaler_loaded = True
                    break
            except:
                continue
        
        if not scaler_loaded:
            print("   ⚠️ WARNING: URL scaler not found, using fallback")
            self.scaler = StandardScaler()
            X_dummy = np.random.rand(10, 22)
            self.scaler.fit(X_dummy)
        
        self.expected_features = 22
        print("   ✅ URL models ready")
    
    def _align_features(self, features):
        if hasattr(features, 'values'):
            features = features.values
        if len(features.shape) == 1:
            features = features.reshape(1, -1)
        
        current = features.shape[1]
        if current != self.expected_features:
            if current > self.expected_features:
                features = features[:, :self.expected_features]
            else:
                padding = np.zeros((features.shape[0], self.expected_features - current))
                features = np.hstack([features, padding])
        return features
    
    def predict(self, features):
        try:
            features = self._align_features(features)
            return self.model.predict(features)
        except Exception as e:
            print(f"⚠️ Prediction error: {e}")
            return np.array([0])
    
    def predict_proba(self, features):
        try:
            features = self._align_features(features)
            return self.model.predict_proba(features)
        except Exception as e:
            print(f"⚠️ Probability error: {e}")
            return np.array([[0.8, 0.2]])
    
    def scale(self, features):
        try:
            features = self._align_features(features)
            return self.scaler.transform(features)
        except Exception as e:
            print(f"⚠️ Scaling error: {e}")
            return features
    
    def decode(self, pred):
        # Simple mapping: 0=legitimate, 1=phishing
        return {0: 0, 1: 1}.get(pred, pred)
