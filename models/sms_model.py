# models/sms_model.py
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import os

class SMSModel:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.label_map = {0: 0, 1: 1}
        self.is_fitted = False
        self.expected_features = 14
        
        # Try to load model
        model_paths = [
            '/home/cheezboi/models/sms_spam_detector_v1.pkl',
            'models/sms_spam_detector_v1.pkl',
            '../models/sms_spam_detector_v1.pkl',
            '/home/cheezboi/Tlhagiso/models/sms_spam_detector_v1.pkl'
        ]
        
        for path in model_paths:
            try:
                if os.path.exists(path):
                    self.model = joblib.load(path)
                    self.is_fitted = True
                    print(f"✅ SMS Model loaded from: {path}")
                    break
            except:
                pass
        
        if self.model is None:
            print("⚠️ Using fallback SMS model")
            from sklearn.naive_bayes import MultinomialNB
            self.model = MultinomialNB()
            X_dummy = np.random.rand(10, self.expected_features)
            y_dummy = np.random.randint(0, 2, 10)
            self.model.fit(X_dummy, y_dummy)
            self.is_fitted = True
    
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
    
    def scale(self, features):
        """Scale features - FIXED: returns scaled features"""
        try:
            features = self._align_features(features)
            if not hasattr(self.scaler, 'mean_'):
                self.scaler.fit(features)
            return self.scaler.transform(features)
        except Exception as e:
            print(f"⚠️ Scaling error: {e}, returning raw features")
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
    
    def decode(self, pred):
        return self.label_map.get(pred, pred)
