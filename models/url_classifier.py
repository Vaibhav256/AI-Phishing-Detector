from sklearn.ensemble import RandomForestClassifier
import numpy as np
import re
from urllib.parse import urlparse
import pandas as pd
import joblib
import os

class URLClassifier:
    def __init__(self, model_path=None):
        try:
            self.model = None
            if model_path and os.path.exists(model_path):
                self.model = joblib.load(model_path)
            else:
                self.model = RandomForestClassifier(n_estimators=100, random_state=42)
                self._train_model()
        except Exception as e:
            print(f"Error loading model: {str(e)}")
            raise

    def _train_model(self):
        urls = [
            "http://legitimate-bank.com",
            "http://suspicious-site.xyz",
            "https://secure-payment.com",
            "http://phishing-attempt.net",
            "https://genuine-service.com",
            "http://malicious-site.top"
        ]
        features = np.array([self.extract_features(url) for url in urls])
        labels = np.array([0, 1, 0, 1, 0, 1])
        self.model.fit(features, labels)

    def extract_features(self, url):
        try:
            features = {}
            parsed = urlparse(url)

            features['length'] = len(url)
            features['num_dots'] = url.count('.')
            features['num_digits'] = sum(c.isdigit() for c in url)
            features['num_special'] = len(re.findall('[^A-Za-z0-9.]', url))
            features['has_http'] = int(url.startswith('http://'))
            features['has_https'] = int(url.startswith('https://'))
            features['domain_length'] = len(parsed.netloc)
            features['num_hyphens'] = url.count('-')
            features['num_underscores'] = url.count('_')
            features['num_parameters'] = len(parsed.query.split('&')) if parsed.query else 0
            features['has_port'] = int(bool(parsed.port))
            features['path_length'] = len(parsed.path)
            features['num_fragments'] = int(bool(parsed.fragment))

            return np.array(list(features.values())).reshape(1, -1)[0]
        except Exception as e:
            print(f"Error extracting features: {str(e)}")
            raise

    def predict_url(self, url):
        try:
            features = self.extract_features(url).reshape(1, -1)
            prediction = self.model.predict_proba(features)
            return {
                'is_malicious': bool(prediction[0][1] > 0.5),
                'confidence': float(max(prediction[0])),
                'raw_scores': prediction[0].tolist(),
                'status': 'success'
            }
        except Exception as e:
            return {
                'error': f"Failed to analyze URL: {str(e)}",
                'is_malicious': False,
                'confidence': 0.0,
                'raw_scores': [0.0, 0.0],
                'status': 'error'
            }

    def save_model(self, path):
        """Save the trained model to disk"""
        try:
            joblib.dump(self.model, path)
            print(f"Model saved successfully to {path}")
            return True
        except Exception as e:
            print(f"Error saving model: {str(e)}")
            return False