from transformers import BertTokenizer, BertForSequenceClassification
import torch
import numpy as np
import os

class EmailAnalyzer:
    def __init__(self, model_path=None):
        try:
            if model_path and os.path.exists(model_path):
                self.model = BertForSequenceClassification.from_pretrained(model_path)
                tokenizer_path = os.path.dirname(model_path)
                self.tokenizer = BertTokenizer.from_pretrained(tokenizer_path)
            else:
                self.tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
                self.model = BertForSequenceClassification.from_pretrained('bert-base-uncased', num_labels=2)
                print("Warning: Using default BERT model. For production, please provide a trained model path.")
        except Exception as e:
            print(f"Error loading model: {str(e)}")
            raise

    def preprocess_text(self, text):
        encoded = self.tokenizer.encode_plus(
            text,
            max_length=512,
            padding='max_length',
            truncation=True,
            return_tensors='pt'
        )
        return encoded

    def analyze_email(self, email_content):
        try:
            inputs = self.preprocess_text(email_content)
            with torch.no_grad():
                outputs = self.model(**inputs)
                probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
                prediction = torch.argmax(probabilities, dim=-1)
                confidence = probabilities[0][prediction.item()].item()

            return {
                'is_phishing': bool(prediction.item()),
                'confidence': confidence,
                'raw_scores': probabilities[0].numpy().tolist(),
                'status': 'success'
            }
        except Exception as e:
            return {
                'is_phishing': False,
                'confidence': 0.0,
                'raw_scores': [0.0, 0.0],
                'status': 'error',
                'error_message': str(e)
            }