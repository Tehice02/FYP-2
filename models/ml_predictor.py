"""
ML Predictor Engine - FIXED VERSION
Loads trained XGBoost models and performs binary/multiclass predictions
Implements severity mapping and confidence calculation
"""

import os
import json
import numpy as np
import joblib
import warnings
from utils.logger import log_error

# Suppress sklearn feature names warning
warnings.filterwarnings('ignore', message='X does not have valid feature names')


class MLPredictor:
    """
    Loads and uses trained XGBoost models for intrusion detection
    Supports both binary (benign vs attack) and multiclass (11 attack types)
    """
    
    def __init__(self):
        """Initialize ML predictor"""
        self.model_dir = os.path.join(os.path.dirname(__file__), 'model_files')
        
        # Models
        self.binary_model = None
        self.multiclass_model = None
        
        # Scalers for feature normalization
        self.scaler_binary = None
        self.scaler_multiclass = None
        
        # Label encoder for attack class names
        self.label_encoder = None
        
        # Feature names
        self.feature_names = None
        
        # Loading status flag
        self.is_loaded = False
        
        # Severity mapping
        self.severity_map = {
            'Benign': 'SAFE',
            'Analysis': 'LOW',
            'Reconnaissance': 'LOW',
            'Fuzzers': 'MEDIUM',
            'Generic': 'MEDIUM',
            'DoS': 'HIGH',
            'Exploits': 'HIGH',
            'Backdoor': 'CRITICAL',
            'Shellcode': 'CRITICAL',
            'Worms': 'CRITICAL'
        }
        
        # Attack class names (in order expected by multiclass model)
        self.attack_classes = [
            'Benign', 'Exploits', 'Fuzzers', 'Generic', 'Reconnaissance',
            'DoS', 'Backdoor', 'Shellcode', 'Analysis', 'Worms'
        ]
    
    def load_models(self):
        """Load trained XGBoost models and scalers"""
        try:
            # Check if model directory exists
            if not os.path.exists(self.model_dir):
                log_error(f"Model directory not found: {self.model_dir}", component='MLPredictor')
                return False
            
            # Load binary model
            binary_model_path = os.path.join(self.model_dir, 'xgboost_binary.pkl')
            if os.path.exists(binary_model_path):
                self.binary_model = joblib.load(binary_model_path)
                print(f"✓ Binary model loaded from {binary_model_path}")
            else:
                log_error(f"Binary model not found: {binary_model_path}", component='MLPredictor')
            
            # Load multiclass model
            multiclass_model_path = os.path.join(self.model_dir, 'xgboost_multiclass.pkl')
            if os.path.exists(multiclass_model_path):
                self.multiclass_model = joblib.load(multiclass_model_path)
                print(f"✓ Multiclass model loaded from {multiclass_model_path}")
            else:
                log_error(f"Multiclass model not found: {multiclass_model_path}", component='MLPredictor')
            
            # Load binary scaler
            scaler_binary_path = os.path.join(self.model_dir, 'scaler_binary.pkl')
            if os.path.exists(scaler_binary_path):
                self.scaler_binary = joblib.load(scaler_binary_path)
                print(f"✓ Binary scaler loaded")
            else:
                log_error(f"Binary scaler not found: {scaler_binary_path}", component='MLPredictor')
            
            # Load multiclass scaler
            scaler_multiclass_path = os.path.join(self.model_dir, 'scaler_multiclass.pkl')
            if os.path.exists(scaler_multiclass_path):
                self.scaler_multiclass = joblib.load(scaler_multiclass_path)
                print(f"✓ Multiclass scaler loaded")
            else:
                log_error(f"Multiclass scaler not found: {scaler_multiclass_path}", component='MLPredictor')
            
            # Load label encoder for attack class names
            label_encoder_path = os.path.join(self.model_dir, 'label_encoder_multiclass.pkl')
            if os.path.exists(label_encoder_path):
                self.label_encoder = joblib.load(label_encoder_path)
                print(f"✓ Label encoder loaded")
            else:
                log_error(f"Label encoder not found: {label_encoder_path}", component='MLPredictor')
            
            # Load feature names
            feature_names_path = os.path.join(self.model_dir, 'feature_names.json')
            if os.path.exists(feature_names_path):
                with open(feature_names_path, 'r') as f:
                    self.feature_names = json.load(f)
                print(f"✓ Feature names loaded ({len(self.feature_names)} features)")
            else:
                log_error(f"Feature names not found: {feature_names_path}", component='MLPredictor')
            
            # Verify we have all required models
            all_loaded = all([
                self.binary_model is not None,
                self.multiclass_model is not None,
                self.scaler_binary is not None,
                self.scaler_multiclass is not None,
                self.label_encoder is not None,
                self.feature_names is not None
            ])
            
            if all_loaded:
                print("✓ All ML models loaded successfully")
                self.is_loaded = True
                return True
            else:
                log_error("Not all models loaded successfully", component='MLPredictor')
                self.is_loaded = False
                return False
        
        except Exception as e:
            log_error(f"Error loading models: {str(e)}", component='MLPredictor')
            self.is_loaded = False
            return False
    
    def predict(self, features_array):
        """
        Make prediction on flow features
        Uses binary model first, then multiclass if attack detected
        
        Args:
            features_array: numpy array of 34 features
            
        Returns:
            Dictionary with prediction results or None on error
        """
        try:
            if self.binary_model is None or self.multiclass_model is None:
                log_error("Models not loaded", component='MLPredictor')
                return None
            
            # Ensure features are proper shape and type
            if features_array.ndim == 1:
                features_array = features_array.reshape(1, -1)
            
            features_array = features_array.astype(np.float32)
            
            # Step 1: Binary classification (Benign vs Attack)
            if self.scaler_binary is not None:
                features_scaled_binary = self.scaler_binary.transform(features_array)
            else:
                features_scaled_binary = features_array
            
            # Get binary prediction
            binary_pred = self.binary_model.predict(features_scaled_binary)[0]
            binary_pred_proba = self.binary_model.predict_proba(features_scaled_binary)[0]
            
            # Extract probabilities (assuming 0=Benign, 1=Attack for binary)
            prob_benign = float(binary_pred_proba[0])
            prob_attack = float(binary_pred_proba[1] if len(binary_pred_proba) > 1 else 0)
            
            is_attack = bool(binary_pred == 1)
            
            # Default result if classified as Benign
            if not is_attack:
                return {
                    'is_attack': False,
                    'attack_type': 'Benign',
                    'confidence_score': round(prob_benign * 100, 2),
                    'severity': 'SAFE'
                }
            
            # Step 2: Multiclass classification (which type of attack)
            if self.scaler_multiclass is not None:
                features_scaled_multiclass = self.scaler_multiclass.transform(features_array)
            else:
                features_scaled_multiclass = features_array
            
            # Get multiclass prediction
            multiclass_pred = self.multiclass_model.predict(features_scaled_multiclass)[0]
            multiclass_pred_proba = self.multiclass_model.predict_proba(features_scaled_multiclass)[0]
            
            # Get attack type and confidence
            if hasattr(self.label_encoder, 'inverse_transform'):
                try:
                    attack_type = self.label_encoder.inverse_transform([multiclass_pred])[0]
                except:
                    # If label encoder fails, use direct class index
                    attack_type = self.attack_classes[int(multiclass_pred)] if int(multiclass_pred) < len(self.attack_classes) else 'Unknown'
            else:
                attack_type = self.attack_classes[int(multiclass_pred)] if int(multiclass_pred) < len(self.attack_classes) else 'Unknown'
            
            # Get confidence as max probability (already in 0-1 range, convert to percentage)
            confidence_score = float(np.max(multiclass_pred_proba)) * 100
            
            # Get severity from attack type
            severity = self.severity_map.get(attack_type, 'MEDIUM')
            
            return {
                'is_attack': True,
                'attack_type': attack_type,
                'confidence_score': round(confidence_score, 2),
                'severity': severity
            }
        
        except Exception as e:
            log_error(f"Prediction error: {str(e)}", component='MLPredictor')
            return None
    
    def predict_batch(self, features_batch):
        """
        Make predictions on a batch of flows
        
        Args:
            features_batch: numpy array of shape (N, 34)
            
        Returns:
            List of prediction dictionaries
        """
        try:
            predictions = []
            for i in range(len(features_batch)):
                pred = self.predict(features_batch[i])
                predictions.append(pred)
            return predictions
        except Exception as e:
            log_error(f"Batch prediction error: {str(e)}", component='MLPredictor')
            return None
    
    def get_model_info(self):
        """Get information about loaded models"""
        info = {
            'binary_model_loaded': self.binary_model is not None,
            'multiclass_model_loaded': self.multiclass_model is not None,
            'scaler_binary_loaded': self.scaler_binary is not None,
            'scaler_multiclass_loaded': self.scaler_multiclass is not None,
            'label_encoder_loaded': self.label_encoder is not None,
            'feature_names_loaded': self.feature_names is not None,
            'num_features': len(self.feature_names) if self.feature_names else 0,
            'attack_classes': self.attack_classes
        }
        return info


class ModelDriftDetector:
    """Detects model drift by monitoring prediction patterns"""
    
    def __init__(self):
        """Initialize drift detector"""
        self.prediction_history = []
        self.max_history = 100
        self.drift_threshold = 0.3  # 30% change
        
    def check_drift(self, prediction):
        """
        Check for model drift in predictions
        
        Args:
            prediction: Dictionary with prediction information
            
        Returns:
            Dictionary with drift detection status
        """
        try:
            self.prediction_history.append(prediction)
            
            # Keep only recent history
            if len(self.prediction_history) > self.max_history:
                self.prediction_history = self.prediction_history[-self.max_history:]
            
            # Need at least 20 predictions to detect drift
            if len(self.prediction_history) < 20:
                return {
                    'drift_detected': False,
                    'message': 'Insufficient data for drift detection'
                }
            
            # Calculate attack rate in recent window
            recent_window = self.prediction_history[-20:]
            recent_attack_rate = sum(1 for p in recent_window if p.get('is_attack', False)) / len(recent_window)
            
            # Calculate attack rate in older window
            older_window = self.prediction_history[-40:-20] if len(self.prediction_history) >= 40 else self.prediction_history[:20]
            older_attack_rate = sum(1 for p in older_window if p.get('is_attack', False)) / len(older_window) if older_window else 0
            
            # Check for significant change
            rate_change = abs(recent_attack_rate - older_attack_rate)
            
            if rate_change > self.drift_threshold:
                return {
                    'drift_detected': True,
                    'message': f'Attack rate changed from {older_attack_rate:.1%} to {recent_attack_rate:.1%}',
                    'rate_change': rate_change
                }
            
            return {
                'drift_detected': False,
                'message': 'No significant drift detected'
            }
        
        except Exception as e:
            log_error(f"Error checking drift: {str(e)}", component='ModelDriftDetector')
            return {
                'drift_detected': False,
                'message': f'Error: {str(e)}'
            }
