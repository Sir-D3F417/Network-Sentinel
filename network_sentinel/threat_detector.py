from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import numpy as np
from collections import deque
import joblib
import os
import logging
import time

class ThreatDetector:
    def __init__(self):
        # Anomaly detection model
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            n_estimators=200,
            max_samples='auto',
            random_state=42
        )
        
        # Classification model for known attack patterns
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        # Feature scaling
        self.scaler = StandardScaler()
        
        # Training data management
        self.training_data = deque(maxlen=10000)
        self.attack_patterns = deque(maxlen=5000)
        self.labels = deque(maxlen=5000)
        
        # Model states
        self.is_anomaly_trained = False
        self.is_classifier_trained = False
        
        # Performance tracking
        self.detection_stats = {
            'true_positives': 0,
            'false_positives': 0,
            'false_negatives': 0,
            'last_training': None
        }
        
        # Add initial state tracking
        self.initial_learning_period = True
        self.min_samples_required = 1000
        self.samples_collected = 0
        
        # Add timestamps for data cleanup
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # 5 minutes
        
        self.load_models()

    def load_models(self):
        """Load pre-trained models if available"""
        try:
            if os.path.exists('models/anomaly_model.joblib'):
                self.isolation_forest = joblib.load('models/anomaly_model.joblib')
                self.is_anomaly_trained = True
                
            if os.path.exists('models/classifier_model.joblib'):
                self.classifier = joblib.load('models/classifier_model.joblib')
                self.is_classifier_trained = True
                
            if os.path.exists('models/scaler.joblib'):
                self.scaler = joblib.load('models/scaler.joblib')
                
        except Exception as e:
            logging.error(f"Error loading models: {str(e)}")

    def save_models(self):
        """Save trained models"""
        try:
            os.makedirs('models', exist_ok=True)
            joblib.dump(self.isolation_forest, 'models/anomaly_model.joblib')
            joblib.dump(self.classifier, 'models/classifier_model.joblib')
            joblib.dump(self.scaler, 'models/scaler.joblib')
        except Exception as e:
            logging.error(f"Error saving models: {str(e)}")

    def is_anomalous(self, features):
        """Legacy method for compatibility - redirects to analyze_packet"""
        anomaly_score, _ = self.analyze_packet(features)
        return anomaly_score

    def analyze_packet(self, features, known_attack=None):
        """Comprehensive packet analysis using both models"""
        try:
            if len(features) == 0:
                return False, None

            # Preprocess features
            features = np.array(features).reshape(1, -1)
            
            # Store for training
            self.training_data.append(features.flatten())
            self.samples_collected += 1
            
            if known_attack is not None:
                self.attack_patterns.append(features.flatten())
                self.labels.append(known_attack)

            # During initial learning period, don't try to classify
            if self.initial_learning_period:
                if self.samples_collected >= self.min_samples_required:
                    self._initial_training()
                    self.initial_learning_period = False
                return False, "Learning"

            # Only transform if scaler is fitted
            if self.is_anomaly_trained:
                scaled_features = self.scaler.transform(features)
            else:
                return False, "Not trained"

            # Check training needs
            self._check_training_needs()

            # Only perform detection if models are trained
            anomaly_score = self._detect_anomaly(scaled_features) if self.is_anomaly_trained else False
            attack_type = self._classify_attack(scaled_features) if self.is_classifier_trained else None

            return anomaly_score, attack_type

        except Exception as e:
            logging.error(f"Error in packet analysis: {str(e)}")
            return False, None

    def _initial_training(self):
        """Perform initial training of models"""
        try:
            logging.info("Starting initial model training...")
            self._train_anomaly_detector()
            if len(set(self.labels)) > 1:
                self._train_classifier()
            logging.info("Initial training completed")
        except Exception as e:
            logging.error(f"Error in initial training: {str(e)}")

    def _detect_anomaly(self, features):
        """Detect anomalies using Isolation Forest"""
        if self.is_anomaly_trained:
            try:
                prediction = self.isolation_forest.predict(features)
                return prediction[0] == -1
            except Exception as e:
                logging.error(f"Error in anomaly detection: {str(e)}")
        return False

    def _classify_attack(self, features):
        """Classify attack type using Random Forest"""
        if not self.is_classifier_trained:
            return None
            
        try:
            prediction = self.classifier.predict(features)
            return prediction[0]
        except Exception as e:
            # Only log error if not in initial learning period
            if not self.initial_learning_period:
                logging.debug(f"Classification not yet available: {str(e)}")
            return None

    def _check_training_needs(self):
        """Check and trigger model training if needed"""
        current_time = time.time()
        
        # Periodic data cleanup
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_data()
            self.last_cleanup = current_time
        
        # Train anomaly detector
        if len(self.training_data) >= 1000 and not self.is_anomaly_trained:
            self._train_anomaly_detector()
            
        # Train classifier
        if (len(self.attack_patterns) >= 500 and not self.is_classifier_trained and 
            len(set(self.labels)) > 1):
            self._train_classifier()
            
        # Periodic retraining
        if (self.detection_stats['last_training'] and 
            current_time - self.detection_stats['last_training'] > 3600):  # Retrain every hour
            self._retrain_models()

    def _train_anomaly_detector(self):
        """Train the anomaly detection model"""
        try:
            X = np.array(list(self.training_data))
            self.scaler.fit(X)
            X_scaled = self.scaler.transform(X)
            self.isolation_forest.fit(X_scaled)
            self.is_anomaly_trained = True
            self.detection_stats['last_training'] = time.time()
            self.save_models()
        except Exception as e:
            logging.error(f"Error training anomaly detector: {str(e)}")

    def _train_classifier(self):
        """Train the attack classifier"""
        try:
            X = np.array(list(self.attack_patterns))
            y = np.array(list(self.labels))
            X_scaled = self.scaler.transform(X)
            self.classifier.fit(X_scaled, y)
            self.is_classifier_trained = True
            self.save_models()
        except Exception as e:
            logging.error(f"Error training classifier: {str(e)}")

    def _cleanup_old_data(self):
        """Clean up old training data to prevent memory leaks"""
        try:
            # Keep only recent data within a sliding window
            cutoff_time = time.time() - 3600  # 1 hour window
            
            # Clean training data
            if hasattr(self, 'training_timestamps'):
                while (self.training_timestamps and 
                       self.training_timestamps[0] < cutoff_time):
                    self.training_timestamps.popleft()
                    self.training_data.popleft()
            
            # Clean attack patterns
            if hasattr(self, 'attack_timestamps'):
                while (self.attack_timestamps and 
                       self.attack_timestamps[0] < cutoff_time):
                    self.attack_timestamps.popleft()
                    self.attack_patterns.popleft()
                    self.labels.popleft()
                    
            logging.debug("Completed periodic data cleanup")
            
        except Exception as e:
            logging.error(f"Error during data cleanup: {str(e)}")
