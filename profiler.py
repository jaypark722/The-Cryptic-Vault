"""
Lightweight profiling and supervised classifier for attacker sessions.

ProfileEngine can:
- build feature vectors from SSH session rows and associated commands
- train a supervised classifier if scikit-learn is available
- fall back to a simple rule-based classifier when sklearn is missing
- predict labels for SSH sessions (returns label + optional score)

The engine intentionally keeps dependencies optional to avoid forcing heavy installs.
"""
from typing import List, Dict, Any, Tuple
import pickle
import time
import logging

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    SKLEARN_AVAILABLE = True
except Exception:
    SKLEARN_AVAILABLE = False

from honeypot_logger import HoneypotLogger

logger = logging.getLogger(__name__)


class ProfileEngine:
    """Lightweight profiling engine with an optional sklearn-based classifier.

    Methods implemented here provide the small API that the Flask admin expects:
      - build_dataset(limit)
      - train(limit)
      - predict_for_ssh_sessions(sessions)
      - save_model(path)
      - load_model(path)
    If scikit-learn is not available, the engine falls back to rule-based predictions.
    """

    def __init__(self, logger: HoneypotLogger = None, db_path: str = None):
        self.logger = logger if logger is not None else HoneypotLogger(db_path=db_path or 'database/honeypot_logs.db')
        self.model = None
        self.feature_names = [
            'command_count', 'distinct_commands', 'contains_cryptic_cat', 'contains_find_db',
            'session_duration', 'has_downloads', 'has_purchases'
        ]

    def _features_from_ssh_session(self, s: Dict[str, Any]) -> List[float]:
        session_id = s.get('session_id')
        commands = self.logger.get_ssh_commands(session_id=session_id, limit=1000)
        command_texts = [c.get('command', '') for c in commands]
        distinct_commands = len(set(command_texts))
        contains_cryptic_cat = int(any('cryptic.xlsx' in c for c in command_texts))
        contains_find_db = int(any('find ' in c and '.db' in c for c in command_texts))
        command_count = int(s.get('command_count', 0))
        try:
            duration = float(self.logger.get_session_duration(session_id))
        except Exception:
            duration = 0.0
        # cross-correlate web sessions by same session_id if present
        web_sessions = self.logger.get_all_sessions(limit=10000)
        web_map = {w['session_id']: w for w in web_sessions}
        has_downloads = 0
        has_purchases = 0
        if session_id in web_map:
            has_downloads = int(web_map[session_id].get('downloads_attempted', 0) > 0)
            has_purchases = int(web_map[session_id].get('purchases_made', 0) > 0)

        return [command_count, distinct_commands, contains_cryptic_cat, contains_find_db, duration, has_downloads, has_purchases]

    def build_dataset(self, limit=500) -> Tuple[List[List[float]], List[Any], List[str]]:
        """Build feature matrix X and label vector y from DB. Labels are taken from ssh_sessions.label when present.
        Returns X, y, session_ids
        """
        sessions = self.logger.get_all_ssh_sessions(limit=limit)
        X = []
        y = []
        session_ids = []
        for s in sessions:
            X.append(self._features_from_ssh_session(s))
            y.append(s.get('label'))
            session_ids.append(s.get('session_id'))
        return X, y, session_ids

    def train(self, limit=1000) -> Dict[str, Any]:
        """Train a RandomForest classifier from labeled SSH sessions.

        Returns a dict with keys: success (bool), message (str), metrics (optional)
        """
        X, y, session_ids = self.build_dataset(limit=limit)
        # Keep only labeled rows
        labeled = [(x, label) for x, label in zip(X, y) if label is not None]
        if not labeled:
            return {'success': False, 'message': 'No labeled SSH sessions found'}

        X_l = [row for row, label in labeled]
        y_l = [label for row, label in labeled]

        if not SKLEARN_AVAILABLE:
            return {'success': False, 'message': 'scikit-learn not available in this environment'}

        try:
            X_train, X_test, y_train, y_test = train_test_split(X_l, y_l, test_size=0.2, random_state=42)
            clf = RandomForestClassifier(n_estimators=100, random_state=42)
            clf.fit(X_train, y_train)
            score = clf.score(X_test, y_test)
            self.model = clf
            return {'success': True, 'message': 'Model trained', 'metrics': {'test_accuracy': float(score)}}
        except Exception as e:
            logger.exception('Training failed')
            return {'success': False, 'message': f'Training failed: {e}'}

    def _rule_based_label(self, features: List[float]) -> Tuple[str, float]:
        """Simple deterministic rule-based fallback.

        Returns (label, score) where score is a confidence in [0,1].
        """
        command_count, distinct_commands, contains_cryptic_cat, contains_find_db, duration, has_downloads, has_purchases = features
        # Heuristic rules (tunable): presence of cryptic cat (data file) is suspicious, find .db indicates reconnaissance
        score = 0.0
        if contains_cryptic_cat:
            score += 0.6
        if contains_find_db:
            score += 0.2
        if command_count > 20:
            score += 0.1
        if has_downloads:
            score += 0.1

        label = 'malicious' if score >= 0.4 else 'benign'
        return label, min(1.0, score)

    def predict_for_ssh_sessions(self, sessions: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Predict labels for a list of ssh session dicts.

        Returns mapping: session_id -> {'label': str, 'score': float}
        """
        results = {}
        for s in sessions:
            sid = s.get('session_id')
            feats = self._features_from_ssh_session(s)
            if self.model is not None and SKLEARN_AVAILABLE:
                try:
                    pred = self.model.predict([feats])[0]
                    prob = None
                    if hasattr(self.model, 'predict_proba'):
                        prob_list = self.model.predict_proba([feats])[0]
                        # If classifier classes are strings, map predicted class to its probability
                        try:
                            cls_index = list(self.model.classes_).index(pred)
                            prob = float(prob_list[cls_index])
                        except Exception:
                            prob = float(max(prob_list))
                    results[sid] = {'label': str(pred), 'score': float(prob) if prob is not None else 0.0}
                except Exception:
                    logger.exception('Model prediction failed, falling back to rules')
                    lab, sc = self._rule_based_label(feats)
                    results[sid] = {'label': lab, 'score': sc}
            else:
                lab, sc = self._rule_based_label(feats)
                results[sid] = {'label': lab, 'score': sc}

        return results

    def save_model(self, path: str) -> bool:
        try:
            with open(path, 'wb') as fh:
                pickle.dump({'model': self.model, 'feature_names': self.feature_names}, fh)
            return True
        except Exception:
            logger.exception('Failed to save model')
            return False

    def load_model(self, path: str) -> bool:
        try:
            with open(path, 'rb') as fh:
                payload = pickle.load(fh)
            self.model = payload.get('model')
            self.feature_names = payload.get('feature_names', self.feature_names)
            return True
        except Exception:
            logger.exception('Failed to load model')
            return False

