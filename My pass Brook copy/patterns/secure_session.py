from flask import session, redirect, url_for, request
from flask_login import current_user
from datetime import datetime, timedelta
from functools import wraps
import json
import base64
import hashlib
import hmac
import os

class SecureSessionManager:
    _instance = None
    _secret_key = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SecureSessionManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if not self._initialized:
            self._initialized = True
            if not self._secret_key:
                # Generate a new key for HMAC signing
                self._secret_key = os.urandom(32)
            # Sessions timeout after 30 minutes of inactivity
            self.session_duration = timedelta(minutes=30)
    
    def _encrypt(self, data):
        # Sign session data with HMAC for tamper protection
        json_data = json.dumps(data)
        encoded = base64.b64encode(json_data.encode())
        signature = hmac.new(self._secret_key, encoded, hashlib.sha256).hexdigest()
        return f"{encoded.decode()}:{signature}"
    
    def _decrypt(self, encrypted_data):
        """Decrypt and verify data"""
        try:
            encoded, signature = encrypted_data.split(':')
            expected_sig = hmac.new(self._secret_key, encoded.encode(), hashlib.sha256).hexdigest()
            
            if not hmac.compare_digest(signature, expected_sig):
                return None
                
            json_data = base64.b64decode(encoded).decode()
            return json.loads(json_data)
        except Exception:
            return None
    
    def start_session(self, user_id):
        """Initialize a new secure session"""
        print(f"Starting session for user {user_id}")
        session_data = {
            'user_id': user_id,
            'login_time': datetime.utcnow().isoformat(),
            'last_activity': datetime.utcnow().isoformat()
        }
        session['user_id'] = user_id
        session['login_time'] = datetime.utcnow().isoformat()
        session['last_activity'] = datetime.utcnow().isoformat()
    
    def get_session_data(self):
        """Get decrypted session data"""
        if 'secure_data' not in session:
            return None
            
        return self._decrypt(session['secure_data'])
    
    def update_activity(self):
        """Update last activity timestamp"""
        if self.is_session_valid():
            session['last_activity'] = datetime.utcnow().isoformat()
            print("Activity timestamp updated")
    
    def is_session_valid(self):
        """Check if current session is valid"""
        print("Checking session validity")
        if 'user_id' not in session:
            print("No user_id in session")
            return False
            
        try:
            last_activity = datetime.fromisoformat(session.get('last_activity'))
            time_diff = datetime.utcnow() - last_activity
            is_valid = time_diff < self.session_duration
            print(f"Session valid: {is_valid}")
            return is_valid
        except Exception as e:
            print(f"Error checking session: {str(e)}")
            return False
    
    def end_session(self):
        """End the current session"""
        print("Ending session")
        session.clear()

def secure_session_required(f):
    """Decorator to ensure valid secure session"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(f"Checking secure session for route: {request.endpoint}")
        
        if not current_user.is_authenticated:
            print("User not authenticated")
            return redirect(url_for('login'))
            
        session_manager = SecureSessionManager()
        
        if not session_manager.is_session_valid():
            print("Invalid session")
            session_manager.end_session()
            return redirect(url_for('login'))
            
        session_manager.update_activity()
        return f(*args, **kwargs)
        
    return decorated_function 